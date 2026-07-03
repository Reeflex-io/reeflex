<?php
/**
 * conformance-demo.php — drives the REAL Reeflex mu-plugin against a LIVE reeflex-core,
 * with WordPress stubbed (see wp-stubs.php). It exercises the primary blocking seam
 * (Hook A: wp_register_ability_args -> wrapped permission_callback) end to end:
 *
 *     intercept  ->  normalize (Action Envelope)  ->  POST /v1/decide  ->  enforce
 *
 * For each scenario it asserts the enforced outcome against an expected value and
 * prints PASS/FAIL. This doubles as a reproducible demo of governance: a destructive
 * agent action in WordPress is blocked before it can run.
 *
 * It does NOT need a WordPress install. The in-WordPress demo (hooks firing inside a
 * real WP, before/after on actual posts) is described in ../DEMO.md.
 *
 * Usage:
 *   php tests/conformance-demo.php [core_url]
 *     core_url defaults to http://127.0.0.1:8099
 *     point it at a DEAD port (e.g. http://127.0.0.1:9) to prove fail-closed
 *
 *   OBSERVE mode (HIL-DESIGN §8):
 *     REEFLEX_MODE=observe php tests/conformance-demo.php [core_url]
 *       All scenarios must resolve to PROCEED — regardless of the would-be verdict.
 *     REEFLEX_MODE=observe php tests/conformance-demo.php http://127.0.0.1:9
 *       Core down + observe → all still PROCEED; each outage is audited (fail-open).
 *
 * Exit code 0 = all scenarios pass, 1 = a scenario failed, 2 = harness error.
 *
 * @package ReeflexWordPress
 */

declare( strict_types=1 );

$adapter_dir = dirname( __DIR__ );                      // the reeflex-wordpress/ directory
$core_url    = $argv[1] ?? 'http://127.0.0.1:8099';

putenv( 'REEFLEX_HARNESS_TMP=' . sys_get_temp_dir() );
require __DIR__ . '/wp-stubs.php';

if ( ! defined( 'REEFLEX_CORE_URL' ) ) { define( 'REEFLEX_CORE_URL', $core_url ); }
if ( ! defined( 'REEFLEX_ENV' ) )      { define( 'REEFLEX_ENV', 'production' ); }
if ( ! defined( 'REEFLEX_AUDIT_LOG' ) ){ define( 'REEFLEX_AUDIT_LOG', sys_get_temp_dir() . '/reeflex-harness-audit.jsonl' ); }
// REEFLEX_MODE: honour env var so observe tests can be run without editing this file.
// e.g.:  REEFLEX_MODE=observe php tests/conformance-demo.php <core_url>
if ( ! defined( 'REEFLEX_MODE' ) )     { define( 'REEFLEX_MODE', getenv( 'REEFLEX_MODE' ) ?: 'enforce' ); }

require $adapter_dir . '/reeflex-gate/class-reeflex-config.php';
require $adapter_dir . '/reeflex-gate/class-reeflex-normalizer.php';
require $adapter_dir . '/reeflex-gate/class-reeflex-core-client.php';
require $adapter_dir . '/reeflex-gate/class-reeflex-audit.php';
require $adapter_dir . '/reeflex-gate/class-reeflex-gate.php';

Reeflex_Gate::register_hooks();
$hookA = $GLOBALS['__filters']['wp_register_ability_args'][0] ?? null;
if ( ! $hookA ) { fwrite( STDERR, "FATAL: Hook A (wp_register_ability_args) not registered\n" ); exit( 2 ); }

/** Run an ability through the wrapped permission_callback; return [outcome, error_code]. */
function run_ability( $hookA, string $ability, array $input ): array {
	$args    = array( 'permission_callback' => static function ( $i = null ) { return true; } );
	$wrapped = $hookA( $args, $ability );
	$result  = ( $wrapped['permission_callback'] )( $input );

	if ( true === $result )            { return array( 'PROCEED', 'allow' ); }
	if ( $result instanceof WP_Error ) { return array( 'BLOCKED', $result->get_error_code() ); }
	return array( 'UNEXPECTED', var_export( $result, true ) );
}

// label => [ability, input, expected_code]  ('allow' = proceed)
$scenarios = array(
	'1. read a post'                                 => array( 'core/get-post',               array( 'id' => 42 ),                                                              'allow' ),
	'2. delete 1 post (soft / trash)'                => array( 'core/delete-post',            array( 'ids' => array( 42 ) ),                                                    'allow' ),
	'3. bulk delete 50 posts FORCE'                  => array( 'core/delete-post',            array( 'ids' => range( 1, 50 ), 'force_delete' => true ),                         'reeflex_hold' ),
	'4. bulk SOFT delete 25 (>=20 -> irreversible)'  => array( 'core/delete-post',            array( 'ids' => range( 1, 25 ) ),                                                 'reeflex_hold' ),
	'5. delete site-wide data FORCE (systemic)'      => array( 'core/delete-site-wide-data',  array( 'force_delete' => true ),                                                  'reeflex_denied' ),
	'6. forged _reeflex_approved=1 (no bypass)'      => array( 'core/delete-post',            array( 'ids' => range( 1, 50 ), 'force_delete' => true, '_reeflex_approved' => '1' ), 'reeflex_hold' ),
	'7. verb collision: fetch-and-delete 30 posts'   => array( 'core/fetch-and-delete-posts', array( 'ids' => range( 1, 30 ) ),                                                 'reeflex_hold' ),
);

// A dead/refused port means every decision must fail-closed (enforce) or
// fail-open/proceed (observe — core outage does NOT block the site).
$fail_closed_run = (bool) preg_match( '#:9(\D|$)#', $core_url ) && false === strpos( $core_url, ':8099' );

// Determine running mode (constant is now defined above from env var or default).
$observe_mode = ( 'observe' === REEFLEX_MODE );

$bar = str_repeat( '-', 100 );
echo $bar . "\n";
$mode_label = $observe_mode ? '   MODE=observe (all PROCEED expected)' : '';
$fc_label   = ( ! $observe_mode && $fail_closed_run ) ? '   (expect fail-closed everywhere)' : '';
$down_label = ( $observe_mode && $fail_closed_run )   ? '   core DOWN — outage audited, site proceeds' : '';
printf( "reeflex-wordpress conformance demo   CORE=%s%s%s%s\n", $core_url, $mode_label, $fc_label, $down_label );
echo $bar . "\n";
printf( "%-50s | %-26s | %s\n", 'SCENARIO (agent action in WordPress)', 'ENFORCED OUTCOME', 'RESULT' );
echo $bar . "\n";

$all_pass = true;
foreach ( $scenarios as $label => $spec ) {
	list( $ability, $input, $expected ) = $spec;

	if ( $observe_mode ) {
		// In observe mode EVERY scenario must PROCEED — regardless of would-be verdict
		// and regardless of whether core is reachable.
		$expected = 'allow';
	} elseif ( $fail_closed_run ) {
		// Enforce + dead core: every decision must fail-closed.
		$expected = 'reeflex_unavailable';
	}

	list( $outcome, $code ) = run_ability( $hookA, $ability, $input );
	$got  = ( 'PROCEED' === $outcome ) ? 'allow' : $code;
	$pass = ( $got === $expected );
	$all_pass = $all_pass && $pass;

	printf( "%-50s | %-26s | %s\n", $label, $outcome . ' (' . $code . ')', $pass ? 'PASS' : 'FAIL expected=' . $expected );
}
echo $bar . "\n";
echo ( $all_pass ? "ALL SCENARIOS PASS" : "SOME SCENARIOS FAILED" ) . "\n";
exit( $all_pass ? 0 : 1 );
