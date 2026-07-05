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
require $adapter_dir . '/reeflex-gate/class-reeflex-holds-store.php';
require $adapter_dir . '/reeflex-gate/class-reeflex-gate.php';

Reeflex_Gate::register_hooks();
$hookA = $GLOBALS['__filters']['wp_register_ability_args'][0] ?? null;
if ( ! $hookA ) { fwrite( STDERR, "FATAL: Hook A (wp_register_ability_args) not registered\n" ); exit( 2 ); }

/**
 * Register (once) a demo ability through the REAL wp_register_ability_args filter
 * (Hook A wraps its permission_callback at registration time, exactly as in
 * production), and return the WP_Ability object. Idempotent per ability name so
 * scenarios that reuse an ability (e.g. multiple 'core/delete-post' calls) share
 * one registered permission_callback, matching how WordPress registers abilities
 * once at bootstrap.
 */
function get_or_register_demo_ability( string $ability ): WP_Ability {
	$existing = wp_get_ability( $ability );
	if ( null !== $existing ) {
		return $existing;
	}
	return WP_Abilities_Registry::get_instance()->register(
		$ability,
		array(
			'permission_callback' => static function ( $i = null ) { return true; },
			'execute_callback'    => static function ( $i ) use ( $ability ) {
				return array( 'reeflex_harness_executed' => true, 'ability' => $ability, 'input' => $i );
			},
		)
	);
}

/**
 * Run an ability through the wrapped permission_callback; return [outcome, error_code].
 *
 * Calls Reeflex_Gate::reset_request_cache() first (fan-out fix, 0.1.7): this
 * harness models each top-level scenario as its OWN incoming HTTP request, so
 * each must start with an empty request-scoped decision memo — otherwise two
 * scenarios that happen to normalize to the SAME canonical envelope (e.g.
 * scenario 3's bulk force-delete and scenario 6's forged-approval replay of
 * the identical ids+force_delete) would collapse into one decide()/hold, which
 * is the correct production behaviour for repeat invocations WITHIN one real
 * request but wrong for two intentionally-distinct scenarios in this harness.
 */
function run_ability( string $ability, array $input ): array {
	Reeflex_Gate::reset_request_cache();
	$result = get_or_register_demo_ability( $ability )->execute( $input );

	if ( true === $result )            { return array( 'PROCEED', 'allow' ); }
	if ( is_array( $result ) )         { return array( 'PROCEED', 'allow' ); } // ability executed successfully
	if ( $result instanceof WP_Error ) { return array( 'BLOCKED', $result->get_error_code() ); }
	return array( 'UNEXPECTED', var_export( $result, true ) );
}

/**
 * Like run_ability() but returns the raw execute() result (array on success, WP_Error on block).
 *
 * Also resets the request-scoped decision memo first — see run_ability()'s
 * docblock. This is what keeps H1 and create_fresh_hold()'s H8/H9/H10 calls
 * (which share H1's exact magnitude.count=45 + force_delete=true canonical
 * envelope) from colliding into a single memoized hold.
 */
function run_ability_full( string $ability, array $input ) {
	Reeflex_Gate::reset_request_cache();
	return get_or_register_demo_ability( $ability )->execute( $input );
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

	list( $outcome, $code ) = run_ability( $ability, $input );
	$got  = ( 'PROCEED' === $outcome ) ? 'allow' : $code;
	$pass = ( $got === $expected );
	$all_pass = $all_pass && $pass;

	printf( "%-50s | %-26s | %s\n", $label, $outcome . ' (' . $code . ')', $pass ? 'PASS' : 'FAIL expected=' . $expected );
}
echo $bar . "\n";
echo ( $all_pass ? "ALL SCENARIOS PASS" : "SOME SCENARIOS FAILED" ) . "\n";

// ============================================================================
// HIL Phase 2 (T1) — hold-aware resubmission: hold -> resolve -> resubmit -> executed
// ============================================================================
// Only meaningful in ENFORCE mode against a REACHABLE core that supports the
// holds queue (core >= v0.1.5) — observe mode never enforces a hold, and a dead
// core means every decision above was already fail-closed. Skipped (not counted
// as a failure) in either of those runs.
$run_hold_scenarios = ( ! $observe_mode && ! $fail_closed_run );

echo $bar . "\n";
if ( ! $run_hold_scenarios ) {
	echo "HIL Phase 2 hold scenarios SKIPPED (observe mode or fail-closed-core run — no live hold to resolve)\n";
	echo $bar . "\n";
	exit( $all_pass ? 0 : 1 );
}

echo "HIL Phase 2 (T1) — hold-aware resubmission   CORE=$core_url\n";
echo $bar . "\n";
printf( "%-50s | %-26s | %s\n", 'SCENARIO', 'RESULT DETAIL', 'RESULT' );
echo $bar . "\n";

$hold_all_pass = true;

// H1: a fresh bulk force-delete produces a hold (distinct id range from scenario 3
// so this is unambiguously a NEW hold, not a coincidental replay).
$h_ability = 'core/delete-post';
$h_input   = array( 'ids' => range( 201, 245 ), 'force_delete' => true );
$h_result  = run_ability_full( $h_ability, $h_input );

$h1_pass = ( $h_result instanceof WP_Error ) && 'reeflex_hold' === $h_result->get_error_code();
printf(
	"%-50s | %-26s | %s\n",
	'H1. bulk force-delete produces a hold',
	( $h_result instanceof WP_Error ) ? $h_result->get_error_code() : 'UNEXPECTED',
	$h1_pass ? 'PASS' : 'FAIL'
);
$hold_all_pass = $hold_all_pass && $h1_pass;

// H2: hold_id + expires_ts are present in the PUBLIC WP_Error data (not just the audit log).
$hold_id    = null;
$expires_ts = null;
if ( $h1_pass ) {
	$data       = $h_result->get_error_data();
	$hold_id    = ( is_array( $data ) && isset( $data['hold_id'] ) ) ? (string) $data['hold_id'] : null;
	$expires_ts = ( is_array( $data ) && isset( $data['expires_ts'] ) ) ? (string) $data['expires_ts'] : null;
}
$h2_pass = ( null !== $hold_id && '' !== $hold_id && null !== $expires_ts && '' !== $expires_ts );
printf(
	"%-50s | %-26s | %s\n",
	'H2. hold_id + expires_ts in WP_Error data',
	$h2_pass ? substr( $hold_id, 0, 20 ) . '...' : 'MISSING',
	$h2_pass ? 'PASS' : 'FAIL'
);
$hold_all_pass = $hold_all_pass && $h2_pass;

// H3: the entry is stored locally (Reeflex_Holds_Store) at the same moment as H1/H2.
$h3_pass = $h2_pass && null !== Reeflex_Holds_Store::get( $hold_id );
printf(
	"%-50s | %-26s | %s\n",
	'H3. pending action stored (Reeflex_Holds_Store)',
	$h3_pass ? 'stored' : 'NOT STORED',
	$h3_pass ? 'PASS' : 'FAIL'
);
$hold_all_pass = $hold_all_pass && $h3_pass;

// H4: resolve the hold via core's real holds API as a human principal.
$h4_pass = false;
if ( $h3_pass ) {
	$resolve_body    = wp_json_encode( array(
		'decision'  => 'approve',
		'principal' => array(
			'type' => 'human',
			'id'   => 'conformance-tester',
		),
		'reason'    => 'conformance harness approval',
	) );
	$resolve_headers = array( 'Content-Type' => 'application/json' );
	$core_token      = Reeflex_Config::core_token();
	if ( '' !== $core_token ) {
		$resolve_headers['Authorization'] = 'Bearer ' . $core_token;
	}
	$resolve_resp = wp_remote_post(
		rtrim( $core_url, '/' ) . '/v1/holds/' . rawurlencode( $hold_id ) . '/resolve',
		array(
			'headers' => $resolve_headers,
			'body'    => $resolve_body,
			'timeout' => 5,
		)
	);
	$h4_pass = ! is_wp_error( $resolve_resp ) && 200 === (int) wp_remote_retrieve_response_code( $resolve_resp );
}
printf(
	"%-50s | %-26s | %s\n",
	'H4. POST /v1/holds/{id}/resolve (approve)',
	$h4_pass ? 'approved' : 'FAILED',
	$h4_pass ? 'PASS' : 'FAIL'
);
$hold_all_pass = $hold_all_pass && $h4_pass;

// H5: Reeflex_Gate::resubmit_hold() re-runs the ORIGINAL ability+input -> executes.
//
// 0.1.6 double-execution dedup fix: a successfully executed entry is now MARKED
// executed (Reeflex_Holds_Store::mark_executed()) rather than delete()'d, so a
// companion hold for the same underlying call can still be recognised and
// deduplicated later (see class-reeflex-holds-store.php's docblock, 'executed_ts').
// This assertion is updated accordingly: get() must still find the entry, now
// carrying a non-empty executed_ts, instead of the pre-0.1.6 "store cleared".
$h5_pass = false;
if ( $h4_pass ) {
	$resubmit_result   = Reeflex_Gate::resubmit_hold( $hold_id );
	$executed          = is_array( $resubmit_result ) && ! empty( $resubmit_result['reeflex_harness_executed'] );
	$stored_after_exec = Reeflex_Holds_Store::get( $hold_id );
	$marked_executed   = is_array( $stored_after_exec ) && ! empty( $stored_after_exec['executed_ts'] );
	$h5_pass           = $executed && $marked_executed;
	printf(
		"%-50s | %-26s | %s\n",
		'H5. resubmit_hold() -> ability executed',
		$executed ? ( $marked_executed ? 'executed, marked executed (0.1.6)' : 'executed, NOT MARKED EXECUTED' )
			: ( ( $resubmit_result instanceof WP_Error ) ? $resubmit_result->get_error_code() : 'UNEXPECTED' ),
		$h5_pass ? 'PASS' : 'FAIL'
	);
} else {
	printf( "%-50s | %-26s | %s\n", 'H5. resubmit_hold() -> ability executed', 'SKIPPED (H4 failed)', 'FAIL' );
}
$hold_all_pass = $hold_all_pass && $h5_pass;

// H6: resubmitting an unknown hold_id fails.
$unknown_result = Reeflex_Gate::resubmit_hold( 'deadbeefdeadbeefdeadbeefdeadbeef' );
$h6_pass        = ( $unknown_result instanceof WP_Error ) && 'reeflex_hold_unknown' === $unknown_result->get_error_code();
printf(
	"%-50s | %-26s | %s\n",
	'H6. resubmit unknown hold_id -> error',
	( $unknown_result instanceof WP_Error ) ? $unknown_result->get_error_code() : 'UNEXPECTED',
	$h6_pass ? 'PASS' : 'FAIL'
);
$hold_all_pass = $hold_all_pass && $h6_pass;

// H7: resubmitting the SAME hold a second time fails (single-use — an approval
// stays single-use even under the new 0.1.6 "mark executed, don't delete" model.
// Since the entry is no longer deleted on H5's success, this is now the SAME
// double-execution dedup path a companion hold would hit — 'reeflex_hold_deduplicated'
// — rather than the pre-0.1.6 local 'reeflex_hold_unknown'; either way the hold
// cannot be resubmitted into a second allow, and the ability must not run again).
if ( $h5_pass ) {
	$second_result = Reeflex_Gate::resubmit_hold( $hold_id );
	$h7_pass       = ( $second_result instanceof WP_Error ) && 'reeflex_hold_deduplicated' === $second_result->get_error_code();
	printf(
		"%-50s | %-26s | %s\n",
		'H7. resubmit already-consumed hold -> fails',
		( $second_result instanceof WP_Error ) ? $second_result->get_error_code() : 'UNEXPECTED',
		$h7_pass ? 'PASS' : 'FAIL'
	);
} else {
	$h7_pass = false;
	printf( "%-50s | %-26s | %s\n", 'H7. resubmit already-consumed hold -> fails', 'SKIPPED (H5 failed)', 'FAIL' );
}
$hold_all_pass = $hold_all_pass && $h7_pass;

// ----------------------------------------------------------------------
// Helpers shared by H8-H10 (deny-path resubmission scenarios).
// ----------------------------------------------------------------------

/** POST /v1/holds/{id}/resolve on the LIVE core. Returns [http_code, decoded_body|null]. */
function core_resolve_hold( string $core_url, string $hold_id, string $decision, string $principal_type, string $principal_id ): array {
	$body    = wp_json_encode( array(
		'decision'  => $decision,
		'principal' => array( 'type' => $principal_type, 'id' => $principal_id ),
		'reason'    => 'conformance harness',
	) );
	$headers = array( 'Content-Type' => 'application/json' );
	$token   = Reeflex_Config::core_token();
	if ( '' !== $token ) { $headers['Authorization'] = 'Bearer ' . $token; }
	$resp = wp_remote_post(
		rtrim( $core_url, '/' ) . '/v1/holds/' . rawurlencode( $hold_id ) . '/resolve',
		array( 'headers' => $headers, 'body' => $body, 'timeout' => 5 )
	);
	if ( is_wp_error( $resp ) ) { return array( 0, null ); }
	$code    = (int) wp_remote_retrieve_response_code( $resp );
	$decoded = json_decode( (string) wp_remote_retrieve_body( $resp ), true );
	return array( $code, is_array( $decoded ) ? $decoded : null );
}

/** Create a fresh hold via a bulk force-delete on a disjoint id range. Returns hold_id or null. */
function create_fresh_hold( string $ability, array $id_range ): ?string {
	$result = run_ability_full( $ability, array( 'ids' => $id_range, 'force_delete' => true ) );
	if ( ! ( $result instanceof WP_Error ) || 'reeflex_hold' !== $result->get_error_code() ) {
		return null;
	}
	$data = $result->get_error_data();
	return ( is_array( $data ) && isset( $data['hold_id'] ) ) ? (string) $data['hold_id'] : null;
}

// H8: reject on core -> resubmit_hold() is denied (never executes).
$h8_hold = create_fresh_hold( $h_ability, range( 401, 445 ) );
$h8_pass = false;
if ( null !== $h8_hold ) {
	list( $code8, ) = core_resolve_hold( $core_url, $h8_hold, 'reject', 'human', 'conformance-tester' );
	if ( 200 === $code8 ) {
		$h8_result = Reeflex_Gate::resubmit_hold( $h8_hold );
		$h8_pass   = ( $h8_result instanceof WP_Error );
		printf(
			"%-50s | %-26s | %s\n",
			'H8. reject on core -> resubmit_hold() denied',
			( $h8_result instanceof WP_Error ) ? $h8_result->get_error_code() : 'UNEXPECTED (executed!)',
			$h8_pass ? 'PASS' : 'FAIL'
		);
	} else {
		printf( "%-50s | %-26s | %s\n", 'H8. reject on core -> resubmit_hold() denied', 'resolve(reject) HTTP ' . $code8, 'FAIL' );
	}
} else {
	printf( "%-50s | %-26s | %s\n", 'H8. reject on core -> resubmit_hold() denied', 'could not create fresh hold', 'FAIL' );
}
$hold_all_pass = $hold_all_pass && $h8_pass;

// H9: expired -> resubmit_hold() is denied. Only meaningful (and only run)
// against a core started with a short REEFLEX_HOLD_TTL_SECONDS for THIS test
// run — against a production-TTL (default 4h) core there is nothing to wait
// for, so this scenario is SKIPPED (not counted as a failure) rather than
// sleeping for hours or producing a false failure.
$test_ttl = getenv( 'REEFLEX_HOLD_TTL_SECONDS' );
if ( false !== $test_ttl && ctype_digit( (string) $test_ttl ) && (int) $test_ttl > 0 && (int) $test_ttl <= 60 ) {
	$h9_hold = create_fresh_hold( $h_ability, range( 501, 545 ) );
	$h9_pass = false;
	if ( null !== $h9_hold ) {
		list( $code9, ) = core_resolve_hold( $core_url, $h9_hold, 'approve', 'human', 'conformance-tester' );
		if ( 200 === $code9 ) {
			sleep( (int) $test_ttl + 2 ); // guarantee we are past the hold's expires_ts
			$h9_result = Reeflex_Gate::resubmit_hold( $h9_hold );
			$h9_pass   = ( $h9_result instanceof WP_Error )
				&& in_array( $h9_result->get_error_code(), array( 'reeflex_hold_expired', 'reeflex_hold_unknown' ), true );
			printf(
				"%-50s | %-26s | %s\n",
				'H9. expired -> resubmit_hold() denied',
				( $h9_result instanceof WP_Error ) ? $h9_result->get_error_code() : 'UNEXPECTED (executed!)',
				$h9_pass ? 'PASS' : 'FAIL'
			);
		} else {
			printf( "%-50s | %-26s | %s\n", 'H9. expired -> resubmit_hold() denied', 'resolve(approve) HTTP ' . $code9, 'FAIL' );
		}
	} else {
		printf( "%-50s | %-26s | %s\n", 'H9. expired -> resubmit_hold() denied', 'could not create fresh hold', 'FAIL' );
	}
	$hold_all_pass = $hold_all_pass && $h9_pass;
} else {
	printf( "%-50s | %-26s | %s\n", 'H9. expired -> resubmit_hold() denied', 'SKIPPED (set REEFLEX_HOLD_TTL_SECONDS<=60 on core+env to run)', 'SKIP' );
}

// H10: actor == approver -> core refuses the RESOLVE itself (403
// actor_is_approver); the hold never becomes approved, so resubmit_hold() is
// also denied (still-pending, never a valid approval).
$h10_hold = create_fresh_hold( $h_ability, range( 601, 645 ) );
$h10_pass = false;
if ( null !== $h10_hold ) {
	// The envelope's agent.id is Reeflex_Config::agent_id() (no REEFLEX_AGENT_ID
	// constant defined in this harness -> defaults to 'agent:wordpress'). Resolve
	// using THAT exact identity as the principal to trigger the actor==approver guard.
	list( $code10, $body10 ) = core_resolve_hold( $core_url, $h10_hold, 'approve', 'human', Reeflex_Config::agent_id() );
	$resolve_blocked = ( 403 === $code10 ) && is_array( $body10 ) && 'actor_is_approver' === ( $body10['error'] ?? '' );
	if ( $resolve_blocked ) {
		$h10_result = Reeflex_Gate::resubmit_hold( $h10_hold );
		$h10_pass   = ( $h10_result instanceof WP_Error );
		printf(
			"%-50s | %-26s | %s\n",
			'H10. actor==approver -> resolve blocked + denied',
			( $h10_result instanceof WP_Error ) ? $h10_result->get_error_code() : 'UNEXPECTED (executed!)',
			$h10_pass ? 'PASS' : 'FAIL'
		);
	} else {
		printf(
			"%-50s | %-26s | %s\n",
			'H10. actor==approver -> resolve blocked + denied',
			'resolve NOT blocked (HTTP ' . $code10 . ')',
			'FAIL'
		);
	}
} else {
	printf( "%-50s | %-26s | %s\n", 'H10. actor==approver -> resolve blocked + denied', 'could not create fresh hold', 'FAIL' );
}
$hold_all_pass = $hold_all_pass && $h10_pass;

echo $bar . "\n";
echo ( $hold_all_pass ? "ALL HOLD SCENARIOS PASS" : "SOME HOLD SCENARIOS FAILED" ) . "\n";
echo $bar . "\n";

$all_pass = $all_pass && $hold_all_pass;
exit( $all_pass ? 0 : 1 );
