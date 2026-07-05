<?php
/**
 * admin-holds-demo.php — drives the REAL Reeflex_Admin class ("Reeflex — Pending
 * approvals", HIL Phase 2 T2) against a LIVE reeflex-core, with WordPress stubbed
 * (see wp-stubs.php). Companion to conformance-demo.php, which covers Hook A/B and
 * Reeflex_Gate::resubmit_hold() directly; this script covers the admin wp-admin
 * surface built on top of that same T1 API.
 *
 * Per the class docblock ("Testability"), this exercises Reeflex_Admin::render_page()
 * (rendering only — no nonce/redirect involved) and
 * Reeflex_Admin::process_resolution() (the pure core-proxy + resubmit logic) DIRECTLY,
 * the same way conformance-demo.php calls Reeflex_Gate::resubmit_hold() directly rather
 * than simulating a full HTTP request cycle. handle_resolve() itself (the admin-post.php
 * nonce/redirect/exit glue) is intentionally NOT exercised here — it is thin WP-request
 * plumbing around process_resolution(), analogous to how conformance-demo.php's own
 * README documents that WordPress's hook-firing *timing* is assumed, not proven, by
 * this style of harness.
 *
 * Usage:
 *   php tests/admin-holds-demo.php [core_url]
 *     core_url defaults to http://127.0.0.1:8099
 *     point it at a DEAD port (e.g. http://127.0.0.1:9) to prove the admin surface
 *     also fails closed on a resolve call — the render smoke tests still run.
 *
 * Exit code 0 = all scenarios pass, 1 = a scenario failed, 2 = harness error.
 *
 * IMPORTANT — core_url is NOT set via the REEFLEX_CORE_URL constant here (unlike
 * conformance-demo.php). This script needs to change the configured core URL mid-run
 * (T2-10, simulating "core went unreachable after the hold was created") and PHP
 * constants cannot be redefined once set. Instead it drives Reeflex_Config's second
 * precedence tier — the reeflex_gate_options DB option — via update_option(), which is
 * exactly what the Settings page does in real WordPress.
 *
 * @package ReeflexWordPress
 */

declare( strict_types=1 );

$adapter_dir = dirname( __DIR__ );                      // the reeflex-wordpress/ directory
$core_url    = $argv[1] ?? 'http://127.0.0.1:8099';

putenv( 'REEFLEX_HARNESS_TMP=' . sys_get_temp_dir() );
require __DIR__ . '/wp-stubs.php';

if ( ! defined( 'REEFLEX_ENV' ) )       { define( 'REEFLEX_ENV', 'production' ); }
if ( ! defined( 'REEFLEX_AUDIT_LOG' ) ) { define( 'REEFLEX_AUDIT_LOG', sys_get_temp_dir() . '/reeflex-admin-harness-audit.jsonl' ); }
if ( ! defined( 'REEFLEX_MODE' ) )      { define( 'REEFLEX_MODE', getenv( 'REEFLEX_MODE' ) ?: 'enforce' ); }

require $adapter_dir . '/reeflex-gate/class-reeflex-config.php';
require $adapter_dir . '/reeflex-gate/class-reeflex-normalizer.php';
require $adapter_dir . '/reeflex-gate/class-reeflex-core-client.php';
require $adapter_dir . '/reeflex-gate/class-reeflex-audit.php';
require $adapter_dir . '/reeflex-gate/class-reeflex-holds-store.php';
require $adapter_dir . '/reeflex-gate/class-reeflex-gate.php';
require $adapter_dir . '/reeflex-gate/class-reeflex-admin.php';

Reeflex_Gate::register_hooks();
Reeflex_Admin::init();

// Point the adapter at the live core via the DB-option path (see file docblock).
update_option(
	Reeflex_Config::OPTION_NAME,
	array(
		'core_url'   => $core_url,
		'core_token' => '',
		'verify_ssl' => true,
		'mode'       => 'enforce',
	)
);

$hookA = $GLOBALS['__filters']['wp_register_ability_args'][0] ?? null;
if ( ! $hookA ) {
	fwrite( STDERR, "FATAL: Hook A (wp_register_ability_args) not registered\n" );
	exit( 2 );
}

$all_pass = true;

/** Print one PASS/FAIL line and fold it into $all_pass. */
function check( string $label, bool $ok, string $detail = '' ): void {
	global $all_pass;
	$all_pass = $all_pass && $ok;
	printf( "%-70s | %s%s\n", $label, $ok ? 'PASS' : 'FAIL', '' !== $detail ? ' - ' . $detail : '' );
}

/** Register (once) a demo ability, mirroring conformance-demo.php's own helper. */
function get_or_register_demo_ability_for_admin( string $ability ): WP_Ability {
	$existing = wp_get_ability( $ability );
	if ( null !== $existing ) {
		return $existing;
	}
	return WP_Abilities_Registry::get_instance()->register(
		$ability,
		array(
			'permission_callback' => static function ( $i = null ) {
				return true;
			},
			'execute_callback'    => static function ( $i ) use ( $ability ) {
				return array( 'reeflex_harness_executed' => true, 'ability' => $ability, 'input' => $i );
			},
		)
	);
}

/** Create a fresh hold via a bulk force-delete on a disjoint id range. Returns hold_id or null. */
function create_fresh_hold_for_admin( string $ability, array $id_range ): ?string {
	$result = get_or_register_demo_ability_for_admin( $ability )->execute(
		array( 'ids' => $id_range, 'force_delete' => true )
	);
	if ( ! ( $result instanceof WP_Error ) || 'reeflex_hold' !== $result->get_error_code() ) {
		return null;
	}
	$data = $result->get_error_data();
	return ( is_array( $data ) && isset( $data['hold_id'] ) ) ? (string) $data['hold_id'] : null;
}

$bar = str_repeat( '-', 100 );
echo $bar . "\n";
echo "reeflex-wordpress admin-holds-demo (HIL Phase 2 T2)   CORE=$core_url\n";
echo $bar . "\n";
printf( "%-70s | %s\n", 'SCENARIO', 'RESULT' );
echo $bar . "\n";

// ----------------------------------------------------------------------
// T2-1: render_page() fails closed for a non-manage_options user.
// ----------------------------------------------------------------------
$GLOBALS['__current_user_can'] = false;
$died                          = false;
try {
	ob_start();
	Reeflex_Admin::render_page();
	ob_end_clean();
} catch ( Reeflex_Test_WPDieException $e ) {
	ob_end_clean();
	$died = true;
}
check( 'T2-1. render_page() denies a non-manage_options user (wp_die)', $died );
$GLOBALS['__current_user_can'] = true;

// ----------------------------------------------------------------------
// T2-2: render_page() with zero pending holds renders an honest empty state.
// ----------------------------------------------------------------------
ob_start();
Reeflex_Admin::render_page();
$html_empty = ob_get_clean();
check(
	'T2-2. render_page() with zero pending holds shows "No pending holds"',
	false !== strpos( $html_empty, 'No pending holds' )
);

// ----------------------------------------------------------------------
// T2-2b: the freeze banner is honest — no fake toggle is ever rendered.
// ----------------------------------------------------------------------
check(
	'T2-2b. freeze banner is present and renders no toggle control',
	false !== stripos( $html_empty, 'Freeze' )
		&& false === stripos( $html_empty, '<input type="checkbox"' )
		&& false === stripos( $html_empty, 'name="reeflex_freeze"' )
);

// A dead port means every /v1/decide AND /v1/holds/*/resolve call must fail closed —
// there is no live hold to create, so the remaining scenarios are skipped (not failed).
$fail_closed_run = (bool) preg_match( '#:9(\D|$)#', $core_url ) && false === strpos( $core_url, ':8099' );

if ( $fail_closed_run ) {
	echo $bar . "\n";
	echo "core is unreachable by design (dead port) -- remaining scenarios SKIPPED (no live hold to create)\n";
	echo $bar . "\n";
	echo ( $all_pass ? "ALL SCENARIOS PASS" : "SOME SCENARIOS FAILED" ) . "\n";
	exit( $all_pass ? 0 : 1 );
}

// ----------------------------------------------------------------------
// T2-3..T2-6: a fresh hold shows up with the 5-second context.
// ----------------------------------------------------------------------
$hold_id = create_fresh_hold_for_admin( 'core/delete-post', range( 701, 745 ) );
check( 'T2-3. fresh bulk force-delete produced a hold', null !== $hold_id, (string) $hold_id );

if ( null !== $hold_id ) {
	$stored_entry = Reeflex_Holds_Store::get( $hold_id );

	ob_start();
	Reeflex_Admin::render_page();
	$html = ob_get_clean();

	$has_ability = false !== strpos( $html, 'core/delete-post' );
	$has_hold_id = false !== strpos( $html, $hold_id );
	$has_axes    = false !== strpos( $html, 'reversibility:' )
		&& false !== strpos( $html, 'blast_radius:' )
		&& false !== strpos( $html, 'externality:' );
	$rule_id     = is_array( $stored_entry ) ? (string) ( $stored_entry['rule_id'] ?? '' ) : '';
	$has_rule    = '' !== $rule_id && false !== strpos( $html, $rule_id );
	$has_session = is_array( $stored_entry ) && false !== strpos( $html, (string) ( $stored_entry['session_id'] ?? "\x00" ) );

	check( 'T2-4. rendered row shows the ability name + hold_id', $has_ability && $has_hold_id );
	check( 'T2-5. rendered row shows all three axes as chips', $has_axes );
	check( 'T2-6. rendered row shows the rule_id', $has_rule, $rule_id );
	check( 'T2-6b. rendered row shows the session_id', $has_session );
} else {
	check( 'T2-4. rendered row shows the ability name + hold_id', false, 'no hold to render' );
	check( 'T2-5. rendered row shows all three axes as chips', false, 'no hold to render' );
	check( 'T2-6. rendered row shows the rule_id', false, 'no hold to render' );
}

// ----------------------------------------------------------------------
// T2-7: reject flow -- closes the hold on core, deletes the local entry,
// executes NOTHING.
// ----------------------------------------------------------------------
if ( null !== $hold_id ) {
	$notice  = Reeflex_Admin::process_resolution( $hold_id, 'reject', 'admin-demo reject', 'admin-tester' );
	$cleared = null === Reeflex_Holds_Store::get( $hold_id );
	check(
		'T2-7. reject: core resolves + local entry cleared, nothing executed',
		'success' === $notice['type'] && $cleared,
		$notice['message']
	);
} else {
	check( 'T2-7. reject: core resolves + local entry cleared, nothing executed', false, 'no hold to reject' );
}

// ----------------------------------------------------------------------
// T2-8: approve flow -- THIS call is the execution step (process_resolution()
// both resolves on core AND calls Reeflex_Gate::resubmit_hold()).
//
// 0.1.6 double-execution dedup fix: a successfully executed entry is now MARKED
// executed (kept, not deleted) so a companion hold for the same underlying call
// can still be recognised and deduplicated later -- see
// class-reeflex-holds-store.php's docblock ('executed_ts') and
// class-reeflex-gate.php's resubmit_hold(). This assertion is updated
// accordingly: the entry is no longer expected to be gone from the store, only
// no longer listed as PENDING (Reeflex_Holds_Store::list_all() filters out
// executed entries -- see T2-8b immediately below), and marked executed.
// ----------------------------------------------------------------------
$hold_id2 = create_fresh_hold_for_admin( 'core/delete-post', range( 801, 845 ) );
if ( null !== $hold_id2 ) {
	$notice2            = Reeflex_Admin::process_resolution( $hold_id2, 'approve', '', 'admin-tester' );
	$stored_after_exec2 = Reeflex_Holds_Store::get( $hold_id2 );
	$marked_executed2   = is_array( $stored_after_exec2 ) && ! empty( $stored_after_exec2['executed_ts'] );
	check(
		'T2-8. approve: core resolves + resubmit_hold() executes + marked executed',
		'success' === $notice2['type'] && $marked_executed2,
		$notice2['message']
	);

	// T2-8b: an executed hold is no longer PENDING -- it must not appear in the
	// "Pending approvals" list (list_all() filters entries with a non-empty
	// executed_ts), even though the raw entry itself still exists for dedup.
	$still_listed_as_pending = array_key_exists( $hold_id2, Reeflex_Holds_Store::list_all() );
	check(
		'T2-8b. executed hold no longer appears in the pending-approvals list',
		! $still_listed_as_pending
	);
} else {
	check( 'T2-8. approve: core resolves + resubmit_hold() executes + marked executed', false, 'could not create fresh hold' );
	check( 'T2-8b. executed hold no longer appears in the pending-approvals list', false, 'could not create fresh hold' );
}

// ----------------------------------------------------------------------
// T2-9: resolving an unknown hold_id is handled honestly (no crash, no fake success).
// ----------------------------------------------------------------------
$notice3 = Reeflex_Admin::process_resolution( 'deadbeefdeadbeefdeadbeefdeadbeef', 'approve', '', 'admin-tester' );
check( 'T2-9. unknown hold_id -> warning notice, no crash', 'warning' === $notice3['type'], $notice3['message'] );

// ----------------------------------------------------------------------
// T2-10: FAIL CLOSED -- core becomes unreachable between hold creation and
// resolution. Nothing executes; the local entry is retained for a retry.
// ----------------------------------------------------------------------
$hold_id3 = create_fresh_hold_for_admin( 'core/delete-post', range( 901, 945 ) );
if ( null !== $hold_id3 ) {
	update_option(
		Reeflex_Config::OPTION_NAME,
		array( 'core_url' => 'http://127.0.0.1:9', 'core_token' => '', 'verify_ssl' => true, 'mode' => 'enforce' )
	);

	$notice4 = Reeflex_Admin::process_resolution( $hold_id3, 'approve', '', 'admin-tester' );
	$kept    = null !== Reeflex_Holds_Store::get( $hold_id3 );
	check(
		'T2-10. core unreachable -> fails closed (error, hold retained, nothing executed)',
		'error' === $notice4['type'] && $kept,
		$notice4['message']
	);

	// Restore the live core for anything after this (none currently, but keeps
	// the script well-behaved if scenarios are appended later).
	update_option(
		Reeflex_Config::OPTION_NAME,
		array( 'core_url' => $core_url, 'core_token' => '', 'verify_ssl' => true, 'mode' => 'enforce' )
	);
} else {
	check(
		'T2-10. core unreachable -> fails closed (error, hold retained, nothing executed)',
		false,
		'could not create fresh hold'
	);
}

echo $bar . "\n";
echo ( $all_pass ? "ALL SCENARIOS PASS" : "SOME SCENARIOS FAILED" ) . "\n";
exit( $all_pass ? 0 : 1 );
