<?php
/**
 * fanout-regression-demo.php — regression test for the WordPress 6.9
 * permission_callback fan-out bug (verified empirically on the live site,
 * ~11 identical holds from ONE bulk force-delete `/run` request).
 *
 * The bug: WordPress 6.9 invokes the wrapped permission_callback (Hook A,
 * wp_register_ability_args) roughly once PER REGISTERED ABILITY for a SINGLE
 * REST `/run` request on ONE action (N ≈ 11-12 on the live site). Before this
 * fix, each of those N invocations independently ran
 * normalize -> decide -> audit -> (on hold) store_pending_hold — so one human
 * action produced N /v1/decide round-trips, N audit records, and N pending
 * holds, all sharing the same canonical envelope_hash. This harness does NOT
 * need real WordPress or a real 11-ability registry to reproduce the shape of
 * the bug: it invokes the wrapped permission_callback directly, N times, for
 * the SAME action within one PHP process/request (no reset in between) — the
 * fix's job is to collapse those N invocations into exactly ONE decide + ONE
 * audit record + (on hold) ONE hold, via Reeflex_Gate's request-scoped
 * decision memo (see class-reeflex-gate.php's $decision_memo docblock).
 *
 * Counting method (stated explicitly per the brief):
 *   - "1 decide happened" is proven by counting NEW LINES appended to the
 *     REEFLEX_AUDIT_LOG JSONL file (Reeflex_Audit::record() is called exactly
 *     once per real decide() — including the observe-mode and fail-closed
 *     paths — and is skipped entirely on a memo HIT, since the memo check
 *     returns before ever reaching decide()/audit()). audit_line_count()
 *     below reads and counts non-empty lines in that file before and after
 *     each scenario; the delta is the number of decides made BY that scenario.
 *   - "N holds exist" is proven by counting entries in
 *     Reeflex_Holds_Store::list_all() before and after each scenario; the
 *     delta is the number of NEW pending holds created by that scenario.
 *
 * Requires a LIVE, REACHABLE core (this regression is about the real
 * decide()/audit()/hold-store side effects of a live decision, not fail-closed
 * behaviour) — see conformance-demo.php for the fail-closed suite.
 *
 * Usage:
 *   php tests/fanout-regression-demo.php [core_url]
 *     core_url defaults to http://127.0.0.1:8099
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
if ( ! defined( 'REEFLEX_AUDIT_LOG' ) ){ define( 'REEFLEX_AUDIT_LOG', sys_get_temp_dir() . '/reeflex-fanout-harness-audit.jsonl' ); }
if ( ! defined( 'REEFLEX_MODE' ) )     { define( 'REEFLEX_MODE', getenv( 'REEFLEX_MODE' ) ?: 'enforce' ); }

require $adapter_dir . '/reeflex-gate/class-reeflex-config.php';
require $adapter_dir . '/reeflex-gate/class-reeflex-normalizer.php';
require $adapter_dir . '/reeflex-gate/class-reeflex-core-client.php';
require $adapter_dir . '/reeflex-gate/class-reeflex-audit.php';
require $adapter_dir . '/reeflex-gate/class-reeflex-holds-store.php';
require $adapter_dir . '/reeflex-gate/class-reeflex-gate.php';

// Start with a clean audit log so line counts are unambiguous from the first
// scenario onward (a leftover file from a previous run would still work,
// since every assertion below uses a BEFORE/AFTER delta, not an absolute
// count — but starting clean makes the raw numbers in the output legible).
$audit_log_path = sys_get_temp_dir() . '/reeflex-fanout-harness-audit.jsonl';
if ( file_exists( $audit_log_path ) ) {
	unlink( $audit_log_path );
}

Reeflex_Gate::register_hooks();
$hookA = $GLOBALS['__filters']['wp_register_ability_args'][0] ?? null;
if ( ! $hookA ) { fwrite( STDERR, "FATAL: Hook A (wp_register_ability_args) not registered\n" ); exit( 2 ); }

$all_pass = true;

/** Print one PASS/FAIL line and fold it into $all_pass. */
function check( string $label, bool $ok, string $detail = '' ): void {
	global $all_pass;
	$all_pass = $all_pass && $ok;
	printf( "%-75s | %s%s\n", $label, $ok ? 'PASS' : 'FAIL', '' !== $detail ? ' - ' . $detail : '' );
}

/** Count non-empty lines currently in the audit log (see file docblock: "Counting method"). */
function audit_line_count(): int {
	$path = Reeflex_Config::audit_log_path();
	if ( ! file_exists( $path ) ) {
		return 0;
	}
	$content = file_get_contents( $path );
	if ( false === $content || '' === trim( $content ) ) {
		return 0;
	}
	return count( array_filter( explode( "\n", $content ), static function ( string $l ): bool {
		return '' !== trim( $l );
	} ) );
}

/** Count currently-pending holds in the store. */
function pending_hold_count(): int {
	return count( Reeflex_Holds_Store::list_all() );
}

/** Register (once) a demo ability, mirroring the other harnesses' own helper. */
function get_or_register_fanout_ability( string $ability ): WP_Ability {
	$existing = wp_get_ability( $ability );
	if ( null !== $existing ) {
		return $existing;
	}
	return WP_Abilities_Registry::get_instance()->register(
		$ability,
		array(
			'permission_callback' => static function ( $i = null ) { return true; },
			'execute_callback'    => static function ( $i ) use ( $ability ) {
				$GLOBALS['__fanout_exec_count'] = ( $GLOBALS['__fanout_exec_count'] ?? 0 ) + 1;
				return array( 'reeflex_harness_executed' => true, 'ability' => $ability, 'input' => $i );
			},
		)
	);
}

$bar = str_repeat( '-', 100 );
echo $bar . "\n";
echo "reeflex-wordpress fan-out regression demo   CORE=$core_url\n";
echo $bar . "\n";
printf( "%-75s | %s\n", 'SCENARIO', 'RESULT' );
echo $bar . "\n";

// A dead port means there is nothing to decide/audit/hold live; this regression
// is specifically about live decide()/audit()/hold-store side effects, so skip
// rather than produce a meaningless fail-closed result (conformance-demo.php
// already covers fail-closed behaviour exhaustively).
$fail_closed_run = (bool) preg_match( '#:9(\D|$)#', $core_url ) && false === strpos( $core_url, ':8099' );
if ( $fail_closed_run ) {
	echo "core is unreachable by design (dead port) -- SKIPPED (needs a live core to decide/audit/hold for real)\n";
	echo $bar . "\n";
	exit( 0 );
}

// ============================================================================
// (a) Fan-out collapse: 12 invocations of the wrapped permission_callback for
// the SAME bulk-force-delete action, within one request (NO reset between).
// This is the exact shape of the live bug: WordPress 6.9 called this closure
// ~11 times for one real bulk force-delete `/run` request.
// ============================================================================
Reeflex_Gate::reset_request_cache();

$fanout_ability = 'core/delete-post';
$fanout_input   = array( 'ids' => range( 9001, 9060 ), 'force_delete' => true ); // count=60, irreversible+broad -> hold
$fanout_obj     = get_or_register_fanout_ability( $fanout_ability );

$holds_before_a = pending_hold_count();
$audit_before_a = audit_line_count();

$results_a  = array();
$hold_ids_a = array();
for ( $i = 0; $i < 12; $i++ ) {
	$r            = $fanout_obj->check_permissions( $fanout_input );
	$results_a[]  = $r;
	if ( $r instanceof WP_Error ) {
		$data         = $r->get_error_data();
		$hold_ids_a[] = ( is_array( $data ) && isset( $data['hold_id'] ) ) ? (string) $data['hold_id'] : null;
	}
}

$holds_after_a = pending_hold_count();
$audit_after_a = audit_line_count();

$all_hold_errors_a = array_reduce(
	$results_a,
	static function ( bool $carry, $r ): bool {
		return $carry && ( $r instanceof WP_Error ) && 'reeflex_hold' === $r->get_error_code();
	},
	true
);
$all_same_hold_id_a = ( 12 === count( $hold_ids_a ) )
	&& ( 1 === count( array_unique( array_filter( $hold_ids_a, static function ( $h ) { return null !== $h; } ) ) ) );

$holds_delta_a = $holds_after_a - $holds_before_a;
$audit_delta_a = $audit_after_a - $audit_before_a;

check(
	'a1. 12x same wrapped permission_callback invocation -> all 12 return reeflex_hold',
	$all_hold_errors_a,
	'12 calls, hold-error count=' . count( array_filter( $results_a, static function ( $r ) { return $r instanceof WP_Error && 'reeflex_hold' === $r->get_error_code(); } ) )
);
check(
	'a2. 12x same action -> exactly 1 hold created (not 12)',
	1 === $holds_delta_a,
	'holds before=' . $holds_before_a . ' after=' . $holds_after_a . ' delta=' . $holds_delta_a
);
check(
	'a3. 12x same action -> exactly 1 decide happened (1 new audit record)',
	1 === $audit_delta_a,
	'audit lines before=' . $audit_before_a . ' after=' . $audit_after_a . ' delta=' . $audit_delta_a
);
check(
	'a4. all 12 invocations returned the SAME memoized hold_id',
	$all_same_hold_id_a,
	'distinct hold_ids seen=' . count( array_unique( array_filter( $hold_ids_a, static function ( $h ) { return null !== $h; } ) ) )
);

// ============================================================================
// (b) Read fan-out: 12 invocations of an allow (read) action -> 0 holds,
// exactly 1 decide/audit record. Proves the memo collapses ALLOW outcomes too,
// not just holds.
// ============================================================================
$read_ability = 'core/get-post';
$read_input   = array( 'id' => 555 );
$read_obj     = get_or_register_fanout_ability( $read_ability );

$holds_before_b = pending_hold_count();
$audit_before_b = audit_line_count();

$results_b = array();
for ( $i = 0; $i < 12; $i++ ) {
	$results_b[] = $read_obj->check_permissions( $read_input );
}

$holds_after_b = pending_hold_count();
$audit_after_b = audit_line_count();

$all_allow_b = array_reduce(
	$results_b,
	static function ( bool $carry, $r ): bool { return $carry && ( true === $r ); },
	true
);
$holds_delta_b = $holds_after_b - $holds_before_b;
$audit_delta_b = $audit_after_b - $audit_before_b;

check(
	'b1. 12x same read action -> all 12 return allow (true)',
	$all_allow_b,
	'allow count=' . count( array_filter( $results_b, static function ( $r ) { return true === $r; } ) ) . '/12'
);
check(
	'b2. 12x same read action -> 0 new holds',
	0 === $holds_delta_b,
	'holds before=' . $holds_before_b . ' after=' . $holds_after_b . ' delta=' . $holds_delta_b
);
check(
	'b3. 12x same read action -> exactly 1 decide happened (1 new audit record)',
	1 === $audit_delta_b,
	'audit lines before=' . $audit_before_b . ' after=' . $audit_after_b . ' delta=' . $audit_delta_b
);

// ============================================================================
// (c) Distinct actions are NOT collapsed: two DIFFERENT actions, each invoked
// 3x (no reset anywhere in this block), within the SAME request as (a)/(b)
// above (still no reset since the top of (a)) -> exactly 2 holds (memo keys
// differ), not 1 (over-collapsed) and not 6 (fan-out fix not working at all).
// ============================================================================
// NOTE: canonical_envelope_hash() covers {action,axes,magnitude,target}, none
// of which include the actual id VALUES -- only count and target.ref (null
// when count != 1). So two bulk-delete inputs that differ ONLY in which ids
// they name (but share the same count) would collide onto the SAME canonical
// hash as each other -- and as (a) above, if the count also matched. To
// genuinely exercise "two DIFFERENT actions -> 2 holds" this scenario uses a
// DIFFERENT ability for Y (core/fetch-and-delete-posts, mirroring the
// verb-collision scenario in conformance-demo.php) and a DIFFERENT count for
// X (61, vs (a)'s 60), so both memo keys are unambiguously distinct from each
// other AND from (a)'s.
$actionX_ability = 'core/delete-post';
$actionX_input   = array( 'ids' => range( 11001, 11061 ), 'force_delete' => true ); // count=61
$actionY_ability = 'core/fetch-and-delete-posts';
$actionY_input   = array( 'ids' => range( 12001, 12035 ) );                        // count=35, delete verb (segment match), count>=20 -> irreversible

$objX = get_or_register_fanout_ability( $actionX_ability );
$objY = get_or_register_fanout_ability( $actionY_ability );

$holds_before_c = pending_hold_count();
$audit_before_c = audit_line_count();

$results_x = array();
for ( $i = 0; $i < 3; $i++ ) { $results_x[] = $objX->check_permissions( $actionX_input ); }
$results_y = array();
for ( $i = 0; $i < 3; $i++ ) { $results_y[] = $objY->check_permissions( $actionY_input ); }

$holds_after_c = pending_hold_count();
$audit_after_c = audit_line_count();

$x_all_hold = array_reduce( $results_x, static function ( bool $carry, $r ): bool {
	return $carry && ( $r instanceof WP_Error ) && 'reeflex_hold' === $r->get_error_code();
}, true );
$y_all_hold = array_reduce( $results_y, static function ( bool $carry, $r ): bool {
	return $carry && ( $r instanceof WP_Error ) && 'reeflex_hold' === $r->get_error_code();
}, true );

$hold_id_x = null;
$hold_id_y = null;
if ( $x_all_hold ) {
	$dx        = $results_x[0]->get_error_data();
	$hold_id_x = ( is_array( $dx ) && isset( $dx['hold_id'] ) ) ? (string) $dx['hold_id'] : null;
}
if ( $y_all_hold ) {
	$dy        = $results_y[0]->get_error_data();
	$hold_id_y = ( is_array( $dy ) && isset( $dy['hold_id'] ) ) ? (string) $dy['hold_id'] : null;
}

$holds_delta_c = $holds_after_c - $holds_before_c;
$audit_delta_c = $audit_after_c - $audit_before_c;

check(
	'c1. action X (3x, no reset) -> all return reeflex_hold, same memoized hold_id',
	$x_all_hold && null !== $hold_id_x,
	(string) $hold_id_x
);
check(
	'c2. action Y (3x, no reset) -> all return reeflex_hold, same memoized hold_id',
	$y_all_hold && null !== $hold_id_y,
	(string) $hold_id_y
);
check(
	'c3. action X and action Y hold_ids are DIFFERENT (distinct memo keys)',
	null !== $hold_id_x && null !== $hold_id_y && $hold_id_x !== $hold_id_y
);
check(
	'c4. 2 distinct actions x3 invocations each -> exactly 2 NEW holds (not 1, not 6)',
	2 === $holds_delta_c,
	'holds before=' . $holds_before_c . ' after=' . $holds_after_c . ' delta=' . $holds_delta_c
);
check(
	'c5. 2 distinct actions x3 invocations each -> exactly 2 decides (2 new audit records, not 6)',
	2 === $audit_delta_c,
	'audit lines before=' . $audit_before_c . ' after=' . $audit_after_c . ' delta=' . $audit_delta_c
);

// ============================================================================
// (d) New request: after reset_request_cache(), the SAME action as (a) ->
// a fresh, DIFFERENT hold is created (memo was genuinely cleared, not just
// coincidentally missed).
// ============================================================================
Reeflex_Gate::reset_request_cache();

$holds_before_d = pending_hold_count();
$audit_before_d = audit_line_count();

$result_d = $fanout_obj->check_permissions( $fanout_input ); // same ability+input as scenario (a)

$holds_after_d = pending_hold_count();
$audit_after_d = audit_line_count();

$d_is_hold = ( $result_d instanceof WP_Error ) && 'reeflex_hold' === $result_d->get_error_code();
$hold_id_d = null;
if ( $d_is_hold ) {
	$dd        = $result_d->get_error_data();
	$hold_id_d = ( is_array( $dd ) && isset( $dd['hold_id'] ) ) ? (string) $dd['hold_id'] : null;
}
$original_hold_id_a = $hold_ids_a[0] ?? null;

check(
	'd1. after reset_request_cache(), same action as (a) -> a FRESH hold_id (memo cleared)',
	$d_is_hold && null !== $hold_id_d && $hold_id_d !== $original_hold_id_a,
	'scenario(a) hold=' . (string) $original_hold_id_a . ' scenario(d) hold=' . (string) $hold_id_d
);
check(
	'd2. the fresh request created exactly 1 new hold',
	1 === ( $holds_after_d - $holds_before_d ),
	'delta=' . ( $holds_after_d - $holds_before_d )
);
check(
	'd3. the fresh request made exactly 1 new decide (1 new audit record)',
	1 === ( $audit_after_d - $audit_before_d ),
	'delta=' . ( $audit_after_d - $audit_before_d )
);

// ============================================================================
// (e) Resubmission bypass: an active resubmission must decide FRESH — it must
// neither be served BY the memo, nor WRITE into it (which would poison the
// memo for later ordinary callers of the same canonical action).
//
// Setup deliberately keeps the ORIGINAL hold-creating decision memoized (no
// reset between creating the hold and resubmitting it) — this is the exact
// condition under which a bug would surface: the resubmission's envelope has
// the SAME canonical hash as the original hold-creating envelope (approval is
// not part of the canonical {action,axes,magnitude,target} projection - see
// Reeflex_Holds_Store::canonical_envelope_hash()), so if resubmit_hold() were
// NOT exempted from the memo, it would be served back the ORIGINAL
// 'reeflex_hold' WP_Error instead of ever calling decide() with
// approval.present=true -- the ability would never execute and every
// approved hold would be stuck forever.
// ============================================================================
Reeflex_Gate::reset_request_cache();

$e_ability = 'core/delete-post';
$e_input   = array( 'ids' => range( 13001, 13060 ), 'force_delete' => true ); // count=60 -> hold
$e_obj     = get_or_register_fanout_ability( $e_ability );

$audit_before_e1 = audit_line_count();
$result_e1       = $e_obj->check_permissions( $e_input ); // populates the memo for this canonical action
$audit_after_e1  = audit_line_count();

$e1_pass  = ( $result_e1 instanceof WP_Error ) && 'reeflex_hold' === $result_e1->get_error_code()
	&& 1 === ( $audit_after_e1 - $audit_before_e1 );
$hold_id_e = null;
if ( $result_e1 instanceof WP_Error ) {
	$de        = $result_e1->get_error_data();
	$hold_id_e = ( is_array( $de ) && isset( $de['hold_id'] ) ) ? (string) $de['hold_id'] : null;
}
check(
	'e1. setup: hold created and memoized (1 decide)',
	$e1_pass && null !== $hold_id_e,
	(string) $hold_id_e
);

// Approve on the live core so resubmit_hold() has a valid approval to consume.
$resolve_body    = wp_json_encode( array(
	'decision'  => 'approve',
	'principal' => array( 'type' => 'human', 'id' => 'fanout-regression-tester' ),
	'reason'    => 'fanout regression harness (e)',
) );
$resolve_headers = array( 'Content-Type' => 'application/json' );
$core_token      = Reeflex_Config::core_token();
if ( '' !== $core_token ) { $resolve_headers['Authorization'] = 'Bearer ' . $core_token; }
$resolve_resp = ( null !== $hold_id_e ) ? wp_remote_post(
	rtrim( $core_url, '/' ) . '/v1/holds/' . rawurlencode( $hold_id_e ) . '/resolve',
	array( 'headers' => $resolve_headers, 'body' => $resolve_body, 'timeout' => 5 )
) : null;
$e2_pass = ( null !== $resolve_resp ) && ! is_wp_error( $resolve_resp )
	&& 200 === (int) wp_remote_retrieve_response_code( $resolve_resp );
check( 'e2. setup: hold approved on core', $e2_pass );

// The critical assertion: resubmit_hold() (which internally sets
// $active_resubmission_hold_id around the SAME ability+input, giving the SAME
// canonical hash as $result_e1 above, still sitting in the memo) must decide
// FRESH -- i.e. actually execute the ability -- rather than being served back
// $result_e1's memoized 'reeflex_hold' WP_Error.
$exec_before_e   = $GLOBALS['__fanout_exec_count'] ?? 0;
$audit_before_e3 = audit_line_count();
$resubmit_result = ( $e1_pass && $e2_pass ) ? Reeflex_Gate::resubmit_hold( (string) $hold_id_e ) : null;
$exec_after_e    = $GLOBALS['__fanout_exec_count'] ?? 0;
$audit_after_e3  = audit_line_count();

$e3_executed = is_array( $resubmit_result ) && ! empty( $resubmit_result['reeflex_harness_executed'] )
	&& 1 === ( $exec_after_e - $exec_before_e );
check(
	'e3. resubmit_hold() is NOT served from the memo -- decides fresh, ability executes',
	$e3_executed,
	is_array( $resubmit_result )
		? 'executed (exec_count delta=' . ( $exec_after_e - $exec_before_e ) . ')'
		: ( ( $resubmit_result instanceof WP_Error ) ? $resubmit_result->get_error_code() : 'UNEXPECTED (served from memo without deciding!)' )
);
check(
	'e4. resubmission made its OWN fresh decide (1 new audit record)',
	1 === ( $audit_after_e3 - $audit_before_e3 ),
	'delta=' . ( $audit_after_e3 - $audit_before_e3 )
);

// The complementary assertion: the resubmission must NOT have overwritten the
// memo entry for this canonical action -- a later ORDINARY (non-resubmission)
// invocation of the SAME action, still without a reset, must see the SAME
// memo entry $result_e1 wrote (the original 'reeflex_hold', same hold_id) --
// proving resubmit_hold() never WRITES to the memo either.
$audit_before_e5 = audit_line_count();
$result_e5       = $e_obj->check_permissions( $e_input );
$audit_after_e5  = audit_line_count();

$hold_id_e5 = null;
if ( $result_e5 instanceof WP_Error ) {
	$de5        = $result_e5->get_error_data();
	$hold_id_e5 = ( is_array( $de5 ) && isset( $de5['hold_id'] ) ) ? (string) $de5['hold_id'] : null;
}
check(
	'e5. resubmission did NOT populate/overwrite the memo -- same old memoized hold_id returned, 0 new decides',
	( $result_e5 instanceof WP_Error ) && 'reeflex_hold' === $result_e5->get_error_code()
		&& $hold_id_e5 === $hold_id_e
		&& 0 === ( $audit_after_e5 - $audit_before_e5 ),
	'hold_id=' . (string) $hold_id_e5 . ' (original=' . (string) $hold_id_e . ') audit delta=' . ( $audit_after_e5 - $audit_before_e5 )
);

echo $bar . "\n";
echo ( $all_pass ? "ALL SCENARIOS PASS" : "SOME SCENARIOS FAILED" ) . "\n";
echo $bar . "\n";
exit( $all_pass ? 0 : 1 );
