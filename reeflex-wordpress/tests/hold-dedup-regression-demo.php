<?php
/**
 * hold-dedup-regression-demo.php — regression test for the double-execution bug
 * found by dev-3's HIL Phase 2 E2E harness (see class-reeflex-gate.php's
 * "Double-gating" docblock and class-reeflex-holds-store.php's `request_id` note).
 *
 * The bug: an MCP-originated ability call can be gated TWICE (defense-in-depth) —
 * Hook A (bound to the ability's own execute()) and Hook B (the MCP adapter layer)
 * each independently call reeflex-core and, when the decision is require_approval,
 * each store their OWN pending hold under a DIFFERENT hold_id — but both holds carry
 * the SAME canonical envelope_hash (the same {action,axes,magnitude,target}), because
 * they are two observations of the exact same underlying call. If a human approves
 * BOTH holds via the wp-admin "Pending approvals" surface, the pre-fix adapter ran
 * `Reeflex_Gate::resubmit_hold()` for each one — which re-executes the ORIGINAL
 * ability — so the action fired TWICE.
 *
 * This harness reproduces the shape of that bug without needing a real MCP call: it
 * fires the SAME ability+input through Hook A TWICE in one PHP process. Each call is
 * an independent POST /v1/decide against a LIVE core, so each produces its own real,
 * resolvable, DIFFERENT hold_id — exactly what Hook A and Hook B would each produce
 * for one real MCP-originated call. It then approves BOTH holds on core (the exact
 * dev-3 scenario: "a human approves BOTH holds") and resubmits BOTH via
 * `Reeflex_Gate::resubmit_hold()`, asserting the underlying ability executed EXACTLY
 * ONCE — proven by an execution counter on the ability's own execute_callback, not by
 * trusting resubmit_hold()'s return value alone.
 *
 * Usage:
 *   php tests/hold-dedup-regression-demo.php [core_url]
 *     core_url defaults to http://127.0.0.1:8099
 *
 * Requires a LIVE, REACHABLE core (this regression is about a live approval flow,
 * not fail-closed behaviour) — see conformance-demo.php for the fail-closed suite.
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
if ( ! defined( 'REEFLEX_AUDIT_LOG' ) ){ define( 'REEFLEX_AUDIT_LOG', sys_get_temp_dir() . '/reeflex-dedup-harness-audit.jsonl' ); }
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

$all_pass = true;

/** Print one PASS/FAIL line and fold it into $all_pass. */
function check( string $label, bool $ok, string $detail = '' ): void {
	global $all_pass;
	$all_pass = $all_pass && $ok;
	printf( "%-75s | %s%s\n", $label, $ok ? 'PASS' : 'FAIL', '' !== $detail ? ' - ' . $detail : '' );
}

/** POST /v1/holds/{id}/resolve on the LIVE core. Returns [http_code, decoded_body|null]. */
function core_resolve_hold( string $core_url, string $hold_id, string $decision ): array {
	$body    = wp_json_encode( array(
		'decision'  => $decision,
		'principal' => array( 'type' => 'human', 'id' => 'dedup-regression-tester' ),
		'reason'    => 'hold-dedup regression harness',
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

$bar = str_repeat( '-', 100 );
echo $bar . "\n";
echo "reeflex-wordpress hold-dedup regression demo   CORE=$core_url\n";
echo $bar . "\n";
printf( "%-75s | %s\n", 'SCENARIO', 'RESULT' );
echo $bar . "\n";

// A dead port means there is nothing to approve/resubmit live; this regression is
// specifically about the live-approval double-execution path, so skip rather than
// produce a meaningless fail-closed result (conformance-demo.php already covers
// fail-closed behaviour exhaustively).
$fail_closed_run = (bool) preg_match( '#:9(\D|$)#', $core_url ) && false === strpos( $core_url, ':8099' );
if ( $fail_closed_run ) {
	echo "core is unreachable by design (dead port) -- SKIPPED (needs a live core to create/approve real holds)\n";
	echo $bar . "\n";
	exit( 0 );
}

// Execution counter lives OUTSIDE Reeflex_Gate entirely — it is incremented only by
// the ability's OWN execute_callback (do_execute()), so it proves how many times the
// underlying WordPress action actually ran, independent of what resubmit_hold()
// reports back.
$GLOBALS['__dedup_exec_count'] = 0;

// Simulate "Hook A and Hook B are handling the SAME incoming HTTP request": both set
// the Mcp-Session-Id header, which Reeflex_Normalizer::resolve_session_id() reads
// FIRST (ahead of the per-call-random wp_get_session_token() stub in wp-stubs.php) —
// exactly what ties two real hooks' holds together as companions (see
// Reeflex_Holds_Store::find_executed_companion_hold_id()'s docblock). D8 below
// verifies two DIFFERENT MCP sessions are correctly NOT conflated.
$_SERVER['HTTP_MCP_SESSION_ID'] = 'dedup-regression-session-A';

$ability = 'core/delete-post';
$input   = array( 'ids' => range( 3001, 3045 ), 'force_delete' => true ); // bulk + force -> irreversible/broad -> require_approval

WP_Abilities_Registry::get_instance()->register(
	$ability,
	array(
		'permission_callback' => static function ( $i = null ) { return true; },
		'execute_callback'    => static function ( $i ) use ( $ability ) {
			++$GLOBALS['__dedup_exec_count'];
			return array(
				'reeflex_harness_executed' => true,
				'ability'                  => $ability,
				'input'                    => $i,
				'exec_no'                  => $GLOBALS['__dedup_exec_count'],
			);
		},
	)
);
$ability_obj = wp_get_ability( $ability );

// ------------------------------------------------------------------
// D1: first call on the action produces a hold (simulates Hook A's own
// require_approval for one MCP-originated call).
// ------------------------------------------------------------------
$result1 = $ability_obj->execute( $input );
$d1_pass = ( $result1 instanceof WP_Error ) && 'reeflex_hold' === $result1->get_error_code();
$hold_1  = null;
if ( $d1_pass ) {
	$data1  = $result1->get_error_data();
	$hold_1 = ( is_array( $data1 ) && isset( $data1['hold_id'] ) ) ? (string) $data1['hold_id'] : null;
}
check( 'D1. first call on the action produces a hold (Hook A)', $d1_pass && null !== $hold_1, (string) $hold_1 );

// ------------------------------------------------------------------
// D2: the SAME ability+input, submitted a second time, is an independent
// /v1/decide call and produces a SECOND, DIFFERENT hold_id (simulates Hook B
// independently gating the SAME MCP-originated call — see class-reeflex-gate.php
// "Double-gating").
// ------------------------------------------------------------------
$result2 = $ability_obj->execute( $input );
$d2_pass = ( $result2 instanceof WP_Error ) && 'reeflex_hold' === $result2->get_error_code();
$hold_2  = null;
if ( $d2_pass ) {
	$data2  = $result2->get_error_data();
	$hold_2 = ( is_array( $data2 ) && isset( $data2['hold_id'] ) ) ? (string) $data2['hold_id'] : null;
}
check(
	'D2. second call on the SAME action produces a DIFFERENT hold (Hook B)',
	$d2_pass && null !== $hold_2 && $hold_2 !== $hold_1,
	(string) $hold_2
);

// ------------------------------------------------------------------
// D3: both hold entries share the SAME envelope_hash — they are two
// observations of one underlying call, not two independent actions.
// ------------------------------------------------------------------
$entry_1 = ( null !== $hold_1 ) ? Reeflex_Holds_Store::get( $hold_1 ) : null;
$entry_2 = ( null !== $hold_2 ) ? Reeflex_Holds_Store::get( $hold_2 ) : null;
$hash_1  = is_array( $entry_1 ) ? (string) ( $entry_1['envelope_hash'] ?? '' ) : '';
$hash_2  = is_array( $entry_2 ) ? (string) ( $entry_2['envelope_hash'] ?? '' ) : '';
check(
	'D3. both holds share the same envelope_hash (same underlying action)',
	'' !== $hash_1 && $hash_1 === $hash_2,
	substr( $hash_1, 0, 16 ) . '... vs ' . substr( $hash_2, 0, 16 ) . '...'
);

// ------------------------------------------------------------------
// D4: a human approves BOTH holds on core — this is literally the dev-3
// scenario ("If a human approves BOTH holds via the wp-admin surface...").
// ------------------------------------------------------------------
list( $code_a1, ) = ( null !== $hold_1 ) ? core_resolve_hold( $core_url, $hold_1, 'approve' ) : array( 0, null );
list( $code_a2, ) = ( null !== $hold_2 ) ? core_resolve_hold( $core_url, $hold_2, 'approve' ) : array( 0, null );
check(
	'D4. both holds independently approved on core',
	200 === $code_a1 && 200 === $code_a2,
	"hold_1 HTTP=$code_a1 hold_2 HTTP=$code_a2"
);

// ------------------------------------------------------------------
// D5: resubmit hold_1 -> the ability actually executes. exec_count becomes 1.
// ------------------------------------------------------------------
$resubmit_1   = Reeflex_Gate::resubmit_hold( (string) $hold_1 );
$exec_after_1 = $GLOBALS['__dedup_exec_count'];
$d5_pass      = is_array( $resubmit_1 ) && ! empty( $resubmit_1['reeflex_harness_executed'] ) && 1 === $exec_after_1;
check( 'D5. resubmit hold_1 -> ability executes (exec_count=1)', $d5_pass, 'exec_count=' . $exec_after_1 );

// ------------------------------------------------------------------
// D6 (THE REGRESSION): resubmit hold_2 — the companion hold for the SAME
// underlying call. Before the fix this ran do_execute() a SECOND time
// (exec_count=2 — the double-execution bug, verbatim). After the fix this is
// deduplicated: exec_count stays at 1, and a distinct 'reeflex_hold_deduplicated'
// WP_Error is returned — not a fresh execution, and not an ordinary deny.
// ------------------------------------------------------------------
$resubmit_2   = Reeflex_Gate::resubmit_hold( (string) $hold_2 );
$exec_after_2 = $GLOBALS['__dedup_exec_count'];
$d6_no_double_exec = ( 1 === $exec_after_2 );
$d6_dedup_result   = ( $resubmit_2 instanceof WP_Error ) && 'reeflex_hold_deduplicated' === $resubmit_2->get_error_code();
$d6_pass = $d6_no_double_exec && $d6_dedup_result;
check(
	'D6. resubmit hold_2 (companion) does NOT re-execute -- deduplicated',
	$d6_pass,
	'exec_count=' . $exec_after_2 . ' result=' .
		( $resubmit_2 instanceof WP_Error ? $resubmit_2->get_error_code() : 'UNEXPECTED (executed again!)' )
);

// ------------------------------------------------------------------
// D7: re-resubmitting hold_1 itself (the one that actually ran) a second time
// must ALSO be a no-op -- an approval stays single-use even under the new
// "mark executed, don't delete" storage model (self-repeat / double-submit).
// ------------------------------------------------------------------
$resubmit_1b   = Reeflex_Gate::resubmit_hold( (string) $hold_1 );
$exec_after_1b = $GLOBALS['__dedup_exec_count'];
$d7_pass       = ( 1 === $exec_after_1b ) && ( $resubmit_1b instanceof WP_Error );
check(
	'D7. re-resubmitting hold_1 itself is also a no-op (single-use)',
	$d7_pass,
	'exec_count=' . $exec_after_1b . ' result=' .
		( $resubmit_1b instanceof WP_Error ? $resubmit_1b->get_error_code() : 'UNEXPECTED (executed again!)' )
);

// ------------------------------------------------------------------
// D8 (SCOPING CHECK — must NOT be deduplicated): a genuinely DIFFERENT MCP
// session submits the SAME action (same envelope_hash by construction) later.
// This is NOT a companion of hold_1/hold_2 — it is a separate call from a
// separate session — so it MUST execute normally, proving the dedup does not
// over-suppress legitimate, unrelated calls that merely share an
// envelope_hash (see Reeflex_Holds_Store::find_executed_companion_hold_id()'s
// scoping rationale: envelope_hash alone is never sufficient).
// ------------------------------------------------------------------
$_SERVER['HTTP_MCP_SESSION_ID'] = 'dedup-regression-session-B';
$result3 = $ability_obj->execute( $input );
$d8_hold_pass = ( $result3 instanceof WP_Error ) && 'reeflex_hold' === $result3->get_error_code();
$hold_3       = null;
if ( $d8_hold_pass ) {
	$data3  = $result3->get_error_data();
	$hold_3 = ( is_array( $data3 ) && isset( $data3['hold_id'] ) ) ? (string) $data3['hold_id'] : null;
}
list( $code_a3, ) = ( null !== $hold_3 ) ? core_resolve_hold( $core_url, $hold_3, 'approve' ) : array( 0, null );
$resubmit_3   = ( null !== $hold_3 ) ? Reeflex_Gate::resubmit_hold( $hold_3 ) : null;
$exec_after_3 = $GLOBALS['__dedup_exec_count'];
$d8_pass      = $d8_hold_pass && 200 === $code_a3
	&& is_array( $resubmit_3 ) && ! empty( $resubmit_3['reeflex_harness_executed'] )
	&& 2 === $exec_after_3;
check(
	'D8. a DIFFERENT MCP session with the same envelope_hash is NOT deduplicated -- executes',
	$d8_pass,
	'exec_count=' . $exec_after_3 . ' result=' .
		( $resubmit_3 instanceof WP_Error ? $resubmit_3->get_error_code() : ( is_array( $resubmit_3 ) ? 'executed' : 'UNEXPECTED' ) )
);

echo $bar . "\n";
echo ( $all_pass ? "ALL SCENARIOS PASS" : "SOME SCENARIOS FAILED" ) . "\n";
echo $bar . "\n";
exit( $all_pass ? 0 : 1 );
