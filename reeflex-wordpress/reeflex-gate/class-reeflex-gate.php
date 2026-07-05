<?php
/**
 * Reeflex Gate — intercept, enforce, audit.
 *
 * Registers two hooks:
 *
 * Hook A — wp_register_ability_args (PRIMARY, BLOCKING):
 *   Fires inside WP_Abilities_Registry::register() at line 120 of
 *   class-wp-abilities-registry.php (abilities-api v0.4.0 / WP 6.9 core).
 *   Wraps every ability's permission_callback with a closure that gates
 *   on Reeflex before granting permission.  Because WP_Ability::execute()
 *   short-circuits at line 571 when check_permissions() returns anything
 *   other than true (including WP_Error), returning WP_Error from our
 *   wrapped callback blocks execution.  This seam covers REST + direct PHP
 *   + MCP-originated ability calls — every path goes through execute().
 *
 *   Trusted verb override: if $args carries a 'reeflex_verb' key (set by
 *   the ability author at registration time), it is captured and passed to
 *   Reeflex_Normalizer as a monotonic-danger override — the trusted verb
 *   is used only if it is at least as dangerous as the heuristic (NEW-3).
 *
 * Hook B — mcp_adapter_pre_tool_call (DEFENSE-IN-DEPTH, MCP layer):
 *   Fires inside ToolsHandler::call_tool() at line 182 of ToolsHandler.php
 *   (mcp-adapter v0.5.0).  Applies only to the 'mcp-adapter/execute-ability'
 *   tool.  Reads {ability_name, parameters} from $args, runs the full
 *   normalize→decide→audit→enforce cycle.  Returns WP_Error to short-circuit.
 *
 * Double-gating:
 *   An MCP-originated ability call activates both hooks. Hook B fires first
 *   (MCP tool layer); Hook A fires second (permission_callback). Both
 *   independently call reeflex-core — this is correct defense-in-depth.
 *   There is NO dedup/nonce-cache between the two /v1/decide calls themselves
 *   (P1-5) — both are real, independent decisions, and (pre-existing, unchanged)
 *   a require_approval on each is stored as two SEPARATE hold_ids
 *   (store_pending_hold() is called from both hooks with no dedup at creation
 *   time). What IS deduplicated, since 0.1.6, is EXECUTION: resubmit_hold() will
 *   run the underlying ability AT MOST ONCE no matter how many of these
 *   companion holds a human later approves — see resubmit_hold()'s own docblock
 *   for the mechanism (envelope_hash + session_id + a tight creation-time
 *   window) and its scoping / residual risk.
 *
 * Exception safety (NEW-2):
 *   Both the permission_callback closure and gate_mcp_tool() are wrapped in
 *   try/catch(\Throwable). Any unexpected exception fails CLOSED — the action
 *   is blocked, the exception message is logged, and a fail-closed deny is
 *   synthesized via Reeflex_Core_Client::fail_closed().
 *
 * Approval (HIL Phase 2 — SPEC §5.1):
 *   A require_approval decision is no longer terminal. Core (>= v0.1.5) returns
 *   `hold_id` + `expires_ts` alongside the decision; both hooks store the pending
 *   action (Reeflex_Holds_Store::save()) at the same moment they return the
 *   `reeflex_hold` WP_Error, and surface hold_id + expires_ts in that error's data
 *   so the caller/operator can route it to a human. Once a human resolves the hold
 *   via core's holds API (`POST /v1/holds/{id}/resolve`), Reeflex_Gate::resubmit_hold()
 *   re-runs the ORIGINAL ability with the ORIGINAL input through this SAME gate,
 *   with the envelope's approval object set to {present:true, hold_id} for that one
 *   call (see $active_resubmission_hold_id below). Core independently validates the
 *   hold (single-use, TTL-bound, action-hash-bound) before ever allowing — this
 *   adapter asserts nothing beyond "here is the hold_id a human resolved."
 *
 *   Double-execution dedup (0.1.6, adapter-side, ON TOP of core's own single-use
 *   validation): core's hold validation makes each INDIVIDUAL hold_id single-use,
 *   but it has no notion of "this is a companion of a hold_id I already validated" —
 *   two DIFFERENT, both-valid hold_ids for the SAME underlying call (see
 *   "Double-gating" above) can each independently pass core's validation and each
 *   trigger a resubmit_hold() call. Reeflex_Holds_Store additionally tracks, per
 *   hold entry, an `executed_ts` (set only once the ability has actually run — see
 *   Reeflex_Holds_Store::mark_executed()). resubmit_hold() checks, before ever
 *   touching the ability, whether this exact hold_id — or another hold sharing
 *   its envelope_hash AND session_id AND created within a tight time window of
 *   it (Reeflex_Holds_Store::find_executed_companion_hold_id()) — has already
 *   executed, and if so short-circuits with a distinct 'reeflex_hold_deduplicated'
 *   result instead of running the ability again.
 *
 * WP_Error data (NEW-1):
 *   Public WP_Error data arrays carry ONLY 'status' and 'reeflex_decision'.
 *   'reeflex_rule' and 'reeflex_reason' are NOT included — WordPress REST API
 *   serializes the data array into the HTTP response, so those fields would
 *   reach the calling agent. Rule + reason are written to error_log keyed by
 *   nonce for operator correlation; the audit JSONL also records both fields.
 *
 * @package ReeflexWordPress
 * @since   0.1.0
 */

declare( strict_types=1 );

defined( 'ABSPATH' ) || exit;

/**
 * Enforcement glue: wraps ability permission callbacks and gates MCP tool calls.
 */
final class Reeflex_Gate {

	/**
	 * Request-scoped: the hold_id of the resubmission currently in flight, or null.
	 *
	 * Set ONLY by resubmit_hold() around its single ability->execute() call, and
	 * always cleared in a finally block. Read by wrap_permission_callback()'s
	 * closure at CALL time (not registration time) so the SAME already-registered
	 * ability picks up the approval for exactly the one re-run that resubmit_hold()
	 * triggers — every other concurrent/subsequent call to the same ability sees
	 * null and gets a normal (approval.present = false) envelope.
	 *
	 * This is a static, not per-instance, because Reeflex_Gate has no instances —
	 * every hook callback is a static method / closure over static state, matching
	 * the rest of this class.
	 *
	 * @var string|null
	 */
	private static ?string $active_resubmission_hold_id = null;

	/**
	 * Request-scoped: the ORIGINAL agent identity {id, on_behalf_of, session_id}
	 * for the resubmission currently in flight, or null.
	 *
	 * LOCKED DECISION (HIL Phase 2 T1.2, non-negotiable per brief): on a
	 * resubmission the envelope MUST carry the ORIGINAL agent identity — the
	 * actor stays the actor; the human/automation that resolved the hold (whose
	 * own WordPress request is what triggers resubmit_hold()) must never become
	 * the actor. Set alongside $active_resubmission_hold_id, from the identity
	 * captured in the pending hold entry at hold-creation time
	 * (Reeflex_Holds_Store), and always cleared in the same finally block.
	 *
	 * @var array{id:string,on_behalf_of:string,session_id:string}|null
	 */
	private static ?array $active_resubmission_agent = null;

	/**
	 * Request-scoped decision memo (fan-out fix, 0.1.7).
	 *
	 * WordPress 6.9 invokes the wrapped permission_callback (Hook A) roughly
	 * once per registered ability for a SINGLE REST `/run` request on ONE
	 * action — WP_Ability::execute()/check_permissions() plumbing calls it far
	 * more than the "once per call" the rest of this class's docblocks assume.
	 * Without this memo, N invocations of the SAME underlying action would
	 * each independently normalize -> decide -> audit -> (on hold) store a
	 * NEW pending hold, multiplying one human action into N core round-trips
	 * and N holds that all share the same canonical envelope_hash.
	 *
	 * Keyed by Reeflex_Holds_Store::canonical_envelope_hash( $envelope ) — the
	 * same {action,axes,magnitude,target} projection used for the existing
	 * execution-time envelope_hash dedup (see resubmit_hold()'s docblock) —
	 * which is stable across repeated normalize() calls for the SAME action
	 * (it deliberately excludes nonce/timestamp/agent/session, so it does NOT
	 * distinguish two genuinely separate calls that happen to be identical;
	 * that is an accepted, pre-existing scoping choice, unchanged here).
	 *
	 * Value cached per key is the exact enforcement result that was returned
	 * on the first (memo-miss) call for that key: `true` (allow / observe) or
	 * a WP_Error (deny / require_approval / fail-closed). A memo HIT returns
	 * that SAME value again WITHOUT calling decide(), audit(), store_pending_hold(),
	 * or dispatch_obligations() a second time — collapsing N invocations of one
	 * action into exactly one decision + one audit record + (on hold) one hold.
	 *
	 * Bypassed entirely — never read, never written — while a resubmission is
	 * in flight (self::$active_resubmission_hold_id !== null): a resubmission
	 * must always decide fresh against core to actually consume the hold; it
	 * must never be served a stale memo entry, and it must never poison the
	 * memo for the ability's normal (non-resubmission) callers.
	 *
	 * Cleared via reset_request_cache(), hooked onto `rest_api_init` in
	 * register_hooks() so each real incoming REST request starts with an empty
	 * memo. In a normal per-request PHP process (mod_php/php-fpm) this static
	 * is already empty on every request; the hook is belt-and-suspenders for
	 * long-lived-worker deployments (e.g. Swoole/RoadRunner) and for the
	 * single-process CLI test harnesses in tests/, which call
	 * reset_request_cache() explicitly at scenario boundaries to model
	 * separate requests.
	 *
	 * @var array<string,true|WP_Error>
	 */
	private static array $decision_memo = array();

	/**
	 * Request-scoped idempotent-wrap guard (fan-out fix, 0.1.7).
	 *
	 * Tracks ability names whose permission_callback has already been wrapped
	 * by wrap_permission_callback() this request. Defends against nested
	 * double-wrapping if `wp_register_ability_args` ever fires more than once
	 * for the same ability within one request (e.g. a plugin re-registering
	 * an ability) — without this guard, a second wrap would close over the
	 * ALREADY-WRAPPED callback and every invocation would normalize/decide
	 * TWICE, nested, defeating the decision memo above (each nested layer
	 * would compute its own memo hit/miss independently).
	 *
	 * Cleared via reset_request_cache() alongside $decision_memo, for the same
	 * per-request reasoning.
	 *
	 * @var array<string,true>
	 */
	private static array $wrapped_ability_names = array();

	// ------------------------------------------------------------------
	// Hook registration
	// ------------------------------------------------------------------

	/**
	 * Register both hooks.
	 *
	 * Called from the mu-plugin loader after all class files are included.
	 * Must be called on or before the `wp_abilities_api_init` action so that
	 * the filter is registered before any ability registers.
	 *
	 * @return void
	 */
	public static function register_hooks(): void {
		/*
		 * Hook A: wp_register_ability_args
		 *
		 * Source: class-wp-abilities-registry.php:120 (abilities-api v0.4.0 /
		 *         WP 6.9 core).
		 * Signature: apply_filters( 'wp_register_ability_args', $args, $name )
		 * We return $args with permission_callback replaced by our wrapping closure.
		 */
		add_filter(
			'wp_register_ability_args',
			array( self::class, 'wrap_permission_callback' ),
			10,
			2
		);

		/*
		 * Hook B: mcp_adapter_pre_tool_call
		 *
		 * Source: ToolsHandler.php:182 (mcp-adapter v0.5.0).
		 * Signature: apply_filters( 'mcp_adapter_pre_tool_call', $args, $tool_name, $mcp_tool, $server )
		 * We short-circuit by returning WP_Error on deny/hold/unavailable.
		 * On allow, we return $args unchanged so tool execution proceeds.
		 */
		add_filter(
			'mcp_adapter_pre_tool_call',
			array( self::class, 'gate_mcp_tool' ),
			10,
			4
		);

		/*
		 * Request-scoped cache reset (fan-out fix, 0.1.7).
		 *
		 * `rest_api_init` fires once per incoming REST request, before route
		 * dispatch — before Hook A's wrapped permission_callback can be invoked
		 * for that request. Clearing the decision memo + wrap guard here keeps
		 * both request-scoped in the belt-and-suspenders sense described in
		 * their own docblocks (real per-request PHP processes already start
		 * with empty statics; this matters for long-lived workers and is
		 * mirrored explicitly by the test harnesses via reset_request_cache()).
		 */
		add_action( 'rest_api_init', array( self::class, 'reset_request_cache' ) );
	}

	/**
	 * Clear the request-scoped decision memo and wrap guard.
	 *
	 * Hooked onto `rest_api_init` (see register_hooks()) so each real incoming
	 * REST request starts with an empty memo. Also called explicitly by the
	 * CLI test harnesses (tests/*.php) at scenario boundaries to model separate
	 * requests within one PHP process — see class docblock on $decision_memo.
	 *
	 * @return void
	 */
	public static function reset_request_cache(): void {
		self::$decision_memo         = array();
		self::$wrapped_ability_names = array();
	}

	// ------------------------------------------------------------------
	// Hook A: wp_register_ability_args
	// ------------------------------------------------------------------

	/**
	 * Wrap the ability's permission_callback with a Reeflex gate closure.
	 *
	 * Called at ability registration time (once per ability per request bootstrap).
	 * The returned closure is stored as the ability's permission_callback and is
	 * invoked every time WP_Ability::check_permissions() is called.
	 *
	 * Trusted verb override (P1-7 / NEW-3 monotonic-danger rule):
	 *   If $args contains 'reeflex_verb', it is captured here at registration time
	 *   (not call time) and passed to normalize(). normalize() compares the trusted
	 *   verb against the heuristic and uses whichever is MORE dangerous — the
	 *   trusted verb can only raise or equal danger, never lower it.
	 *   The key is stripped from $args so WP_Ability::prepare_properties() does
	 *   not reject it as an unknown property.
	 *
	 * Exception safety (NEW-2):
	 *   The gating body is wrapped in try/catch(\Throwable). Any exception in
	 *   normalize(), decide(), audit(), or dispatch_obligations() fails CLOSED:
	 *   the exception is logged and a fail-closed deny is enforced.
	 *
	 * Flow inside the closure:
	 *   1. Call the original permission_callback.
	 *   2. If original did NOT grant (false or WP_Error) → return its result
	 *      unchanged.  We never widen access: Reeflex only narrows.
	 *   3. If original granted (true) → try { normalize → decide → audit →
	 *      obligations → enforce } catch(\Throwable) { fail closed }.
	 *
	 * @param  array  $args  Ability registration args (mutable).
	 * @param  string $name  Namespaced ability name (e.g. 'core/delete-post').
	 * @return array  Modified $args with permission_callback replaced.
	 */
	public static function wrap_permission_callback( array $args, string $name ): array {
		// Idempotent-wrap guard (fan-out fix, 0.1.7): if wp_register_ability_args
		// fires more than once for the SAME ability within one request, do not
		// wrap a second time. A second wrap would close over the ALREADY-wrapped
		// callback, nesting two independent normalize->decide->audit layers
		// around every future invocation — see $wrapped_ability_names docblock.
		if ( isset( self::$wrapped_ability_names[ $name ] ) ) {
			return $args;
		}

		// Guard: skip abilities that have no permission callback.
		if ( empty( $args['permission_callback'] ) || ! is_callable( $args['permission_callback'] ) ) {
			return $args;
		}

		self::$wrapped_ability_names[ $name ] = true;

		$original_callback = $args['permission_callback'];
		$ability_name      = $name;

		// Capture trusted verb override at registration time (P1-7 / NEW-3).
		// Strip the key from $args so WP_Ability::prepare_properties() doesn't reject it.
		$trusted_verb = '';
		if ( isset( $args['reeflex_verb'] ) && is_string( $args['reeflex_verb'] ) ) {
			$trusted_verb = $args['reeflex_verb'];
			unset( $args['reeflex_verb'] );
		}

		$args['permission_callback'] = static function ( $input = null ) use (
			$original_callback,
			$ability_name,
			$trusted_verb
		) {
			// Step 1: run the original permission check.
			$original_result = $original_callback( $input );

			// Step 2: if original did NOT grant, do not widen — return as-is.
			if ( true !== $original_result ) {
				return $original_result;
			}

			// Normalize $input to array for Reeflex processing.
			$input_arr = is_array( $input ) ? $input : array();

			// Initialise $envelope so the catch block can reference it even if
			// normalize() throws before the assignment completes.
			$envelope = array();

			// Fan-out fix (0.1.7): a resubmission must ALWAYS decide fresh against
			// core to actually consume the hold — it is never read from, and never
			// written to, the request-scoped decision memo (see $decision_memo
			// docblock). $memo_key stays null until normalize() has produced an
			// envelope to hash; a null key is never looked up or stored (see
			// memoize() below) — there is nothing safe to key an exception that
			// happened before an envelope existed.
			$bypass_memo = ( null !== self::$active_resubmission_hold_id );
			$memo_key    = null;

			// Step 3: gate in a try/catch so any unexpected exception fails CLOSED (NEW-2).
			try {
				// Step 3a: normalize → envelope. approval.present is true, and the agent
				// identity is the ORIGINAL actor's (not the live request's), ONLY when
				// this call is the one resubmit_hold() is currently re-running (HIL
				// Phase 2 T1.2 — LOCKED DECISION: actor stays actor).
				$envelope = Reeflex_Normalizer::normalize(
					$ability_name,
					$input_arr,
					$trusted_verb,
					self::$active_resubmission_hold_id,
					self::$active_resubmission_agent
				);

				// Step 3a.1 (fan-out fix, 0.1.7): compute the request-scoped memo key
				// from the CANONICAL envelope projection — stable across repeated
				// normalize() calls for the same underlying action (unlike the full
				// envelope, which differs on nonce/timestamp every call). A HIT means
				// this exact canonical action has already been decided within this
				// request: return that SAME enforcement result immediately, WITHOUT
				// calling decide(), audit(), store_pending_hold(), or
				// dispatch_obligations() again — this is what collapses WordPress
				// 6.9's N permission_callback invocations for one action into exactly
				// one decision.
				$memo_key = Reeflex_Holds_Store::canonical_envelope_hash( $envelope );
				if ( ! $bypass_memo && isset( self::$decision_memo[ $memo_key ] ) ) {
					return self::$decision_memo[ $memo_key ];
				}

				// Step 3b: POST to /v1/decide.
				$decision = Reeflex_Core_Client::decide( $envelope );

				// OBSERVE (HIL-DESIGN §8): record the would-be verdict, never enforce, always proceed.
				if ( 'observe' === Reeflex_Config::mode() ) {
					Reeflex_Audit::record( $envelope, $decision, 'observe' );
					// action always proceeds in observe mode.
					return self::memoize( $memo_key, $bypass_memo, true );
				}

				// Step 3c: audit before enforcement (record always exists even on fatal).
				$nonce   = $envelope['meta']['nonce'] ?? 'unknown';
				$outcome = self::decision_to_outcome( $decision['decision'], $decision['rule'] ?? '' );
				Reeflex_Audit::record( $envelope, $decision, $outcome );

				// Step 3c.1: HIL Phase 2 — a fresh hold is stored at the SAME moment the
				// reeflex_hold WP_Error is returned, so a human can resolve it later and
				// the ORIGINAL call can be re-run byte-identical (resubmit_hold()).
				if ( 'require_approval' === $decision['decision'] ) {
					self::store_pending_hold( $ability_name, $input_arr, $envelope, $decision );
				}

				// Step 3d: dispatch obligations on allow (P2-11).
				if ( 'allow' === $decision['decision'] ) {
					self::dispatch_obligations( $decision['obligations'] ?? array(), $envelope, $decision );
				}

				// Step 3e: log rule+reason server-side for operator correlation (NEW-1).
				// These are NOT in the public WP_Error data — the REST API serializes data[].
				if ( 'allow' !== $decision['decision'] ) {
					if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
						// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Intentional debug-gated diagnostic; the authoritative record is the JSONL audit log.
						error_log( sprintf(
							'[reeflex] decision=%s rule=%s nonce=%s reason=%s',
							$decision['decision'] ?? 'unknown',
							$decision['rule'] ?? 'unknown',
							$nonce,
							$decision['reason'] ?? ''
						) );
					}
				}

				// Step 3f: enforce, then memoize the exact result returned (fan-out fix, 0.1.7).
				return self::memoize( $memo_key, $bypass_memo, self::enforce_from_permission_callback( $decision ) );

			} catch ( \Throwable $e ) {
				// OBSERVE fail-open (HIL-DESIGN §8): never break the site in observe mode.
				if ( 'observe' === Reeflex_Config::mode() ) {
					if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
						// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Intentional debug-gated diagnostic; the authoritative record is the JSONL audit log.
						error_log( '[reeflex] observe: exception, failing OPEN (action proceeds): ' . $e->getMessage() );
					}
					Reeflex_Audit::record(
						$envelope,
						Reeflex_Core_Client::fail_closed( 'exception in observe (failed open): ' . $e->getMessage() ),
						'observe'
					);
					// action always proceeds in observe mode.
					return self::memoize( $memo_key, $bypass_memo, true );
				}

				// ENFORCE: unexpected exception: fail CLOSED (NEW-2). Log and deny.
				if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
					// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Intentional debug-gated diagnostic; the authoritative record is the JSONL audit log.
					error_log( '[reeflex] unexpected exception in permission gate, failing closed: ' . $e->getMessage() );
				}
				return self::memoize(
					$memo_key,
					$bypass_memo,
					self::enforce_from_permission_callback(
						Reeflex_Core_Client::fail_closed( 'unexpected exception: ' . $e->getMessage() )
					)
				);
			}
		};

		return $args;
	}

	/**
	 * Store $result in the request-scoped decision memo under $memo_key, then
	 * return it — a one-line "cache-then-return" helper so every return path
	 * inside wrap_permission_callback()'s gated block is memoized identically
	 * (fan-out fix, 0.1.7; see $decision_memo docblock).
	 *
	 * No-op (does not write) when $bypass_memo is true (an active resubmission
	 * must never populate the memo) or when $memo_key is null (normalize()
	 * threw before an envelope existed to hash — nothing safe to key by).
	 *
	 * @param  string|null $memo_key     Reeflex_Holds_Store::canonical_envelope_hash() of
	 *                                    the envelope, or null if none was computed.
	 * @param  bool        $bypass_memo  True while a resubmission is in flight.
	 * @param  true|WP_Error $result     The exact value this call is about to return.
	 * @return true|WP_Error  $result, unchanged.
	 */
	private static function memoize( ?string $memo_key, bool $bypass_memo, $result ) {
		if ( ! $bypass_memo && null !== $memo_key ) {
			self::$decision_memo[ $memo_key ] = $result;
		}
		return $result;
	}

	// ------------------------------------------------------------------
	// Hook B: mcp_adapter_pre_tool_call
	// ------------------------------------------------------------------

	/**
	 * Gate the 'mcp-adapter/execute-ability' MCP tool call before it executes.
	 *
	 * Source: ToolsHandler.php:182 (mcp-adapter v0.5.0).
	 * The filter receives $args (tool arguments array) as its first parameter.
	 * Returning a WP_Error short-circuits execution in ToolsHandler::call_tool().
	 *
	 * We only act on tool_name === 'mcp-adapter/execute-ability'; all other
	 * tools are passed through unchanged (Reeflex gates the underlying ability
	 * via Hook A regardless).
	 *
	 * Exception safety (NEW-2):
	 *   The gating body is wrapped in try/catch(\Throwable). Any unexpected
	 *   exception fails CLOSED and returns a reeflex_unavailable WP_Error.
	 *
	 * Note: Hook A and Hook B both independently call reeflex-core for MCP-
	 * originated calls. This is intentional defense-in-depth (P1-5).
	 *
	 * @param  array|WP_Error  $args       Tool arguments (or WP_Error from a prior filter).
	 * @param  string          $tool_name  MCP tool name.
	 * @param  mixed           $mcp_tool   McpTool instance (unused here).
	 * @param  mixed           $server     McpServer instance (unused here).
	 * @return array|WP_Error  $args unchanged on allow; WP_Error on deny/hold/unavailable.
	 */
	public static function gate_mcp_tool( $args, string $tool_name, $mcp_tool, $server ) {
		// Pass through non-execute-ability tools; Hook A covers their underlying abilities.
		if ( 'mcp-adapter/execute-ability' !== $tool_name ) {
			return $args;
		}

		// If a prior filter already short-circuited, respect it.
		if ( is_wp_error( $args ) ) {
			return $args;
		}

		if ( ! is_array( $args ) ) {
			// Unexpected type — fail closed immediately (before try/catch scope).
			return new WP_Error(
				'reeflex_unavailable',
				'Reeflex governance temporarily unavailable.',
				array( 'status' => 503, 'reeflex_decision' => 'deny' )
			);
		}

		$ability_name = isset( $args['ability_name'] ) ? (string) $args['ability_name'] : '';
		$parameters   = isset( $args['parameters'] ) && is_array( $args['parameters'] )
			? $args['parameters']
			: array();

		if ( '' === $ability_name ) {
			// Missing ability_name: invalid call; pass through (not our validation concern).
			return $args;
		}

		// Initialise $envelope so the catch block can reference it even if
		// normalize() throws before the assignment completes.
		$envelope = array();

		// Gate in a try/catch so any unexpected exception fails CLOSED (NEW-2).
		try {
			// Normalize. HIL Phase 2 (SPEC §5.1): resubmission always re-runs the ability
			// directly via wp_get_ability()->execute() (Reeflex_Gate::resubmit_hold()), which
			// only ever fires Hook A — this MCP tool-call layer is not part of that flow, so
			// approval.present is always false here.
			$envelope = Reeflex_Normalizer::normalize( $ability_name, $parameters );

			$decision = Reeflex_Core_Client::decide( $envelope );

			// OBSERVE (HIL-DESIGN §8): record the would-be verdict, never enforce, always proceed.
			if ( 'observe' === Reeflex_Config::mode() ) {
				Reeflex_Audit::record( $envelope, $decision, 'observe' );
				return $args;   // action always proceeds in observe mode.
			}

			// Audit before enforcement.
			$nonce   = $envelope['meta']['nonce'] ?? 'unknown';
			$outcome = self::decision_to_outcome( $decision['decision'], $decision['rule'] ?? '' );
			Reeflex_Audit::record( $envelope, $decision, $outcome );

			// HIL Phase 2: store the pending action so it can be resolved + resubmitted later.
			// See wrap_permission_callback()'s Step 3c.1 — same helper, same entry shape. Note
			// (P1-5, pre-existing): an MCP-originated call also fires Hook A independently, which
			// stores its OWN hold under a DIFFERENT hold_id from core; only Hook A's hold_id is
			// resubmittable via resubmit_hold() (it is the one tied to wp_get_ability()->execute()).
			if ( 'require_approval' === $decision['decision'] ) {
				self::store_pending_hold( $ability_name, $parameters, $envelope, $decision );
			}

			// Log rule+reason server-side for operator correlation (NEW-1).
			if ( 'allow' !== $decision['decision'] ) {
				if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
					// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Intentional debug-gated diagnostic; the authoritative record is the JSONL audit log.
					error_log( sprintf(
						'[reeflex] mcp decision=%s rule=%s nonce=%s reason=%s',
						$decision['decision'] ?? 'unknown',
						$decision['rule'] ?? 'unknown',
						$nonce,
						$decision['reason'] ?? ''
					) );
				}
			}

			if ( 'allow' === $decision['decision'] ) {
				// Dispatch obligations on allow (P2-11).
				self::dispatch_obligations( $decision['obligations'] ?? array(), $envelope, $decision );
				return $args;   // proceed; Hook A will also run independently.
			}

			// deny / require_approval / fail-closed: short-circuit.
			return self::enforce_as_wp_error_for_mcp( $decision );

		} catch ( \Throwable $e ) {
			// OBSERVE fail-open (HIL-DESIGN §8): never break the site in observe mode.
			if ( 'observe' === Reeflex_Config::mode() ) {
				if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
					// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Intentional debug-gated diagnostic; the authoritative record is the JSONL audit log.
					error_log( '[reeflex] observe: exception, failing OPEN (action proceeds): ' . $e->getMessage() );
				}
				Reeflex_Audit::record(
					$envelope,
					Reeflex_Core_Client::fail_closed( 'exception in observe (failed open): ' . $e->getMessage() ),
					'observe'
				);
				return $args;   // action always proceeds in observe mode.
			}

			// ENFORCE: unexpected exception: fail CLOSED (NEW-2). Log and deny.
			if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
				// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Intentional debug-gated diagnostic; the authoritative record is the JSONL audit log.
				error_log( '[reeflex] unexpected exception in MCP gate, failing closed: ' . $e->getMessage() );
			}
			return self::enforce_as_wp_error_for_mcp(
				Reeflex_Core_Client::fail_closed( 'unexpected exception: ' . $e->getMessage() )
			);
		}
	}

	// ------------------------------------------------------------------
	// Enforcement helpers
	// ------------------------------------------------------------------

	/**
	 * Apply the decision from within a permission_callback context.
	 *
	 * permission_callback return contract:
	 *   true     → permission granted; proceed to do_execute().
	 *   WP_Error → permission denied with detail (logged via _doing_it_wrong;
	 *              WP_Ability::execute() surfaces a generic error to the caller).
	 *
	 * Error code semantics (P2-14):
	 *   reeflex_denied      (403) — policy deny: a rule fired.
	 *   reeflex_hold        (202) — require_approval: held pending human resolution
	 *                                (HIL Phase 2 — see hold_error_data()).
	 *   reeflex_unavailable (503) — fail-closed: core unreachable or infrastructure error.
	 *
	 * Public WP_Error data (NEW-1):
	 *   'status' and 'reeflex_decision' are always included. WordPress REST API
	 *   serializes WP_Error data[] into the HTTP response body, so 'reeflex_rule'
	 *   and 'reeflex_reason' are deliberately absent — they are logged server-side
	 *   (error_log) and recorded in the audit JSONL instead. HIL Phase 2 (SPEC §5.1):
	 *   on a hold, 'hold_id' and 'expires_ts' ARE included — unlike rule/reason they
	 *   are not policy-internal detail; the caller/operator needs them to route the
	 *   action to a human and later resubmit it.
	 *
	 * @param  array $decision   Decision from core (or fail-closed).
	 * @return true|WP_Error
	 */
	private static function enforce_from_permission_callback( array $decision ) {
		$rule           = $decision['rule'] ?? 'unknown';
		$is_fail_closed = ( 'reeflex.adapter/fail_closed' === $rule );

		switch ( $decision['decision'] ) {
			case 'allow':
				return true;

			case 'deny':
				if ( $is_fail_closed ) {
					// Infrastructure failure: 503 + reeflex_unavailable (P2-14).
					return new WP_Error(
						'reeflex_unavailable',
						'Reeflex governance temporarily unavailable.',
						array(
							'status'           => 503,
							'reeflex_decision' => 'deny',
						)
					);
				}
				// Policy deny: 403. Rule+reason are in error_log and audit JSONL (NEW-1).
				return new WP_Error(
					'reeflex_denied',
					'Action denied by Reeflex policy.',
					array(
						'status'           => 403,
						'reeflex_decision' => 'deny',
					)
				);

			case 'require_approval':
				// HIL Phase 2 (SPEC §5.1): held, not terminal — hold_id + expires_ts let
				// the caller route this to a human and, once approved, resubmit it via
				// Reeflex_Gate::resubmit_hold( $hold_id ).
				return new WP_Error(
					'reeflex_hold',
					'Action requires human approval.',
					self::hold_error_data( $decision )
				);

			default:
				// Unknown decision value: fail closed (P2-14).
				return new WP_Error(
					'reeflex_unavailable',
					'Reeflex governance temporarily unavailable.',
					array(
						'status'           => 503,
						'reeflex_decision' => $decision['decision'] ?? 'unknown',
					)
				);
		}
	}

	/**
	 * Build a WP_Error for the MCP tool layer (Hook B).
	 *
	 * Same semantics as enforce_from_permission_callback.
	 * Always returns WP_Error (ToolsHandler checks is_wp_error() to short-circuit).
	 *
	 * Public data arrays carry 'status' and 'reeflex_decision' (NEW-1); on a hold,
	 * also 'hold_id' + 'expires_ts' (HIL Phase 2 — see hold_error_data()).
	 *
	 * @param  array $decision   Decision from core.
	 * @return WP_Error
	 */
	private static function enforce_as_wp_error_for_mcp( array $decision ): WP_Error {
		$rule           = $decision['rule'] ?? 'unknown';
		$is_fail_closed = ( 'reeflex.adapter/fail_closed' === $rule );

		switch ( $decision['decision'] ) {
			case 'deny':
				if ( $is_fail_closed ) {
					return new WP_Error(
						'reeflex_unavailable',
						'Reeflex governance temporarily unavailable.',
						array(
							'status'           => 503,
							'reeflex_decision' => 'deny',
						)
					);
				}
				return new WP_Error(
					'reeflex_denied',
					'Action denied by Reeflex policy.',
					array(
						'status'           => 403,
						'reeflex_decision' => 'deny',
					)
				);

			case 'require_approval':
				// HIL Phase 2 (SPEC §5.1): held, not terminal — see hold_error_data().
				// Note (P1-5, pre-existing): this hold_id is Hook B's OWN hold, distinct
				// from any hold Hook A independently created for the same MCP call.
				return new WP_Error(
					'reeflex_hold',
					'Action requires human approval.',
					self::hold_error_data( $decision )
				);

			default:
				return new WP_Error(
					'reeflex_unavailable',
					'Reeflex governance temporarily unavailable.',
					array(
						'status'           => 503,
						'reeflex_decision' => $decision['decision'] ?? 'unknown',
					)
				);
		}
	}

	/**
	 * Build the public WP_Error data array for a require_approval decision.
	 *
	 * HIL Phase 2 (SPEC §5.1): 'hold_id' and 'expires_ts' are included whenever
	 * core sent them (Reeflex_Core_Client::decide() passes them through). They
	 * are deliberately public — unlike 'reeflex_rule'/'reeflex_reason' (NEW-1)
	 * they are not policy-internal detail; the caller needs them to route the
	 * hold to a human and, once approved, resubmit it via resubmit_hold().
	 *
	 * @param  array $decision  Decision from core.
	 * @return array
	 */
	private static function hold_error_data( array $decision ): array {
		$data = array(
			'status'           => 202,
			'reeflex_decision' => 'require_approval',
		);
		if ( isset( $decision['hold_id'] ) ) {
			$data['hold_id'] = $decision['hold_id'];
		}
		if ( isset( $decision['expires_ts'] ) ) {
			$data['expires_ts'] = $decision['expires_ts'];
		}
		return $data;
	}

	// ------------------------------------------------------------------
	// HIL Phase 2 — hold storage & resubmission (T1)
	// ------------------------------------------------------------------

	/**
	 * Store a pending hold so it can be resolved and re-run later.
	 *
	 * Called at the SAME moment a require_approval decision is turned into the
	 * public reeflex_hold WP_Error, from both Hook A and Hook B. A no-op if core
	 * did not include a hold_id (e.g. an older core without HIL support) — there
	 * is nothing to key the entry by, and the hold remains terminal exactly as in
	 * v0.1 for that call.
	 *
	 * @param  string $ability   Namespaced ability name.
	 * @param  array  $input     The ORIGINAL input array passed to the ability
	 *                           (stored verbatim for a byte-identical re-run).
	 * @param  array  $envelope  The Action Envelope that produced the hold.
	 * @param  array  $decision  The require_approval Decision (carries hold_id + expires_ts).
	 * @return void
	 */
	private static function store_pending_hold(
		string $ability,
		array $input,
		array $envelope,
		array $decision
	): void {
		$hold_id = isset( $decision['hold_id'] ) ? (string) $decision['hold_id'] : '';
		if ( '' === $hold_id ) {
			if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
				// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Intentional debug-gated diagnostic; the authoritative record is the JSONL audit log.
				error_log(
					'[reeflex] WARN: require_approval decision carried no hold_id — core may predate ' .
					'HIL support (< v0.1.5). This hold is terminal; resubmit_hold() has nothing to key.'
				);
			}
			return;
		}

		Reeflex_Holds_Store::save(
			array(
				'hold_id'       => $hold_id,
				'ability'       => $ability,
				'input'         => $input,
				'envelope_hash' => Reeflex_Holds_Store::canonical_envelope_hash( $envelope ),
				'rule_id'       => $decision['rule'] ?? 'unknown',
				'created_ts'    => gmdate( 'Y-m-d\TH:i:s\Z' ),
				'expires_ts'    => isset( $decision['expires_ts'] ) ? (string) $decision['expires_ts'] : '',
				'session_id'    => $envelope['agent']['session_id'] ?? 'unknown',
				// LOCKED DECISION (T1.2): the full ORIGINAL agent identity, so
				// resubmit_hold() can put the actor back exactly as it was —
				// never the identity of whoever resolves/resubmits the hold.
				'agent'         => array(
					'id'           => (string) ( $envelope['agent']['id'] ?? '' ),
					'on_behalf_of' => (string) ( $envelope['agent']['on_behalf_of'] ?? '' ),
					'session_id'   => (string) ( $envelope['agent']['session_id'] ?? '' ),
				),
			)
		);
	}

	/**
	 * Re-submit a previously-held action after a human has approved it.
	 *
	 * Flow (T1, extended 0.1.6 with step a.1 + revised step c):
	 *   a. Load the stored entry (Reeflex_Holds_Store::get()). Missing → 'reeflex_hold_unknown'.
	 *   a.1. Double-execution dedup (0.1.6 — see class docblock "Double-gating" and
	 *      Reeflex_Holds_Store's own docblock for 'executed_ts'): BEFORE anything
	 *      else, check whether this exact hold_id, or another hold created "in the
	 *      same wave" (same envelope_hash + session_id, within a tight
	 *      creation-time window — see find_executed_companion_hold_id()), has
	 *      ALREADY executed. If so, the underlying ability must NOT run again —
	 *      this hold's local record is cleaned up and a distinct
	 *      'reeflex_hold_deduplicated' result is returned instead. This covers both:
	 *        - a companion hold for the SAME originating call (Hook A + Hook B each
	 *          produced their own hold_id for one MCP-originated call — the bug this
	 *          fix closes); and
	 *        - a repeat resubmission of the SAME hold_id itself (e.g. a double
	 *          admin-post submit) — needed because, since 0.1.6, a successfully
	 *          executed entry is marked executed rather than deleted (so a
	 *          companion can still find it), so it would otherwise still be
	 *          resubmittable.
	 *      Then: locally past its own expires_ts → 'reeflex_hold_expired' (a fast
	 *      local check; core is still the authority and would reach the same
	 *      conclusion via hold validation).
	 *   b. Re-execute the ORIGINAL ability with the ORIGINAL input via
	 *      wp_get_ability( $ability )->execute( $input ). Around that single call,
	 *      $active_resubmission_hold_id is set so the SAME gate (Hook A wraps
	 *      permission_callback) builds this one envelope with
	 *      approval = {present:true, hold_id} — everything else (action, axes,
	 *      magnitude, target, agent identity) is built exactly as a fresh call
	 *      would build it, and the ORIGINAL agent identity stays the actor (never
	 *      the approver, which is never even read into the envelope here).
	 *   c. Core validates the hold: allow → the wrapped permission_callback returns
	 *      true → WP_Ability::execute() runs do_execute() → its result is returned.
	 *      Deny (consumed/expired/mismatch/actor_is_approver/fail-closed/...) →
	 *      the gate's own WP_Error is returned unchanged, carrying core's reason
	 *      server-side (error_log + audit JSONL) exactly as any other deny. Either
	 *      way an approval is single-use: on a confirmed execution the entry is
	 *      marked executed (Reeflex_Holds_Store::mark_executed() — kept, not
	 *      deleted, so a companion hold found later via step a.1 can still be
	 *      deduplicated); on a gate-enforced deny (nothing executed) the entry is
	 *      deleted exactly as before 0.1.6, so a genuinely failed/denied
	 *      resubmission still cannot be retried into a later allow.
	 *   d. Fails closed: an ability that is no longer registered, or that throws
	 *      while executing, returns a WP_Error rather than silently succeeding.
	 *
	 * Residual scoping risk (double-execution dedup, 0.1.6) — read before relying
	 * on this as a general-purpose idempotency guarantee: envelope_hash alone
	 * covers only {action,axes,magnitude,target} (SPEC's own hash projection) — it
	 * does NOT include session_id, nonce, or hold_id, so two genuinely SEPARATE,
	 * deliberate, identical actions (e.g. the same bulk-delete performed twice on
	 * purpose) share the same envelope_hash. find_executed_companion_hold_id()
	 * additionally requires the SAME session_id (for an MCP-originated call, the
	 * Mcp-Session-Id HTTP header — identical for Hook A and Hook B because both
	 * handle the SAME incoming HTTP request) AND a created_ts within a tight
	 * window of each other (Hook A and Hook B fire milliseconds apart for one
	 * real call). The one case this does NOT distinguish: a human/agent who
	 * deliberately submits the exact SAME action twice on purpose, in the SAME
	 * MCP session, within that same tight window, would have the second
	 * submission wrongly deduplicated as a companion of the first. This is
	 * judged an acceptable, narrow trade-off (see
	 * Reeflex_Holds_Store::find_executed_companion_hold_id()'s own docblock for
	 * the full rationale) — but it is a real, deliberate scoping choice, not an
	 * oversight, called out here explicitly per the fix's own design brief.
	 *
	 * Auditing: the underlying decision (allow or a hold-validation deny) is
	 * already written by the normal per-decision audit inside step (b) — the
	 * envelope's approval={present:true, hold_id} makes that record identifiable
	 * as a resubmission (Reeflex_Audit::build_record()). This method additionally
	 * audits the cases resolved BEFORE ever reaching the gate (unknown/expired/
	 * deduplicated hold, ability no longer registered, unexpected exception),
	 * which would otherwise leave no trace.
	 *
	 * @param  string $hold_id  The hold_id returned in the original require_approval response.
	 * @return mixed|WP_Error   The ability's execute() return value on a fresh execution;
	 *                          WP_Error on any failure OR on a deduplicated no-op (code
	 *                          'reeflex_hold_deduplicated' — distinct from both a fresh
	 *                          execution and an ordinary deny). Never assumes success —
	 *                          fail-closed throughout.
	 */
	public static function resubmit_hold( string $hold_id ) {
		$entry = Reeflex_Holds_Store::get( $hold_id );

		if ( null === $entry ) {
			self::audit_synthetic_resubmission(
				$hold_id,
				'',
				'',
				'hold is unknown to this adapter (never existed, or already swept)',
				'reeflex.adapter/hold_unknown'
			);
			return new WP_Error(
				'reeflex_hold_unknown',
				'This hold is unknown to this site.',
				array( 'status' => 404 )
			);
		}

		$ability       = isset( $entry['ability'] ) ? (string) $entry['ability'] : '';
		$input         = isset( $entry['input'] ) && is_array( $entry['input'] ) ? $entry['input'] : array();
		$session_id    = isset( $entry['session_id'] ) ? (string) $entry['session_id'] : '';
		$envelope_hash = isset( $entry['envelope_hash'] ) ? (string) $entry['envelope_hash'] : '';
		$created_ts    = isset( $entry['created_ts'] ) ? (string) $entry['created_ts'] : '';
		$executed_ts   = isset( $entry['executed_ts'] ) ? (string) $entry['executed_ts'] : '';

		// Double-execution dedup (0.1.6) — see method docblock step a.1. Two cases:
		// (i) this EXACT hold_id already executed once (repeat/double-submit), or
		// (ii) a DIFFERENT hold created "in the same wave" (companion — same
		// envelope_hash + session_id, within a tight creation-time window) already
		// executed. Either way the ability must not run again for this hold.
		$already_executed_via = '' !== $executed_ts
			? $hold_id
			: Reeflex_Holds_Store::find_executed_companion_hold_id( $envelope_hash, $session_id, $created_ts, $hold_id );

		if ( null !== $already_executed_via ) {
			Reeflex_Holds_Store::delete( $hold_id );
			self::audit_synthetic_resubmission(
				$hold_id,
				$ability,
				$session_id,
				'action already executed via hold ' . $already_executed_via .
					' (same envelope_hash + session_id, created in the same wave — double-gating dedup, 0.1.6)',
				'reeflex.adapter/hold_deduplicated'
			);
			return new WP_Error(
				'reeflex_hold_deduplicated',
				'This action was already executed via a companion hold for the same underlying call; no action taken.',
				array(
					'status'                => 200,
					'reeflex_decision'      => 'deduplicated',
					'already_executed_via'  => $already_executed_via,
				)
			);
		}

		// Fast local expiry check — core is still authoritative (it would deny with
		// reeflex_hold_expired via the normal hold-validation path below regardless).
		$expires_ts    = isset( $entry['expires_ts'] ) ? (string) $entry['expires_ts'] : '';
		$expires_epoch = '' !== $expires_ts ? strtotime( $expires_ts ) : false;
		if ( false !== $expires_epoch && time() >= $expires_epoch ) {
			Reeflex_Holds_Store::delete( $hold_id );
			self::audit_synthetic_resubmission(
				$hold_id,
				$ability,
				$session_id,
				'hold past its expires_ts (adapter-side check)',
				'reeflex.adapter/hold_expired'
			);
			return new WP_Error(
				'reeflex_hold_expired',
				'This hold has expired.',
				array( 'status' => 410 )
			);
		}

		$ability_obj = function_exists( 'wp_get_ability' ) ? wp_get_ability( $ability ) : null;

		if ( ! is_object( $ability_obj ) || ! method_exists( $ability_obj, 'execute' ) ) {
			self::audit_synthetic_resubmission(
				$hold_id,
				$ability,
				$session_id,
				'ability is no longer registered',
				'reeflex.adapter/hold_ability_unavailable'
			);
			return new WP_Error(
				'reeflex_hold_ability_unavailable',
				'The action for this hold is no longer available on this site.',
				array( 'status' => 503 )
			);
		}

		// Attach the approval — AND the ORIGINAL agent identity (LOCKED DECISION,
		// T1.2) — to THIS ability call only (request-scoped; see the
		// $active_resubmission_hold_id / $active_resubmission_agent docblocks).
		// Always cleared, even on exception.
		$stored_agent = isset( $entry['agent'] ) && is_array( $entry['agent'] ) ? $entry['agent'] : array();
		self::$active_resubmission_hold_id = $hold_id;
		self::$active_resubmission_agent   = $stored_agent;
		try {
			$result = $ability_obj->execute( $input );
		} catch ( \Throwable $e ) {
			if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
				// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Intentional debug-gated diagnostic; the authoritative record is the JSONL audit log.
				error_log( '[reeflex] resubmit_hold: exception executing ability, failing closed: ' . $e->getMessage() );
			}
			self::audit_synthetic_resubmission(
				$hold_id,
				$ability,
				$session_id,
				'unexpected exception executing ability: ' . $e->getMessage(),
				'reeflex.adapter/hold_execute_exception'
			);
			return new WP_Error(
				'reeflex_hold_execute_failed',
				'Resubmission failed due to an unexpected error.',
				array( 'status' => 503 )
			);
		} finally {
			self::$active_resubmission_hold_id = null;
			self::$active_resubmission_agent   = null;
		}

		// Either outcome (allow -> executed, or a gate-enforced deny) is TERMINAL for
		// this hold: an approval is single-use, and a denied resubmission cannot be
		// retried into an allow by calling resubmit_hold() again. The decision itself
		// (allow or deny) was already audited inside execute() -> the wrapped
		// permission_callback -> the normal per-decision audit (see method docblock).
		//
		// Double-execution dedup (0.1.6): a non-WP_Error $result means the wrapped
		// permission_callback returned true and WP_Ability::execute() actually ran
		// do_execute() — i.e. the action executed. That entry is MARKED executed
		// (kept, not deleted) so a companion hold for the same call, resubmitted
		// later, can be recognised via step a.1 above and deduplicated instead of
		// re-running the action. A WP_Error result means the gate itself denied
		// this resubmission (nothing executed) — that entry is deleted exactly as
		// before 0.1.6, since a genuinely failed/denied resubmission must still be
		// retryable-as-a-fresh-attempt-only, never treated as "already executed".
		if ( $result instanceof WP_Error ) {
			Reeflex_Holds_Store::delete( $hold_id );
		} else {
			Reeflex_Holds_Store::mark_executed( $hold_id );
		}

		return $result;
	}

	/**
	 * Write a minimal synthetic audit record for a resubmission outcome that was
	 * resolved entirely inside resubmit_hold() — before ever reaching the gate, so
	 * the normal per-decision audit path never ran for it.
	 *
	 * @param  string $hold_id     The hold_id being resubmitted.
	 * @param  string $ability     Ability name, if known ('' if the hold itself was unknown).
	 * @param  string $session_id  The original session_id, if known.
	 * @param  string $reason      Human-readable reason (server-side / audit only).
	 * @param  string $rule        Synthetic adapter-side rule id, namespaced 'reeflex.adapter/...'
	 *                             to match the existing fail_closed convention.
	 * @return void
	 */
	private static function audit_synthetic_resubmission(
		string $hold_id,
		string $ability,
		string $session_id,
		string $reason,
		string $rule
	): void {
		$envelope = array(
			'agent'    => array(
				'id'           => Reeflex_Config::agent_id(),
				'on_behalf_of' => null,
				'session_id'   => '' !== $session_id ? $session_id : 'unknown',
			),
			'action'   => array(
				'namespace' => 'wordpress',
				'verb'      => 'unknown',
				'ability'   => '' !== $ability ? $ability : 'unknown',
			),
			'target'    => array( 'environment' => Reeflex_Config::env() ),
			'magnitude' => array( 'count' => 1 ),
			'axes'      => array(),
			'approval'  => array(
				'present' => true,
				'hold_id' => $hold_id,
			),
			'meta'      => array( 'nonce' => 'resubmit:' . $hold_id ),
		);
		$decision = array(
			'decision'    => 'deny',
			'reason'      => $reason,
			'rule'        => $rule,
			'obligations' => array(),
		);
		Reeflex_Audit::record( $envelope, $decision, 'fail_closed_deny' );
	}

	// ------------------------------------------------------------------
	// Obligation dispatch (P2-11)
	// ------------------------------------------------------------------

	/**
	 * Dispatch obligations returned by core on an allow decision.
	 *
	 * For each obligation string the adapter:
	 *   1. Fires do_action('reeflex_obligation', $obligation, $envelope, $decision)
	 *      so operators can hook custom obligation handlers.
	 *   2. Recognizes 'audit:full' as a no-op-but-acknowledged (the audit record
	 *      is already written before this method is called).
	 *   3. error_logs a warning for any obligation it does not explicitly recognise,
	 *      so nothing passes silently (SPEC §7: "honors every returned obligation").
	 *
	 * Recognized obligations:
	 *   audit:full — acknowledged; audit record already written.
	 *
	 * Upgrade path: add cases for 'rate_limit', 'redact:pii', etc.
	 *
	 * @param  array  $obligations  Array of obligation strings from the Decision.
	 * @param  array  $envelope     The Action Envelope (passed to action hook).
	 * @param  array  $decision     The full Decision (passed to action hook).
	 * @return void
	 */
	private static function dispatch_obligations(
		array $obligations,
		array $envelope,
		array $decision
	): void {
		$recognized = array( 'audit:full' );

		foreach ( $obligations as $obligation ) {
			if ( ! is_string( $obligation ) || '' === $obligation ) {
				continue;
			}

			/**
			 * Fires when reeflex-core returns an obligation on an allow decision.
			 *
			 * @param string $obligation  The obligation identifier (e.g. 'audit:full').
			 * @param array  $envelope    The Action Envelope that was decided on.
			 * @param array  $decision    The full Decision returned by core.
			 */
			do_action( 'reeflex_obligation', $obligation, $envelope, $decision );

			if ( ! in_array( $obligation, $recognized, true ) ) {
				if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
					// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Intentional debug-gated diagnostic; the authoritative record is the JSONL audit log.
					error_log(
						'[reeflex] WARN: unrecognized obligation "' . $obligation . '" — ' .
						'no built-in handler; reeflex_obligation action was fired for operator hooks.'
					);
				}
			}
		}
	}

	// ------------------------------------------------------------------
	// Utility helpers
	// ------------------------------------------------------------------

	/**
	 * Map a Decision string to an audit 'applied' outcome label.
	 *
	 * Distinguishes fail-closed deny from policy deny using the rule field (P2-14).
	 *
	 * @param  string $decision_value  'allow'|'deny'|'require_approval'|other
	 * @param  string $rule            The rule that fired.
	 * @return string
	 */
	private static function decision_to_outcome( string $decision_value, string $rule ): string {
		if ( 'deny' === $decision_value && 'reeflex.adapter/fail_closed' === $rule ) {
			return 'fail_closed_deny';
		}
		$map = array(
			'allow'            => 'allow',
			'deny'             => 'deny',
			'require_approval' => 'hold',
		);
		return $map[ $decision_value ] ?? 'fail_closed_deny';
	}
}
