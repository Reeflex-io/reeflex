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
 *   There is NO dedup/nonce-cache between them (P1-5).
 *
 * Exception safety (NEW-2):
 *   Both the permission_callback closure and gate_mcp_tool() are wrapped in
 *   try/catch(\Throwable). Any unexpected exception fails CLOSED — the action
 *   is blocked, the exception message is logged, and a fail-closed deny is
 *   synthesized via Reeflex_Core_Client::fail_closed().
 *
 * Approval (P0-1):
 *   There is NO agent-controlled approval path in v0.1. require_approval
 *   decisions are always terminal — the action is held. See
 *   Reeflex_Normalizer::normalize() docblock for the roadmap design of the
 *   server-side approval flow that would safely implement re-submission.
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
		// Guard: skip abilities that have no permission callback.
		if ( empty( $args['permission_callback'] ) || ! is_callable( $args['permission_callback'] ) ) {
			return $args;
		}

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

			// Step 3: gate in a try/catch so any unexpected exception fails CLOSED (NEW-2).
			try {
				// Step 3a: normalize → envelope (approval always false in v0.1, P0-1).
				$envelope = Reeflex_Normalizer::normalize( $ability_name, $input_arr, $trusted_verb );

				// Step 3b: POST to /v1/decide.
				$decision = Reeflex_Core_Client::decide( $envelope );

				// Step 3c: audit before enforcement (record always exists even on fatal).
				$nonce   = $envelope['meta']['nonce'] ?? 'unknown';
				$outcome = self::decision_to_outcome( $decision['decision'], $decision['rule'] ?? '' );
				Reeflex_Audit::record( $envelope, $decision, $outcome );

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

				// Step 3f: enforce.
				return self::enforce_from_permission_callback( $decision );

			} catch ( \Throwable $e ) {
				// Unexpected exception: fail CLOSED (NEW-2). Log and deny.
				if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
					// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Intentional debug-gated diagnostic; the authoritative record is the JSONL audit log.
					error_log( '[reeflex] unexpected exception in permission gate, failing closed: ' . $e->getMessage() );
				}
				return self::enforce_from_permission_callback(
					Reeflex_Core_Client::fail_closed( 'unexpected exception: ' . $e->getMessage() )
				);
			}
		};

		return $args;
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

		// Gate in a try/catch so any unexpected exception fails CLOSED (NEW-2).
		try {
			// Normalize (approval always false in v0.1, P0-1).
			$envelope = Reeflex_Normalizer::normalize( $ability_name, $parameters );

			$decision = Reeflex_Core_Client::decide( $envelope );

			// Audit before enforcement.
			$nonce   = $envelope['meta']['nonce'] ?? 'unknown';
			$outcome = self::decision_to_outcome( $decision['decision'], $decision['rule'] ?? '' );
			Reeflex_Audit::record( $envelope, $decision, $outcome );

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
			// Unexpected exception: fail CLOSED (NEW-2). Log and deny.
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
	 *   reeflex_hold        (202) — require_approval: terminal hold in v0.1.
	 *   reeflex_unavailable (503) — fail-closed: core unreachable or infrastructure error.
	 *
	 * Public WP_Error data (NEW-1):
	 *   ONLY 'status' and 'reeflex_decision' are included. WordPress REST API
	 *   serializes WP_Error data[] into the HTTP response body, so 'reeflex_rule'
	 *   and 'reeflex_reason' are deliberately absent — they are logged server-side
	 *   (error_log) and recorded in the audit JSONL instead.
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
				// Hold is TERMINAL in v0.1 (P0-1). No re-submission path.
				return new WP_Error(
					'reeflex_hold',
					'Action requires human approval.',
					array(
						'status'           => 202,
						'reeflex_decision' => 'require_approval',
					)
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
	 * Public data arrays carry ONLY 'status' and 'reeflex_decision' (NEW-1).
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
				// Terminal hold in v0.1 (P0-1).
				return new WP_Error(
					'reeflex_hold',
					'Action requires human approval.',
					array(
						'status'           => 202,
						'reeflex_decision' => 'require_approval',
					)
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
