<?php
/**
 * Reeflex Admin — wp-admin "Reeflex — Pending approvals" surface (HIL Phase 2 T2).
 *
 * A human-in-the-loop console for holds created by Reeflex_Gate when core returns
 * `require_approval` (SPEC §5.1). Lists everything Reeflex_Holds_Store::list_all()
 * currently has pending, and lets a `manage_options` user approve-and-run or reject
 * each one, without ever exposing the core bearer token to the browser.
 *
 * WHAT THIS CLASS DOES NOT DO (by design):
 *   - It does not decide anything. Every allow/deny/require_approval verdict still
 *     comes from reeflex-core alone (POST /v1/holds/{id}/resolve). This class only
 *     proxies that one HTTP call server-side and, on an approved resolution, invokes
 *     Reeflex_Gate::resubmit_hold() — the SAME public method the T1 conformance
 *     harness drives directly. No policy logic, no LLM, no free-text decision input
 *     lives here.
 *   - It does not alter Reeflex_Gate::resubmit_hold()'s identity behaviour. The
 *     approver (whoever clicks the button on this page) is sent to core as the
 *     RESOLVING principal only (`principal.id` on /v1/holds/{id}/resolve — i.e. "who
 *     approved this"). resubmit_hold() independently re-derives the envelope's
 *     ORIGINAL agent identity from the stored hold entry, exactly as it does when
 *     driven from the T1 harness or any other caller — this class never touches
 *     that logic and never passes the approver's identity into the resubmitted
 *     envelope.
 *   - It does not add a freeze toggle. Freeze (REEFLEX_FREEZE) is a reeflex-core
 *     operator-side environment variable with no corresponding read/write HTTP
 *     endpoint (see render_freeze_banner()) — inventing one here would either be a
 *     fake control (if WP can't actually flip it) or a scope-creeping new core API
 *     surface. Neither is acceptable, so the banner says so honestly instead.
 *
 * HONEST NOTE — approval executes on click:
 *   Resolving a hold as "approve" on core (HTTP 200, hold status -> approved) is
 *   immediately followed, in the SAME request, by Reeflex_Gate::resubmit_hold() —
 *   which re-runs the original WordPress ability with its original input. There is
 *   no separate "approved, run later" step: clicking "Approve & run" on this page
 *   IS the execution step. This is stated in the page copy (render_page()) as well
 *   as here, per the HIL Phase 2 T2 brief's explicit instruction to bake this in
 *   rather than let an operator assume approval alone is inert.
 *
 * HONEST NOTE — MCP-originated holds (Hook B) — FIXED in 0.1.6:
 *   An MCP-originated ability call can be gated twice: Hook A
 *   (wp_register_ability_args, bound to the ability's own execute()) and Hook B
 *   (mcp_adapter_pre_tool_call, the MCP tool-call layer) both independently call
 *   core (see class-reeflex-gate.php's own docblock, "Double-gating"). If BOTH
 *   produce a require_approval, they are STILL stored as two SEPARATE hold_ids
 *   (Reeflex_Gate::store_pending_hold() is called from both hooks with no dedup at
 *   CREATION time — documented, pre-existing P1-5, unchanged) — this page can show
 *   what looks like two rows for the same underlying call.
 *
 *   What changed in 0.1.6: approving BOTH of those rows here no longer runs the
 *   action twice. Reeflex_Gate::resubmit_hold() now deduplicates holds created
 *   "in the same wave" — same envelope_hash, same session_id, created within a
 *   tight time window of each other (Reeflex_Holds_Store's 'executed_ts' field
 *   and find_executed_companion_hold_id() — see that class's docblock): the
 *   FIRST approved hold for a given underlying call actually executes the
 *   ability; approving the SECOND (companion) hold afterward resolves it on
 *   core and closes the local record, but is a safe no-op — it will NOT execute
 *   anything again. process_resolution() reports this outcome honestly (a
 *   distinct success message, not a plain "executed" or a failure) rather than
 *   pretending nothing happened. See Reeflex_Gate::resubmit_hold()'s own
 *   docblock for the residual scoping risk (a deliberate identical repeat
 *   submitted in the SAME MCP session within that same tight window would also
 *   be deduplicated — a narrow, documented trade-off, not a general-purpose
 *   idempotency guarantee for genuinely separate calls).
 *
 * Security:
 *   - Every entry point (render_page(), handle_resolve()) checks
 *     current_user_can('manage_options') before doing anything else.
 *   - handle_resolve() is registered on admin_post_{action} and additionally
 *     verifies a per-hold nonce (the nonce action string embeds the hold_id, so a
 *     nonce harvested from one hold's form cannot be replayed against another).
 *   - All output is escaped at the point of echo (esc_html/esc_attr/esc_url); all
 *     input is sanitized on read (sanitize_text_field/sanitize_textarea_field +
 *     wp_unslash).
 *   - The core bearer token (Reeflex_Config::core_token()) is read and used only
 *     inside resolve_on_core(), which runs server-side as part of handling the
 *     admin-post.php POST; it is never placed in any HTML, redirect URL, or notice
 *     shown to the browser.
 *
 * Testability:
 *   process_resolution() is deliberately a pure, side-effect-documented method that
 *   takes plain strings and returns a plain array — no $_POST, no nonce, no
 *   redirect/exit. handle_resolve() is the thin WP-request glue around it. This
 *   mirrors how tests/conformance-demo.php drives Reeflex_Gate::resubmit_hold()
 *   directly rather than simulating a full HTTP request cycle; see
 *   tests/admin-holds-demo.php.
 *
 * @package ReeflexWordPress
 * @since   0.1.6
 */

declare( strict_types=1 );

defined( 'ABSPATH' ) || exit;

/**
 * Registers and renders the "Reeflex — Pending approvals" wp-admin page.
 */
final class Reeflex_Admin {

	/**
	 * Capability required for every entry point on this surface.
	 *
	 * @var string
	 */
	private const CAPABILITY = 'manage_options';

	/**
	 * admin.php page slug.
	 *
	 * @var string
	 */
	private const PAGE_SLUG = 'reeflex-holds';

	/**
	 * admin-post.php action name (both Approve and Reject post here; the specific
	 * decision is read from the 'decision' field and validated against an allow-list).
	 *
	 * @var string
	 */
	private const ACTION_RESOLVE = 'reeflex_hold_resolve';

	/**
	 * Nonce action prefix. The full nonce action is this prefix concatenated with
	 * the specific hold_id being acted on, so a nonce is only valid for ONE hold.
	 *
	 * @var string
	 */
	private const NONCE_PREFIX = 'reeflex_hold_action_';

	/**
	 * Transient key prefix for the one-shot post-redirect notice, keyed per WP user.
	 *
	 * @var string
	 */
	private const NOTICE_TRANSIENT_PREFIX = 'reeflex_gate_hold_notice_';

	/**
	 * How long a stashed notice survives if never displayed (seconds).
	 *
	 * @var int
	 */
	private const NOTICE_TTL = 60;

	// ------------------------------------------------------------------
	// Registration
	// ------------------------------------------------------------------

	/**
	 * Register admin hooks.
	 *
	 * Safe to call at file-load time from the mu-plugin loader; WordPress queues
	 * the callbacks and only fires them in the appropriate context (admin_menu on
	 * every wp-admin request; admin_post_{action} only when that exact POST arrives).
	 *
	 * @return void
	 */
	public static function init(): void {
		add_action( 'admin_menu', array( self::class, 'add_menu_page' ) );
		add_action( 'admin_post_' . self::ACTION_RESOLVE, array( self::class, 'handle_resolve' ) );
	}

	// ------------------------------------------------------------------
	// Menu
	// ------------------------------------------------------------------

	/**
	 * Register the top-level "Reeflex" admin menu, with a pending-count badge.
	 *
	 * A dedicated top-level menu (rather than nesting under Settings, where the
	 * Reeflex Gate configuration page already lives) because this is an
	 * operational surface an admin needs to check routinely, not a one-time
	 * configuration screen.
	 *
	 * @return void
	 */
	public static function add_menu_page(): void {
		$count = count( Reeflex_Holds_Store::list_all() );

		$menu_title = esc_html__( 'Reeflex', 'reeflex-gate' );
		if ( $count > 0 ) {
			// Mirrors WordPress core's own "awaiting-mod" bubble markup (used for the
			// Comments menu's pending-comment count) — standard, expected wp-admin idiom.
			// $count is an int from count(), never user input; absint() is defense-in-depth.
			$menu_title .= sprintf(
				' <span class="awaiting-mod count-%1$d"><span class="pending-count">%1$d</span></span>',
				absint( $count )
			);
		}

		add_menu_page(
			esc_html__( 'Reeflex — Pending approvals', 'reeflex-gate' ),
			$menu_title,
			self::CAPABILITY,
			self::PAGE_SLUG,
			array( self::class, 'render_page' ),
			'dashicons-shield-alt'
		);
	}

	// ------------------------------------------------------------------
	// Render: page
	// ------------------------------------------------------------------

	/**
	 * Render the full "Reeflex — Pending approvals" page.
	 *
	 * @return void
	 */
	public static function render_page(): void {
		if ( ! current_user_can( self::CAPABILITY ) ) {
			wp_die( esc_html__( 'You do not have permission to access this page.', 'reeflex-gate' ) );
		}

		$notice = self::consume_notice();

		?>
		<div class="wrap">
			<h1><?php echo esc_html__( 'Reeflex — Pending approvals', 'reeflex-gate' ); ?></h1>

			<?php if ( null !== $notice ) : ?>
				<div class="notice notice-<?php echo esc_attr( $notice['type'] ); ?> is-dismissible">
					<p><?php echo esc_html( $notice['message'] ); ?></p>
				</div>
			<?php endif; ?>

			<?php self::render_freeze_banner(); ?>

			<p>
				<strong><?php echo esc_html__( 'Approving executes.', 'reeflex-gate' ); ?></strong>
				<?php echo esc_html__(
					'Resolving a hold here calls reeflex-core (POST /v1/holds/{id}/resolve). This is not a two-step "approve, then run later" flow: clicking "Approve & run" below is itself the execution step — on an approved resolution this page immediately re-runs the original WordPress action with its original input, in the same request.',
					'reeflex-gate'
				); ?>
			</p>
			<p class="description">
				<?php echo esc_html__(
					'Note on MCP-originated actions: a call made through the MCP Adapter can be gated twice (defense-in-depth) and may show up here as two separate holds for the same underlying call. If you approve both, the underlying action executes AT MOST ONCE: the first approval runs it; approving the companion hold afterward is a safe no-op (it resolves and closes that record but does not run the action again).',
					'reeflex-gate'
				); ?>
			</p>

			<p>
				<a href="<?php echo esc_url( self::page_url() ); ?>" class="button">
					<?php echo esc_html__( 'Refresh', 'reeflex-gate' ); ?>
				</a>
			</p>

			<?php self::render_holds_table(); ?>
		</div>
		<?php
	}

	// ------------------------------------------------------------------
	// Render: freeze banner
	// ------------------------------------------------------------------

	/**
	 * Render the freeze (kill-switch) status banner.
	 *
	 * HONEST LIMITATION (per brief — do not invent a core endpoint, do not fake a
	 * toggle): freeze is controlled exclusively by the REEFLEX_FREEZE environment
	 * variable on the reeflex-core PROCESS (see decide.py — re-read on every
	 * /v1/decide call, rule id 'reeflex.policy/frozen' when it fires). As of this
	 * writing reeflex-core exposes no GET endpoint that reports that value — the
	 * only routes are POST /v1/decide, GET/POST /v1/holds..., and GET /healthz
	 * (which returns only {"status":"ok"}). There is therefore no live value this
	 * page can honestly display, and nothing here can flip it — so no toggle is
	 * rendered. If a future core version adds a real status endpoint, this method
	 * is the one place to wire it in; do not fabricate a value in the meantime.
	 *
	 * @return void
	 */
	private static function render_freeze_banner(): void {
		?>
		<div class="notice notice-info" style="margin-left:0;">
			<p><strong><?php echo esc_html__( 'Freeze (kill-switch)', 'reeflex-gate' ); ?></strong></p>
			<p>
				<?php echo esc_html__(
					'Freeze is set on the reeflex-core operator side, via the REEFLEX_FREEZE environment variable on the core process — not from WordPress. reeflex-core currently has no API that reports whether freeze is on, so this page cannot show a live status here, and there is nothing for a toggle on this page to actually control — so none is shown.',
					'reeflex-gate'
				); ?>
			</p>
			<p>
				<?php echo esc_html__(
					'If write actions are being denied with reason "frozen by operator" (rule reeflex.policy/frozen), the operator has frozen all non-read actions on core. Ask the core operator to unset REEFLEX_FREEZE (or set it to false/0/no) to lift it.',
					'reeflex-gate'
				); ?>
			</p>
		</div>
		<?php
	}

	// ------------------------------------------------------------------
	// Render: holds table
	// ------------------------------------------------------------------

	/**
	 * Render the pending-holds table (or an empty state).
	 *
	 * @return void
	 */
	private static function render_holds_table(): void {
		$holds = Reeflex_Holds_Store::list_all();

		if ( empty( $holds ) ) {
			?>
			<p><?php echo esc_html__( 'No pending holds.', 'reeflex-gate' ); ?></p>
			<?php
			return;
		}

		?>
		<table class="widefat striped">
			<thead>
				<tr>
					<th><?php echo esc_html__( 'Ability', 'reeflex-gate' ); ?></th>
					<th><?php echo esc_html__( 'Magnitude', 'reeflex-gate' ); ?></th>
					<th><?php echo esc_html__( 'Axes', 'reeflex-gate' ); ?></th>
					<th><?php echo esc_html__( 'Rule', 'reeflex-gate' ); ?></th>
					<th><?php echo esc_html__( 'Session', 'reeflex-gate' ); ?></th>
					<th><?php echo esc_html__( 'Age / expires', 'reeflex-gate' ); ?></th>
					<th><?php echo esc_html__( 'Resolve', 'reeflex-gate' ); ?></th>
				</tr>
			</thead>
			<tbody>
				<?php foreach ( $holds as $hold_id => $entry ) : ?>
					<?php self::render_hold_row( (string) $hold_id, is_array( $entry ) ? $entry : array() ); ?>
				<?php endforeach; ?>
			</tbody>
		</table>
		<?php
	}

	/**
	 * Render one pending-hold table row: the 5-second context plus the
	 * Approve/Reject form.
	 *
	 * @param  string $hold_id
	 * @param  array  $entry    A Reeflex_Holds_Store entry (see that class's docblock).
	 * @return void
	 */
	private static function render_hold_row( string $hold_id, array $entry ): void {
		$context = self::describe_hold( $entry );

		$ability    = isset( $entry['ability'] ) ? (string) $entry['ability'] : 'unknown';
		$rule_id    = isset( $entry['rule_id'] ) ? (string) $entry['rule_id'] : 'unknown';
		$session_id = isset( $entry['session_id'] ) ? (string) $entry['session_id'] : 'unknown';
		$created_ts = isset( $entry['created_ts'] ) ? (string) $entry['created_ts'] : '';
		$expires_ts = isset( $entry['expires_ts'] ) ? (string) $entry['expires_ts'] : '';

		?>
		<tr>
			<td>
				<code><?php echo esc_html( $ability ); ?></code>
				<br />
				<span class="description"><?php echo esc_html( 'hold_id: ' . $hold_id ); ?></span>
				<?php if ( ! $context['hash_matches'] ) : ?>
					<br />
					<span class="description" style="color:#996800;">
						<?php echo esc_html__( 'context recomputed for display; may not exactly match the original decision', 'reeflex-gate' ); ?>
					</span>
				<?php endif; ?>
			</td>
			<td><?php echo esc_html( (string) $context['count'] ); ?></td>
			<td>
				<?php foreach ( $context['axes'] as $axis => $value ) : ?>
					<span class="reeflex-axis-chip" style="display:inline-block;border:1px solid #c3c4c7;border-radius:3px;padding:1px 6px;margin:1px;font-size:11px;white-space:nowrap;">
						<?php echo esc_html( $axis . ': ' . $value ); ?>
					</span>
				<?php endforeach; ?>
			</td>
			<td><code><?php echo esc_html( $rule_id ); ?></code></td>
			<td><code><?php echo esc_html( $session_id ); ?></code></td>
			<td>
				<?php echo esc_html( self::format_age( $created_ts ) ); ?>
				<br />
				<?php echo esc_html( self::format_ttl( $expires_ts ) ); ?>
			</td>
			<td>
				<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
					<?php wp_nonce_field( self::NONCE_PREFIX . $hold_id, '_reeflex_nonce' ); ?>
					<input type="hidden" name="action" value="<?php echo esc_attr( self::ACTION_RESOLVE ); ?>" />
					<input type="hidden" name="hold_id" value="<?php echo esc_attr( $hold_id ); ?>" />
					<p>
						<textarea
							name="reason"
							rows="2"
							style="width:100%;"
							placeholder="<?php echo esc_attr( __( 'Optional reason', 'reeflex-gate' ) ); ?>"
						></textarea>
					</p>
					<p>
						<button
							type="submit"
							name="decision"
							value="approve"
							class="button button-primary"
							onclick="<?php echo esc_attr( 'return confirm(\'' . __( 'Approve and RUN this action now? This executes it immediately.', 'reeflex-gate' ) . '\');' ); ?>"
						>
							<?php echo esc_html__( 'Approve & run', 'reeflex-gate' ); ?>
						</button>
						<button
							type="submit"
							name="decision"
							value="reject"
							class="button"
							onclick="<?php echo esc_attr( 'return confirm(\'' . __( 'Reject this hold? It will be closed and cannot be resubmitted.', 'reeflex-gate' ) . '\');' ); ?>"
						>
							<?php echo esc_html__( 'Reject', 'reeflex-gate' ); ?>
						</button>
					</p>
				</form>
			</td>
		</tr>
		<?php
	}

	// ------------------------------------------------------------------
	// admin-post.php handler (WP request glue)
	// ------------------------------------------------------------------

	/**
	 * admin-post.php entry point for both Approve and Reject.
	 *
	 * Reads and validates the POSTed hold_id/decision/reason, hands off to
	 * process_resolution() for the actual work, stashes the resulting notice for
	 * display after redirect, and always redirects back to the pending-approvals
	 * page. Never returns to the caller (mirrors the standard WP admin-post.php
	 * contract: handlers must redirect-or-die, not echo a response body).
	 *
	 * @return void
	 */
	public static function handle_resolve(): void {
		if ( ! current_user_can( self::CAPABILITY ) ) {
			wp_die( esc_html__( 'You do not have permission to perform this action.', 'reeflex-gate' ) );
		}

		$hold_id = isset( $_POST['hold_id'] ) ? sanitize_text_field( wp_unslash( (string) $_POST['hold_id'] ) ) : '';

		// The nonce action embeds the specific hold_id (NONCE_PREFIX . $hold_id), so a
		// nonce harvested from one hold's form on this same page cannot be replayed
		// against a different hold_id. check_admin_referer() dies on failure.
		check_admin_referer( self::NONCE_PREFIX . $hold_id, '_reeflex_nonce' );

		$decision = isset( $_POST['decision'] ) ? sanitize_text_field( wp_unslash( (string) $_POST['decision'] ) ) : '';
		$reason   = isset( $_POST['reason'] ) ? sanitize_textarea_field( wp_unslash( (string) $_POST['reason'] ) ) : '';

		$allowed_decisions = array( 'approve', 'reject' );
		if ( '' === $hold_id || ! in_array( $decision, $allowed_decisions, true ) ) {
			self::stash_notice(
				array(
					'type'    => 'error',
					'message' => __( 'Malformed request: missing hold_id or an invalid decision value.', 'reeflex-gate' ),
				)
			);
			self::redirect_to_page();
			return;
		}

		$current_user   = wp_get_current_user();
		$approver_login = ( $current_user && $current_user->exists() && '' !== (string) $current_user->user_login )
			? (string) $current_user->user_login
			: 'unknown';

		$notice = self::process_resolution( $hold_id, $decision, $reason, $approver_login );
		self::stash_notice( $notice );
		self::redirect_to_page();
	}

	/**
	 * Redirect back to the pending-approvals page and terminate the request.
	 *
	 * Split out from handle_resolve() only so the exit() is in one obvious place;
	 * not itself called by any test (see class docblock — Testability).
	 *
	 * @return void
	 */
	private static function redirect_to_page(): void {
		wp_safe_redirect( self::page_url() );
		exit;
	}

	// ------------------------------------------------------------------
	// Core proxy + resolution logic (pure; directly testable)
	// ------------------------------------------------------------------

	/**
	 * Resolve one pending hold against reeflex-core, then — for an approved
	 * resolution — resubmit it. No WP nonce/capability/redirect concerns live
	 * here; those belong to handle_resolve(). See class docblock, "Testability".
	 *
	 * @param  string $hold_id         The hold_id to resolve.
	 * @param  string $decision        'approve'|'reject' — caller must have already
	 *                                 validated this against the allow-list.
	 * @param  string $reason          Optional human-supplied reason (already
	 *                                 sanitized by the caller); sent to core verbatim
	 *                                 as the resolve request's 'reason' field.
	 * @param  string $approver_login  The WordPress user_login of whoever is
	 *                                 resolving this hold; becomes principal.id on
	 *                                 core's /v1/holds/{id}/resolve call — i.e. WHO
	 *                                 APPROVED, never the original agent identity.
	 *                                 Reeflex_Gate::resubmit_hold() independently
	 *                                 re-derives the ORIGINAL actor from the stored
	 *                                 hold entry regardless of this value (LOCKED
	 *                                 DECISION, T1.2 — untouched by this class).
	 * @return array{type:string,message:string}  'type' is 'success'|'error'|'warning'
	 *                                             (maps to a WP admin-notice CSS class).
	 */
	public static function process_resolution( string $hold_id, string $decision, string $reason, string $approver_login ): array {
		$entry = Reeflex_Holds_Store::get( $hold_id );
		if ( null === $entry ) {
			return array(
				'type'    => 'warning',
				'message' => sprintf(
					/* translators: %s: hold id */
					__( 'Hold %s is no longer pending on this site (already resolved, expired, or swept). Nothing to do.', 'reeflex-gate' ),
					$hold_id
				),
			);
		}

		list( $http_code, $body, $transport_error ) = self::resolve_on_core( $hold_id, $decision, $reason, $approver_login );

		if ( null !== $transport_error ) {
			// FAIL CLOSED in spirit: core unreachable means nothing executes. The
			// local entry is left in place so the operator can retry once core is
			// back — dropping it here would silently orphan a still-pending hold.
			return array(
				'type'    => 'error',
				'message' => __( 'Could not reach reeflex-core to resolve this hold. The hold is unchanged; try again once core is reachable.', 'reeflex-gate' ),
			);
		}

		if ( 200 !== $http_code ) {
			$reason_text = 'HTTP ' . $http_code;
			if ( is_array( $body ) ) {
				if ( isset( $body['reason'] ) && is_string( $body['reason'] ) ) {
					$reason_text = $body['reason'];
				} elseif ( isset( $body['error'] ) && is_string( $body['error'] ) ) {
					$reason_text = $body['error'];
				}
			}

			// Terminal on core (hold not found, or no longer pending/expired): the
			// local entry is stale and can never again be approved — drop it so it
			// stops cluttering the pending list. Any other 4xx/5xx (auth, policy,
			// validation, internal error) leaves the local entry for a retry.
			if ( in_array( $http_code, array( 404, 409 ), true ) ) {
				Reeflex_Holds_Store::delete( $hold_id );
			}

			return array(
				'type'    => 'error',
				'message' => sprintf(
					/* translators: 1: HTTP status code, 2: reason/error text from core */
					__( 'reeflex-core did not resolve this hold (HTTP %1$d: %2$s).', 'reeflex-gate' ),
					$http_code,
					$reason_text
				),
			);
		}

		// core resolved the hold (200).
		if ( 'reject' === $decision ) {
			Reeflex_Holds_Store::delete( $hold_id );
			return array(
				'type'    => 'success',
				'message' => __( 'Hold rejected and closed. Nothing was executed.', 'reeflex-gate' ),
			);
		}

		// 'approve': THIS call is the execution step (see class docblock + page copy).
		$result = Reeflex_Gate::resubmit_hold( $hold_id );

		if ( $result instanceof WP_Error ) {
			// Double-execution dedup (0.1.6): this hold's action already ran via a
			// companion hold for the same underlying call (see class docblock,
			// "HONEST NOTE — MCP-originated holds (Hook B) — FIXED in 0.1.6").
			// Nothing executed on THIS call, but that is the CORRECT outcome, not a
			// failure — report it as such rather than the generic "did not execute"
			// error message below.
			if ( 'reeflex_hold_deduplicated' === $result->get_error_code() ) {
				return array(
					'type'    => 'success',
					'message' => __(
						'Approved on reeflex-core. This action was already executed via a companion hold for the same underlying call, so nothing was executed again here (expected double-gating dedup behaviour, not an error).',
						'reeflex-gate'
					),
				);
			}

			return array(
				'type'    => 'error',
				'message' => sprintf(
					/* translators: 1: WP_Error code, 2: WP_Error message */
					__( 'Approved on reeflex-core, but the action did not execute (%1$s: %2$s).', 'reeflex-gate' ),
					$result->get_error_code(),
					$result->get_error_message()
				),
			);
		}

		return array(
			'type'    => 'success',
			'message' => __( 'Approved and executed.', 'reeflex-gate' ),
		);
	}

	/**
	 * POST {core_url}/v1/holds/{id}/resolve.
	 *
	 * Deliberately NOT built on Reeflex_Core_Client (which is scoped to
	 * POST /v1/decide) — this hits a different core endpoint — but reuses its
	 * configuration precedence (Reeflex_Config::core_url/core_token/verify_ssl/
	 * request_timeout) so the connection settings are identical to the decision
	 * path, including the same TLS-verification and token-handling posture.
	 *
	 * The bearer token is read here, used once, and discarded — never logged,
	 * never returned, never placed in the notice shown to the browser (mirrors
	 * Reeflex_Core_Client::decide()'s own handling).
	 *
	 * @param  string $hold_id
	 * @param  string $decision        'approve'|'reject'.
	 * @param  string $reason          Optional; omitted from the payload if empty.
	 * @param  string $approver_login  Becomes principal.id (principal.type is
	 *                                 always 'human' — this page is a human
	 *                                 approval surface).
	 * @return array{0:int,1:array|null,2:string|null}  [http_code, decoded_body_or_null, transport_error_or_null]
	 */
	private static function resolve_on_core( string $hold_id, string $decision, string $reason, string $approver_login ): array {
		$base_url = Reeflex_Config::core_url();
		if ( '' === $base_url ) {
			return array( 0, null, 'REEFLEX_CORE_URL is not configured or was rejected as invalid' );
		}

		$url = rtrim( $base_url, '/' ) . '/v1/holds/' . rawurlencode( $hold_id ) . '/resolve';

		$payload = array(
			'decision'  => $decision,
			'principal' => array(
				'type' => 'human',
				'id'   => '' !== $approver_login ? $approver_login : 'unknown',
			),
		);
		if ( '' !== $reason ) {
			$payload['reason'] = $reason;
		}

		$body = wp_json_encode( $payload );
		if ( false === $body ) {
			return array( 0, null, 'request JSON encoding failed' );
		}

		$headers = array( 'Content-Type' => 'application/json' );
		// Stripped of control characters as defense-in-depth against CRLF/NUL header
		// injection, mirroring Reeflex_Core_Client::decide(). Discarded immediately
		// after use; never logged.
		$token = (string) preg_replace( '/[\x00-\x1F\x7F]/', '', Reeflex_Config::core_token() );
		if ( '' !== $token ) {
			$headers['Authorization'] = 'Bearer ' . $token;
		}
		unset( $token );

		$response = wp_remote_post(
			$url,
			array(
				'headers'     => $headers,
				'body'        => $body,
				'timeout'     => Reeflex_Config::request_timeout(),
				'redirection' => 0,
				'httpversion' => '1.1',
				'blocking'    => true,
				'sslverify'   => Reeflex_Config::verify_ssl(),
			)
		);

		if ( is_wp_error( $response ) ) {
			return array( 0, null, $response->get_error_message() );
		}

		$http_code = (int) wp_remote_retrieve_response_code( $response );
		$raw_body  = wp_remote_retrieve_body( $response );
		$decoded   = '' !== $raw_body ? json_decode( $raw_body, true ) : null;

		return array( $http_code, is_array( $decoded ) ? $decoded : null, null );
	}

	// ------------------------------------------------------------------
	// Display-only context reconstruction
	// ------------------------------------------------------------------

	/**
	 * Recompute the {count, axes} DISPLAY context for a stored hold entry.
	 *
	 * The Holds Store (T1) deliberately does not persist magnitude/axes — only a
	 * canonical envelope_hash for correlation (see class-reeflex-holds-store.php's
	 * own docblock). Since the entry DOES store the original ability + input
	 * verbatim, this method calls the same Reeflex_Normalizer::normalize() the gate
	 * used at hold-creation time — with the entry's own ORIGINAL agent identity
	 * pinned in via the $agent_override parameter (never the admin viewing this
	 * page) — to reconstruct a DISPLAY-ONLY envelope. This is never sent anywhere
	 * and never feeds a decision; it exists purely so the admin sees the
	 * magnitude/axes context without reeflex-core needing a new "hold detail" field.
	 *
	 * Fidelity note: an ability's 'reeflex_verb' trusted-verb override (captured at
	 * ability REGISTRATION time — see Reeflex_Gate::wrap_permission_callback()) is
	 * not itself persisted in the hold entry, only its downstream effect on the
	 * ORIGINAL decision's axes/verb. Recomputing here without that override can
	 * occasionally show a lower-danger verb/axis than what was actually decided on.
	 * 'hash_matches' compares the recomputed canonical hash against the one stored
	 * at hold-creation time so the UI can flag any such drift honestly (see
	 * render_hold_row()) instead of silently presenting a possibly-stale picture.
	 *
	 * @param  array $entry  A Reeflex_Holds_Store entry.
	 * @return array{count:int,axes:array<string,string>,hash_matches:bool}
	 */
	private static function describe_hold( array $entry ): array {
		$ability = isset( $entry['ability'] ) ? (string) $entry['ability'] : '';
		$input   = isset( $entry['input'] ) && is_array( $entry['input'] ) ? $entry['input'] : array();
		$agent   = isset( $entry['agent'] ) && is_array( $entry['agent'] ) ? $entry['agent'] : null;

		if ( '' === $ability ) {
			return array(
				'count'        => 0,
				'axes'         => array(),
				'hash_matches' => false,
			);
		}

		try {
			$envelope = Reeflex_Normalizer::normalize( $ability, $input, '', null, $agent );
		} catch ( \Throwable $e ) {
			// Display-only reconstruction; never let a normalize() failure break
			// the admin page — degrade to an honest "unknown" row instead.
			return array(
				'count'        => 0,
				'axes'         => array(),
				'hash_matches' => false,
			);
		}

		$recomputed_hash = Reeflex_Holds_Store::canonical_envelope_hash( $envelope );
		$stored_hash     = isset( $entry['envelope_hash'] ) ? (string) $entry['envelope_hash'] : '';

		return array(
			'count'        => (int) ( $envelope['magnitude']['count'] ?? 0 ),
			'axes'         => array(
				'reversibility' => (string) ( $envelope['axes']['reversibility'] ?? 'unknown' ),
				'blast_radius'  => (string) ( $envelope['axes']['blast_radius'] ?? 'unknown' ),
				'externality'   => (string) ( $envelope['axes']['externality'] ?? 'unknown' ),
			),
			'hash_matches' => ( '' !== $stored_hash && hash_equals( $stored_hash, $recomputed_hash ) ),
		);
	}

	// ------------------------------------------------------------------
	// Notice stash (post-redirect-get, one shot, per WP user)
	// ------------------------------------------------------------------

	/**
	 * Stash a one-shot notice for the current WP user, to be shown after redirect.
	 *
	 * @param  array $notice  {type, message} — see process_resolution()'s return shape.
	 * @return void
	 */
	private static function stash_notice( array $notice ): void {
		set_transient( self::notice_key(), $notice, self::NOTICE_TTL );
	}

	/**
	 * Fetch and clear the current WP user's stashed notice, if any.
	 *
	 * @return array{type:string,message:string}|null
	 */
	private static function consume_notice(): ?array {
		$key    = self::notice_key();
		$notice = get_transient( $key );
		if ( false === $notice || ! is_array( $notice ) ) {
			return null;
		}
		delete_transient( $key );

		$type = isset( $notice['type'] ) && in_array( $notice['type'], array( 'success', 'error', 'warning' ), true )
			? (string) $notice['type']
			: 'info';

		return array(
			'type'    => $type,
			'message' => isset( $notice['message'] ) ? (string) $notice['message'] : '',
		);
	}

	/**
	 * Per-user transient key for the post-redirect notice.
	 *
	 * @return string
	 */
	private static function notice_key(): string {
		return self::NOTICE_TRANSIENT_PREFIX . get_current_user_id();
	}

	// ------------------------------------------------------------------
	// Small formatting helpers
	// ------------------------------------------------------------------

	/**
	 * URL of this plugin's admin page.
	 *
	 * @return string
	 */
	private static function page_url(): string {
		return admin_url( 'admin.php?page=' . self::PAGE_SLUG );
	}

	/**
	 * Human-readable "N ago" for a created_ts.
	 *
	 * @param  string $created_ts  ISO 8601 UTC, or '' if unknown.
	 * @return string
	 */
	private static function format_age( string $created_ts ): string {
		$epoch = self::parse_iso8601( $created_ts );
		if ( 0 === $epoch ) {
			return __( 'unknown age', 'reeflex-gate' );
		}
		return sprintf(
			/* translators: %s: a short duration, e.g. "5m" */
			__( '%s ago', 'reeflex-gate' ),
			self::format_duration( max( 0, time() - $epoch ) )
		);
	}

	/**
	 * Human-readable "expires in N" / "EXPIRED" for an expires_ts.
	 *
	 * @param  string $expires_ts  ISO 8601 UTC, or '' if unknown.
	 * @return string
	 */
	private static function format_ttl( string $expires_ts ): string {
		$epoch = self::parse_iso8601( $expires_ts );
		if ( 0 === $epoch ) {
			return __( 'no expiry recorded', 'reeflex-gate' );
		}
		$remaining = $epoch - time();
		if ( $remaining <= 0 ) {
			return __( 'EXPIRED', 'reeflex-gate' );
		}
		return sprintf(
			/* translators: %s: a short duration, e.g. "2h" */
			__( 'expires in %s', 'reeflex-gate' ),
			self::format_duration( $remaining )
		);
	}

	/**
	 * Coarse "Ns" / "Nm" / "Nh" / "Nd" duration formatter — deliberately not
	 * dependent on WordPress's human_time_diff() to keep this class's WordPress
	 * surface small and its output deterministic for tests.
	 *
	 * @param  int $seconds  Non-negative.
	 * @return string
	 */
	private static function format_duration( int $seconds ): string {
		if ( $seconds < MINUTE_IN_SECONDS ) {
			return $seconds . 's';
		}
		if ( $seconds < HOUR_IN_SECONDS ) {
			return ( (int) floor( $seconds / MINUTE_IN_SECONDS ) ) . 'm';
		}
		if ( $seconds < DAY_IN_SECONDS ) {
			return ( (int) floor( $seconds / HOUR_IN_SECONDS ) ) . 'h';
		}
		return ( (int) floor( $seconds / DAY_IN_SECONDS ) ) . 'd';
	}

	/**
	 * Parse an ISO 8601 UTC timestamp ("2026-07-04T12:00:00Z") to a Unix epoch.
	 *
	 * Mirrors Reeflex_Holds_Store::parse_iso8601() (private there; duplicated here
	 * rather than exposed, to avoid widening that class's public API for a display
	 * concern).
	 *
	 * @param  string $iso
	 * @return int  Epoch seconds, or 0 on empty/unparseable input.
	 */
	private static function parse_iso8601( string $iso ): int {
		if ( '' === $iso ) {
			return 0;
		}
		$ts = strtotime( $iso );
		return false !== $ts ? $ts : 0;
	}
}
