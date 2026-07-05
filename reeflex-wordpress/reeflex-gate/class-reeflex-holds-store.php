<?php
/**
 * Reeflex Holds Store — persists pending held actions for later resubmission.
 *
 * HIL Phase 2 (T1): when core returns `require_approval` it also returns a
 * `hold_id` (SPEC §5.1). The action itself never ran — WordPress has already
 * forgotten the exact call by the time a human resolves the hold minutes or
 * hours later. This class is the adapter's memory of that call: it stores
 * enough to re-run the ORIGINAL ability with the ORIGINAL input, byte-
 * identical, once Reeflex_Gate::resubmit_hold() is invoked.
 *
 * Storage: ONE wp_options row (autoload=no — this data is only read on the
 * resubmission path, never on every page load), an array keyed by hold_id.
 *
 * Per-entry schema:
 *   hold_id        string   the hold_id returned by core
 *   ability        string   the namespaced ability name (e.g. 'core/delete-post')
 *   input          array    the ORIGINAL input array passed to the ability,
 *                           stored verbatim (PHP's options API round-trips
 *                           arrays losslessly, so this is byte-identical on read)
 *   envelope_hash  string   sha256 of the canonical {action,axes,magnitude,target}
 *                           projection of the envelope that produced the hold —
 *                           mirrors reeflex-core's canonical_hash() (holds.py) for
 *                           operator/T2 display; core re-derives and validates its
 *                           own copy independently, this is not trusted at enforce
 *                           time — it is metadata, not a security control.
 *   rule_id        string   the rule that fired (decision.rule)
 *   created_ts     string   ISO 8601 UTC, when the adapter stored the entry
 *   expires_ts     string   ISO 8601 UTC, copied from core's response
 *   session_id     string   the envelope's agent.session_id. For an MCP-originated
 *                           call, this is resolved from the Mcp-Session-Id HTTP
 *                           header (Reeflex_Normalizer::resolve_session_id(),
 *                           source #1) — the SAME header value for Hook A and
 *                           Hook B, since both are handling the SAME incoming HTTP
 *                           request. Used (alongside envelope_hash + created_ts)
 *                           for the resubmission double-execution dedup scope —
 *                           see find_executed_companion_hold_id() below.
 *   executed_ts    string   ISO 8601 UTC, set by Reeflex_Holds_Store::mark_executed()
 *                           the moment Reeflex_Gate::resubmit_hold() confirms the
 *                           underlying ability actually ran for THIS hold_id (see that
 *                           method's docblock). '' (absent) until then. Once set, the
 *                           entry is deliberately KEPT (not delete()'d) until sweep()
 *                           drops it on the normal expires_ts+grace schedule, so a
 *                           companion hold approved later can still be recognised as
 *                           "already executed" and deduplicated instead of re-running
 *                           the action. A hold whose resubmission was DENIED/failed
 *                           (never executed) is still delete()'d as before — only a
 *                           confirmed execution is preserved this way.
 *
 * Security note: this store never contains an approval decision or identity —
 * only the adapter's own record of an attempt that is still pending (or, once
 * executed_ts is set, a short-lived record of an attempt that already ran, kept
 * only so a companion hold can be deduplicated). The only consumer that can turn
 * a hold into an allow is reeflex-core (SPEC §5.1); this class cannot forge that
 * outcome.
 *
 * @package ReeflexWordPress
 * @since   0.1.4
 */

declare( strict_types=1 );

defined( 'ABSPATH' ) || exit;

/**
 * Reads and writes the single `reeflex_gate_holds` option.
 */
final class Reeflex_Holds_Store {

	/**
	 * DB option name — a single row holding ALL pending holds, keyed by hold_id.
	 *
	 * @var string
	 */
	public const OPTION_NAME = 'reeflex_gate_holds';

	/**
	 * How long past an entry's own expires_ts it is kept before sweep() drops it.
	 *
	 * The hold itself is unusable once core's expires_ts has passed (core denies
	 * with reeflex_hold_expired), but the adapter keeps a short grace window so a
	 * T2 admin screen can still show "this one expired" instead of the row simply
	 * vanishing. Nothing lingers past TTL + this grace period.
	 *
	 * @var int
	 */
	private const SWEEP_GRACE_SECONDS = 24 * HOUR_IN_SECONDS;

	// ------------------------------------------------------------------
	// Public API
	// ------------------------------------------------------------------

	/**
	 * Store (or overwrite) one pending hold entry.
	 *
	 * @param  array $entry  See class docblock for the required shape. Must
	 *                       contain a non-empty 'hold_id' or the call is a no-op.
	 * @return void
	 */
	public static function save( array $entry ): void {
		$hold_id = isset( $entry['hold_id'] ) ? (string) $entry['hold_id'] : '';
		if ( '' === $hold_id ) {
			// Defensive: never store an entry we could not key.
			return;
		}

		$all              = self::raw_all();
		$all[ $hold_id ]  = $entry;
		self::persist( $all );
	}

	/**
	 * Fetch one pending hold entry by hold_id.
	 *
	 * Sweeps expired-past-grace entries first (lazy sweep on read, per class docblock).
	 *
	 * @param  string $hold_id
	 * @return array|null  The stored entry, or null if unknown / already swept.
	 */
	public static function get( string $hold_id ): ?array {
		self::sweep();
		$all = self::raw_all();
		return isset( $all[ $hold_id ] ) && is_array( $all[ $hold_id ] ) ? $all[ $hold_id ] : null;
	}

	/**
	 * Remove one entry (called on successful resubmission or on a terminal deny —
	 * a hold that will never again resolve to allow has nothing left to keep).
	 *
	 * @param  string $hold_id
	 * @return void
	 */
	public static function delete( string $hold_id ): void {
		$all = self::raw_all();
		if ( isset( $all[ $hold_id ] ) ) {
			unset( $all[ $hold_id ] );
			self::persist( $all );
		}
	}

	/**
	 * Mark one entry as executed (the underlying ability actually ran for this
	 * hold_id), WITHOUT deleting it.
	 *
	 * Called by Reeflex_Gate::resubmit_hold() the moment it confirms a fresh
	 * execution (never on a gate-enforced deny — see that method's docblock).
	 * The entry is deliberately kept (not delete()'d) so a companion hold sharing
	 * the same envelope_hash + session_id (within the tight window — see
	 * find_executed_companion_hold_id()), resubmitted later, can be recognised as
	 * "already executed" and deduplicated instead of re-running the action. It is
	 * dropped, like any other entry, once sweep() finds it past its own
	 * expires_ts + grace window — nothing lingers forever.
	 *
	 * A no-op if the hold_id is unknown (defensive; should not happen in practice
	 * since the caller just loaded this same entry via get()).
	 *
	 * @param  string $hold_id
	 * @return void
	 */
	public static function mark_executed( string $hold_id ): void {
		$all = self::raw_all();
		if ( isset( $all[ $hold_id ] ) && is_array( $all[ $hold_id ] ) ) {
			$all[ $hold_id ]['executed_ts'] = gmdate( 'Y-m-d\TH:i:s\Z' );
			self::persist( $all );
		}
	}

	/**
	 * How close together (in seconds) two holds' created_ts must be to be
	 * considered "created in the same wave" for double-execution dedup purposes.
	 *
	 * Rationale: Hook A and Hook B, for one real MCP-originated call, run back to
	 * back within a single synchronous PHP request — milliseconds apart — so a
	 * window of this size comfortably covers real Hook A/Hook B pairing (with
	 * generous margin for a slow OPA subprocess or network hiccup) while staying
	 * far tighter than any realistic gap between two DELIBERATELY separate calls
	 * (which involve, at minimum, a human/agent formulating and issuing a second,
	 * distinct request). See find_executed_companion_hold_id()'s own docblock for
	 * the residual risk this does not eliminate.
	 *
	 * @var int
	 */
	private const COMPANION_WINDOW_SECONDS = 30;

	/**
	 * Find another hold entry (different hold_id) that was created "in the same
	 * wave" as the given hold — same envelope_hash, same session_id, and created
	 * within COMPANION_WINDOW_SECONDS of it — and has already been marked executed.
	 *
	 * Scoping rationale (double-execution dedup — see class-reeflex-gate.php
	 * "Double-gating" and Reeflex_Gate::resubmit_hold()):
	 *   envelope_hash alone is NOT enough to identify "the same call" — two
	 *   genuinely separate, deliberate, identical actions (e.g. the same bulk
	 *   delete performed twice on purpose) share the same envelope_hash by
	 *   design (SPEC's own hash projection covers only {action,axes,magnitude,
	 *   target} — it deliberately excludes session/nonce/hold_id). Three
	 *   conditions must ALL hold before two holds are treated as companions of
	 *   one underlying call:
	 *     1. envelope_hash matches — same action, same axes, same magnitude,
	 *        same target.
	 *     2. session_id matches — for an MCP-originated call this is the
	 *        Mcp-Session-Id HTTP header (Reeflex_Normalizer::resolve_session_id(),
	 *        source #1), identical for Hook A and Hook B because both are
	 *        handling the SAME incoming HTTP request.
	 *     3. created_ts within COMPANION_WINDOW_SECONDS — Hook A and Hook B fire
	 *        milliseconds apart for one real call; this rules out two unrelated
	 *        holds that merely happen to share an envelope_hash AND a session_id
	 *        (e.g. two different bulk actions submitted minutes apart in one long
	 *        MCP session) from ever being conflated.
	 *
	 * RESIDUAL RISK (documented per the fix's own design brief, not eliminated):
	 *   a human/agent who deliberately submits the SAME action twice on purpose,
	 *   in the SAME MCP session, within COMPANION_WINDOW_SECONDS of each other,
	 *   would have the second one wrongly deduplicated as if it were a companion
	 *   of the first. This is judged an acceptable, narrow trade-off — a genuine
	 *   duplicate submission within a ~30-second window of the first is far more
	 *   likely to itself be an accidental double-submit than a considered second
	 *   decision — but it is a real, deliberate scoping choice, not an oversight.
	 *
	 * Fails safe (returns null / no dedup) when envelope_hash or session_id is
	 * empty, or created_ts is missing/unparseable on either side: the hold simply
	 * behaves as it did before this fix (still correctly single-use via its own
	 * delete()-on-terminal-outcome path).
	 *
	 * @param  string $envelope_hash    The querying hold's envelope_hash.
	 * @param  string $session_id       The querying hold's session_id.
	 * @param  string $created_ts       The querying hold's created_ts (ISO 8601 UTC).
	 * @param  string $exclude_hold_id  The querying hold's own hold_id (never
	 *                                  matched against itself here — the caller
	 *                                  checks its OWN executed_ts separately).
	 * @return string|null  The companion hold_id, or null if none found.
	 */
	public static function find_executed_companion_hold_id(
		string $envelope_hash,
		string $session_id,
		string $created_ts,
		string $exclude_hold_id
	): ?string {
		$query_epoch = self::parse_iso8601( $created_ts );
		if ( '' === $envelope_hash || '' === $session_id || 0 === $query_epoch ) {
			return null;
		}

		self::sweep();
		$all = self::raw_all();

		foreach ( $all as $candidate_hold_id => $entry ) {
			if ( $candidate_hold_id === $exclude_hold_id || ! is_array( $entry ) ) {
				continue;
			}
			$entry_hash       = isset( $entry['envelope_hash'] ) ? (string) $entry['envelope_hash'] : '';
			$entry_session    = isset( $entry['session_id'] ) ? (string) $entry['session_id'] : '';
			$entry_exec_ts    = isset( $entry['executed_ts'] ) ? (string) $entry['executed_ts'] : '';
			$entry_created_ts = isset( $entry['created_ts'] ) ? (string) $entry['created_ts'] : '';
			$entry_epoch      = self::parse_iso8601( $entry_created_ts );

			if (
				$entry_hash === $envelope_hash
				&& $entry_session === $session_id
				&& '' !== $entry_exec_ts
				&& 0 !== $entry_epoch
				&& abs( $entry_epoch - $query_epoch ) <= self::COMPANION_WINDOW_SECONDS
			) {
				return (string) $candidate_hold_id;
			}
		}

		return null;
	}

	/**
	 * List all currently-stored PENDING hold entries (sweeping first).
	 *
	 * For T2 (the wp-admin holds surface): keyed by hold_id, same shape as get().
	 *
	 * Excludes entries with a non-empty executed_ts (double-execution dedup,
	 * 0.1.6): once resubmit_hold() confirms an entry's action actually ran, the
	 * entry is kept internally — see mark_executed() — ONLY so a companion hold
	 * for the same underlying call can still be recognised and deduplicated; it
	 * is no longer pending and has nothing left for an operator to approve or
	 * reject, so it is filtered out of the "Pending approvals" list here rather
	 * than showing a stale, already-resolved row.
	 *
	 * @return array<string,array>  hold_id => entry
	 */
	public static function list_all(): array {
		self::sweep();
		return array_filter(
			self::raw_all(),
			static function ( $entry ): bool {
				return is_array( $entry ) && empty( $entry['executed_ts'] );
			}
		);
	}

	/**
	 * Drop entries whose expires_ts is more than SWEEP_GRACE_SECONDS in the past.
	 *
	 * Lazy: invoked from get() / list_all(). No cron, no background process —
	 * mirrors reeflex-core's own lazy-expiry design (holds.py).
	 *
	 * An entry with an unparseable expires_ts is conservatively KEPT (never lose
	 * track of a pending hold due to a parse failure).
	 *
	 * @return void
	 */
	public static function sweep(): void {
		$all     = self::raw_all();
		$now     = time();
		$changed = false;

		foreach ( $all as $hold_id => $entry ) {
			$expires_ts    = is_array( $entry ) && isset( $entry['expires_ts'] ) ? (string) $entry['expires_ts'] : '';
			$expires_epoch = self::parse_iso8601( $expires_ts );
			if ( 0 === $expires_epoch ) {
				continue; // unparseable / missing: conservative — keep.
			}
			if ( $now >= ( $expires_epoch + self::SWEEP_GRACE_SECONDS ) ) {
				unset( $all[ $hold_id ] );
				$changed = true;
			}
		}

		if ( $changed ) {
			self::persist( $all );
		}
	}

	// ------------------------------------------------------------------
	// Canonical envelope hash (metadata only — see class docblock security note)
	// ------------------------------------------------------------------

	/**
	 * Compute sha256 over the canonical {action,axes,magnitude,target} projection
	 * of an envelope, mirroring reeflex-core's canonical_hash() (holds.py).
	 *
	 * Keys are sorted recursively (ksort at every level) before encoding, matching
	 * Python's json.dumps(..., sort_keys=True, separators=(",", ":")). Stored as
	 * metadata for operator/T2 display and audit correlation — core computes and
	 * validates its own independent copy at enforce time; this value is never
	 * trusted as a security check by the adapter.
	 *
	 * @param  array $envelope  The Action Envelope that produced the hold.
	 * @return string  Lowercase hex sha256.
	 */
	public static function canonical_envelope_hash( array $envelope ): string {
		$projection = array();
		foreach ( array( 'action', 'axes', 'magnitude', 'target' ) as $key ) {
			if ( isset( $envelope[ $key ] ) ) {
				$projection[ $key ] = $envelope[ $key ];
			}
		}
		self::ksort_recursive( $projection );

		$json = wp_json_encode( $projection );
		return hash( 'sha256', false !== $json ? $json : '' );
	}

	/**
	 * Recursively ksort() an array in place (all nested arrays too).
	 *
	 * @param  array $arr  Passed by reference.
	 * @return void
	 */
	private static function ksort_recursive( array &$arr ): void {
		ksort( $arr );
		foreach ( $arr as &$value ) {
			if ( is_array( $value ) ) {
				self::ksort_recursive( $value );
			}
		}
		unset( $value );
	}

	// ------------------------------------------------------------------
	// Internal storage helpers
	// ------------------------------------------------------------------

	/**
	 * Read the raw option value.
	 *
	 * @return array<string,array>
	 */
	private static function raw_all(): array {
		$raw = get_option( self::OPTION_NAME, array() );
		return is_array( $raw ) ? $raw : array();
	}

	/**
	 * Persist the full holds array back to the single option row (autoload=no —
	 * this data is only needed on the resubmission path, never on every page load).
	 *
	 * @param  array<string,array> $all
	 * @return void
	 */
	private static function persist( array $all ): void {
		update_option( self::OPTION_NAME, $all, false );
	}

	/**
	 * Parse an ISO 8601 UTC timestamp ("2026-07-04T12:00:00Z") to a Unix epoch.
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
