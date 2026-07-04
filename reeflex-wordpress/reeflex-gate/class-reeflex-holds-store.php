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
 *   session_id     string   the envelope's agent.session_id
 *
 * Security note: this store never contains an approval decision or identity —
 * only the adapter's own record of an attempt that is still pending. The only
 * consumer that can turn a hold into an allow is reeflex-core (SPEC §5.1); this
 * class cannot forge that outcome.
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
	 * List all currently-stored pending hold entries (sweeping first).
	 *
	 * For T2 (the wp-admin holds surface): keyed by hold_id, same shape as get().
	 *
	 * @return array<string,array>  hold_id => entry
	 */
	public static function list_all(): array {
		self::sweep();
		return self::raw_all();
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
