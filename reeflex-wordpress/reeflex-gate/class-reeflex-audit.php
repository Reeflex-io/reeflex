<?php
/**
 * Reeflex Audit — append-only JSONL decision record per SPEC §6 / §7.
 *
 * One record per decision, written to the configured audit log path.
 * Write failures are absorbed (error_log only) and MUST NOT affect the
 * decision that was already made: the enforcement result is authoritative,
 * audit is observability.
 *
 * Record shape mirrors adapter.py _audit() fields so the observation plane
 * can ingest both mock and WordPress records with the same parser.
 *
 * @package ReeflexWordPress
 * @since   0.1.0
 */

declare( strict_types=1 );

defined( 'ABSPATH' ) || exit;

/**
 * Writes one signed audit record to the JSONL audit log.
 *
 * Audit failure MUST NOT change or block the decision (SPEC §6 AUDIT contract).
 * The try/catch in record() guarantees this.
 *
 * Full cryptographic signing of audit records is on the roadmap (see SPEC §6
 * implementation-status note). The 'signature' stub mirrors what meta.signature
 * carries in the envelope so auditors can correlate records.
 */
final class Reeflex_Audit {

	/**
	 * Emit one JSONL audit record.
	 *
	 * Called AFTER the decision is received and BEFORE enforcement so the
	 * record exists even if enforcement itself encounters a PHP fatal.
	 *
	 * @param array  $envelope  The Action Envelope that was submitted to core.
	 * @param array  $decision  The Decision returned by core (or the fail-closed deny).
	 * @param string $applied   The outcome applied: 'allow'|'deny'|'hold'|'fail_closed_deny'.
	 * @return void
	 */
	public static function record( array $envelope, array $decision, string $applied ): void {
		try {
			$record = self::build_record( $envelope, $decision, $applied );
			$line   = wp_json_encode( $record, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES );

			if ( false === $line ) {
				// JSON encoding failed — log minimally; do not alter decision.
				error_log( '[reeflex] WARN: audit record JSON encoding failed for nonce ' .
					( $envelope['meta']['nonce'] ?? 'unknown' ) );
				return;
			}

			$path = Reeflex_Config::audit_log_path();

			// Ensure the directory exists (graceful for first run).
			$dir = dirname( $path );
			if ( ! is_dir( $dir ) ) {
				// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_mkdir
				mkdir( $dir, 0755, true );
			}

			// Append-only write with exclusive lock (P2-9).
			// flock() prevents interleaved partial lines under concurrent requests.
			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen
			$fh = fopen( $path, 'a' );
			if ( false === $fh ) {
				error_log( '[reeflex] WARN: cannot open audit log for writing: ' . $path );
				return;
			}

			// Acquire exclusive lock before writing (P2-9).
			if ( flock( $fh, LOCK_EX ) ) {
				// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
				fwrite( $fh, $line . "\n" );
				fflush( $fh );
				flock( $fh, LOCK_UN );
			} else {
				// Lock failed (e.g. NFS without lock support): write anyway but warn.
				error_log( '[reeflex] WARN: could not acquire flock on audit log; writing without lock.' );
				// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
				fwrite( $fh, $line . "\n" );
				fflush( $fh );
			}

			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
			fclose( $fh );

		} catch ( Throwable $e ) {
			// Audit failure MUST NOT affect the decision (SPEC §6).
			error_log( '[reeflex] WARN: audit write threw exception: ' . $e->getMessage() );
		}
	}

	// ------------------------------------------------------------------
	// Internal helpers
	// ------------------------------------------------------------------

	/**
	 * Sanitize a string field for inclusion in the audit record.
	 *
	 * Strips ASCII control characters (P2-9) to prevent log injection.
	 * Keeps printable ASCII and valid UTF-8.
	 *
	 * @param  string $value
	 * @return string
	 */
	private static function sanitize_field( string $value ): string {
		// Strip C0 and C1 control characters and DEL (U+007F).
		return (string) preg_replace( '/[\x00-\x1F\x7F]/u', '', $value );
	}

	/**
	 * Build the audit record array.
	 *
	 * Contains an envelope summary (not a full dump of potentially large
	 * params) plus the decision and applied outcome, matching adapter.py's
	 * record fields so both can be consumed by the same JSONL parser.
	 *
	 * String fields are sanitized to prevent control-character log injection (P2-9).
	 * on_behalf_of now contains 'user:<ID>' (integer, no PII login name) per P2-12.
	 *
	 * @param array  $envelope
	 * @param array  $decision
	 * @param string $applied
	 * @return array
	 */
	private static function build_record(
		array $envelope,
		array $decision,
		string $applied
	): array {
		return array(
			'ts'           => gmdate( 'Y-m-d\TH:i:s\Z' ),
			'session_id'   => self::sanitize_field( (string) ( $envelope['agent']['session_id'] ?? 'unknown' ) ),
			'ability'      => self::sanitize_field( (string) ( $envelope['action']['ability'] ?? 'unknown' ) ),
			'verb'         => self::sanitize_field( (string) ( $envelope['action']['verb'] ?? 'unknown' ) ),
			'environment'  => self::sanitize_field( (string) ( $envelope['target']['environment'] ?? 'unknown' ) ),
			'count'        => $envelope['magnitude']['count'] ?? 1,
			'axes'         => $envelope['axes'] ?? array(),
			'nonce'        => self::sanitize_field( (string) ( $envelope['meta']['nonce'] ?? 'unknown' ) ),
			// Stub signature: carried through so records can be correlated with
			// the envelope that produced them. Full signing = roadmap (SPEC §6).
			'signature'    => self::sanitize_field( (string) ( $envelope['meta']['signature'] ?? 'ed25519:stub:missing' ) ),
			'agent_id'     => self::sanitize_field( (string) ( $envelope['agent']['id'] ?? 'unknown' ) ),
			// P2-12: on_behalf_of is 'user:<ID>' (no login name / PII).
			'on_behalf_of' => self::sanitize_field( (string) ( $envelope['agent']['on_behalf_of'] ?? 'unknown' ) ),
			'decision'     => self::sanitize_field( (string) ( $decision['decision'] ?? 'unknown' ) ),
			'rule'         => self::sanitize_field( (string) ( $decision['rule'] ?? 'unknown' ) ),
			'reason'       => self::sanitize_field( (string) ( $decision['reason'] ?? '' ) ),
			'obligations'  => $decision['obligations'] ?? array(),
			'applied'      => self::sanitize_field( $applied ),
		);
	}
}
