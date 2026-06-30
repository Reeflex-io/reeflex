<?php
/**
 * Reeflex Config — runtime configuration resolver.
 *
 * Reads all tunable values from WordPress constants (set in wp-config.php).
 * No secrets are ever hardcoded. The core URL is the sole trust anchor for
 * the decision engine and is intentionally NOT overridable by any WordPress
 * filter — a later-loading plugin cannot redirect decisions to an attacker-
 * controlled server.
 *
 * @package ReeflexWordPress
 * @since   0.1.0
 */

declare( strict_types=1 );

defined( 'ABSPATH' ) || exit;

/**
 * Resolves Reeflex adapter configuration from WP constants only.
 *
 * All values carry safe defaults so the adapter runs out of the box in
 * a development environment without any configuration. Operators MUST set
 * REEFLEX_CORE_URL (and ideally REEFLEX_ENV) for production use.
 *
 * Constants (define in wp-config.php):
 *   REEFLEX_CORE_URL   — base URL of reeflex-core (required for production).
 *                        Must be https:// in production. http:// is accepted
 *                        ONLY for loopback hosts (127.0.0.1, localhost, ::1)
 *                        OR when REEFLEX_ENV === 'dev'. Any other http:// URL
 *                        is rejected as a misconfiguration; decide() will
 *                        fail-closed.  Default: '' (fail-closed until configured).
 *   REEFLEX_ENV        — target environment label; default 'production'.
 *   REEFLEX_AGENT_ID   — agent identity string; default 'agent:wordpress'.
 *   REEFLEX_AUDIT_LOG  — absolute filesystem path to the JSONL audit log.
 *                        Default: WP_CONTENT_DIR/reeflex-audit.jsonl
 *                        (outside uploads/ so the file is not web-accessible).
 *   REEFLEX_TIMEOUT    — HTTP timeout in seconds for core requests; default 5.
 *
 * Security note — no reeflex_core_url filter:
 *   The filter present in v0.1.0 was removed (P1-4). The core URL is a trust
 *   anchor: allowing any plugin to override it at runtime would let a
 *   compromised or malicious plugin redirect all governance decisions to an
 *   attacker-controlled endpoint, achieving silent allow of any action.
 *   If you need to change the URL for testing, redefine the constant.
 */
final class Reeflex_Config {

	/**
	 * Loopback host patterns that are exempt from the https-only requirement.
	 *
	 * @var array<int,string>
	 */
	private const LOOPBACK_HOSTS = array( '127.0.0.1', 'localhost', '::1' );

	/**
	 * Base URL of the reeflex-core decision engine.
	 *
	 * Returns '' when the configured URL is invalid or missing, which causes
	 * Reeflex_Core_Client::decide() to produce a fail-closed deny — the
	 * correct response to a misconfigured adapter.
	 *
	 * Scheme policy (P1-4):
	 *   https  -> always accepted.
	 *   http   -> accepted ONLY for loopback hosts or when REEFLEX_ENV='dev'.
	 *   other  -> rejected; '' returned; error_log warning emitted.
	 *
	 * @return string  Validated URL, or '' on misconfiguration.
	 */
	public static function core_url(): string {
		if ( ! defined( 'REEFLEX_CORE_URL' ) || '' === (string) REEFLEX_CORE_URL ) {
			error_log(
				'[reeflex] WARN: REEFLEX_CORE_URL is not defined. ' .
				'All governance decisions will fail-closed until this constant is set in wp-config.php.'
			);
			return '';
		}

		$url = (string) REEFLEX_CORE_URL;

		// Reject paths with directory-traversal sequences regardless of source.
		if ( false !== strpos( $url, '..' ) ) {
			error_log( '[reeflex] WARN: REEFLEX_CORE_URL contains ".." — rejected as misconfigured.' );
			return '';
		}

		$scheme = strtolower( (string) parse_url( $url, PHP_URL_SCHEME ) );
		$host   = strtolower( (string) parse_url( $url, PHP_URL_HOST ) );

		if ( 'https' === $scheme ) {
			// https is always acceptable.
			return $url;
		}

		if ( 'http' === $scheme ) {
			// http is acceptable ONLY for loopback or dev environment.
			if ( in_array( $host, self::LOOPBACK_HOSTS, true ) ) {
				return $url;
			}
			if ( 'dev' === self::env() ) {
				return $url;
			}
			error_log(
				'[reeflex] WARN: REEFLEX_CORE_URL uses http:// with a non-loopback host ' .
				'in a non-dev environment — rejected (SSRF risk). Use https://.'
			);
			return '';
		}

		error_log(
			'[reeflex] WARN: REEFLEX_CORE_URL has an unrecognised scheme "' .
			esc_html( $scheme ) . '" — rejected as misconfigured.'
		);
		return '';
	}

	/**
	 * Environment label written into every envelope's target.environment.
	 *
	 * Lowercase by convention; keep it consistent across restarts.
	 *
	 * @return string  'production' | 'staging' | 'dev' | custom
	 */
	public static function env(): string {
		return defined( 'REEFLEX_ENV' ) ? (string) REEFLEX_ENV : 'production';
	}

	/**
	 * Agent identity string for the envelope's agent.id field.
	 *
	 * This identifies the adapter/agent, not the human user — the human
	 * principal goes into agent.on_behalf_of via the normalizer.
	 *
	 * @return string  e.g. 'agent:wordpress'
	 */
	public static function agent_id(): string {
		return defined( 'REEFLEX_AGENT_ID' ) ? (string) REEFLEX_AGENT_ID : 'agent:wordpress';
	}

	/**
	 * Absolute path to the JSONL audit log file.
	 *
	 * Security (P2-8): defaults to WP_CONTENT_DIR/reeflex-audit.jsonl, which is
	 * outside the uploads/ directory and therefore not directly web-accessible on
	 * a standard WordPress install. If REEFLEX_AUDIT_LOG points inside an uploads/
	 * directory, a warning is logged so the operator can act.
	 *
	 * Path safety: paths containing '..' segments are rejected and fall back to
	 * the safe default.
	 *
	 * @return string  Absolute path to the audit log file.
	 */
	public static function audit_log_path(): string {
		$safe_default = WP_CONTENT_DIR . '/reeflex-audit.jsonl';

		if ( ! defined( 'REEFLEX_AUDIT_LOG' ) || '' === (string) REEFLEX_AUDIT_LOG ) {
			return $safe_default;
		}

		$configured = (string) REEFLEX_AUDIT_LOG;

		// Reject directory-traversal attempts in the configured path.
		if ( false !== strpos( $configured, '..' ) ) {
			error_log(
				'[reeflex] WARN: REEFLEX_AUDIT_LOG contains ".." — rejected; using safe default.'
			);
			return $safe_default;
		}

		// Warn if the path is inside an uploads/ directory (web-accessible risk).
		$uploads_dir = trailingslashit( WP_CONTENT_DIR ) . 'uploads';
		if ( 0 === strpos( $configured, $uploads_dir ) ) {
			error_log(
				'[reeflex] WARN: REEFLEX_AUDIT_LOG is inside the uploads/ directory and may be ' .
				'web-accessible. Move it outside uploads/ or add a .htaccess deny rule.'
			);
		}

		return $configured;
	}

	/**
	 * HTTP request timeout for POST /v1/decide, in seconds.
	 *
	 * Keep this short: the adapter is on the hot path of every ability
	 * execution. The fail-closed logic fires on timeout, so a generous
	 * timeout only delays the deny; a tight timeout surfaces it fast.
	 *
	 * @return int
	 */
	public static function request_timeout(): int {
		return defined( 'REEFLEX_TIMEOUT' ) ? (int) REEFLEX_TIMEOUT : 5;
	}
}
