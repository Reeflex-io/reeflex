<?php
/**
 * Reeflex Config — runtime configuration resolver.
 *
 * Precedence model (three fields exposed to the Settings UI):
 *
 *   core_url():
 *     1. Constant REEFLEX_CORE_URL if defined AND non-empty  (trust anchor; wins always).
 *     2. DB option reeflex_gate_options['core_url']          (Settings page path).
 *     3. ''  → fail-closed (no URL configured).
 *     The same scheme-validation rule applies to whichever source is used.
 *
 *   core_token():
 *     1. Constant REEFLEX_CORE_TOKEN if defined              (trust anchor; wins always).
 *     2. DB option reeflex_gate_options['core_token']        (Settings page path).
 *     3. ''  → no Authorization header sent.
 *
 *   verify_ssl():
 *     1. Constant REEFLEX_VERIFY_SSL if defined              (trust anchor; wins always).
 *     2. DB option reeflex_gate_options['verify_ssl']        (Settings page path).
 *     3. true → TLS verification ON (secure default).
 *     Default true: verification ON. Disable ONLY for dev endpoints with untrusted/
 *     self-signed or internal certs. Keep true in production — this
 *     setting protects the decision call from MITM interception.
 *
 * All other values (env, agent_id, audit_log_path, request_timeout) remain
 * constant-only; no Settings UI is provided for them.
 *
 * Constants always win over the DB option — a constant defined in wp-config.php
 * is a server-side trust anchor that an admin or agent cannot override through
 * the UI.  Allowing a DB value to override a constant would let a malicious or
 * compromised admin re-point or disable the governance gate — a bypass.
 *
 * Option name:  reeflex_gate_options  (single array option).
 * Keys:         core_url, core_token, verify_ssl.
 *
 * @package ReeflexWordPress
 * @since   0.1.0
 */

declare( strict_types=1 );

defined( 'ABSPATH' ) || exit;

/**
 * Resolves Reeflex adapter configuration.
 *
 * Priority: wp-config.php constants > DB option (Settings page) > safe default.
 * Constants are trust anchors and always win over the DB value.
 *
 * Constants accepted in wp-config.php:
 *   REEFLEX_CORE_URL   — base URL of reeflex-core (required for production).
 *                        When defined + non-empty, it wins over any DB/Settings
 *                        value and the Settings field is rendered read-only.
 *                        Must be https:// in production. http:// is accepted
 *                        ONLY for loopback hosts (127.0.0.1, localhost, ::1).
 *                        Any other http:// URL is rejected; decide() will
 *                        fail-closed. Developers who need http:// to a
 *                        non-loopback host must set REEFLEX_CORE_URL as a
 *                        constant (operator-trusted path), not via the UI.
 *                        Default: '' (fail-closed until configured).
 *   REEFLEX_CORE_TOKEN — bearer token for Authorization header. Optional.
 *                        When defined, it wins over any DB/Settings value and
 *                        the Settings token field is rendered read-only.
 *   REEFLEX_VERIFY_SSL — boolean; controls TLS certificate verification on the
 *                        POST /v1/decide HTTP request. When defined, it wins
 *                        over any DB/Settings value and the Settings checkbox
 *                        is rendered disabled. Default: true (verification ON).
 *                        Set to false ONLY for dev/staging endpoints with
 *                        untrusted or self-signed certs. Never
 *                        disable in production — MITM protection for the
 *                        governance decision call.
 *   REEFLEX_MODE       — 'enforce'|'observe'; default 'enforce'. In observe the
 *                        gate audits but never enforces (HIL-DESIGN §8). Every
 *                        decision is recorded to the audit log with mode=observe,
 *                        but the action always proceeds — even when core is
 *                        unreachable (fail-open). Use observe to see what Reeflex
 *                        would have stopped before turning enforcement on. When
 *                        defined, it wins over any DB/Settings value and the
 *                        Settings select is rendered disabled.
 *   REEFLEX_ENV        — target environment label; default 'production'.
 *   REEFLEX_AGENT_ID   — agent identity string; default 'agent:wordpress'.
 *   REEFLEX_AUDIT_LOG  — absolute path to JSONL audit log.
 *                        Default: WP_CONTENT_DIR/reeflex-audit.jsonl.
 *   REEFLEX_TIMEOUT    — HTTP timeout in seconds for /v1/decide; default 5.
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
	 * DB option name that stores the Settings page values.
	 *
	 * @var string
	 */
	public const OPTION_NAME = 'reeflex_gate_options';

	/**
	 * Loopback host patterns that are exempt from the https-only requirement.
	 *
	 * @var array<int,string>
	 */
	private const LOOPBACK_HOSTS = array( '127.0.0.1', 'localhost', '::1' );

	// ------------------------------------------------------------------
	// Public getters (decision-path use)
	// ------------------------------------------------------------------

	/**
	 * Base URL of the reeflex-core decision engine.
	 *
	 * Precedence:
	 *   1. REEFLEX_CORE_URL constant (defined + non-empty) — trust anchor.
	 *   2. DB option reeflex_gate_options['core_url'].
	 *   3. '' — fail-closed.
	 *
	 * The same scheme-validation rule is applied to BOTH sources (P1-4):
	 *   https  → always accepted.
	 *   http   → accepted ONLY for loopback hosts (127.0.0.1, localhost, ::1).
	 *   other  → rejected; '' returned; error_log warning emitted.
	 *   '..'   → rejected (SSRF/traversal guard).
	 *
	 * Note: there is NO http-in-dev exception for the DB-sourced value.  A dev
	 * environment that genuinely needs http:// to a non-loopback host must use
	 * the REEFLEX_CORE_URL constant (operator-trusted, validated via the same
	 * sanitize_core_url() but with the constant being an explicit operator act).
	 *
	 * Returns '' when the configured URL is invalid or missing, which causes
	 * Reeflex_Core_Client::decide() to produce a fail-closed deny.
	 *
	 * @return string  Validated URL, or '' on misconfiguration.
	 */
	public static function core_url(): string {
		// Source 1: constant (trust anchor).
		if ( defined( 'REEFLEX_CORE_URL' ) && '' !== (string) REEFLEX_CORE_URL ) {
			return self::sanitize_core_url( (string) REEFLEX_CORE_URL, 'REEFLEX_CORE_URL (constant)' );
		}

		// Source 2: DB option (Settings page).
		$options = self::stored_options();
		$db_url  = isset( $options['core_url'] ) ? (string) $options['core_url'] : '';

		if ( '' !== $db_url ) {
			return self::sanitize_core_url( $db_url, 'reeflex_gate_options[core_url] (settings)' );
		}

		// Source 3: no URL configured — fail-closed path.
		if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
			// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Intentional debug-gated diagnostic; the authoritative record is the JSONL audit log.
			error_log(
				'[reeflex] WARN: No core URL is configured. ' .
				'All governance decisions will fail-closed until a URL is set in ' .
				'wp-config.php (REEFLEX_CORE_URL) or the Reeflex Gate settings page.'
			);
		}
		return '';
	}

	/**
	 * Bearer token for the Authorization header sent to reeflex-core.
	 *
	 * Precedence:
	 *   1. REEFLEX_CORE_TOKEN constant (defined) — trust anchor.
	 *   2. DB option reeflex_gate_options['core_token'].
	 *   3. '' — no Authorization header will be sent.
	 *
	 * Security: the token is never logged anywhere in this class.
	 *
	 * @return string  Token string, or '' if not configured.
	 */
	public static function core_token(): string {
		// Source 1: constant (trust anchor).
		if ( defined( 'REEFLEX_CORE_TOKEN' ) ) {
			return (string) REEFLEX_CORE_TOKEN;
		}

		// Source 2: DB option (Settings page).
		$options = self::stored_options();
		return isset( $options['core_token'] ) ? (string) $options['core_token'] : '';
	}

	/**
	 * Whether TLS certificate verification is enabled for POST /v1/decide.
	 *
	 * Precedence:
	 *   1. REEFLEX_VERIFY_SSL constant (defined) — trust anchor.
	 *   2. DB option reeflex_gate_options['verify_ssl'].
	 *   3. true — verification ON (secure default).
	 *
	 * Default true: TLS verification is ON. Disable ONLY for development
	 * endpoints with untrusted or self-signed certificates.
	 * Keep true in production — this protects the governance decision call from
	 * MITM interception.
	 *
	 * @return bool  True = verify TLS certificate (production default); false = skip (dev only).
	 */
	public static function verify_ssl(): bool {
		// Source 1: constant (trust anchor).
		if ( defined( 'REEFLEX_VERIFY_SSL' ) ) {
			return (bool) REEFLEX_VERIFY_SSL;
		}

		// Source 2: DB option (Settings page).
		$options = self::stored_options();
		return (bool) $options['verify_ssl'];
	}

	// ------------------------------------------------------------------
	// Lock-state helpers (used by Settings UI only)
	// ------------------------------------------------------------------

	/**
	 * Whether the core URL is locked by a wp-config.php constant.
	 *
	 * True when REEFLEX_CORE_URL is defined AND non-empty.  When true the
	 * Settings field renders read-only; the DB value is ignored at runtime.
	 *
	 * @return bool
	 */
	public static function core_url_is_locked(): bool {
		return defined( 'REEFLEX_CORE_URL' ) && '' !== (string) REEFLEX_CORE_URL;
	}

	/**
	 * Whether the core token is locked by a wp-config.php constant.
	 *
	 * True when REEFLEX_CORE_TOKEN is defined (even if the value is '').
	 * When true the Settings field renders read-only; the DB value is ignored.
	 *
	 * @return bool
	 */
	public static function core_token_is_locked(): bool {
		return defined( 'REEFLEX_CORE_TOKEN' );
	}

	/**
	 * Whether the SSL verification setting is locked by a wp-config.php constant.
	 *
	 * True when REEFLEX_VERIFY_SSL is defined (any value, including false).
	 * When true the Settings checkbox renders disabled; the DB value is ignored.
	 *
	 * @return bool
	 */
	public static function verify_ssl_is_locked(): bool {
		return defined( 'REEFLEX_VERIFY_SSL' );
	}

	/**
	 * Enforcement mode: 'enforce' (default) or 'observe'.
	 *
	 * Precedence:
	 *   1. REEFLEX_MODE constant (defined) — trust anchor; wins always.
	 *   2. DB option reeflex_gate_options['mode'].
	 *   3. 'enforce' — safe default (full enforcement on).
	 *
	 * In 'observe' mode the gate audits every decision (with mode=observe in the
	 * record) but NEVER enforces — the action always proceeds. Core outages do NOT
	 * block the site in observe (fail-open). Use observe to see what Reeflex would
	 * have stopped before turning enforcement on. See HIL-DESIGN §8.
	 *
	 * Any value other than 'observe' (case-insensitive, trimmed) resolves to
	 * 'enforce' so the safe default is maintained on misconfiguration.
	 *
	 * @return string 'enforce'|'observe'
	 */
	public static function mode(): string {
		// Source 1: constant (trust anchor).
		if ( defined( 'REEFLEX_MODE' ) ) {
			$c = strtolower( trim( (string) REEFLEX_MODE ) );
			return 'observe' === $c ? 'observe' : 'enforce';
		}

		// Source 2: DB option (Settings page).
		$options = self::stored_options();
		return 'observe' === $options['mode'] ? 'observe' : 'enforce';
	}

	/**
	 * Whether the enforcement mode is locked by a wp-config.php constant.
	 *
	 * True when REEFLEX_MODE is defined (any value). When true the Settings
	 * select renders disabled; the DB value is ignored at runtime.
	 *
	 * @return bool
	 */
	public static function mode_is_locked(): bool {
		return defined( 'REEFLEX_MODE' );
	}

	// ------------------------------------------------------------------
	// Raw stored option (for pre-filling the Settings form only)
	// ------------------------------------------------------------------

	/**
	 * Return the raw stored options array from the DB (unvalidated).
	 *
	 * Used only by the Settings UI to pre-fill form fields.  Never use this
	 * in the decision path — use core_url(), core_token(), verify_ssl(), and
	 * mode() instead.
	 *
	 * @return array{core_url: string, core_token: string, verify_ssl: bool, mode: string}
	 */
	public static function stored_options(): array {
		$raw = get_option( self::OPTION_NAME, array() );
		if ( ! is_array( $raw ) ) {
			$raw = array();
		}
		return array(
			'core_url'   => isset( $raw['core_url'] ) ? (string) $raw['core_url'] : '',
			'core_token' => isset( $raw['core_token'] ) ? (string) $raw['core_token'] : '',
			// array_key_exists so a deliberately saved false is preserved; a never-saved
			// key defaults to true (verification ON — secure default).
			'verify_ssl' => array_key_exists( 'verify_ssl', $raw ) ? (bool) $raw['verify_ssl'] : true,
			// Any value other than 'observe' falls back to 'enforce' (safe default).
			'mode'       => ( isset( $raw['mode'] ) && 'observe' === $raw['mode'] ) ? 'observe' : 'enforce',
		);
	}

	// ------------------------------------------------------------------
	// Constant-only getters (no Settings UI; unchanged from v0.1.0)
	// ------------------------------------------------------------------

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
			if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
				// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Intentional debug-gated diagnostic; the authoritative record is the JSONL audit log.
				error_log(
					'[reeflex] WARN: REEFLEX_AUDIT_LOG contains ".." — rejected; using safe default.'
				);
			}
			return $safe_default;
		}

		// Warn if the path is inside an uploads/ directory (web-accessible risk).
		$uploads_dir = trailingslashit( WP_CONTENT_DIR ) . 'uploads';
		if ( 0 === strpos( $configured, $uploads_dir ) ) {
			if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
				// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Intentional debug-gated diagnostic; the authoritative record is the JSONL audit log.
				error_log(
					'[reeflex] WARN: REEFLEX_AUDIT_LOG is inside the uploads/ directory and may be ' .
					'web-accessible. Move it outside uploads/ or add a .htaccess deny rule.'
				);
			}
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

	// ------------------------------------------------------------------
	// URL validation — single source of truth (P1 / MED-1)
	// ------------------------------------------------------------------

	/**
	 * Validate a URL string against the Reeflex scheme policy.
	 *
	 * This is the SINGLE implementation of the URL validation rule used by
	 * both core_url() (runtime path) and Reeflex_Settings (save path).
	 * Having one implementation prevents the two from diverging.
	 *
	 * Rule (P1 — no http-in-dev exception):
	 *   https         → always accepted.
	 *   http loopback → accepted (127.0.0.1, localhost, ::1 only).
	 *   http other    → rejected unconditionally (SSRF / token-exfiltration risk).
	 *   '..'          → rejected (traversal guard).
	 *   other scheme  → rejected.
	 *
	 * Rationale for removing the REEFLEX_ENV==='dev' exception:
	 *   A dev-env deployment that has no REEFLEX_CORE_URL constant and uses the
	 *   Settings page could be pointed at http://attacker-controlled-host, causing
	 *   the bearer token to be POSTed there.  The exception is therefore a
	 *   token-exfiltration vector.  Developers who genuinely need http:// to a
	 *   non-loopback host must set REEFLEX_CORE_URL as a wp-config.php constant
	 *   (an explicit, operator-privileged act), not through the Settings UI.
	 *
	 * Returns '' on rejection, which causes decide() to fail-closed.
	 *
	 * @param  string $url     The URL to validate.
	 * @param  string $source  Human-readable source label for the error_log message.
	 * @return string          Validated URL or '' on rejection.
	 */
	public static function sanitize_core_url( string $url, string $source = 'reeflex' ): string {
		// Reject directory-traversal sequences regardless of source.
		if ( false !== strpos( $url, '..' ) ) {
			if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
				// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Intentional debug-gated diagnostic; the authoritative record is the JSONL audit log.
				error_log(
					'[reeflex] WARN: ' . $source . ' contains ".." — rejected as misconfigured.'
				);
			}
			return '';
		}

		$scheme = strtolower( (string) wp_parse_url( $url, PHP_URL_SCHEME ) );
		$host   = strtolower( (string) wp_parse_url( $url, PHP_URL_HOST ) );

		if ( 'https' === $scheme ) {
			// https is always acceptable.
			return $url;
		}

		if ( 'http' === $scheme ) {
			// http is acceptable ONLY for loopback hosts — no dev-env exception.
			if ( in_array( $host, self::LOOPBACK_HOSTS, true ) ) {
				return $url;
			}
			if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
				// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Intentional debug-gated diagnostic; the authoritative record is the JSONL audit log.
				error_log(
					'[reeflex] WARN: ' . $source . ' uses http:// with a non-loopback host — ' .
					'rejected (SSRF / token-exfiltration risk). Use https://, or set ' .
					'REEFLEX_CORE_URL as a wp-config.php constant for non-loopback http://.'
				);
			}
			return '';
		}

		if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
			// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Intentional debug-gated diagnostic; the authoritative record is the JSONL audit log.
			error_log(
				'[reeflex] WARN: ' . $source . ' has an unrecognised scheme "' .
				$scheme . '" — rejected as misconfigured.'
			);
		}
		return '';
	}
}
