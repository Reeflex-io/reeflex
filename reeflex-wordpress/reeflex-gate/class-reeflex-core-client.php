<?php
/**
 * Reeflex Core Client — POST /v1/decide with strict fail-closed behaviour.
 *
 * This class is the enforcement boundary: it talks to reeflex-core and
 * NEVER allows on error. Any failure — connection refused, timeout, non-200,
 * malformed JSON, missing 'decision' field — triggers the fail-closed deny.
 *
 * Mirrors adapter.py _call_core() in spirit; uses WordPress HTTP API
 * (wp_remote_post) instead of urllib so it integrates with WP's transport
 * layer (cURL, streams, proxy settings).
 *
 * @package ReeflexWordPress
 * @since   0.1.0
 */

declare( strict_types=1 );

defined( 'ABSPATH' ) || exit;

/**
 * Submits an Action Envelope to reeflex-core and returns the Decision.
 *
 * FAIL-CLOSED contract:
 *   On ANY error (WP_Error, non-200, invalid JSON, missing 'decision') this
 *   class returns a deny Decision. It NEVER returns allow on a communication
 *   failure. This is a hard invariant — do not change it.
 */
final class Reeflex_Core_Client {

	/**
	 * Rule identifier used in fail-closed synthetic decisions.
	 *
	 * @var string
	 */
	private const FAIL_CLOSED_RULE = 'reeflex.adapter/fail_closed';

	/**
	 * POST the envelope to /v1/decide and return a Decision array.
	 *
	 * @param  array $envelope  A fully-populated Action Envelope (SPEC §2).
	 * @return array  Decision: {decision, reason, rule, obligations, modulation}.
	 *                Always has at minimum {decision:'deny'} on error.
	 *                HIL Phase 2 (SPEC §5.1): on a 'require_approval' decision, core
	 *                (>= v0.1.5) additionally returns 'hold_id' and 'expires_ts'. Both
	 *                are passed through onto the returned Decision ONLY when core sent
	 *                them — see ensure_complete().
	 */
	public static function decide( array $envelope ): array {
		$base_url = Reeflex_Config::core_url();

		// Empty URL means misconfigured or SSRF-rejected (P1-4); fail closed immediately.
		if ( '' === $base_url ) {
			return self::fail_closed( 'REEFLEX_CORE_URL is not configured or was rejected as invalid' );
		}

		$url  = rtrim( $base_url, '/' ) . '/v1/decide';
		$body = wp_json_encode( $envelope );

		if ( false === $body ) {
			return self::fail_closed( 'envelope JSON encoding failed' );
		}

		// Build request headers.
		// The token is fetched here, stripped of control characters as defense-in-depth
		// against CRLF/NUL header injection (MED-2), used once, and never logged (P2-13).
		$headers = array( 'Content-Type' => 'application/json' );
		$token   = (string) preg_replace( '/[\x00-\x1F\x7F]/', '', Reeflex_Config::core_token() );
		if ( '' !== $token ) {
			$headers['Authorization'] = 'Bearer ' . $token;
		}
		// $token is discarded after this point; it is not recorded in any log.
		unset( $token );

		// Resolve TLS verification setting (constant > DB > true).
		$verify_ssl = Reeflex_Config::verify_ssl();

		// Dev-guard: warn loudly if TLS verification has been disabled for a non-loopback
		// https endpoint. The request still proceeds — this is a log-only guard intended
		// to catch accidental production misconfiguration. Loopback hosts (127.0.0.1,
		// localhost, ::1) are exempt because TLS is meaningless on loopback anyway.
		if ( ! $verify_ssl ) {
			$parsed_scheme = strtolower( (string) wp_parse_url( $url, PHP_URL_SCHEME ) );
			$parsed_host   = strtolower( (string) wp_parse_url( $url, PHP_URL_HOST ) );
			$loopback      = array( '127.0.0.1', 'localhost', '::1' );
			if ( 'https' === $parsed_scheme && ! in_array( $parsed_host, $loopback, true ) ) {
				if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
					// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Intentional debug-gated diagnostic; the authoritative record is the JSONL audit log.
					error_log(
						'[reeflex] WARNING: TLS certificate verification is DISABLED for a non-loopback ' .
						'https endpoint (' . $parsed_host . '). This is for development/staging only ' .
						'(e.g. untrusted staging certs). Enable verify_ssl in production to prevent MITM ' .
						'interception of the governance decision call.'
					);
				}
			}
		}

		$response = wp_remote_post(
			$url,
			array(
				'headers'     => $headers,
				'body'        => $body,
				'timeout'     => Reeflex_Config::request_timeout(),
				'redirection' => 0,    // never follow redirects on the decision endpoint
				'httpversion' => '1.1',
				'blocking'    => true,
				'sslverify'   => $verify_ssl,
			)
		);

		// WP_Error = transport failure (connection refused, timeout, DNS, TLS).
		if ( is_wp_error( $response ) ) {
			return self::fail_closed( 'core unreachable: ' . $response->get_error_message() );
		}

		$http_code = (int) wp_remote_retrieve_response_code( $response );
		$raw_body  = wp_remote_retrieve_body( $response );

		// Non-200: unconditionally fail-closed (P0-2).
		//
		// Rationale: accepting a parsed allow/deny from a non-200 body creates a
		// fail-open vector — a misbehaving or attacked core could return HTTP 500
		// with {decision:'allow'} and bypass all governance.  A legitimate core
		// always returns 200 for any successful decision (allow, deny, or
		// require_approval). An error status means the decision process itself
		// failed, which is an infrastructure event, not a policy event.
		if ( 200 !== $http_code ) {
			return self::fail_closed( sprintf( 'core returned HTTP %d', $http_code ) );
		}

		// 200 but non-JSON body.
		$parsed = null;
		if ( '' !== $raw_body ) {
			$parsed = json_decode( $raw_body, true );
		}

		if ( null === $parsed ) {
			return self::fail_closed( 'core response was not valid JSON' );
		}

		// 200 + JSON but missing 'decision' field.
		if ( ! isset( $parsed['decision'] ) ) {
			return self::fail_closed( "core response missing 'decision' field" );
		}

		// Validate decision value is one of the three expected outcomes.
		$valid = array( 'allow', 'deny', 'require_approval' );
		if ( ! in_array( $parsed['decision'], $valid, true ) ) {
			return self::fail_closed(
				sprintf( "core returned unknown decision value '%s'", (string) $parsed['decision'] )
			);
		}

		return self::ensure_complete( $parsed );
	}

	// ------------------------------------------------------------------
	// Internal helpers
	// ------------------------------------------------------------------

	/**
	 * Build a fail-closed deny Decision.
	 *
	 * Called on any communication or parse error. NEVER returns allow.
	 * Mirrors adapter.py _fail_closed_decision() exactly.
	 *
	 * The detailed transport $reason is sent to error_log ONLY (P2-13) —
	 * it is NOT placed in the public-facing 'reason' field to avoid leaking
	 * internal infrastructure details to the agent.
	 *
	 * @param  string $reason  Internal failure description (goes to error_log, never to callers).
	 * @return array
	 */
	public static function fail_closed( string $reason ): array {
		// Log the detailed reason server-side only (P2-13).
		if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
			// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Intentional debug-gated diagnostic; the authoritative record is the JSONL audit log.
			error_log( '[reeflex] fail-closed: ' . $reason );
		}

		return array(
			'decision'    => 'deny',
			// Generic public reason: transport detail must not reach the agent (P2-13).
			'reason'      => 'Reeflex governance temporarily unavailable.',
			'rule'        => self::FAIL_CLOSED_RULE,
			'obligations' => array(),
			'modulation'  => null,
		);
	}

	/**
	 * Ensure the Decision array has all expected fields with safe defaults.
	 *
	 * The engine contract guarantees all fields, but defensive defaults avoid
	 * PHP notices and enforce adapter-side completeness.
	 *
	 * HIL Phase 2 (SPEC §5.1): 'hold_id' and 'expires_ts' are added to the
	 * returned Decision ONLY when core included them (a 'require_approval'
	 * response from core >= v0.1.5). Their absence never changes the shape
	 * of an 'allow' or 'deny' Decision.
	 *
	 * @param  array $parsed  Decoded JSON response from core.
	 * @return array
	 */
	private static function ensure_complete( array $parsed ): array {
		$decision = array(
			'decision'    => $parsed['decision'],
			'reason'      => $parsed['reason'] ?? '',
			'rule'        => $parsed['rule'] ?? 'unknown',
			'obligations' => isset( $parsed['obligations'] ) && is_array( $parsed['obligations'] )
				? $parsed['obligations']
				: array(),
			'modulation'  => $parsed['modulation'] ?? null,
		);

		// Pass through hold_id / expires_ts only when core actually sent them (P2-14 style:
		// additive, never assumed). See holds.py / decide.py in reeflex-core for the source.
		if ( isset( $parsed['hold_id'] ) && is_string( $parsed['hold_id'] ) && '' !== $parsed['hold_id'] ) {
			$decision['hold_id'] = $parsed['hold_id'];
		}
		if ( isset( $parsed['expires_ts'] ) && is_string( $parsed['expires_ts'] ) && '' !== $parsed['expires_ts'] ) {
			$decision['expires_ts'] = $parsed['expires_ts'];
		}

		return $decision;
	}
}
