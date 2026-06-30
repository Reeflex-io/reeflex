<?php
/**
 * wp-stubs.php — minimal WordPress shims so the Reeflex mu-plugin classes can be
 * loaded and exercised under plain PHP CLI, with wp_remote_post() actually hitting
 * a real reeflex-core over HTTP.
 *
 * This is a TEST HARNESS, not WordPress. It stubs only the small WordPress surface
 * the adapter touches. Decision authority always stays in reeflex-core — these stubs
 * do not make any allow/deny choice; they only let the adapter run outside WordPress.
 *
 * @package ReeflexWordPress
 */

declare( strict_types=1 );

// --- Constants the adapter expects -----------------------------------------
if ( ! defined( 'ABSPATH' ) )          { define( 'ABSPATH', __DIR__ . '/' ); }
if ( ! defined( 'WP_CONTENT_DIR' ) )   { define( 'WP_CONTENT_DIR', getenv( 'REEFLEX_HARNESS_TMP' ) ?: sys_get_temp_dir() ); }
if ( ! defined( 'AUTH_SALT' ) )        { define( 'AUTH_SALT', 'harness-auth-salt' ); }
if ( ! defined( 'LOGGED_IN_COOKIE' ) ) { define( 'LOGGED_IN_COOKIE', 'wordpress_logged_in_harness' ); }

// --- Filter/action registry ------------------------------------------------
$GLOBALS['__filters'] = array();

function add_filter( $hook, $cb, $prio = 10, $args = 1 ) {
	$GLOBALS['__filters'][ $hook ][] = $cb;
	return true;
}
function apply_filters( $hook, $value, ...$rest ) {
	if ( empty( $GLOBALS['__filters'][ $hook ] ) ) { return $value; }
	foreach ( $GLOBALS['__filters'][ $hook ] as $cb ) {
		$value = $cb( $value, ...$rest );
	}
	return $value;
}
function do_action( $hook, ...$args ) { /* no-op in the harness */ }

// --- WP_Error --------------------------------------------------------------
class WP_Error {
	public $code; public $message; public $data;
	public function __construct( $code = '', $message = '', $data = '' ) {
		$this->code = $code; $this->message = $message; $this->data = $data;
	}
	public function get_error_code()    { return $this->code; }
	public function get_error_message() { return $this->message; }
	public function get_error_data()    { return $this->data; }
}
function is_wp_error( $thing ) { return $thing instanceof WP_Error; }

// --- Current user (synthetic) ----------------------------------------------
class WP_User {
	public $ID = 7; public $user_login = 'editor-bot'; public $roles = array( 'editor' );
	public function exists() { return true; }
}
function wp_get_current_user() { return new WP_User(); }

// Unique per process so each harness invocation gets a FRESH core session ledger.
// (Reusing one session_id across runs accumulates the R5 session-delete budget, so
// a read in a delete-heavy session is correctly held — a real engine behaviour.)
function wp_get_session_token() { return 'harness-' . getmypid() . '-' . substr( md5( uniqid( '', true ) ), 0, 10 ); }
function wp_hash( $data, $scheme = 'auth' ) { return hash_hmac( 'sha256', (string) $data, AUTH_SALT . '-' . $scheme ); }
function trailingslashit( $s )   { return rtrim( (string) $s, '/\\' ) . '/'; }
function untrailingslashit( $s ) { return rtrim( (string) $s, '/\\' ); }

// --- Misc helpers ----------------------------------------------------------
function wp_generate_uuid4() {
	$d = random_bytes( 16 );
	$d[6] = chr( ( ord( $d[6] ) & 0x0f ) | 0x40 );
	$d[8] = chr( ( ord( $d[8] ) & 0x3f ) | 0x80 );
	return vsprintf( '%s%s-%s-%s-%s-%s%s%s', str_split( bin2hex( $d ), 4 ) );
}
function wp_json_encode( $data, $flags = 0, $depth = 512 ) { return json_encode( $data, $flags, $depth ); }
function sanitize_text_field( $s ) { return trim( preg_replace( '/[\r\n\t]+/', ' ', (string) $s ) ); }

// --- HTTP API: wp_remote_post -> real HTTP via streams (no curl dependency) -
function wp_remote_post( $url, $args = array() ) {
	$body    = $args['body'] ?? '';
	$timeout = $args['timeout'] ?? 5;
	$headers = '';
	foreach ( (array) ( $args['headers'] ?? array() ) as $k => $v ) { $headers .= "$k: $v\r\n"; }

	$ctx = stream_context_create( array(
		'http' => array(
			'method'        => 'POST',
			'header'        => $headers,
			'content'       => $body,
			'timeout'       => $timeout,
			'ignore_errors' => true, // capture 4xx/5xx bodies instead of failing
		),
		'ssl'  => array( 'verify_peer' => true, 'verify_peer_name' => true ),
	) );

	$raw = @file_get_contents( $url, false, $ctx );
	if ( false === $raw ) {
		return new WP_Error( 'http_request_failed', 'connection failed for ' . $url );
	}

	$code = 0;
	if ( isset( $http_response_header[0] ) && preg_match( '#\s(\d{3})\s#', $http_response_header[0], $m ) ) {
		$code = (int) $m[1];
	}
	return array( 'response' => array( 'code' => $code ), 'body' => $raw );
}
function wp_remote_retrieve_response_code( $r ) { return is_array( $r ) ? ( $r['response']['code'] ?? 0 ) : 0; }
function wp_remote_retrieve_body( $r )          { return is_array( $r ) ? ( $r['body'] ?? '' ) : ''; }
