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
if ( ! defined( 'HOUR_IN_SECONDS' ) )  { define( 'HOUR_IN_SECONDS', 3600 ); }

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
if ( ! function_exists( 'absint' ) ) {
	function absint( $n ) { return abs( (int) $n ); }
}
if ( ! function_exists( 'sanitize_text_field' ) ) {
	function sanitize_text_field( $str ) { return trim( preg_replace( '/[\r\n\t ]+/', ' ', strip_tags( (string) $str ) ) ); }
}
if ( ! function_exists( 'wp_parse_url' ) ) {
	function wp_parse_url( $url, $component = -1 ) { return parse_url( $url, $component ); }
}
if ( ! function_exists( 'wp_strip_all_tags' ) ) {
	function wp_strip_all_tags( $string ) { return trim( strip_tags( (string) $string ) ); }
}
if ( ! function_exists( 'wp_unslash' ) ) {
	function wp_unslash( $value ) { return is_string( $value ) ? stripslashes( $value ) : $value; }
}

// WordPress options API: the harness has no DB, so options are kept in a
// process-local in-memory array — good enough for one harness invocation
// (Reeflex_Holds_Store needs real persistence across calls WITHIN one run;
// Reeflex_Config::stored_options() still sees 'not set' for anything never
// update_option()'d, so the constant > DB option precedence is unaffected).
$GLOBALS['__options'] = array();
function get_option( $option, $default = false ) {
	return array_key_exists( $option, $GLOBALS['__options'] ) ? $GLOBALS['__options'][ $option ] : $default;
}
function update_option( $option, $value, $autoload = null ) {
	$GLOBALS['__options'][ $option ] = $value;
	return true;
}
function delete_option( $option ) {
	unset( $GLOBALS['__options'][ $option ] );
	return true;
}

// --- Minimal WP_Ability + WP_Abilities_Registry stub ------------------------
// Mirrors the real Abilities API shape referenced throughout the adapter's own
// docblocks (WP_Abilities_Registry::register(), WP_Ability::execute()) closely
// enough to exercise Reeflex_Gate::resubmit_hold()'s wp_get_ability(...)->execute()
// call for real, through the SAME wp_register_ability_args filter Hook A hangs off.
class WP_Ability {
	private $name;
	private $args;
	public function __construct( string $name, array $args ) {
		$this->name = $name;
		$this->args = $args;
	}
	public function check_permissions( $input = null ) {
		$cb = $this->args['permission_callback'] ?? null;
		if ( ! is_callable( $cb ) ) { return true; }
		return $cb( $input );
	}
	public function execute( $input = null ) {
		$perm = $this->check_permissions( $input );
		if ( true !== $perm ) { return $perm; }
		$exec = $this->args['execute_callback'] ?? null;
		if ( is_callable( $exec ) ) { return $exec( $input ); }
		return array( 'reeflex_harness_executed' => true, 'ability' => $this->name, 'input' => $input );
	}
}
class WP_Abilities_Registry {
	private static $instance;
	private $registered = array();
	public static function get_instance() {
		if ( null === self::$instance ) { self::$instance = new self(); }
		return self::$instance;
	}
	public function register( string $name, array $args ) {
		$args = apply_filters( 'wp_register_ability_args', $args, $name );
		$this->registered[ $name ] = new WP_Ability( $name, $args );
		return $this->registered[ $name ];
	}
	public function get_registered( string $name ) {
		return $this->registered[ $name ] ?? null;
	}
}
function wp_get_ability( string $name ) {
	return WP_Abilities_Registry::get_instance()->get_registered( $name );
}

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

// selected() is a WordPress template helper used by the Settings page select field.
// Returns ' selected="selected"' when $selected == $current, mirroring WP core behaviour.
if ( ! function_exists( 'selected' ) ) {
	function selected( $selected, $current = true, $echo = true ) {
		$result = ( (string) $selected === (string) $current ) ? ' selected="selected"' : '';
		if ( $echo ) {
			echo $result; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- mirrors WP core; value is a fixed attribute string.
		}
		return $result;
	}
}
