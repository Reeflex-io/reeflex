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
if ( ! defined( 'MINUTE_IN_SECONDS' ) ){ define( 'MINUTE_IN_SECONDS', 60 ); }
if ( ! defined( 'HOUR_IN_SECONDS' ) )  { define( 'HOUR_IN_SECONDS', 3600 ); }
if ( ! defined( 'DAY_IN_SECONDS' ) )   { define( 'DAY_IN_SECONDS', 86400 ); }

// --- Resolving as a principal core can VERIFY (reeflex-core 0.2.0, RFX-84) --
//
// Every one of the four live-core harnesses resolves a hold, and since 0.2.0
// reeflex-core refuses a resolve whose approver it cannot tie to the calling
// credential (403 principal_not_verified). Presenting no Authorization header
// at all -- what these harnesses did -- is exactly that case.
//
// So the harness now presents a credential BOUND to the principal each
// scenario approves as. Both sides read the same file
// (harness-resolver-tokens.json): core is started with
// REEFLEX_RESOLVER_TOKENS pointed at it, and the lookup below finds the token
// for a given principal id. One source of truth, so the harness and the core
// it talks to cannot drift.
//
// Absent or unreadable -> "" -> no Authorization header, i.e. the pre-0.2.0
// behaviour, which still works against a core running the documented opt-out
// (REEFLEX_REQUIRE_VERIFIED_APPROVER=false).

/**
 * The bearer token bound to `$principal_id` in the harness resolver map.
 *
 * @param string $principal_id The principal a scenario is approving as.
 * @return string The token, or '' when the map is absent/unreadable/has no
 *                entry (caller then sends no Authorization header).
 */
function reeflex_harness_token_for( string $principal_id ): string {
	static $map = null;
	if ( null === $map ) {
		$map  = array();
		$path = getenv( 'REEFLEX_HARNESS_RESOLVER_TOKENS' );
		if ( ! is_string( $path ) || '' === $path ) {
			$path = __DIR__ . '/harness-resolver-tokens.json';
		}
		$raw = is_readable( $path ) ? file_get_contents( $path ) : false;
		if ( false !== $raw ) {
			$parsed = json_decode( $raw, true );
			if ( is_array( $parsed ) ) {
				foreach ( $parsed as $token => $principal ) {
					if ( is_array( $principal ) && isset( $principal['id'] ) ) {
						$map[ (string) $principal['id'] ] = (string) $token;
					}
				}
			}
		}
	}
	return $map[ $principal_id ] ?? '';
}

/**
 * Print a one-line diagnosis when core refused a resolve for a reason the
 * harness can actually do something about.
 *
 * A scenario table row reading "FAIL" over a 403 sends the reader to the
 * source. This names the cause and the fix, once, at the moment it happens --
 * the same discipline reeflex-core's own refusal now follows.
 *
 * @param int        $code HTTP status from the resolve call.
 * @param array|null $body Decoded response body, if any.
 * @return void
 */
function reeflex_harness_explain_resolve_refusal( int $code, $body ): void {
	static $said = false;
	if ( $said || 403 !== $code || ! is_array( $body ) ) {
		return;
	}
	if ( 'principal_not_verified' !== ( $body['error'] ?? '' ) ) {
		return;
	}
	$said = true;
	fwrite(
		STDERR,
		"\n[harness] reeflex-core refused this resolve: the approver is not bound to the calling credential.\n"
		. "[harness] Since reeflex-core 0.2.0 REEFLEX_REQUIRE_VERIFIED_APPROVER defaults to true.\n"
		. "[harness] Start the core under test with:\n"
		. "[harness]   REEFLEX_RESOLVER_TOKENS=" . __DIR__ . "/harness-resolver-tokens.json\n"
		. "[harness] (or, to run these harnesses against the pre-0.2.0 behaviour,\n"
		. "[harness]  REEFLEX_REQUIRE_VERIFIED_APPROVER=false).\n\n"
	);
}

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
// add_action is a plain alias of add_filter in real WordPress core; mirrored here
// so Reeflex_Admin::init() (admin_menu, admin_post_{action}) can register.
function add_action( $hook, $cb, $prio = 10, $args = 1 ) { return add_filter( $hook, $cb, $prio, $args ); }

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
function wp_salt( $scheme = 'auth' ) { return AUTH_SALT . '-salt-' . $scheme; }
function trailingslashit( $s )   { return rtrim( (string) $s, '/\\' ) . '/'; }
function untrailingslashit( $s ) { return rtrim( (string) $s, '/\\' ); }

// wp_upload_dir() — RFX-27: class-reeflex-config.php::audit_log_path() calls this
// to derive the WP.org-convention default audit path (uploads/reeflex-gate/...).
// Without this stub every harness that touches audit_log_path() (fanout- and
// hold-dedup-regression-demo.php) died with a fatal "undefined function" BEFORE
// running a single scenario — found 2026-08-20 because nothing invoked those two
// scripts in any automation (see RFX-27 report). Shape matches real WordPress:
// only 'basedir'/'error' are read by the caller, but the full key set is mirrored
// for anything else that might call this stub later.
function wp_upload_dir() {
	$base = rtrim( WP_CONTENT_DIR, '/\\' ) . '/uploads';
	return array(
		'path'    => $base,
		'url'     => 'http://harness.invalid/wp-content/uploads',
		'subdir'  => '',
		'basedir' => $base,
		'baseurl' => 'http://harness.invalid/wp-content/uploads',
		'error'   => false,
	);
}

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

// -----------------------------------------------------------------------
// Admin-surface shims (HIL Phase 2 T2 — Reeflex_Admin). Added only because
// class-reeflex-admin.php is now exercised by tests/admin-holds-demo.php.
// These are deliberately simplified versions of the real WordPress functions
// (e.g. esc_url() here is a plain htmlspecialchars, not WP's full URL
// sanitizer) — good enough for a CLI test harness that never renders in a
// real browser; NOT a substitute for testing against real WordPress.
// -----------------------------------------------------------------------

// --- Capability check --------------------------------------------------
// Toggle via $GLOBALS['__current_user_can'] = false; in a test to exercise
// the fail-closed "no permission" path. Defaults to true (admin user).
if ( ! function_exists( 'current_user_can' ) ) {
	function current_user_can( $capability ) {
		return $GLOBALS['__current_user_can'] ?? true;
	}
}

// --- wp_die(): throws instead of terminating the process ---------------
// Mirrors the well-established wp-phpunit convention (WPDieException) so a
// capability/nonce failure can be asserted with a try/catch instead of
// killing the whole CLI test run.
class Reeflex_Test_WPDieException extends \Exception {}
if ( ! function_exists( 'wp_die' ) ) {
	function wp_die( $message = '', $title = '', $args = array() ) {
		throw new Reeflex_Test_WPDieException( is_string( $message ) ? $message : 'wp_die' );
	}
}

// --- Escaping / i18n (simplified) ---------------------------------------
if ( ! function_exists( 'esc_html' ) ) {
	function esc_html( $text ) { return htmlspecialchars( (string) $text, ENT_QUOTES, 'UTF-8' ); }
}
if ( ! function_exists( 'esc_attr' ) ) {
	function esc_attr( $text ) { return htmlspecialchars( (string) $text, ENT_QUOTES, 'UTF-8' ); }
}
if ( ! function_exists( 'esc_url' ) ) {
	function esc_url( $url ) { return htmlspecialchars( (string) $url, ENT_QUOTES, 'UTF-8' ); }
}
if ( ! function_exists( '__' ) ) {
	function __( $text, $domain = 'default' ) { return $text; }
}
if ( ! function_exists( 'esc_html__' ) ) {
	function esc_html__( $text, $domain = 'default' ) { return esc_html( __( $text, $domain ) ); }
}
if ( ! function_exists( 'esc_attr__' ) ) {
	function esc_attr__( $text, $domain = 'default' ) { return esc_attr( __( $text, $domain ) ); }
}

// --- Nonces (deterministic, NOT cryptographically equivalent to WP core) ---
if ( ! function_exists( 'wp_create_nonce' ) ) {
	function wp_create_nonce( $action = -1 ) {
		return substr( hash( 'sha256', 'nonce:' . $action . ':' . AUTH_SALT ), 0, 10 );
	}
}
if ( ! function_exists( 'wp_nonce_field' ) ) {
	function wp_nonce_field( $action = -1, $name = '_wpnonce', $referer = true, $echo = true ) {
		$field = '<input type="hidden" name="' . esc_attr( $name ) . '" value="' . esc_attr( wp_create_nonce( $action ) ) . '" />';
		if ( $echo ) {
			echo $field; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- already esc_attr()'d above.
		}
		return $field;
	}
}
if ( ! function_exists( 'check_admin_referer' ) ) {
	function check_admin_referer( $action = -1, $query_arg = '_wpnonce' ) {
		$sent = $_REQUEST[ $query_arg ] ?? '';
		if ( ! hash_equals( wp_create_nonce( $action ), (string) $sent ) ) {
			wp_die( 'invalid nonce' );
		}
		return true;
	}
}

// --- Admin URL / redirect / menu (recorded, not "real") ------------------
if ( ! function_exists( 'admin_url' ) ) {
	function admin_url( $path = '' ) { return 'https://harness.example.test/wp-admin/' . ltrim( (string) $path, '/' ); }
}
if ( ! function_exists( 'wp_safe_redirect' ) ) {
	function wp_safe_redirect( $location, $status = 302 ) {
		$GLOBALS['__last_redirect'] = $location;
		return true;
	}
}
if ( ! function_exists( 'add_menu_page' ) ) {
	function add_menu_page( $page_title, $menu_title, $capability, $menu_slug, $callback = '', $icon_url = '', $position = null ) {
		$GLOBALS['__admin_menu'][ $menu_slug ] = compact( 'page_title', 'menu_title', 'capability', 'menu_slug', 'callback', 'icon_url', 'position' );
		return $menu_slug;
	}
}

// --- Current user id + transients (in-memory, per-process) ---------------
if ( ! function_exists( 'get_current_user_id' ) ) {
	function get_current_user_id() {
		$u = wp_get_current_user();
		return ( $u && $u->exists() ) ? (int) $u->ID : 0;
	}
}
$GLOBALS['__transients'] = array();
if ( ! function_exists( 'set_transient' ) ) {
	function set_transient( $key, $value, $expiration = 0 ) {
		$GLOBALS['__transients'][ $key ] = $value;
		return true;
	}
}
if ( ! function_exists( 'get_transient' ) ) {
	function get_transient( $key ) {
		return $GLOBALS['__transients'][ $key ] ?? false;
	}
}
if ( ! function_exists( 'delete_transient' ) ) {
	function delete_transient( $key ) {
		unset( $GLOBALS['__transients'][ $key ] );
		return true;
	}
}

// --- Additional sanitizer used by the admin surface -----------------------
if ( ! function_exists( 'sanitize_textarea_field' ) ) {
	function sanitize_textarea_field( $str ) { return trim( (string) $str ); }
}
