<?php
/**
 * Plugin Name:  Reeflex Gate
 * Plugin URI:   https://github.com/Reeflex-io/reeflex
 * Description:  Deterministic governance for every WordPress agent action via reeflex-core (allow / deny / require-approval, fail-closed).
 * Version:      0.1.4
 * Requires at least: 6.9
 * Requires PHP: 7.4
 * Author:       Reeflex
 * Author URI:   https://github.com/Reeflex-io
 * License:      GPLv2 or later
 * License URI:  https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:  reeflex-gate
 * Domain Path:  /languages
 */

/**
 * Reeflex Gate — dual-form loader (mu-plugin + standard plugin).
 *
 * INSTALL FORMS
 * -------------
 * mu-plugin form:
 *   Drop reeflex-gate.php into wp-content/mu-plugins/ and place the companion
 *   reeflex-gate/ directory alongside it.  mu-plugins auto-load top-level .php
 *   files only; this loader requires all class files from the subdirectory.
 *   Class directory: wp-content/mu-plugins/reeflex-gate/
 *
 * Standard-plugin form:
 *   Install the whole reeflex-wordpress/ directory as a plugin under
 *   wp-content/plugins/reeflex-wordpress/.  WordPress treats reeflex-gate.php
 *   as the plugin main file.  All class files live alongside it in the same
 *   directory (reeflex-gate/ sub-dir is absent → loader falls back to __DIR__).
 *
 * CLASS-DIRECTORY DETECTION (the dual-form trick)
 * ------------------------------------------------
 * If __DIR__/reeflex-gate/ exists  → mu form  → load from that subdirectory.
 * Otherwise                        → std form  → load from __DIR__ itself.
 * One file, two layouts, zero branching at runtime beyond this one is_dir().
 *
 * WHAT THIS PLUGIN DOES
 * ---------------------
 * It is a Reeflex adapter for WordPress: it intercepts every WordPress
 * Abilities API ability before it executes, normalizes the action into a
 * universal Action Envelope (Reeflex SPEC §2), asks reeflex-core to decide
 * (POST /v1/decide), and enforces the decision:
 *
 *   allow            -> ability runs normally.
 *   deny             -> ability is blocked; WP_Error('reeflex_denied') returned.
 *   require_approval -> ability is held; WP_Error('reeflex_hold') returned, carrying
 *                        hold_id + expires_ts (core >= v0.1.5). Once a human resolves
 *                        the hold via core's holds API, Reeflex_Gate::resubmit_hold()
 *                        re-runs the original call.
 *   core unreachable -> FAIL CLOSED: deny; WP_Error('reeflex_unavailable') returned.
 *
 * Two hooks are registered:
 *
 *   Hook A — apply_filters('wp_register_ability_args', $args, $name)
 *     Source: class-wp-abilities-registry.php:120 (abilities-api v0.4.0 / WP 6.9+).
 *     PRIMARY blocking seam. Wraps every ability's permission_callback so that
 *     Reeflex gates the action before WP_Ability::execute() can reach do_execute().
 *     Covers REST + direct PHP + MCP-originated calls (all paths go through execute()).
 *
 *   Hook B — apply_filters('mcp_adapter_pre_tool_call', $args, $tool_name, $mcp_tool, $server)
 *     Source: ToolsHandler.php:182 (mcp-adapter v0.5.0).
 *     DEFENSE-IN-DEPTH. Fires only for the 'mcp-adapter/execute-ability' tool.
 *     Adds MCP-layer fidelity (reads the MCP session ID from HTTP header) and
 *     cleaner MCP error propagation. A WP_Error return short-circuits execution.
 *
 * CONFIGURATION (set in wp-config.php — constants always win over Settings page)
 * -------------------------------------------------------------------------------
 *   REEFLEX_CORE_URL   — base URL of reeflex-core (required for production).
 *                        When set, locks the API URL field on the Settings page.
 *   REEFLEX_CORE_TOKEN — bearer token for Authorization header (optional).
 *                        When set, locks the Token field on the Settings page.
 *   REEFLEX_VERIFY_SSL — verify the core's TLS certificate (default: true).
 *                        Set false ONLY for dev/staging certs (e.g. api-dev).
 *                        When set, locks the Verify TLS checkbox on the Settings page.
 *   REEFLEX_ENV        — 'production'|'staging'|'dev' (default: 'production').
 *   REEFLEX_AGENT_ID   — agent identity string (default: 'agent:wordpress').
 *   REEFLEX_AUDIT_LOG  — absolute path to JSONL audit log
 *                        (default: wp-content/reeflex-audit.jsonl, outside uploads/).
 *   REEFLEX_TIMEOUT    — HTTP timeout in seconds for /v1/decide (default: 5).
 *
 * SETTINGS PAGE (normal-plugin install)
 * --------------------------------------
 *   Settings > Reeflex Gate provides three fields — API URL, Token, and
 *   Verify TLS — as a convenience alternative to wp-config.php constants.
 *   Constants, when defined, always override Settings values and lock the fields read-only.
 *
 * @package  ReflexWordPress
 * @since    0.1.0
 * @license  Apache-2.0
 * @link     https://github.com/Reeflex-io/reeflex
 */

declare( strict_types=1 );

// Abort if accessed directly (not inside WordPress).
defined( 'ABSPATH' ) || exit;

// ------------------------------------------------------------------
// CLASS-DIRECTORY DETECTION — the dual-form trick.
//
// mu form:  reeflex-gate.php lives in mu-plugins/; classes are in
//           mu-plugins/reeflex-gate/ — the subdirectory exists.
// std form: reeflex-gate.php is the plugin main; all files including
//           classes live in the same plugin directory alongside it —
//           __DIR__/reeflex-gate/ does NOT exist; use __DIR__ itself.
// ------------------------------------------------------------------

$reeflex_dir = is_dir( __DIR__ . '/reeflex-gate' ) ? __DIR__ . '/reeflex-gate/' : __DIR__ . '/';

require_once $reeflex_dir . 'class-reeflex-config.php';
require_once $reeflex_dir . 'class-reeflex-normalizer.php';
require_once $reeflex_dir . 'class-reeflex-core-client.php';
require_once $reeflex_dir . 'class-reeflex-audit.php';
require_once $reeflex_dir . 'class-reeflex-holds-store.php';
require_once $reeflex_dir . 'class-reeflex-gate.php';
require_once $reeflex_dir . 'class-reeflex-settings.php';

unset( $reeflex_dir );

// ------------------------------------------------------------------
// Register hooks.
//
// Timing is critical for Hook A:
//   - wp_register_ability_args fires inside WP_Abilities_Registry::register()
//     which is called from abilities registered on 'wp_abilities_api_init'.
//   - 'wp_abilities_api_init' fires the first time WP_Abilities_Registry::get_instance()
//     is called, which WP 6.9 / the abilities-api plugin does at 'init' priority 10.
//   - mu-plugins load before regular plugins and before 'init', so our filter
//     is registered well before any ability registers.  Correct.
//   - Standard-plugin form: WordPress loads plugins before 'init' too, so
//     the filter registration timing is equivalent.
//
// No add_action wrapper is needed: add_filter() is safe to call at file-load
// time; WordPress queues it correctly regardless of install form.
// ------------------------------------------------------------------

Reeflex_Gate::register_hooks();

// Settings page: attaches admin_menu + admin_init hooks.
// Inert on the front end and in non-admin (CLI/cron) contexts.
Reeflex_Settings::init();

// ------------------------------------------------------------------
// Settings row action link — standard-plugin form only.
//
// In the mu-plugin form, WordPress never shows this file in the
// Plugins list, so the filter never fires and this closure is inert.
// In the standard-plugin form, adds a "Settings" link in the plugin
// row for quick navigation to Settings > Reeflex Gate.
// ------------------------------------------------------------------

add_filter(
	'plugin_action_links_' . plugin_basename( __FILE__ ),
	static function ( $links ) {
		$url = admin_url( 'options-general.php?page=reeflex-gate' );
		array_unshift( $links, '<a href="' . esc_url( $url ) . '">' . esc_html__( 'Settings', 'reeflex-gate' ) . '</a>' );
		return $links;
	}
);
