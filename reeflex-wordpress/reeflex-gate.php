<?php
/**
 * Reeflex Gate — WordPress mu-plugin loader.
 *
 * Drop this file into wp-content/mu-plugins/ and place the companion
 * reeflex-gate/ directory alongside it.  mu-plugins only auto-load top-level
 * .php files, so this loader requires all class files from the subdirectory.
 *
 * What this plugin does
 * ---------------------
 * It is a Reeflex adapter for WordPress: it intercepts every WordPress
 * Abilities API ability before it executes, normalizes the action into a
 * universal Action Envelope (Reeflex SPEC §2), asks reeflex-core to decide
 * (POST /v1/decide), and enforces the decision:
 *
 *   allow            -> ability runs normally.
 *   deny             -> ability is blocked; WP_Error('reeflex_denied') returned.
 *   require_approval -> ability is held; WP_Error('reeflex_hold') returned.
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
 * Configuration (set in wp-config.php):
 *   REEFLEX_CORE_URL  — base URL of reeflex-core (required for production).
 *   REEFLEX_ENV       — 'production'|'staging'|'dev' (default: 'production').
 *   REEFLEX_AGENT_ID  — agent identity string (default: 'agent:wordpress').
 *   REEFLEX_AUDIT_LOG — absolute path to JSONL audit log (default: wp-content/reeflex-audit.jsonl, outside the web-served uploads/ dir).
 *   REEFLEX_TIMEOUT   — HTTP timeout in seconds for /v1/decide (default: 5).
 *
 * @package       ReflexWordPress
 * @since         0.1.0
 * @license       Apache-2.0
 * @link          https://github.com/reeflex-io/reeflex-wordpress
 *
 * Plugin Name:   Reeflex Gate
 * Plugin URI:    https://reeflex.io
 * Description:   Deterministic governance for every WordPress agent action via reeflex-core.
 * Version:       0.1.0
 * Requires PHP:  7.4
 * License:       Apache-2.0
 */

declare( strict_types=1 );

// Abort if accessed directly (not inside WordPress).
defined( 'ABSPATH' ) || exit;

// ------------------------------------------------------------------
// Load class files from the companion subdirectory.
// mu-plugins auto-load top-level .php files only; the subdirectory
// must be required explicitly by this loader.
// ------------------------------------------------------------------

$_reeflex_gate_dir = __DIR__ . '/reeflex-gate/';

require_once $_reeflex_gate_dir . 'class-reeflex-config.php';
require_once $_reeflex_gate_dir . 'class-reeflex-normalizer.php';
require_once $_reeflex_gate_dir . 'class-reeflex-core-client.php';
require_once $_reeflex_gate_dir . 'class-reeflex-audit.php';
require_once $_reeflex_gate_dir . 'class-reeflex-gate.php';

unset( $_reeflex_gate_dir );

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
//
// No add_action wrapper is needed: add_filter() is safe to call at file-load
// time from a mu-plugin; WordPress queues it correctly.
// ------------------------------------------------------------------

Reeflex_Gate::register_hooks();
