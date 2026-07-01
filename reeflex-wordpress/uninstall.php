<?php
/**
 * Reeflex Gate — uninstall cleanup (standard-plugin form only).
 * Removes the stored settings (including the bearer token) on plugin delete.
 * Intentionally does NOT delete the audit log (wp-content/reeflex-audit.jsonl):
 * that JSONL is a governance/compliance record; destroying it on uninstall
 * would itself be a governance failure. Operators remove it manually.
 */
defined( 'WP_UNINSTALL_PLUGIN' ) || exit;
delete_option( 'reeflex_gate_options' );
