<?php
/**
 * Reeflex Settings — WordPress admin Settings page.
 *
 * Provides a Settings > Reeflex Gate page with exactly three fields:
 *
 *   1. API URL      — maps to reeflex-core base URL (MANDATORY for any action to
 *                     be allowed; an empty URL means everything is blocked).
 *   2. Token        — optional bearer token for Authorization header.
 *   3. Verify TLS   — checkbox; controls TLS certificate verification on the
 *                     POST /v1/decide call. Default: checked (ON). Uncheck ONLY
 *                     for dev/staging endpoints with untrusted certs.
 *
 * Trust-anchor rule (invariant):
 *   A value defined in wp-config.php via a constant ALWAYS wins over the
 *   DB/Settings value at runtime.  When a constant is set the field renders
 *   read-only so the admin sees it is locked.  Saving the form with a locked
 *   field present has no effect on runtime behaviour; the constant wins.
 *
 *   REEFLEX_CORE_URL   set + non-empty → API URL field locked.
 *   REEFLEX_CORE_TOKEN set (any value) → Token field locked.
 *   REEFLEX_VERIFY_SSL set (any value) → Verify TLS checkbox locked.
 *
 * Security posture:
 *   - Nonce + capability enforced by the Settings API (register_setting).
 *   - render_page() additionally checks current_user_can('manage_options').
 *   - The stored token is NEVER echoed into page HTML as a field value.
 *     Presence is indicated by a placeholder string only.
 *   - A blank token submission does NOT wipe an existing token; the operator
 *     must tick the explicit "Remove token" checkbox to clear it.
 *   - URL sanitization delegates to Reeflex_Config::sanitize_core_url() —
 *     the single implementation of the scheme/loopback rule. Invalid URLs are
 *     rejected with an admin notice and the previous value is kept.
 *   - All output is escaped at the point of output (esc_attr, esc_html, esc_url).
 *
 * Upgrade notes:
 *   - Full token rotation UI (show last-N chars, rotation timestamp) is a
 *     roadmap item.  Current design: set-or-clear, no partial display.
 *
 * @package ReeflexWordPress
 * @since   0.1.1
 */

declare( strict_types=1 );

defined( 'ABSPATH' ) || exit;

/**
 * Registers and renders the Reeflex Gate admin settings page.
 *
 * Only attaches hooks in admin context; inert on the front end and CLI.
 * Call Reeflex_Settings::init() from the mu-plugin loader after all class
 * files are required.
 */
final class Reeflex_Settings {

	/**
	 * Option group name used with register_setting() and settings_fields().
	 *
	 * @var string
	 */
	private const OPTION_GROUP = 'reeflex_gate_group';

	/**
	 * Settings section ID.
	 *
	 * @var string
	 */
	private const SECTION_ID = 'reeflex_gate_main';

	/**
	 * Register admin hooks.
	 *
	 * Safe to call at file-load time from the mu-plugin loader; WordPress
	 * queues the callbacks and fires them only in the appropriate context.
	 *
	 * @return void
	 */
	public static function init(): void {
		add_action( 'admin_menu', array( self::class, 'add_menu_page' ) );
		add_action( 'admin_init', array( self::class, 'register_settings' ) );
	}

	// ------------------------------------------------------------------
	// Menu
	// ------------------------------------------------------------------

	/**
	 * Register the options sub-page under Settings.
	 *
	 * @return void
	 */
	public static function add_menu_page(): void {
		add_options_page(
			esc_html__( 'Reeflex Gate', 'reeflex-gate' ),  // page <title>
			esc_html__( 'Reeflex Gate', 'reeflex-gate' ),  // menu label
			'manage_options',
			'reeflex-gate',
			array( self::class, 'render_page' )
		);
	}

	// ------------------------------------------------------------------
	// Settings API registration
	// ------------------------------------------------------------------

	/**
	 * Register the setting, section, and fields via the Settings API.
	 *
	 * The Settings API handles nonce generation and verification as well as
	 * the manage_options capability check on the options.php POST handler.
	 * Our sanitize callback provides additional URL validation and the
	 * blank-token-keep behaviour.
	 *
	 * @return void
	 */
	public static function register_settings(): void {
		register_setting(
			self::OPTION_GROUP,
			Reeflex_Config::OPTION_NAME,
			array(
				'sanitize_callback' => array( self::class, 'sanitize_options' ),
				'default'           => array(
					'core_url'   => '',
					'core_token' => '',
					'verify_ssl' => true,
					'mode'       => 'enforce',
				),
			)
		);

		add_settings_section(
			self::SECTION_ID,
			esc_html__( 'Core Connection', 'reeflex-gate' ),
			array( self::class, 'render_section_intro' ),
			'reeflex-gate'
		);

		add_settings_field(
			'reeflex_core_url',
			esc_html__( 'API URL', 'reeflex-gate' ),
			array( self::class, 'render_field_url' ),
			'reeflex-gate',
			self::SECTION_ID
		);

		add_settings_field(
			'reeflex_core_token',
			esc_html__( 'Token', 'reeflex-gate' ),
			array( self::class, 'render_field_token' ),
			'reeflex-gate',
			self::SECTION_ID
		);

		add_settings_field(
			'reeflex_verify_ssl',
			esc_html__( 'Verify TLS certificate', 'reeflex-gate' ),
			array( self::class, 'render_field_verify_ssl' ),
			'reeflex-gate',
			self::SECTION_ID
		);

		add_settings_field(
			'reeflex_mode',
			esc_html__( 'Enforcement mode', 'reeflex-gate' ),
			array( self::class, 'render_field_mode' ),
			'reeflex-gate',
			self::SECTION_ID
		);
	}

	// ------------------------------------------------------------------
	// Sanitize callback
	// ------------------------------------------------------------------

	/**
	 * Sanitize and validate the submitted options array.
	 *
	 * Called by the Settings API before the option is stored.
	 * The Settings API has already verified the nonce and the
	 * manage_options capability at this point.
	 *
	 * core_url:
	 *   - Trim + esc_url_raw.
	 *   - Delegates to Reeflex_Config::sanitize_core_url() — single source of truth.
	 *     Rule: https always; http only for loopback; everything else rejected.
	 *   - If invalid: add_settings_error; keep previous value.
	 *   - Locked (constant defined): silently keep previous value (constant wins anyway).
	 *
	 * core_token:
	 *   - Trim + strip_tags + strip control characters (CRLF/NUL — header-injection guard).
	 *   - If submitted field is blank AND the "Remove token" checkbox is NOT ticked:
	 *     keep the existing stored token (do not wipe on accidental blank submit).
	 *   - If "Remove token" is ticked: store ''.
	 *   - Locked (constant defined): silently keep previous value (constant wins anyway).
	 *
	 * @param  mixed $input  Raw POST data (expected array).
	 * @return array         Sanitized options array.
	 */
	public static function sanitize_options( $input ): array {
		// Retrieve current stored values as fallback.
		$current = Reeflex_Config::stored_options();

		$out = array(
			'core_url'   => $current['core_url'],
			'core_token' => $current['core_token'],
			'verify_ssl' => $current['verify_ssl'],
			'mode'       => $current['mode'],
		);

		if ( ! is_array( $input ) ) {
			// Unexpected type — keep existing values without change.
			return $out;
		}

		// --- core_url ---
		if ( Reeflex_Config::core_url_is_locked() ) {
			// Constant wins; ignore submitted value; keep existing DB value as-is.
			// (The DB value is irrelevant at runtime when the constant is set, but
			// we preserve it so the field doesn't blank out when the lock is later
			// removed.)
			$out['core_url'] = $current['core_url'];
		} else {
			$submitted_url = isset( $input['core_url'] ) ? trim( (string) $input['core_url'] ) : '';
			$submitted_url = esc_url_raw( $submitted_url );

			if ( '' === $submitted_url ) {
				// Empty is allowed (means fail-closed); store empty.
				$out['core_url'] = '';
			} else {
				// Delegate to the single URL validator in Reeflex_Config (MED-1).
				// Returns '' on rejection; non-empty string on success.
				$validated = Reeflex_Config::sanitize_core_url(
					$submitted_url,
					'reeflex_gate_options[core_url] (settings save)'
				);
				if ( '' === $validated ) {
					// Invalid scheme/structure: reject and show admin error.
					add_settings_error(
						Reeflex_Config::OPTION_NAME,
						'reeflex_invalid_url',
						esc_html__(
							'API URL was not saved: it must be https://, or http:// for loopback hosts only (127.0.0.1, localhost, ::1). The previous value was kept.',
							'reeflex-gate'
						),
						'error'
					);
					$out['core_url'] = $current['core_url'];
				} else {
					$out['core_url'] = $validated;
				}
			}
		}

		// --- core_token ---
		if ( Reeflex_Config::core_token_is_locked() ) {
			// Constant wins; ignore submitted value; keep existing DB value as-is.
			$out['core_token'] = $current['core_token'];
		} else {
			// Check explicit "Remove token" checkbox first.
			$remove_token = ! empty( $input['remove_token'] );

			if ( $remove_token ) {
				// Operator explicitly requested token removal.
				$out['core_token'] = '';
			} else {
				$submitted_token = isset( $input['core_token'] ) ? trim( wp_strip_all_tags( (string) $input['core_token'] ) ) : '';
				// Strip control characters (C0, DEL) to prevent CRLF/NUL header injection (MED-2).
				$submitted_token = (string) preg_replace( '/[\x00-\x1F\x7F]/', '', $submitted_token );

				if ( '' === $submitted_token ) {
					// Blank submit without remove checkbox: keep existing token.
					// This prevents accidental wipe when the password field is left
					// empty (browsers do not pre-fill password fields).
					$out['core_token'] = $current['core_token'];
				} else {
					$out['core_token'] = $submitted_token;
				}
			}
		}

		// --- verify_ssl ---
		if ( Reeflex_Config::verify_ssl_is_locked() ) {
			// Constant wins; ignore submitted value; keep existing DB value as-is.
			// (The DB value is irrelevant at runtime when the constant is set, but
			// we preserve it so the field doesn't flip when the lock is later removed.)
			$out['verify_ssl'] = $current['verify_ssl'];
		} else {
			// An unchecked checkbox sends no key in the POST array → false.
			// This is correct explicit-uncheck behaviour (unlike the token blank-keep rule).
			$out['verify_ssl'] = ! empty( $input['verify_ssl'] );
		}

		// --- mode ---
		if ( Reeflex_Config::mode_is_locked() ) {
			// Constant wins; ignore submitted value; keep existing DB value as-is.
			// (The DB value is irrelevant at runtime when the constant is set, but
			// we preserve it so the field doesn't change when the lock is later removed.)
			$out['mode'] = $current['mode'];
		} else {
			$out['mode'] = ( isset( $input['mode'] ) && 'observe' === $input['mode'] ) ? 'observe' : 'enforce';
		}

		return $out;
	}

	// ------------------------------------------------------------------
	// Render: page wrapper
	// ------------------------------------------------------------------

	/**
	 * Render the full settings page.
	 *
	 * The Settings API nonce is rendered by settings_fields().
	 * We also perform an explicit capability check here as defense-in-depth
	 * (the add_options_page capability arg and the Settings API POST handler
	 * both check manage_options; this is a third layer).
	 *
	 * @return void
	 */
	public static function render_page(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to access this page.', 'reeflex-gate' ) );
		}
		?>
		<div class="wrap">
			<h1><?php echo esc_html__( 'Reeflex Gate', 'reeflex-gate' ); ?></h1>
			<p><?php echo esc_html__( 'Configure the connection to reeflex-core, the governance decision engine.', 'reeflex-gate' ); ?></p>

			<?php self::render_status_block(); ?>

			<form method="post" action="options.php">
				<?php
				// Outputs nonce, action, and option_page fields for this group.
				settings_fields( self::OPTION_GROUP );
				do_settings_sections( 'reeflex-gate' );
				submit_button( esc_html__( 'Save Settings', 'reeflex-gate' ) );
				?>
			</form>
		</div>
		<?php
	}

	// ------------------------------------------------------------------
	// Render: section intro
	// ------------------------------------------------------------------

	/**
	 * Render the intro text for the main settings section.
	 *
	 * @return void
	 */
	public static function render_section_intro(): void {
		?>
		<p>
			<?php echo esc_html__(
				'Fields marked "Locked" are defined in wp-config.php and cannot be changed here. Constants always take precedence over these settings.',
				'reeflex-gate'
			); ?>
		</p>
		<?php
	}

	// ------------------------------------------------------------------
	// Render: API URL field
	// ------------------------------------------------------------------

	/**
	 * Render the API URL settings field.
	 *
	 * Locked state: if REEFLEX_CORE_URL is defined + non-empty, the input is
	 * rendered disabled with the constant value shown and a "Locked" notice.
	 *
	 * Empty state: if the effective URL is '' (no constant, no DB value), a
	 * red warning is shown because the gate will fail-closed on every action.
	 *
	 * @return void
	 */
	public static function render_field_url(): void {
		$locked   = Reeflex_Config::core_url_is_locked();
		$stored   = Reeflex_Config::stored_options();
		$field_id = 'reeflex_core_url';

		// The displayed value depends on lock state:
		//   locked → show the constant value (informational; the field is disabled).
		//   unlocked → show the stored DB value.
		// Keep the raw string; escape at the point of output — no pre-escaping.
		if ( $locked ) {
			$display_value_raw = (string) REEFLEX_CORE_URL;
		} else {
			$display_value_raw = $stored['core_url'];
		}

		// Effective URL for the status warning check (uses the same precedence as core_url()).
		$effective_url = Reeflex_Config::core_url();

		if ( $locked ) {
			// Disabled input showing the constant value.
			?>
			<input
				type="url"
				id="<?php echo esc_attr( $field_id ); ?>"
				name="<?php echo esc_attr( Reeflex_Config::OPTION_NAME . '[core_url]' ); ?>"
				value="<?php echo esc_attr( $display_value_raw ); ?>"
				class="regular-text"
				disabled
				aria-describedby="<?php echo esc_attr( $field_id . '-desc' ); ?>"
			/>
			<p class="description" id="<?php echo esc_attr( $field_id . '-desc' ); ?>">
				<strong><?php echo esc_html__( 'Locked — defined in wp-config.php (REEFLEX_CORE_URL).', 'reeflex-gate' ); ?></strong>
				<?php echo esc_html__( 'To change this value, update the constant in wp-config.php.', 'reeflex-gate' ); ?>
			</p>
			<?php
		} else {
			// Editable input.
			?>
			<input
				type="url"
				id="<?php echo esc_attr( $field_id ); ?>"
				name="<?php echo esc_attr( Reeflex_Config::OPTION_NAME . '[core_url]' ); ?>"
				value="<?php echo esc_attr( $display_value_raw ); ?>"
				class="regular-text"
				placeholder="https://reeflex-core.example.com"
				aria-describedby="<?php echo esc_attr( $field_id . '-desc' ); ?>"
			/>
			<p class="description" id="<?php echo esc_attr( $field_id . '-desc' ); ?>">
				<?php echo esc_html__(
					'Base URL of the reeflex-core decision engine. Must be https:// in production. Required — if empty, Reeflex blocks all agent actions (fail-closed).',
					'reeflex-gate'
				); ?>
			</p>
			<?php
		}

		// Red warning if no URL is in effect (fail-closed applies to all actions).
		if ( '' === $effective_url ) {
			?>
			<p class="description" style="color:#d63638;font-weight:bold;margin-top:6px;">
				<?php echo esc_html__(
					'Warning: No API URL is configured. Reeflex is blocking all agent actions until an API URL is set.',
					'reeflex-gate'
				); ?>
			</p>
			<?php
		}

		// Source label for transparency.
		self::render_source_label(
			$locked ? 'constant' : ( '' !== $stored['core_url'] ? 'settings' : 'not_set' )
		);
	}

	// ------------------------------------------------------------------
	// Render: Token field
	// ------------------------------------------------------------------

	/**
	 * Render the bearer token settings field.
	 *
	 * Security:
	 *   - The stored token value is NEVER echoed into page HTML (not even as a
	 *     hidden field value). The password input always has an empty value="".
	 *   - Presence is indicated by a placeholder description string only.
	 *   - A "Remove token" checkbox provides the only explicit clear path.
	 *
	 * Locked state: if REEFLEX_CORE_TOKEN is defined, the field is disabled
	 * and a "Locked" notice is shown. The token value is not displayed.
	 *
	 * @return void
	 */
	public static function render_field_token(): void {
		$locked    = Reeflex_Config::core_token_is_locked();
		$stored    = Reeflex_Config::stored_options();
		$has_token = '' !== $stored['core_token'];
		$field_id  = 'reeflex_core_token';

		if ( $locked ) {
			// Token is locked via constant; show disabled field (no value displayed).
			?>
			<input
				type="password"
				id="<?php echo esc_attr( $field_id ); ?>"
				name="<?php echo esc_attr( Reeflex_Config::OPTION_NAME . '[core_token]' ); ?>"
				value=""
				class="regular-text"
				disabled
				autocomplete="new-password"
				aria-describedby="<?php echo esc_attr( $field_id . '-desc' ); ?>"
			/>
			<p class="description" id="<?php echo esc_attr( $field_id . '-desc' ); ?>">
				<strong><?php echo esc_html__( 'Locked — defined in wp-config.php (REEFLEX_CORE_TOKEN).', 'reeflex-gate' ); ?></strong>
				<?php echo esc_html__( 'To change this value, update the constant in wp-config.php.', 'reeflex-gate' ); ?>
			</p>
			<?php
		} else {
			// Editable token field.  Value is always empty — see security note above.
			?>
			<input
				type="password"
				id="<?php echo esc_attr( $field_id ); ?>"
				name="<?php echo esc_attr( Reeflex_Config::OPTION_NAME . '[core_token]' ); ?>"
				value=""
				class="regular-text"
				autocomplete="new-password"
				aria-describedby="<?php echo esc_attr( $field_id . '-desc' ); ?>"
			/>
			<p class="description" id="<?php echo esc_attr( $field_id . '-desc' ); ?>">
				<?php if ( $has_token ) : ?>
					<?php echo esc_html__(
						'A token is saved. Leave this field blank to keep the existing token. To replace it, enter a new token.',
						'reeflex-gate'
					); ?>
				<?php else : ?>
					<?php echo esc_html__(
						'Optional. If set, the adapter sends Authorization: Bearer <token> to reeflex-core. Leave blank if core is public.',
						'reeflex-gate'
					); ?>
				<?php endif; ?>
			</p>

			<?php if ( $has_token ) : ?>
				<?php
				// "Remove token" checkbox — the only way to explicitly clear the stored token.
				$remove_field_id = 'reeflex_remove_token';
				?>
				<label style="display:block;margin-top:6px;">
					<input
						type="checkbox"
						id="<?php echo esc_attr( $remove_field_id ); ?>"
						name="<?php echo esc_attr( Reeflex_Config::OPTION_NAME . '[remove_token]' ); ?>"
						value="1"
					/>
					<?php echo esc_html__( 'Remove the saved token (explicitly clears it on save).', 'reeflex-gate' ); ?>
				</label>
			<?php endif; ?>
			<?php
		}

		// Source label for transparency (token value is NOT shown, only set/not set).
		$token_source = $locked
			? 'constant'
			: ( $has_token ? 'settings' : 'not_set' );
		self::render_source_label( $token_source, true );
	}

	// ------------------------------------------------------------------
	// Render: Verify TLS field
	// ------------------------------------------------------------------

	/**
	 * Render the Verify TLS certificate settings field.
	 *
	 * Locked state: if REEFLEX_VERIFY_SSL is defined, the checkbox is disabled
	 * and a "Locked" notice is shown reflecting the constant value.
	 *
	 * Warning state: when the effective value is false (verification OFF), a red
	 * warning is displayed to make the risk visible to the operator.
	 *
	 * @return void
	 */
	public static function render_field_verify_ssl(): void {
		$locked    = Reeflex_Config::verify_ssl_is_locked();
		$effective = Reeflex_Config::verify_ssl();
		$field_id  = 'reeflex_verify_ssl';

		if ( $locked ) {
			// Checkbox is locked via constant; render disabled, reflecting constant value.
			?>
			<label>
				<input
					type="checkbox"
					id="<?php echo esc_attr( $field_id ); ?>"
					name="<?php echo esc_attr( Reeflex_Config::OPTION_NAME . '[verify_ssl]' ); ?>"
					value="1"
					<?php checked( $effective ); ?>
					disabled
					aria-describedby="<?php echo esc_attr( $field_id . '-desc' ); ?>"
				/>
				<?php echo esc_html__(
					'Verify the TLS certificate of the core endpoint. Keep enabled in production. Uncheck ONLY for your own self-signed or internal core endpoint with an untrusted certificate, at your own risk.',
					'reeflex-gate'
				); ?>
			</label>
			<p class="description" id="<?php echo esc_attr( $field_id . '-desc' ); ?>">
				<strong><?php echo esc_html__( 'Locked — defined in wp-config.php (REEFLEX_VERIFY_SSL).', 'reeflex-gate' ); ?></strong>
				<?php echo esc_html__( 'To change this value, update the constant in wp-config.php.', 'reeflex-gate' ); ?>
			</p>
			<?php
		} else {
			// Editable checkbox.
			?>
			<label>
				<input
					type="checkbox"
					id="<?php echo esc_attr( $field_id ); ?>"
					name="<?php echo esc_attr( Reeflex_Config::OPTION_NAME . '[verify_ssl]' ); ?>"
					value="1"
					<?php checked( $effective ); ?>
					aria-describedby="<?php echo esc_attr( $field_id . '-desc' ); ?>"
				/>
				<?php echo esc_html__(
					'Verify the TLS certificate of the core endpoint. Keep enabled in production. Uncheck ONLY for your own self-signed or internal core endpoint with an untrusted certificate, at your own risk.',
					'reeflex-gate'
				); ?>
			</label>
			<?php
		}

		// Red warning when verification is OFF (regardless of lock state).
		if ( ! $effective ) {
			?>
			<p class="description" style="color:#d63638;font-weight:bold;margin-top:6px;">
				<?php echo esc_html__(
					'Warning: TLS certificate verification is DISABLED. This is for a self-signed or internal core endpoint only. Never disable it in production.',
					'reeflex-gate'
				); ?>
			</p>
			<?php
		}

		// Source label for transparency.
		self::render_source_label( $locked ? 'constant' : 'settings' );
	}

	// ------------------------------------------------------------------
	// Render: status block
	// ------------------------------------------------------------------

	/**
	 * Render a short summary block showing the effective source per field.
	 *
	 * Shown at the top of the page for quick operator orientation.
	 * Does NOT display any token value — only "set" or "not set".
	 *
	 * @return void
	 */
	private static function render_status_block(): void {
		$url_effective  = Reeflex_Config::core_url();
		$url_source     = self::get_url_source_label();
		$token_source   = self::get_token_source_label();
		$ssl_source     = self::get_ssl_source_label();
		$ssl_effective  = Reeflex_Config::verify_ssl();
		$mode_effective = Reeflex_Config::mode();
		$mode_source    = self::get_mode_source_label();

		?>
		<div class="notice notice-info" style="margin-left:0;">
			<p><strong><?php echo esc_html__( 'Reeflex Gate — effective configuration', 'reeflex-gate' ); ?></strong></p>
			<table>
				<tr>
					<td style="padding-right:16px;"><strong><?php echo esc_html__( 'API URL source:', 'reeflex-gate' ); ?></strong></td>
					<td><?php echo esc_html( $url_source ); ?></td>
					<td style="padding-left:16px;">
						<?php if ( '' !== $url_effective ) : ?>
							<code><?php echo esc_url( $url_effective ); ?></code>
						<?php else : ?>
							<span style="color:#d63638;"><?php echo esc_html__( 'not set — fail-closed active', 'reeflex-gate' ); ?></span>
						<?php endif; ?>
					</td>
				</tr>
				<tr>
					<td style="padding-right:16px;"><strong><?php echo esc_html__( 'Token source:', 'reeflex-gate' ); ?></strong></td>
					<td><?php echo esc_html( $token_source ); ?></td>
					<td style="padding-left:16px;">
						<?php echo esc_html( self::get_token_presence_label() ); ?>
					</td>
				</tr>
				<tr>
					<td style="padding-right:16px;"><strong><?php echo esc_html__( 'TLS verification:', 'reeflex-gate' ); ?></strong></td>
					<td><?php echo esc_html( $ssl_source ); ?></td>
					<td style="padding-left:16px;">
						<?php if ( $ssl_effective ) : ?>
							<?php echo esc_html__( 'ON', 'reeflex-gate' ); ?>
						<?php else : ?>
							<span style="color:#d63638;font-weight:bold;"><?php echo esc_html__( 'OFF', 'reeflex-gate' ); ?></span>
						<?php endif; ?>
					</td>
				</tr>
				<tr>
					<td style="padding-right:16px;"><strong><?php echo esc_html__( 'Enforcement mode:', 'reeflex-gate' ); ?></strong></td>
					<td><?php echo esc_html( $mode_source ); ?></td>
					<td style="padding-left:16px;">
						<?php if ( 'observe' === $mode_effective ) : ?>
							<span><?php echo esc_html__( 'Observe (enforcement OFF)', 'reeflex-gate' ); ?></span>
						<?php else : ?>
							<?php echo esc_html__( 'Enforce', 'reeflex-gate' ); ?>
						<?php endif; ?>
					</td>
				</tr>
			</table>
		</div>
		<?php
	}

	// ------------------------------------------------------------------
	// Private helpers
	// ------------------------------------------------------------------

	/**
	 * Render a small "source:" label below a field.
	 *
	 * @param  string $source    'constant' | 'settings' | 'not_set'
	 * @param  bool   $is_token  If true, suppress any value display (token fields).
	 * @return void
	 */
	private static function render_source_label( string $source, bool $is_token = false ): void {
		$map = array(
			'constant' => __( 'Source: wp-config.php constant (locked)', 'reeflex-gate' ),
			'settings' => __( 'Source: settings page (database)', 'reeflex-gate' ),
			'not_set'  => __( 'Source: not set', 'reeflex-gate' ),
		);
		$label = $map[ $source ] ?? $map['not_set'];
		?>
		<p class="description" style="font-style:italic;margin-top:4px;">
			<?php echo esc_html( $label ); ?>
		</p>
		<?php
	}

	/**
	 * Human-readable source label for the URL (for status block).
	 *
	 * @return string
	 */
	private static function get_url_source_label(): string {
		if ( Reeflex_Config::core_url_is_locked() ) {
			return __( 'wp-config.php constant (REEFLEX_CORE_URL)', 'reeflex-gate' );
		}
		$stored = Reeflex_Config::stored_options();
		if ( '' !== $stored['core_url'] ) {
			return __( 'Settings page (database)', 'reeflex-gate' );
		}
		return __( 'not set', 'reeflex-gate' );
	}

	/**
	 * Human-readable source label for the token (for status block; no value shown).
	 *
	 * @return string
	 */
	private static function get_token_source_label(): string {
		if ( Reeflex_Config::core_token_is_locked() ) {
			return __( 'wp-config.php constant (REEFLEX_CORE_TOKEN)', 'reeflex-gate' );
		}
		$stored = Reeflex_Config::stored_options();
		if ( '' !== $stored['core_token'] ) {
			return __( 'Settings page (database)', 'reeflex-gate' );
		}
		return __( 'not set', 'reeflex-gate' );
	}

	/**
	 * "set" / "not set" presence label for the token (never the value).
	 *
	 * @return string
	 */
	private static function get_token_presence_label(): string {
		$effective = Reeflex_Config::core_token();
		return '' !== $effective
			? __( 'set', 'reeflex-gate' )
			: __( 'not set', 'reeflex-gate' );
	}

	/**
	 * Human-readable source label for TLS verification (for status block).
	 *
	 * @return string
	 */
	private static function get_ssl_source_label(): string {
		if ( Reeflex_Config::verify_ssl_is_locked() ) {
			return __( 'wp-config.php constant (REEFLEX_VERIFY_SSL)', 'reeflex-gate' );
		}
		return __( 'Settings page (database)', 'reeflex-gate' );
	}

	// ------------------------------------------------------------------
	// Render: Enforcement mode field
	// ------------------------------------------------------------------

	/**
	 * Render the Enforcement mode settings field.
	 *
	 * A <select> with two options: 'enforce' (default) and 'observe'.
	 *
	 * Locked state: if REEFLEX_MODE is defined, the select is disabled and a
	 * "Locked" notice is shown reflecting the constant value.
	 *
	 * Observe notice: when the effective mode is 'observe', an informational
	 * (not red) notice reminds the operator that enforcement is OFF.
	 *
	 * @return void
	 */
	public static function render_field_mode(): void {
		$locked    = Reeflex_Config::mode_is_locked();
		$effective = Reeflex_Config::mode();
		$field_id  = 'reeflex_mode';

		$field_name = Reeflex_Config::OPTION_NAME . '[mode]';
		?>
		<select
			id="<?php echo esc_attr( $field_id ); ?>"
			name="<?php echo esc_attr( $field_name ); ?>"
			<?php if ( $locked ) : ?>disabled<?php endif; ?>
			aria-describedby="<?php echo esc_attr( $field_id . '-desc' ); ?>"
		>
			<option value="enforce" <?php selected( $effective, 'enforce' ); ?>>
				<?php echo esc_html__( 'Enforce — block/hold risky actions (default)', 'reeflex-gate' ); ?>
			</option>
			<option value="observe" <?php selected( $effective, 'observe' ); ?>>
				<?php echo esc_html__( 'Observe — record verdicts, enforce nothing', 'reeflex-gate' ); ?>
			</option>
		</select>

		<?php if ( $locked ) : ?>
			<p class="description" id="<?php echo esc_attr( $field_id . '-desc' ); ?>">
				<strong><?php echo esc_html__( 'Locked — defined in wp-config.php (REEFLEX_MODE).', 'reeflex-gate' ); ?></strong>
				<?php echo esc_html__( 'To change this value, update the constant in wp-config.php.', 'reeflex-gate' ); ?>
			</p>
		<?php else : ?>
			<p class="description" id="<?php echo esc_attr( $field_id . '-desc' ); ?>">
				<?php echo esc_html__(
					'Observe: every verdict is recorded to the audit log, but nothing is enforced — the action always proceeds. Use it to see what Reeflex would have stopped before turning enforcement on. In observe, a core outage does NOT block the site (fail-open).',
					'reeflex-gate'
				); ?>
			</p>
		<?php endif; ?>

		<?php if ( 'observe' === $effective ) : ?>
			<p class="description" style="margin-top:6px;">
				<?php echo esc_html__(
					'Enforcement is OFF. All agent actions are proceeding unchecked. Switch to Enforce when you are ready to apply governance.',
					'reeflex-gate'
				); ?>
			</p>
		<?php endif; ?>

		<?php
		// Source label for transparency.
		self::render_source_label( $locked ? 'constant' : 'settings' );
	}

	/**
	 * Human-readable source label for enforcement mode (for status block).
	 *
	 * @return string
	 */
	private static function get_mode_source_label(): string {
		if ( Reeflex_Config::mode_is_locked() ) {
			return __( 'wp-config.php constant (REEFLEX_MODE)', 'reeflex-gate' );
		}
		return __( 'Settings page (database)', 'reeflex-gate' );
	}

}
