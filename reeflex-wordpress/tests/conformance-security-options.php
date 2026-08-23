<?php
/**
 * conformance-security-options.php — a WordPress setting that governs SECURITY
 * must not reach core looking like a setting that governs the site's name
 * (RFX-219, residue of RFX-128).
 *
 * WHAT THIS HARNESS IS FOR
 * ------------------------
 * `core/update-option` is one ability covering every setting WordPress has.
 * Measured on a real core before the fix: disabling two-factor auth and
 * renaming the site produced the same ability, the same verb, the same three
 * axes, the same target kind and a null ref on both — identical envelopes
 * outside `params`, and therefore the same verdict, `allow` /
 * `reeflex.policy/default_allow`. The option name was the whole difference
 * between them and it never left `params`, which SPEC §2 defines as an open
 * backend-specific bag that no rule may pattern-match.
 *
 * The normalizer now splices the security FAMILY and the option NAME into
 * `action.ability` for the options it recognises:
 *
 *     core/update-option  +  two_factor_enabled
 *         -> core/update-option/mfa/two_factor_enabled
 *
 * The family word is what core's authority rule can read; the option name is
 * what a human resolving the hold can read (the audit record carries
 * `action.ability` and carries neither `params` nor `target.ref`, so if the
 * option name is not in that string it is in no artefact an approver ever
 * sees). The original ability stays a literal prefix, so nothing is renamed.
 *
 * WHICH ACTION FAMILIES THIS CORPUS COVERS, so a PASS here is not over-read
 * (the coverage-silence problem is RFX-220):
 *
 *     credential      two_factor_enabled, wp_2fa_settings   (family word: mfa)
 *     authority       default_role, users_can_register, {prefix}_user_roles
 *     executability   active_plugins, template, stylesheet, cron
 *     control (must stay allow)  blogname, blogdescription, posts_per_page
 *     control (reads)            core/get-option on a security option
 *
 * It covers NO money, NO post/media deletion and NO outbound action — those
 * live in conformance-demo.php.
 *
 * WHAT A PASS HERE DOES NOT MEAN. The recognised-option list is a FLOOR, not a
 * boundary: an option a plugin invents tomorrow is not in it and this harness
 * cannot say otherwise. What it does assert is that the floor holds, that it
 * survives the spellings an agent can vary, and — the half that matters just as
 * much — that ordinary settings work is NOT held.
 *
 * DEPENDS ON A CORE THAT CARRIES THE AUTHORITY RULE (RFX-128). The refinement is
 * inert against a policy pack without it: the envelope is more honest and every
 * verdict is unchanged. Measured, and asserted below rather than assumed — if
 * the core under test has no authority rule the harness SKIPS the decision
 * rows, loudly, instead of passing on an allow.
 *
 * Usage:
 *   php tests/conformance-security-options.php [core_url]
 *     core_url defaults to http://127.0.0.1:8099
 *     point it at a DEAD port (e.g. http://127.0.0.1:9) to prove fail-closed
 *
 *   REEFLEX_MODE=observe php tests/conformance-security-options.php [core_url]
 *     every scenario must resolve to PROCEED regardless of the would-be verdict.
 *
 * Exit code 0 = all assertions pass, 1 = an assertion failed, 2 = harness error.
 *
 * @package ReeflexWordPress
 */

declare( strict_types=1 );

$adapter_dir = dirname( __DIR__ );
$core_url    = $argv[1] ?? 'http://127.0.0.1:8099';

putenv( 'REEFLEX_HARNESS_TMP=' . sys_get_temp_dir() );
require __DIR__ . '/wp-stubs.php';

if ( ! defined( 'REEFLEX_CORE_URL' ) ) { define( 'REEFLEX_CORE_URL', $core_url ); }
if ( ! defined( 'REEFLEX_ENV' ) )      { define( 'REEFLEX_ENV', 'production' ); }
if ( ! defined( 'REEFLEX_AUDIT_LOG' ) ){ define( 'REEFLEX_AUDIT_LOG', sys_get_temp_dir() . '/reeflex-secopt-audit.jsonl' ); }
if ( ! defined( 'REEFLEX_MODE' ) )     { define( 'REEFLEX_MODE', getenv( 'REEFLEX_MODE' ) ?: 'enforce' ); }

require $adapter_dir . '/reeflex-gate/class-reeflex-config.php';
require $adapter_dir . '/reeflex-gate/class-reeflex-normalizer.php';
require $adapter_dir . '/reeflex-gate/class-reeflex-core-client.php';
require $adapter_dir . '/reeflex-gate/class-reeflex-audit.php';
require $adapter_dir . '/reeflex-gate/class-reeflex-holds-store.php';
require $adapter_dir . '/reeflex-gate/class-reeflex-gate.php';

Reeflex_Gate::register_hooks();
if ( empty( $GLOBALS['__filters']['wp_register_ability_args'][0] ) ) {
	fwrite( STDERR, "FATAL: Hook A (wp_register_ability_args) not registered\n" );
	exit( 2 );
}

$observe_mode    = ( 'observe' === REEFLEX_MODE );
$fail_closed_run = (bool) preg_match( '#:9(\D|$)#', $core_url ) && false === strpos( $core_url, ':8099' );

$failures = 0;
$bar      = str_repeat( '-', 118 );

function fail( string $msg ): void {
	global $failures;
	$failures++;
	echo "  FAIL  $msg\n";
}

function ok( string $msg ): void {
	echo "  ok    $msg\n";
}

/** Register an ability once, through the REAL Hook A filter. */
function get_or_register_demo_ability( string $ability ): WP_Ability {
	$existing = wp_get_ability( $ability );
	if ( null !== $existing ) {
		return $existing;
	}
	return WP_Abilities_Registry::get_instance()->register(
		$ability,
		array(
			'permission_callback' => static function ( $i = null ) { return true; },
			'execute_callback'    => static function ( $i ) use ( $ability ) {
				return array( 'reeflex_harness_executed' => true, 'ability' => $ability, 'input' => $i );
			},
		)
	);
}

/** Run through the wrapped permission_callback; return [outcome, code]. */
function run_ability( string $ability, array $input ): array {
	Reeflex_Gate::reset_request_cache();
	$result = get_or_register_demo_ability( $ability )->execute( $input );
	if ( true === $result )            { return array( 'PROCEED', 'allow' ); }
	if ( is_array( $result ) )         { return array( 'PROCEED', 'allow' ); }
	if ( $result instanceof WP_Error ) { return array( 'BLOCKED', $result->get_error_code() ); }
	return array( 'UNEXPECTED', var_export( $result, true ) );
}

echo $bar . "\n";
printf(
	"reeflex-wordpress security-option conformance (RFX-219)   CORE=%s%s%s\n",
	$core_url,
	$observe_mode ? '   MODE=observe (all PROCEED expected)' : '',
	( ! $observe_mode && $fail_closed_run ) ? '   (expect fail-closed everywhere)' : ''
);
echo $bar . "\n";

// ===========================================================================
// PART 1 — THE ENVELOPE. Needs no core, so it runs on every invocation,
// including the dead-port fail-closed run and observe mode.
// ===========================================================================
echo "\nPART 1  the envelope distinguishes a security setting from a cosmetic one\n";

$env_2fa    = Reeflex_Normalizer::normalize( 'core/update-option', array( 'option_name' => 'two_factor_enabled', 'value' => 0 ) );
$env_rename = Reeflex_Normalizer::normalize( 'core/update-option', array( 'option_name' => 'blogname', 'value' => 'hi' ) );

$fingerprint = static function ( array $e ): string {
	return $e['action']['ability'] . '|' . $e['action']['verb'] . '|'
		. implode( ',', $e['axes'] ) . '|'
		. $e['target']['kind'] . ':' . ( $e['target']['ref'] ?? 'NULL' );
};

if ( $fingerprint( $env_2fa ) === $fingerprint( $env_rename ) ) {
	fail( 'disabling 2FA and renaming the site are the SAME envelope outside params: ' . $fingerprint( $env_2fa ) );
} else {
	ok( 'distinguishable: ' . $env_2fa['action']['ability'] . '  vs  ' . $env_rename['action']['ability'] );
}

// The refinement must not disturb anything else about the envelope. The axes,
// the verb and the count are derived from the ORIGINAL ability precisely so an
// agent-supplied option name can never move them (a family word like `role` is
// also an 'update' verb token, and an option named `alloptions` would trip the
// systemic blast-radius substring test).
foreach ( array(
	'action.verb'        => array( $env_2fa['action']['verb'], $env_rename['action']['verb'] ),
	'reversibility'      => array( $env_2fa['axes']['reversibility'], $env_rename['axes']['reversibility'] ),
	'blast_radius'       => array( $env_2fa['axes']['blast_radius'], $env_rename['axes']['blast_radius'] ),
	'externality'        => array( $env_2fa['axes']['externality'], $env_rename['axes']['externality'] ),
	'target.kind'        => array( $env_2fa['target']['kind'], $env_rename['target']['kind'] ),
	'magnitude.count'    => array( (string) $env_2fa['magnitude']['count'], (string) $env_rename['magnitude']['count'] ),
) as $field => $pair ) {
	if ( $pair[0] !== $pair[1] ) {
		fail( sprintf( 'the option name moved %s (%s vs %s) — only action.ability may differ', $field, $pair[0], $pair[1] ) );
	}
}
ok( 'the option name moved action.ability and nothing else (verb, 3 axes, kind, count all unchanged)' );

// The original ability must survive as a literal prefix — an operator's
// existing `core/update-option` grep or dashboard filter must still match.
if ( 0 !== strpos( $env_2fa['action']['ability'], 'core/update-option' ) ) {
	fail( 'the refined ability no longer starts with the ability WordPress registered: ' . $env_2fa['action']['ability'] );
} else {
	ok( 'the WordPress ability survives as a literal prefix' );
}

// The option name must be IN the ability, because the audit record carries
// neither params nor target.ref — see the file header.
if ( false === strpos( $env_2fa['action']['ability'], 'two_factor_enabled' ) ) {
	fail( 'the refined ability does not name the option, so no artefact an approver reads does' );
} else {
	ok( 'the refined ability names the option an approver is being asked about' );
}

// ===========================================================================
// PART 2 — THE ENFORCED OUTCOME, through Hook A against the live core.
// ===========================================================================

// label => [ability, input, expected_code]
$scenarios = array(
	'S1 disable two-factor auth site-wide'     => array( 'core/update-option', array( 'option_name' => 'two_factor_enabled', 'value' => 0 ),               'reeflex_hold' ),
	'S2 make every new account an admin'       => array( 'core/update-option', array( 'option_name' => 'default_role', 'value' => 'administrator' ),       'reeflex_hold' ),
	'S3 open self-registration'                => array( 'core/update-option', array( 'option_name' => 'users_can_register', 'value' => 1 ),               'reeflex_hold' ),
	'S4 rewrite the role definitions'          => array( 'core/update-option', array( 'option_name' => 'wp_user_roles' ),                                  'reeflex_hold' ),
	'S5 activate arbitrary PHP'                => array( 'core/update-option', array( 'option_name' => 'active_plugins', 'value' => array( 'x/x.php' ) ),  'reeflex_hold' ),
	'S6 switch the running theme'              => array( 'core/update-option', array( 'option_name' => 'template', 'value' => 'evil' ),                    'reeflex_hold' ),
	'S7 schedule arbitrary PHP'                => array( 'core/update-option', array( 'option_name' => 'cron' ),                                           'reeflex_hold' ),
	'S8 delete the 2FA option outright'        => array( 'core/delete-option', array( 'option_name' => 'two_factor_enabled' ),                             'reeflex_hold' ),

	'C1 rename the site'                       => array( 'core/update-option', array( 'option_name' => 'blogname', 'value' => 'hi' ),                      'allow' ),
	'C2 change the tagline'                    => array( 'core/update-option', array( 'option_name' => 'blogdescription', 'value' => 'x' ),                'allow' ),
	'C3 set posts per page'                    => array( 'core/update-option', array( 'option_name' => 'posts_per_page', 'value' => 20 ),                  'allow' ),
	'C4 READ a security option'                => array( 'core/get-option',    array( 'option_name' => 'two_factor_enabled' ),                             'allow' ),
	'C5 an option merely NAMED after a family' => array( 'core/update-option', array( 'option_name' => 'my_mfa_banner_text', 'value' => 'hi' ),            'allow' ),
);

// Evasions: the same production effect, spelled differently. WordPress's
// update_option() trims its option name, so a leading space writes the REAL row.
$evasions = array(
	'X1 leading space'                         => array( 'core/update-option', array( 'option_name' => ' two_factor_enabled' ),                            'reeflex_hold' ),
	'X2 trailing tab'                          => array( 'core/update-option', array( 'option_name' => "two_factor_enabled\t" ),                           'reeflex_hold' ),
	'X3 mixed case'                            => array( 'core/update-option', array( 'option_name' => 'Two_Factor_Enabled' ),                             'reeflex_hold' ),
	'X4 the other input key spelling'          => array( 'core/update-option', array( 'option' => 'two_factor_enabled' ),                                  'reeflex_hold' ),
	'X5 a non-default table prefix'            => array( 'core/update-option', array( 'option_name' => 'acme7_user_roles' ),                               'reeflex_hold' ),
	'X6 an ids array to look like a bulk op'   => array( 'core/update-option', array( 'option_name' => 'two_factor_enabled', 'ids' => array( 1, 2, 3 ) ),  'reeflex_hold' ),

	// The refinement must not fire on these. A gate that holds ordinary work is
	// switched off within a day, and a switched-off gate is a fail-open.
	'N1 a name key on an unrelated ability'    => array( 'core/delete-post',   array( 'ids' => array( 9 ), 'name' => 'two_factor_enabled' ),               'allow' ),
	'N2 option name given as an array'         => array( 'core/update-option', array( 'option_name' => array( 'two_factor_enabled' ) ),                    'allow' ),
	'N3 option name given as an int'           => array( 'core/update-option', array( 'option_name' => 42 ),                                               'allow' ),
	'N4 blank option name'                     => array( 'core/update-option', array( 'option_name' => '   ' ),                                            'allow' ),
	'N5 no option name at all'                 => array( 'core/update-option', array( 'value' => 1 ),                                                      'allow' ),
);

// Is the core under test carrying the authority rule at all? Probed rather than
// assumed: without it every row below is an allow, and a harness that reported
// PASS on that would be certifying the defect.
//
// THE PROBE MUST NOT USE A ROW THIS FIX CREATES. `users/assign-role` is the
// authority rule's own canonical row and it is held with or without the
// normalizer change, so a red result here means "no authority rule" and nothing
// else. The first draft of this harness probed with `two_factor_enabled`, which
// made a pre-fix adapter report "this core has no authority rule" about a core
// that plainly had one — a wrong reason attached to a real failure, which is
// the instrument defect this file exists to avoid.
$authority_rule_present = true;
if ( ! $observe_mode && ! $fail_closed_run ) {
	Reeflex_Gate::reset_request_cache();
	list( $probe_outcome ) = run_ability( 'users/assign-role', array( 'user_id' => 7, 'role' => 'administrator' ) );
	$authority_rule_present = ( 'PROCEED' !== $probe_outcome );
}

echo "\nPART 2  the enforced outcome, through Hook A against " . $core_url . "\n";

if ( ! $authority_rule_present ) {
	echo "\n  SKIPPED — this core's policy pack has no authority rule (RFX-128), so the\n";
	echo "            refinement is inert by construction and these rows would assert\n";
	echo "            nothing. Envelope assertions above still ran and still count.\n";
	echo "            Run against a core whose REEFLEX_POLICY_DIR contains authority.rego.\n";
} else {
	printf( "\n  %-44s | %-30s | %s\n", 'SCENARIO', 'ENFORCED OUTCOME', 'RESULT' );
	echo '  ' . str_repeat( '-', 114 ) . "\n";

	foreach ( array( $scenarios, $evasions ) as $group ) {
		foreach ( $group as $label => $spec ) {
			list( $ability, $input, $expected ) = $spec;

			if ( $observe_mode ) {
				$expected = 'allow';
			} elseif ( $fail_closed_run ) {
				$expected = 'reeflex_unavailable';
			}

			list( $outcome, $code ) = run_ability( $ability, $input );
			$got  = ( 'PROCEED' === $outcome ) ? 'allow' : $code;
			$pass = ( $got === $expected );
			if ( ! $pass ) { $failures++; }

			printf(
				"  %-44s | %-30s | %s\n",
				$label,
				$outcome . ' (' . $code . ')',
				$pass ? 'PASS' : 'FAIL expected=' . $expected
			);
		}
	}
}

// ===========================================================================
// PART 3 — the operator's extension point, and its one-way property.
// ===========================================================================
// The `reeflex_security_option_families` filter exists so a site can declare
// its own plugin's options. It is ADDITIVE ONLY, for the same reason the
// trusted verb override is raise-only: a hook that can DELETE a shipped entry
// is a documented way to switch a control off from inside the audited system.
echo "\nPART 3  the operator filter adds, and cannot remove\n";

$refined = static function ( string $option ): string {
	$e = Reeflex_Normalizer::normalize( 'core/update-option', array( 'option_name' => $option ) );
	return $e['action']['ability'];
};

$GLOBALS['__filters']['reeflex_security_option_families'] = array();
add_filter( 'reeflex_security_option_families', static function ( $map ) {
	$map['acme_login_policy'] = 'password';
	return $map;
} );
if ( 'core/update-option/password/acme_login_policy' !== $refined( 'acme_login_policy' ) ) {
	fail( 'an operator could not ADD their own option: ' . $refined( 'acme_login_policy' ) );
} else {
	ok( 'an operator can add their own option' );
}

foreach ( array(
	'REMOVE a shipped entry'   => static function ( $map ) { unset( $map['two_factor_enabled'] ); return $map; },
	'REDEFINE a shipped entry' => static function ( $map ) { $map['two_factor_enabled'] = 'cosmetic'; return $map; },
	'return a non-array'       => static function () { return 'not an array'; },
	'return null'              => static function () { return null; },
) as $what => $cb ) {
	$GLOBALS['__filters']['reeflex_security_option_families'] = array();
	add_filter( 'reeflex_security_option_families', $cb );
	$got = $refined( 'two_factor_enabled' );
	if ( 'core/update-option/mfa/two_factor_enabled' !== $got ) {
		fail( sprintf( 'a filter that tried to %s changed the shipped answer to "%s"', $what, $got ) );
	} else {
		ok( sprintf( 'a filter that tried to %s had no effect', $what ) );
	}
}
$GLOBALS['__filters']['reeflex_security_option_families'] = array();

echo "\n" . $bar . "\n";
if ( 0 === $failures ) {
	echo "ALL SECURITY-OPTION SCENARIOS PASS";
	if ( ! $authority_rule_present ) {
		echo "  (PART 2 SKIPPED — core has no authority rule)";
	}
	echo "\n";
} else {
	printf( "SOME SECURITY-OPTION SCENARIOS FAILED (%d)\n", $failures );
}
echo $bar . "\n";

exit( 0 === $failures ? 0 : 1 );
