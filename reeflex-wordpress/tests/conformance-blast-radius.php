<?php
/**
 * conformance-blast-radius.php — SPEC §4.2 conformance for axes.blast_radius.
 *
 * Drives the REAL Reeflex_Normalizer::normalize() (WordPress stubbed via
 * wp-stubs.php) against the SHARED vector file
 * `reeflex-spec/conformance/blast-radius.json` — the same file the Claude Code
 * adapter's runner reads (`reeflex-claude/tests/test_conformance_blast_radius.py`).
 *
 * WHY IT IS SHARED. Before RFX-131 each reference adapter derived blast_radius
 * its own way — this one by substring matching on the ability name, the Claude
 * Code one from the shape of the command's target — SPEC §7 said an adapter
 * "MUST pass the conformance suite" for the axes, and for this axis there was no
 * suite to pass. A harness carrying its own expectations would let the two
 * adapters keep disagreeing while both stayed green; the boundary at exactly 20
 * entities is what that actually cost.
 *
 * A case with no `wordpress` binding is NOT APPLICABLE here and is reported BY
 * NAME, never silently skipped, so the number of cases exercised stays legible
 * (RFX-105..110).
 *
 * UNLIKE the other four harnesses in this directory, this one needs NO live
 * reeflex-core and no network: blast_radius is resolved entirely inside the
 * normalizer. It therefore runs unconditionally in gate.py rather than SKIPPING
 * when --core-url is absent, which is the whole point of separating it.
 *
 * Usage:
 *   php tests/conformance-blast-radius.php
 *
 * Exit code 0 = every applicable case conforms, 1 = a case failed, 2 = harness error.
 *
 * @package ReeflexWordPress
 */

declare( strict_types=1 );

$adapter_dir = dirname( __DIR__ );                 // reeflex-wordpress/
$repo_root   = dirname( $adapter_dir );            // monorepo root
$vectors     = $repo_root . '/reeflex-spec/conformance/blast-radius.json';

if ( ! is_readable( $vectors ) ) {
	fwrite( STDERR, "HARNESS ERROR: SPEC §4.2 vectors not readable at $vectors\n"
		. "This harness asserts nothing without them — fix the path rather than skipping.\n" );
	exit( 2 );
}

$doc = json_decode( (string) file_get_contents( $vectors ), true );
if ( ! is_array( $doc ) || empty( $doc['cases'] ) ) {
	fwrite( STDERR, "HARNESS ERROR: $vectors did not parse into cases\n" );
	exit( 2 );
}

putenv( 'REEFLEX_HARNESS_TMP=' . sys_get_temp_dir() );
require __DIR__ . '/wp-stubs.php';

if ( ! defined( 'REEFLEX_ENV' ) )       { define( 'REEFLEX_ENV', 'production' ); }
if ( ! defined( 'REEFLEX_AUDIT_LOG' ) ) { define( 'REEFLEX_AUDIT_LOG', sys_get_temp_dir() . '/reeflex-blast-radius-audit.jsonl' ); }
if ( ! defined( 'REEFLEX_MODE' ) )      { define( 'REEFLEX_MODE', 'enforce' ); }

require $adapter_dir . '/reeflex-gate/class-reeflex-config.php';
require $adapter_dir . '/reeflex-gate/class-reeflex-normalizer.php';

const ADAPTER = 'wordpress';

// The boundary is shared DATA, not a per-adapter constant — that is what caught
// the two adapters disagreeing at exactly 20.
$expected_broad_min = 20;
if ( (int) ( $doc['broad_min'] ?? 0 ) !== $expected_broad_min ) {
	fwrite( STDERR, sprintf(
		"FAIL: vector file declares broad_min=%s; this adapter is built for %d\n",
		var_export( $doc['broad_min'] ?? null, true ),
		$expected_broad_min
	) );
	exit( 1 );
}

$pass = 0;
$fail = 0;
$na   = array();

printf( "%-44s %-11s %-11s %s\n", 'CASE', 'EXPECT', 'GOT', '' );
echo str_repeat( '-', 92 ) . "\n";

foreach ( $doc['cases'] as $case ) {
	$name     = (string) $case['name'];
	$bindings = $case['bindings'] ?? array();

	if ( ! isset( $bindings[ ADAPTER ] ) ) {
		$na[] = $name;
		continue;
	}

	$b        = $bindings[ ADAPTER ];
	$expect   = (string) $case['expect']['blast_radius'];
	$scope    = isset( $b['trusted_scope'] ) ? (string) $b['trusted_scope'] : '';
	$envelope = Reeflex_Normalizer::normalize(
		(string) $b['ability'],
		(array) ( $b['input'] ?? array() ),
		'',      // trusted_verb
		null,    // approval_hold_id
		null,    // agent_override
		$scope
	);
	$got = (string) $envelope['axes']['blast_radius'];

	if ( $got === $expect ) {
		++$pass;
		printf( "%-44s %-11s %-11s PASS\n", $name, $expect, $got );
	} else {
		++$fail;
		printf( "%-44s %-11s %-11s FAIL\n", $name, $expect, $got );
		printf( "    ability=%s input=%s%s\n",
			$b['ability'],
			json_encode( $b['input'] ?? array() ),
			'' !== $scope ? " reeflex_scope=$scope" : ''
		);
		printf( "    given.target_shape=%s\n", (string) ( $case['given']['target_shape'] ?? '?' ) );
	}
}

echo str_repeat( '-', 92 ) . "\n";
printf(
	"SPEC §4.2 / %s: %d passed, %d failed, %d of %d cases exercised.\n",
	ADAPTER,
	$pass,
	$fail,
	$pass + $fail,
	count( $doc['cases'] )
);
if ( $na ) {
	printf( "NOT APPLICABLE to this adapter (%d): %s\n", count( $na ), implode( ', ', $na ) );
}

if ( 0 === $pass + $fail ) {
	fwrite( STDERR, "HARNESS ERROR: no case in the vector file binds to this adapter — "
		. "this harness would pass while asserting nothing.\n" );
	exit( 2 );
}

exit( $fail > 0 ? 1 : 0 );
