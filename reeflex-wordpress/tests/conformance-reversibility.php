<?php
/**
 * conformance-reversibility.php — runs reeflex-spec/conformance/reversibility.json
 * against the REAL Reeflex_Normalizer.
 *
 * SPEC §7 says an adapter MUST pass the conformance suite for the axes. For
 * `reversibility` there was no suite until RFX-164; this script is the
 * WordPress side of it, the sibling of dev-1's blast_radius runner.
 *
 * It needs NO core and NO network — it drives the normalizer in-process and
 * compares axes.reversibility against the vector file. That matters for the
 * gate: `wp-conformance` SKIPS without --core-url, and a harness that only ever
 * skips is a harness nothing runs.
 *
 * Usage:  php tests/conformance-reversibility.php
 * Exit:   0 all vectors pass, 1 any vector fails.
 *
 * @package ReeflexWordPress
 */

declare( strict_types=1 );

$adapter_dir = dirname( __DIR__ );
$repo_root   = dirname( $adapter_dir );
$vectors     = $repo_root . '/reeflex-spec/conformance/reversibility.json';

putenv( 'REEFLEX_HARNESS_TMP=' . sys_get_temp_dir() );
require $adapter_dir . '/tests/wp-stubs.php';

if ( ! defined( 'REEFLEX_ENV' ) )       { define( 'REEFLEX_ENV', 'production' ); }
if ( ! defined( 'REEFLEX_AUDIT_LOG' ) ) { define( 'REEFLEX_AUDIT_LOG', sys_get_temp_dir() . '/reeflex-reversibility-conformance.jsonl' ); }
if ( ! defined( 'REEFLEX_MODE' ) )      { define( 'REEFLEX_MODE', 'enforce' ); }

require $adapter_dir . '/reeflex-gate/class-reeflex-config.php';
require $adapter_dir . '/reeflex-gate/class-reeflex-normalizer.php';

echo str_repeat( '=', 100 ) . "\n";
echo "reeflex-wordpress reversibility conformance (SPEC §2 / RFX-164)\n";
echo str_repeat( '=', 100 ) . "\n";

if ( ! is_readable( $vectors ) ) {
	fwrite( STDERR, "FATAL: vector file not readable: $vectors\n" );
	exit( 1 );
}
$doc = json_decode( (string) file_get_contents( $vectors ), true );
if ( ! is_array( $doc ) || empty( $doc['cases'] ) ) {
	fwrite( STDERR, "FATAL: vector file has no cases: $vectors\n" );
	exit( 1 );
}

echo sprintf( "vectors: %s (%d cases)\n\n", $vectors, count( $doc['cases'] ) );

$pass = 0;
$fail = 0;
$skip = 0;
$contradictions = 0;

foreach ( $doc['cases'] as $case ) {
	$name = (string) ( $case['name'] ?? '(unnamed)' );

	if ( ! isset( $case['bindings']['wordpress'] ) ) {
		printf( "%-38s %s\n", $name, 'SKIP - no wordpress binding' );
		$skip++;
		continue;
	}

	$bind    = $case['bindings']['wordpress'];
	$ability = (string) ( $bind['ability'] ?? '' );
	$input   = is_array( $bind['input'] ?? null ) ? $bind['input'] : array();
	$want    = (string) ( $case['expect']['reversibility'] ?? '' );

	$env  = Reeflex_Normalizer::normalize( $ability, $input );
	$got  = (string) $env['axes']['reversibility'];
	$blast = (string) $env['axes']['blast_radius'];

	// Rule 2 of the vector file, checked on every case rather than only where
	// a case asserts it: nothing may be recoverable AND broad/systemic.
	if ( 'recoverable' === $got && in_array( $blast, array( 'broad', 'systemic' ), true ) ) {
		$contradictions++;
	}

	if ( $got === $want ) {
		printf( "%-38s PASS  %-13s (blast %s)\n", $name, $got, $blast );
		$pass++;
	} else {
		printf(
			"%-38s FAIL  want %-13s got %-13s (ability %s, blast %s)\n",
			$name,
			$want,
			$got,
			$ability,
			$blast
		);
		$fail++;
	}
}

echo "\n" . str_repeat( '-', 100 ) . "\n";
printf( "PASS %d   FAIL %d   SKIP %d\n", $pass, $fail, $skip );
printf(
	"self-contradictory envelopes (recoverable AND broad/systemic): %d\n",
	$contradictions
);
echo str_repeat( '-', 100 ) . "\n";

if ( $fail > 0 || $contradictions > 0 ) {
	echo "REVERSIBILITY CONFORMANCE FAILED\n";
	exit( 1 );
}
echo "ALL REVERSIBILITY VECTORS PASS\n";
exit( 0 );
