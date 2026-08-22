<?php
/**
 * repro-rfx131-blast-radius.php — RFX-131 reproduction, adapter side.
 *
 * Drives the REAL Reeflex_Normalizer::normalize() (WordPress stubbed via
 * tests/wp-stubs.php) over abilities that are, semantically, table-wide or
 * site-wide destruction — but whose NAMES do not contain any of the ten
 * SYSTEMIC_SEGMENTS or five BULK_SEGMENTS strings.
 *
 * It prints the resolved axes as JSON lines so the core-side half of the
 * reproduction (repro-rfx131-blast-radius.py) can feed the same envelopes to
 * `opa eval` against the shipped policy pack.
 *
 * No network. No WordPress install. Nothing live is touched.
 *
 * Usage:  php scripts/repro-rfx131-blast-radius.php  > /tmp/rfx131-envelopes.jsonl
 *
 * @package ReeflexWordPress
 */

declare( strict_types=1 );

$repo_root   = dirname( __DIR__ );
$adapter_dir = $repo_root . '/reeflex-wordpress';

putenv( 'REEFLEX_HARNESS_TMP=' . sys_get_temp_dir() );
require $adapter_dir . '/tests/wp-stubs.php';

if ( ! defined( 'REEFLEX_ENV' ) )       { define( 'REEFLEX_ENV', 'production' ); }
if ( ! defined( 'REEFLEX_AUDIT_LOG' ) ) { define( 'REEFLEX_AUDIT_LOG', sys_get_temp_dir() . '/reeflex-rfx131-audit.jsonl' ); }
if ( ! defined( 'REEFLEX_MODE' ) )      { define( 'REEFLEX_MODE', 'enforce' ); }

require $adapter_dir . '/reeflex-gate/class-reeflex-config.php';
require $adapter_dir . '/reeflex-gate/class-reeflex-normalizer.php';

/**
 * Each case: an ability whose real-world effect is stated in `effect`, the input
 * the agent supplies, and what a competent human auditor would call the blast
 * radius. `expect_honest` is NOT what the code does — it is the claim under test.
 */
$cases = array(
	// --- The ticket's own example -------------------------------------
	array(
		'name'          => 'truncate-postmeta',
		'ability'       => 'core/truncate-postmeta',
		'input'         => array(),
		'effect'        => 'TRUNCATE wp_postmeta — every meta row for every post on the site',
		'expect_honest' => 'systemic',
	),
	// --- Same effect, other names an ability author would plausibly pick
	array(
		'name'          => 'drop-table-users',
		'ability'       => 'db/drop-table',
		'input'         => array( 'table' => 'wp_users' ),
		'effect'        => 'DROP TABLE wp_users — schema change, removes every account',
		'expect_honest' => 'systemic',
	),
	array(
		'name'          => 'empty-trash',
		'ability'       => 'core/empty-trash',
		'input'         => array(),
		'effect'        => 'permanently deletes every trashed post/page/attachment',
		'expect_honest' => 'broad',
	),
	array(
		'name'          => 'flush-rewrite-rules',
		'ability'       => 'core/flush-rewrites',
		'input'         => array(),
		'effect'        => 'rewrites the site-wide permalink structure',
		'expect_honest' => 'systemic',
	),
	array(
		'name'          => 'wipe-users-table',
		'ability'       => 'core/wipe-users',
		'input'         => array(),
		'effect'        => 'deletes every WordPress user',
		'expect_honest' => 'systemic',
	),
	array(
		'name'          => 'deactivate-plugins',
		'ability'       => 'plugins/deactivate',
		'input'         => array(),
		'effect'        => 'no ids => WordPress deactivates the lot',
		'expect_honest' => 'broad',
	),
	// --- Controls: the names the substring list DOES catch ------------
	array(
		'name'          => 'CONTROL delete-all-users',
		'ability'       => 'core/delete-all-users',
		'input'         => array(),
		'effect'        => 'same as wipe-users, but the name says all-users',
		'expect_honest' => 'systemic',
	),
	array(
		'name'          => 'CONTROL bulk-delete-posts',
		'ability'       => 'posts/bulk-delete',
		'input'         => array(),
		'effect'        => 'the name says bulk',
		'expect_honest' => 'broad',
	),
	// --- The mirror image: name says systemic, effect is one row -------
	array(
		'name'          => 'MIRROR single row, alarming name',
		'ability'       => 'posts/delete-all-revisions-of-post',
		'input'         => array( 'ids' => array( 7 ) ),
		'effect'        => 'one post revision. The name contains "all-".',
		'expect_honest' => 'single',
	),
);

$rows = array();
foreach ( $cases as $case ) {
	$envelope = Reeflex_Normalizer::normalize( $case['ability'], $case['input'] );
	$rows[]   = array(
		'name'          => $case['name'],
		'ability'       => $case['ability'],
		'effect'        => $case['effect'],
		'expect_honest' => $case['expect_honest'],
		'got'           => $envelope['axes']['blast_radius'],
		'reversibility' => $envelope['axes']['reversibility'],
		'verb'          => $envelope['action']['verb'],
		'envelope'      => $envelope,
	);
}

// Human-readable table on stderr, machine-readable JSONL on stdout.
fwrite( STDERR, sprintf( "%-34s %-14s %-14s %-9s %s\n", 'CASE', 'HONEST', 'NORMALIZER', 'AGREE?', 'EFFECT' ) );
fwrite( STDERR, str_repeat( '-', 132 ) . "\n" );
$disagree = 0;
foreach ( $rows as $r ) {
	$agree = ( $r['expect_honest'] === $r['got'] );
	if ( ! $agree ) {
		++$disagree;
	}
	fwrite( STDERR, sprintf(
		"%-34s %-14s %-14s %-9s %s\n",
		$r['name'],
		$r['expect_honest'],
		$r['got'],
		$agree ? 'yes' : 'NO',
		$r['effect']
	) );
	echo json_encode( $r ) . "\n";
}
fwrite( STDERR, str_repeat( '-', 132 ) . "\n" );
fwrite( STDERR, sprintf( "%d of %d cases: the normalizer's blast_radius is not the honest one.\n", $disagree, count( $rows ) ) );
