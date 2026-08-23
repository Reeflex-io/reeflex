<?php
/**
 * conformance-decisions.php — runs reeflex-spec/conformance/decisions.json
 * against the REAL Reeflex_Normalizer and a LIVE reeflex-core (RFX-167).
 *
 * WHAT MAKES THIS DIFFERENT FROM ITS TWO SIBLINGS. conformance-blast-radius.php
 * and conformance-reversibility.php each assert ONE AXIS, in-process, with no
 * core. They have to: an axis is the adapter's output and nothing else. But R2
 * and R3 — the only two rules in the shipped pack that hold a destructive
 * action — are CONJUNCTIONS of both axes, so each per-axis suite can be fully
 * green while a production destruction is still answered `allow` with no human.
 * Scoring that needs the DECISION, so this harness needs a core, and it is
 * therefore wired into gate.py's live-core group rather than wp-spec-conformance.
 *
 * It never hand-writes an envelope: every one comes out of the real normalizer
 * through Reeflex_Normalizer::normalize(), exactly as in production.
 *
 * Usage:
 *   php tests/conformance-decisions.php [core_url]
 *     core_url defaults to http://127.0.0.1:8099
 *
 * Exit: 0 every row behaves as decisions.json records it
 *       1 a row does not — including a row that has SILENTLY CLOSED and must be
 *         promoted, which is a failure on purpose (RFX-158's convention)
 *       2 harness error, or a core that cannot score this corpus
 *
 * @package ReeflexWordPress
 */

declare( strict_types=1 );

$adapter_dir = dirname( __DIR__ );
$repo_root   = dirname( $adapter_dir );
$corpus_path = $repo_root . '/reeflex-spec/conformance/decisions.json';
$core_url    = $argv[1] ?? 'http://127.0.0.1:8099';

putenv( 'REEFLEX_HARNESS_TMP=' . sys_get_temp_dir() );
require $adapter_dir . '/tests/wp-stubs.php';

if ( ! defined( 'REEFLEX_CORE_URL' ) )  { define( 'REEFLEX_CORE_URL', $core_url ); }
if ( ! defined( 'REEFLEX_ENV' ) )       { define( 'REEFLEX_ENV', 'production' ); }
if ( ! defined( 'REEFLEX_AUDIT_LOG' ) ) { define( 'REEFLEX_AUDIT_LOG', sys_get_temp_dir() . '/reeflex-decision-conformance.jsonl' ); }
if ( ! defined( 'REEFLEX_MODE' ) )      { define( 'REEFLEX_MODE', 'enforce' ); }

require $adapter_dir . '/reeflex-gate/class-reeflex-config.php';
require $adapter_dir . '/reeflex-gate/class-reeflex-normalizer.php';

// ---------------------------------------------------------------------------
// Core transport. Deliberately plain curl rather than Reeflex_Core_Client: the
// client applies the adapter's own fail-closed/observe policy, and this harness
// must score what CORE ANSWERED, not what the adapter did about it.
// ---------------------------------------------------------------------------

/**
 * POST an envelope to /v1/decide.
 *
 * @param string $core_url Base URL of the live core.
 * @param array  $envelope Action Envelope.
 * @return array{decision:string,rule:string,http:int}
 */
function rfx_decide( string $core_url, array $envelope ): array {
	$ch = curl_init( rtrim( $core_url, '/' ) . '/v1/decide' );
	curl_setopt_array(
		$ch,
		array(
			CURLOPT_POST           => true,
			CURLOPT_POSTFIELDS     => (string) json_encode( $envelope ),
			CURLOPT_HTTPHEADER     => array( 'Content-Type: application/json' ),
			CURLOPT_RETURNTRANSFER => true,
			CURLOPT_TIMEOUT        => 30,
		)
	);
	$body = curl_exec( $ch );
	$http = (int) curl_getinfo( $ch, CURLINFO_HTTP_CODE );
	$err  = curl_error( $ch );
	curl_close( $ch );

	if ( false === $body ) {
		return array( 'decision' => 'TRANSPORT-ERROR', 'rule' => $err, 'http' => 0 );
	}
	$d = json_decode( (string) $body, true );
	if ( ! is_array( $d ) || ! isset( $d['decision'] ) ) {
		return array( 'decision' => 'TRANSPORT-ERROR', 'rule' => "http $http: " . substr( (string) $body, 0, 160 ), 'http' => $http );
	}
	return array(
		'decision' => (string) $d['decision'],
		'rule'     => (string) ( $d['rule'] ?? '' ),
		'http'     => $http,
	);
}

/** True when core's fully-qualified rule id ends in the short name the corpus records. */
function rfx_rule_is( string $got, string $want ): bool {
	if ( '' === $want ) {
		return true;
	}
	return $got === $want || str_ends_with( $got, '/' . $want );
}

/** Return $envelope with the named axes replaced. Values of 'undecided' are ignored. */
function rfx_with_axes( array $envelope, array $axes, array $only = array() ): array {
	foreach ( $axes as $axis => $value ) {
		if ( 'undecided' === $value ) {
			continue;
		}
		if ( array() !== $only && ! in_array( $axis, $only, true ) ) {
			continue;
		}
		$envelope['axes'][ $axis ] = $value;
	}
	return $envelope;
}

/**
 * Give an envelope its own session and its own nonce before it is scored.
 *
 * TWO REAL CONTROLS MADE THE FIRST DRAFT OF THIS HARNESS MEASURE NOTHING, and
 * both are worth stating rather than quietly working around:
 *
 * 1. REPLAY. Scoring one operation under substituted axes means POSTing four
 *    envelopes that differ only in `axes`. Reeflex_Normalizer::make_nonce()
 *    derives the nonce from (session, timestamp, ability, count) — none of
 *    which change — so core answered the second POST onwards with HTTP 400
 *    `replay: nonce already seen`. That is the replay guard working correctly;
 *    an operation re-scored under different axes is a different envelope and
 *    must carry a different nonce.
 *
 * 2. THE FRAGMENTATION LEDGER. R5 accumulates magnitude.count per session over
 *    a rolling window. Left on one session, a 45-entity row scored four times
 *    would cross the budget partway through the corpus and later rows would be
 *    answered by R5 rather than by the rule under test — a decision that is
 *    correct for the product and wrong for this instrument.
 *
 * So every POST is isolated. THE LIMIT THAT BUYS: this corpus scores
 * SINGLE-ACTION decisions (R1-R4) only. It says nothing about R5, by
 * construction, and a row here going green is not evidence about budgets.
 */
function rfx_isolate( array $envelope ): array {
	static $seq = 0;
	$seq++;
	$envelope['agent']['session_id'] = sprintf( 'rfx167_sess_%s_%d', bin2hex( random_bytes( 6 ) ), $seq );
	$envelope['meta']['nonce']       = bin2hex( random_bytes( 16 ) );
	return $envelope;
}

// ---------------------------------------------------------------------------
// Preconditions
// ---------------------------------------------------------------------------

echo str_repeat( '=', 108 ) . "\n";
echo "reeflex-wordpress DECISION conformance (RFX-167) — the conjunction, not the axis\n";
echo str_repeat( '=', 108 ) . "\n";

if ( ! is_readable( $corpus_path ) ) {
	fwrite( STDERR, "FATAL: corpus not readable: $corpus_path\n" );
	exit( 2 );
}
$corpus = json_decode( (string) file_get_contents( $corpus_path ), true );
if ( ! is_array( $corpus ) || empty( $corpus['cases'] ) ) {
	fwrite( STDERR, "FATAL: corpus has no cases: $corpus_path\n" );
	exit( 2 );
}

/*
 * CAN THIS CORE SCORE THE CORPUS AT ALL? Every `open` row's second assertion is
 * "substituting honest axes DOES produce the required decision" — which is
 * vacuous, and silently so, against a core whose pack has no R2/R3. Probe with a
 * synthetic envelope rather than with a corpus row, so the probe cannot be
 * satisfied by the very thing it is checking for (dev-1--048's instrument
 * defect, one round earlier: the presence probe used a row the fix created).
 */
$probe = Reeflex_Normalizer::normalize( 'probe/delete-things', array( 'ids' => range( 1, 45 ) ) );
$probe['axes']['reversibility'] = 'irreversible';
$probe['axes']['blast_radius']  = 'broad';
$probe['target']['environment'] = 'production';
$probe_result = rfx_decide( $core_url, rfx_isolate( $probe ) );

if ( 'TRANSPORT-ERROR' === $probe_result['decision'] ) {
	fwrite( STDERR, "FATAL: no live core at $core_url — {$probe_result['rule']}\n" );
	exit( 2 );
}
if ( 'require_approval' !== $probe_result['decision'] ) {
	fwrite(
		STDERR,
		sprintf(
			"FATAL: the core at %s does not carry R2 (irreversible+broad+production -> require_approval).\n"
			. "It answered %s / %s. This corpus scores DECISIONS; against a pack without R2 and R3\n"
			. "every `open` row would pass for the wrong reason. Refusing to print a verdict.\n",
			$core_url,
			$probe_result['decision'],
			$probe_result['rule']
		)
	);
	exit( 2 );
}

printf( "corpus: %s (%d cases)\n", $corpus_path, count( $corpus['cases'] ) );
printf( "core:   %s — R2 present (probe: %s / %s)\n", $core_url, $probe_result['decision'], $probe_result['rule'] );

/*
 * CROSS-CHECK AGAINST THE PER-AXIS VECTOR FILES. The whole point of this file is
 * that per-axis vectors are necessary and not sufficient, so its own `required
 * axes` must not drift away from them. Where a sibling file exists, every value
 * this corpus claims is checked against the case it cites. Where one does not
 * exist yet (the axis fixes are unmerged at the time of writing) that is PRINTED,
 * not passed over.
 */
$axis_files = array(
	'reversibility' => $repo_root . '/reeflex-spec/conformance/reversibility.json',
	'blast_radius'  => $repo_root . '/reeflex-spec/conformance/blast-radius.json',
);
$axis_expect  = array();
$xcheck_notes = array();
foreach ( $axis_files as $axis => $path ) {
	if ( ! is_readable( $path ) ) {
		$xcheck_notes[] = sprintf( 'NOT PRESENT AT THIS TIP: %s — %s cross-check SKIPPED', basename( $path ), $axis );
		continue;
	}
	$doc = json_decode( (string) file_get_contents( $path ), true );
	foreach ( (array) ( $doc['cases'] ?? array() ) as $c ) {
		if ( isset( $c['name'], $c['expect'][ $axis ] ) ) {
			$axis_expect[ $axis ][ (string) $c['name'] ] = (string) $c['expect'][ $axis ];
		}
	}
	$xcheck_notes[] = sprintf( 'present: %s (%d cases) — %s cross-check ON', basename( $path ), count( $axis_expect[ $axis ] ?? array() ), $axis );
}
foreach ( $xcheck_notes as $n ) {
	echo "        $n\n";
}
echo "\n";

// ---------------------------------------------------------------------------
// Score
// ---------------------------------------------------------------------------

$failures  = array();
$promote   = array();
$counts    = array( 'holds' => 0, 'open' => 0, 'no_rule' => 0 );
$xchecked  = 0;

foreach ( $corpus['cases'] as $case ) {
	$name   = (string) ( $case['name'] ?? '(unnamed)' );
	$status = (string) ( $case['status'] ?? '' );
	$bind   = $case['bindings']['wordpress'] ?? null;

	if ( ! is_array( $bind ) ) {
		printf( "%-38s SKIP  no wordpress binding\n", $name );
		continue;
	}

	$required   = (array) ( $case['required'] ?? array() );
	$want_dec   = (string) ( $required['decision'] ?? '' );
	$want_rule  = (string) ( $required['rule'] ?? '' );
	$want_axes  = (array) ( $required['axes'] ?? ( $case['honest_axes'] ?? array() ) );

	// -- the cited per-axis vectors must agree with what this file claims ----
	foreach ( (array) ( $case['axes_source'] ?? array() ) as $axis => $citation ) {
		if ( ! isset( $axis_expect[ $axis ] ) || ! is_string( $citation ) || false === strpos( $citation, '::' ) ) {
			continue;
		}
		$cited = substr( $citation, strpos( $citation, '::' ) + 2 );
		if ( ! isset( $axis_expect[ $axis ][ $cited ] ) ) {
			$failures[] = sprintf( '%s: axes_source cites %s, which is not a case in the %s vectors', $name, $citation, $axis );
			continue;
		}
		$xchecked++;
		if ( isset( $want_axes[ $axis ] ) && 'undecided' !== $want_axes[ $axis ]
			&& $axis_expect[ $axis ][ $cited ] !== $want_axes[ $axis ] ) {
			$failures[] = sprintf(
				'%s: this corpus claims %s=%s but %s says %s — the decision corpus has drifted from the axis vectors',
				$name, $axis, $want_axes[ $axis ], $citation, $axis_expect[ $axis ][ $cited ]
			);
		}
	}

	$envelope = Reeflex_Normalizer::normalize(
		(string) ( $bind['ability'] ?? '' ),
		is_array( $bind['input'] ?? null ) ? $bind['input'] : array()
	);
	$shipped = rfx_decide( $core_url, rfx_isolate( $envelope ) );
	if ( 'TRANSPORT-ERROR' === $shipped['decision'] ) {
		$failures[] = sprintf( '%s: %s', $name, $shipped['rule'] );
		continue;
	}

	$as_shipped_axes = sprintf( '%s/%s', $envelope['axes']['reversibility'], $envelope['axes']['blast_radius'] );

	if ( 'holds' === $status ) {
		$counts['holds']++;
		$ok = ( $shipped['decision'] === $want_dec ) && rfx_rule_is( $shipped['rule'], $want_rule );
		printf(
			"[holds  ] %-38s %-17s %-30s %s\n",
			$name, $shipped['decision'], $shipped['rule'], $ok ? 'OK' : 'REGRESSION'
		);
		if ( ! $ok ) {
			$failures[] = sprintf(
				'%s: this row HELD and no longer does — want %s/%s, got %s/%s (adapter axes %s)',
				$name, $want_dec, $want_rule, $shipped['decision'], $shipped['rule'], $as_shipped_axes
			);
		}
		continue;
	}

	if ( 'no_rule' === $status ) {
		$counts['no_rule']++;
		$honest     = rfx_decide( $core_url, rfx_isolate( rfx_with_axes( $envelope, $want_axes ) ) );
		$still_none = ( 'allow' === $shipped['decision'] && 'allow' === $honest['decision'] );
		printf(
			"[no_rule] %-38s %-17s honest-axes: %-17s %s\n",
			$name, $shipped['decision'], $honest['decision'], $still_none ? 'no rule reaches it' : 'A RULE NOW COVERS IT'
		);
		if ( ! $still_none ) {
			$promote[] = sprintf(
				'%s: recorded as no_rule (%s), but the canon now answers %s as shipped / %s with honest axes. '
				. 'Rewrite the row as `open` or `holds` and say which rule closed it.',
				$name, (string) ( $case['open_ticket'] ?? '' ), $shipped['decision'], $honest['decision']
			);
		}
		continue;
	}

	if ( 'open' !== $status ) {
		$failures[] = sprintf( '%s: unknown status "%s"', $name, $status );
		continue;
	}

	// -- open ---------------------------------------------------------------
	$counts['open']++;
	$honest     = rfx_decide( $core_url, rfx_isolate( rfx_with_axes( $envelope, $want_axes ) ) );
	$rev_only   = rfx_decide( $core_url, rfx_isolate( rfx_with_axes( $envelope, $want_axes, array( 'reversibility' ) ) ) );
	$blast_only = rfx_decide( $core_url, rfx_isolate( rfx_with_axes( $envelope, $want_axes, array( 'blast_radius' ) ) ) );

	$closes_on = 'neither';
	if ( $honest['decision'] === $want_dec ) {
		$rev_alone   = ( $rev_only['decision'] === $want_dec );
		$blast_alone = ( $blast_only['decision'] === $want_dec );
		if ( $rev_alone && $blast_alone ) {
			$closes_on = 'either';
		} elseif ( $rev_alone ) {
			$closes_on = 'reversibility';
		} elseif ( $blast_alone ) {
			$closes_on = 'blast_radius';
		} else {
			$closes_on = 'both';
		}
	}
	$want_closes_on = (string) ( $case['closes_on'] ?? '' );

	printf(
		"[open   ] %-38s %-17s (adapter %s)\n", $name, $shipped['decision'], $as_shipped_axes
	);
	printf(
		"           %-38s reversibility alone: %-17s blast_radius alone: %-17s both: %s\n",
		'', $rev_only['decision'], $blast_only['decision'], $honest['decision']
	);

	// (a) has it silently closed?
	$has_closed = ( $shipped['decision'] === $want_dec && rfx_rule_is( $shipped['rule'], $want_rule ) );
	if ( $has_closed ) {
		$promote[] = sprintf(
			'%s: THIS ROW NOW CLOSES (%s / %s, adapter axes %s). Promote it to status "holds" and delete the '
			. 'open_ticket/closes_on exclusion — a gap recorded after it was fixed is a claim nobody re-checked.',
			$name, $shipped['decision'], $shipped['rule'], $as_shipped_axes
		);
	}

	// (b) does the canon deliver once the axes are honest?
	if ( $honest['decision'] !== $want_dec || ! rfx_rule_is( $honest['rule'], $want_rule ) ) {
		$failures[] = sprintf(
			'%s: with HONEST axes (%s) the canon still answers %s / %s, not %s / %s. This row is not an adapter '
			. 'gap — either the required decision is wrong or a rule is missing.',
			$name,
			json_encode( $want_axes ),
			$honest['decision'],
			$honest['rule'],
			$want_dec,
			$want_rule
		);
	}

	/*
	 * (c) is the conjunction still the reason?
	 *
	 * `closes_on` is NOT a property of the row alone. It is a property of the row
	 * ON A GIVEN ADAPTER, because "substitute reversibility only" means something
	 * different depending on what the adapter already reports for the other axis.
	 * Measured: on origin/main `user/all` closes on reversibility alone, because
	 * main's adapter already prices it systemic; from a doubly-understated
	 * baseline it needs both. Neither answer is wrong and comparing them across
	 * trees is how a fix stops looking like a no-op.
	 *
	 * So the corpus records the adapter axes it measured `closes_on` against, and
	 * the assertion only runs when this tree's adapter still reports them. When it
	 * does not, that is an ADAPTER IMPROVEMENT (or regression) and the corpus must
	 * be re-recorded deliberately — reported as a failure with the new numbers in
	 * hand, never passed over.
	 */
	$want_shipped_axes = (string) ( $case['as_shipped_axes'] ?? '' );
	if ( '' === $want_shipped_axes ) {
		$failures[] = sprintf( '%s: an `open` row must record as_shipped_axes; it is what makes closes_on scoreable', $name );
	} elseif ( $as_shipped_axes !== $want_shipped_axes && ! $has_closed ) {
		// When the row has already closed, "promote it" is the whole instruction
		// and re-recording as_shipped_axes for a row that is about to stop being
		// `open` would be noise. Only report the move while the row stays open —
		// which is the interesting case: the adapter improved and the row DIDN'T.
		$promote[] = sprintf(
			'%s: THE ADAPTER MOVED. Corpus recorded axes %s; this tree reports %s. On this tree the row is reached by '
			. '"%s" (reversibility alone -> %s, blast_radius alone -> %s, both -> %s). Re-record as_shipped_axes and '
			. 'closes_on against this adapter and name the change that moved it.',
			$name, $want_shipped_axes, $as_shipped_axes, $closes_on,
			$rev_only['decision'], $blast_only['decision'], $honest['decision']
		);
	} elseif ( '' !== $want_closes_on && $closes_on !== $want_closes_on ) {
		$failures[] = sprintf(
			'%s: on the SAME adapter axes (%s), closes_on was recorded as "%s" and measures "%s" (reversibility alone '
			. '-> %s, blast_radius alone -> %s, both -> %s). The adapter did not move, so the canon did.',
			$name, $as_shipped_axes, $want_closes_on, $closes_on,
			$rev_only['decision'], $blast_only['decision'], $honest['decision']
		);
	}
}

// ---------------------------------------------------------------------------
// Verdict
// ---------------------------------------------------------------------------

echo "\n" . str_repeat( '-', 108 ) . "\n";
printf(
	"rows: %d holds, %d open, %d no_rule    per-axis values cross-checked: %d\n",
	$counts['holds'], $counts['open'], $counts['no_rule'], $xchecked
);
if ( 0 === $xchecked ) {
	echo "NOTE: 0 values cross-checked — the per-axis vector files are not in this tree.\n";
}
echo str_repeat( '-', 108 ) . "\n";

foreach ( $promote as $p ) {
	echo "PROMOTE  $p\n";
}
foreach ( $failures as $f ) {
	echo "FAIL     $f\n";
}

if ( $promote || $failures ) {
	printf( "\nDECISION CONFORMANCE FAILED (%d to promote, %d failures)\n", count( $promote ), count( $failures ) );
	exit( 1 );
}
echo "\nALL DECISION VECTORS BEHAVE AS RECORDED\n";
exit( 0 );
