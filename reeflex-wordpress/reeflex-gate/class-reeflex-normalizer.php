<?php
/**
 * Reeflex Normalizer — maps a WordPress ability into an Action Envelope.
 *
 * This is the hard, valuable part of the adapter: translating a backend-
 * specific operation into the three-axis universal envelope that reeflex-core
 * evaluates with deterministic Rego rules.
 *
 * Governing principle: NO agent-controlled input may ever lower risk or
 * grant allow. When unknown → most-restrictive.
 *
 * Axis mapping rationale (mirrors adapter.py docstring, adapted for WordPress):
 *
 *   verb (segment-based, danger-priority order — P1-7 / NEW-3 monotonic-danger):
 *     Ability name is split on '/', '-', '_' into segments. Verb families are
 *     checked most-dangerous-first so a name like 'fetch-and-delete' resolves
 *     to 'delete', not 'read'. Trusted registration-time override: if $args
 *     carries a 'reeflex_verb' key (set by the ability author), the trusted verb
 *     is used ONLY if it is at least as dangerous as the heuristic — it may only
 *     raise or equal danger, never lower it (NEW-3). If the trusted verb would
 *     downgrade danger, the heuristic verb is used instead and a warning is logged.
 *
 *     danger rank (lower = more dangerous): delete=0, transact=1, execute=2,
 *     emit=3, update=4, create=5, read=6, default=2 (execute, conservative)
 *
 *     delete → transact → execute → emit → update → create → read → execute (default)
 *
 *   reversibility:
 *     force/permanent/hard-delete/bypass-trash  -> irreversible
 *     soft-delete / trash                       -> recoverable
 *     bulk delete (count ≥ 20)                  -> irreversible (mirrors adapter.py)
 *     simple update / create                    -> recoverable
 *     emit (publish/email/webhook to public)    -> irreversible
 *     read                                      -> reversible
 *     transact/execute                          -> irreversible
 *     unknown                                   -> irreversible (SPEC §2 default)
 *
 *   NOTE on annotations (P1-3): ability annotations (readonly, destructive)
 *   are a property of ability REGISTRATION, not call-time input. They are
 *   NOT read from $input here. When registration-arg annotations are plumbed
 *   through, read them from $args in wrap_permission_callback and pass them
 *   as a trusted parameter — never from agent-supplied input.
 *
 *   blast_radius:
 *     systemic signals in name               -> systemic (overrides count)
 *     bulk signals in name (bulk/batch/-all) -> broad (overrides count)
 *     ids array length > 20                  -> broad
 *     ids array length > 1                   -> scoped
 *     ids array length == 1                  -> single
 *     no ids, no bulk signal                 -> single
 *     agent-supplied 'count' may RAISE risk but never lower it (P1-6):
 *       used only when ids is absent; clamped so it cannot assert 'single'
 *       for a bulk-signalling ability.
 *
 *   externality:
 *     emit verb / outbound signals           -> outbound
 *     everything else                        -> internal
 *     physical (none in WP)                  -> n/a (never produced)
 *
 *   approval (P0-1):
 *     Always emitted as present:false/by:null/role:null in v0.1.
 *     No agent-controlled approval path exists yet — holds are terminal.
 *     See normalize() docblock for the full upgrade path design.
 *
 * @package ReeflexWordPress
 * @since   0.1.0
 */

declare( strict_types=1 );

defined( 'ABSPATH' ) || exit;

/**
 * Produces a valid, signed Action Envelope from a WordPress ability name and input array.
 *
 * Called once per ability execution, on the hot path. Kept stateless (pure
 * function on inputs) so it is trivially testable without a WordPress
 * environment beyond the defined constants.
 */
final class Reeflex_Normalizer {

	// ------------------------------------------------------------------
	// Verb segment tables (P1-7: danger-priority order, segment matching).
	// ------------------------------------------------------------------

	/**
	 * Verb families checked in most-dangerous-first order.
	 *
	 * Each family is an array of lowercase segments. The ability name is split
	 * on '/', '-', '_' and the first family with ANY matching segment wins.
	 * This prevents substring collisions ('thread' matching 'read', 'budget'
	 * matching 'get', 'fetch-and-delete' mapping to 'read' instead of 'delete').
	 *
	 * Order: delete → transact → execute → emit → update → create → read
	 * Default (no match): execute (conservative).
	 *
	 * @var array<string,array<int,string>>  verb => segments
	 */
	private const VERB_SEGMENTS = array(
		'delete'   => array( 'delete', 'trash', 'remove', 'purge', 'destroy', 'wipe' ),
		'transact' => array( 'pay', 'refund', 'charge', 'invoice', 'payment', 'transaction' ),
		'execute'  => array( 'run', 'trigger', 'deploy', 'execute', 'exec', 'invoke', 'dispatch' ),
		'emit'     => array( 'publish', 'send', 'email', 'notify', 'webhook', 'broadcast', 'mail' ),
		'update'   => array( 'update', 'edit', 'set', 'modify', 'patch', 'reset', 'restore', 'change', 'move', 'rename', 'assign', 'role', 'approve', 'reject', 'activate', 'deactivate' ),
		'create'   => array( 'create', 'add', 'insert', 'upload', 'import', 'generate', 'clone', 'duplicate', 'register', 'install' ),
		'read'     => array( 'get', 'list', 'read', 'query', 'fetch', 'search', 'find', 'view', 'show', 'count', 'check', 'export', 'download' ),
	);

	/**
	 * Ability name segments (lowercase) that imply outbound externality.
	 *
	 * @var array<int,string>
	 */
	private const OUTBOUND_SEGMENTS = array(
		'publish', 'send', 'email', 'notify', 'webhook', 'broadcast', 'mail', 'outbound', 'api',
	);

	/**
	 * Ability name segments (lowercase) that imply a systemic blast radius.
	 * Overrides count entirely.
	 *
	 * @var array<int,string>
	 */
	private const SYSTEMIC_SEGMENTS = array(
		'all-users', 'all-options', 'site-wide', 'reset-all', 'purge-all',
		'allusers', 'alloptions', 'sitewide', 'resetall', 'purgeall',
	);

	/**
	 * Ability name segments (lowercase) that imply a bulk (broad) blast radius.
	 * Overrides count; cannot be lowered by an absent ids array.
	 *
	 * @var array<int,string>
	 */
	private const BULK_SEGMENTS = array(
		'bulk', 'batch', 'mass', 'every', 'all',
	);

	// ------------------------------------------------------------------
	// Public entry point
	// ------------------------------------------------------------------

	/**
	 * Normalize a WordPress ability call into an Action Envelope.
	 *
	 * Approval (P0-1 — v0.1 behaviour):
	 *   approval.present is always false in v0.1. No trusted approval source
	 *   exists yet: the agent controls its own input, so any approval signal
	 *   from the input array is worthless. require_approval decisions are
	 *   TERMINAL for now — the action is held and the operator must manually
	 *   re-submit or build the approval UI.
	 *
	 *   Upgrade path (ROADMAP — do NOT implement until the server-side flow is built):
	 *     1. On require_approval, store a hold record in the WP options table
	 *        keyed by the envelope nonce, with HMAC-signed approval token.
	 *     2. The approval UI (admin screen or Slack bot) verifies the token,
	 *        consumes (deletes) the hold record, and writes a signed approval
	 *        receipt back to WP options.
	 *     3. The ORIGINAL caller (agent) is notified and re-submits the
	 *        original envelope. The adapter retrieves and verifies the receipt
	 *        (server-to-server, never from agent-controlled input), then sets
	 *        approval.present=true in the re-submitted envelope.
	 *     4. Core sees approval.present=true + the same nonce → allow.
	 *     5. Receipt is consumed (one-time-use) immediately after verification.
	 *   Until this flow is built, do NOT read any approval signal from $input.
	 *
	 * @param string $ability         Namespaced ability name, e.g. 'core/delete-post'.
	 * @param array  $input           Input array passed to the ability's callback.
	 * @param string $trusted_verb    Optional: registration-time verb override from $args
	 *                                (set by ability author via reeflex_verb key). Empty = auto.
	 * @return array  A fully-populated Action Envelope (SPEC §2).
	 */
	public static function normalize(
		string $ability,
		array $input,
		string $trusted_verb = ''
	): array {
		$ability_lower    = strtolower( $ability );
		$ability_segments = self::split_segments( $ability_lower );

		// -- VERB ----------------------------------------------------------
		// Heuristic verb from ability name segments (always computed first).
		$heuristic_verb = self::map_verb( $ability_segments );

		// Trusted registration-time override: may only raise or equal danger (NEW-3).
		// If the trusted verb would lower danger (higher rank number), ignore it and
		// use the heuristic, logging a warning for the ability author.
		if ( '' !== $trusted_verb && self::is_valid_verb( $trusted_verb ) ) {
			$trusted_rank   = self::verb_danger_rank( $trusted_verb );
			$heuristic_rank = self::verb_danger_rank( $heuristic_verb );
			if ( $trusted_rank <= $heuristic_rank ) {
				// trusted verb is equally or more dangerous: use it.
				$verb = $trusted_verb;
			} else {
				// trusted verb would downgrade danger: reject override (NEW-3).
				$verb = $heuristic_verb;
				error_log( sprintf(
					'[reeflex] NEW-3: trusted verb "%s" (rank %d) would downgrade heuristic ' .
					'"%s" (rank %d) for ability "%s" — trusted verb IGNORED; using heuristic.',
					$trusted_verb,
					$trusted_rank,
					$heuristic_verb,
					$heuristic_rank,
					$ability
				) );
			}
		} else {
			$verb = $heuristic_verb;
		}

		// -- COUNT (magnitude) --------------------------------------------
		$count = self::resolve_count( $input );

		// -- AXES ---------------------------------------------------------
		$reversibility = self::resolve_reversibility( $ability_lower, $ability_segments, $verb, $input, $count );
		$blast_radius  = self::resolve_blast_radius( $ability_lower, $ability_segments, $input, $count );
		$externality   = self::resolve_externality( $ability_segments, $verb );

		// -- TARGET -------------------------------------------------------
		$kind = self::infer_kind( $ability_segments );
		$ref  = self::infer_ref( $input, $count, $kind );

		// -- AGENT --------------------------------------------------------
		$user         = wp_get_current_user();
		// P2-12: use user ID (integer), not user_login (PII).
		$on_behalf_of = ( $user && $user->exists() && $user->ID )
			? 'user:' . $user->ID
			: 'user:anonymous';

		$session_id = self::resolve_session_id( $user );

		// -- META (timestamp, nonce, stub signature) ----------------------
		$timestamp = gmdate( 'Y-m-d\TH:i:s\Z' );
		$nonce     = self::make_nonce( $session_id, $timestamp, $ability, $count );
		// Stub signature: full ed25519 signing is roadmapped pending Vault key
		// management integration (see SPEC §6 implementation-status note).
		// Upgrade path: replace this stub with Vault-signed ed25519 once the
		// key management path is implemented in reeflex-core.
		$signature = 'ed25519:stub:' . substr( $nonce, 0, 16 );

		// -- SANITIZED PARAMS (strip internal Reeflex keys) ---------------
		// _reeflex_approved / _reeflex_approval_token are stripped so they
		// never reach the envelope or reeflex-core (P0-1).
		$params = $input;
		unset( $params['_reeflex_approved'], $params['_reeflex_approval_token'] );

		// -- APPROVAL (P0-1: always false in v0.1) ------------------------
		// No agent-controlled approval path. See normalize() docblock for
		// the roadmap design of the server-side approval flow.
		$approval = array(
			'present' => false,
			'by'      => null,
			'role'    => null,
		);

		return array(
			'reeflex_version' => '0.1',
			'agent'           => array(
				'id'           => Reeflex_Config::agent_id(),
				'on_behalf_of' => $on_behalf_of,
				'session_id'   => $session_id,
			),
			'action'          => array(
				'namespace' => 'wordpress',
				'verb'      => $verb,
				'ability'   => $ability,
			),
			'target'          => array(
				'kind'        => $kind,
				'ref'         => $ref,
				'environment' => Reeflex_Config::env(),
			),
			'params'          => $params,
			'magnitude'       => array(
				'count' => $count,
			),
			'axes'            => array(
				'reversibility' => $reversibility,
				'blast_radius'  => $blast_radius,
				'externality'   => $externality,
			),
			'approval'        => $approval,
			'trajectory_ref'  => null,   // optional in v0.1; richer drift analysis = roadmap
			'context'         => array(),
			'meta'            => array(
				'timestamp' => $timestamp,
				'nonce'     => $nonce,
				'signature' => $signature,
			),
		);
	}

	// ------------------------------------------------------------------
	// Verb mapping (P1-7: segment-based, danger-priority)
	// ------------------------------------------------------------------

	/**
	 * Split a lowercase ability name into segments on '/', '-', '_'.
	 *
	 * e.g. 'core/delete-post' → ['core', 'delete', 'post']
	 *
	 * @param string $ability_lower
	 * @return array<int,string>
	 */
	private static function split_segments( string $ability_lower ): array {
		return array_filter(
			preg_split( '/[\/\-_]/', $ability_lower ) ?: array(),
			static function ( string $s ): bool { return '' !== $s; }
		);
	}

	/**
	 * Map ability segments to a normalized SPEC §3 verb.
	 *
	 * Checks verb families in most-dangerous-first order (delete → transact →
	 * execute → emit → update → create → read). The first family that contains
	 * ANY segment from the ability name wins.
	 *
	 * Conservative default: 'execute' (never 'read' on unknown).
	 *
	 * @param array<int,string> $segments  Lowercased segments from the ability name.
	 * @return string  One of: read|create|update|delete|execute|transact|emit
	 */
	private static function map_verb( array $segments ): string {
		foreach ( self::VERB_SEGMENTS as $verb => $verb_tokens ) {
			foreach ( $segments as $seg ) {
				if ( in_array( $seg, $verb_tokens, true ) ) {
					return $verb;
				}
			}
		}
		// No segment matched any family: conservative execute.
		return 'execute';
	}

	/**
	 * Check that a trusted verb override is one of the seven valid verbs.
	 *
	 * @param string $verb
	 * @return bool
	 */
	private static function is_valid_verb( string $verb ): bool {
		return in_array(
			$verb,
			array( 'read', 'create', 'update', 'delete', 'execute', 'transact', 'emit' ),
			true
		);
	}

	/**
	 * Return the danger rank of a verb (NEW-3: monotonic-danger enforcement).
	 *
	 * Lower number = MORE dangerous.  Used to enforce that a trusted registration-
	 * time verb override may only raise or equal danger vs the heuristic — never
	 * lower it.  If the trusted verb's rank is higher (less dangerous) than the
	 * heuristic verb's rank, the override is rejected and the heuristic is used.
	 *
	 * Rank table:
	 *   delete   = 0  (most dangerous: data is destroyed)
	 *   transact = 1  (financial / external side-effects, often irreversible)
	 *   execute  = 2  (arbitrary code / side-effects; used as conservative default)
	 *   emit     = 3  (outbound: message sent, cannot be un-sent)
	 *   update   = 4  (mutations, but typically reversible)
	 *   create   = 5  (additive; lower risk than mutation)
	 *   read     = 6  (least dangerous: no state change)
	 *   unknown  = 2  (conservative: execute-level danger)
	 *
	 * @param string $verb  One of the seven SPEC §3 verbs (or any string).
	 * @return int  Danger rank: 0 = most dangerous, 6 = least dangerous.
	 */
	private static function verb_danger_rank( string $verb ): int {
		$ranks = array(
			'delete'   => 0,
			'transact' => 1,
			'execute'  => 2,
			'emit'     => 3,
			'update'   => 4,
			'create'   => 5,
			'read'     => 6,
		);
		// Unknown verb: conservative default (execute = rank 2).
		return $ranks[ $verb ] ?? 2;
	}

	// ------------------------------------------------------------------
	// Count / magnitude (P1-6: ids-first, agent count may only raise risk)
	// ------------------------------------------------------------------

	/**
	 * Derive the count of affected entities from input.
	 *
	 * Trust hierarchy (P1-6):
	 *   1. input['ids'] array length — structurally verifiable.
	 *   2. input['count'] — agent-supplied; accepted ONLY to raise risk, never
	 *      to assert a lower bound. Its only effect: if ids is absent and
	 *      'count' > 1, it may push blast_radius to scoped/broad. It can never
	 *      reduce a broad signal to single.
	 *   3. Fallback: 1.
	 *
	 * NOTE: policy authors MUST NOT rely solely on magnitude.count when ids is
	 * absent, because an agent may omit ids to force count=1. Blast-radius
	 * signals from the ability name (bulk/batch/-all) provide the reliable
	 * broad signal regardless of count.
	 *
	 * SPEC §2: magnitude.count MUST be an int >= 1.
	 *
	 * @param array $input
	 * @return int  Always >= 1.
	 */
	private static function resolve_count( array $input ): int {
		if ( isset( $input['ids'] ) && is_array( $input['ids'] ) ) {
			return max( 1, count( $input['ids'] ) );
		}
		// Agent-supplied count: accept as-is for magnitude, but blast_radius
		// resolution cross-checks bulk signals independently (resolve_blast_radius).
		if ( isset( $input['count'] ) && is_numeric( $input['count'] ) ) {
			return max( 1, (int) $input['count'] );
		}
		return 1;
	}

	// ------------------------------------------------------------------
	// Axis: reversibility
	// ------------------------------------------------------------------

	/**
	 * Estimate whether the action is reversible, recoverable, or irreversible.
	 *
	 * Conservative defaults (SPEC §2): when in doubt, choose irreversible.
	 *
	 * Annotation note (P1-3):
	 *   Ability annotations (readonly, destructive) are read from registration
	 *   args, not from $input. v0.1 relies solely on ability-name heuristics +
	 *   conservative defaults. When registration-arg annotations are plumbed
	 *   through the adapter, pass them as a trusted parameter from
	 *   wrap_permission_callback's $args capture — never from $input.
	 *
	 * Decision tree:
	 *   1. Emit verb → irreversible (message sent, data public).
	 *   2. Explicit hard-delete signals in ability name or input → irreversible.
	 *   3. Trash in ability name → recoverable.
	 *   4. Delete verb with count ≥ 20 → irreversible (mirrors adapter.py large-bulk rule).
	 *   5. Delete verb (all other cases) → recoverable (WP trash default).
	 *   6. Read → reversible.
	 *   7. Create/update → recoverable.
	 *   8. Transact/execute → irreversible.
	 *   9. Unknown → irreversible (SPEC §2 safe default).
	 *
	 * @param string            $ability_lower
	 * @param array<int,string> $ability_segments
	 * @param string            $verb
	 * @param array             $input
	 * @param int               $count
	 * @return string  'reversible'|'recoverable'|'irreversible'
	 */
	private static function resolve_reversibility(
		string $ability_lower,
		array $ability_segments,
		string $verb,
		array $input,
		int $count
	): string {
		// 1. Emits always reach the outside world: irreversible once sent/published.
		if ( 'emit' === $verb ) {
			return 'irreversible';
		}

		// 2. Explicit hard-delete signals in input or ability name.
		//    'bypass-trash' added as a signal (P3).
		$force_delete = ! empty( $input['force_delete'] ) || ! empty( $input['force'] );
		$has_hard_signal = $force_delete
			|| false !== strpos( $ability_lower, 'permanent' )
			|| false !== strpos( $ability_lower, 'hard-delete' )
			|| false !== strpos( $ability_lower, 'force-delete' )
			|| false !== strpos( $ability_lower, 'bypass-trash' )
			|| false !== strpos( $ability_lower, 'purge' );

		if ( $has_hard_signal ) {
			return 'irreversible';
		}

		switch ( $verb ) {
			case 'read':
				return 'reversible';

			case 'create':
			case 'update':
				// Updates can be reverted by another update; creates can be deleted.
				return 'recoverable';

			case 'delete':
				// Soft-delete / trash is recoverable.
				if ( false !== strpos( $ability_lower, 'trash' ) ) {
					return 'recoverable';
				}
				// Large bulk delete treated as irreversible (mirrors adapter.py:
				// "bulk delete >= 20 -> irreversible (treat large bulk as unrecoverable)").
				if ( $count >= 20 ) {
					return 'irreversible';
				}
				// Generic delete without hard signals and small count -> recoverable.
				return 'recoverable';

			case 'transact':
			case 'execute':
				// Payments and arbitrary executions: unknown outcome → irreversible.
				return 'irreversible';

			default:
				// SPEC §2: unknown reversibility → irreversible.
				return 'irreversible';
		}
	}

	// ------------------------------------------------------------------
	// Axis: blast_radius (P1-6)
	// ------------------------------------------------------------------

	/**
	 * Estimate how many entities are affected.
	 *
	 * Resolution order (most-restrictive wins; P1-6):
	 *   1. Systemic signals in ability name → systemic (overrides everything).
	 *   2. Bulk signals in ability name (bulk/batch/-all/all-/every/mass) → broad
	 *      (overrides agent-supplied count; cannot be lowered).
	 *   3. ids array present → use its length: >20=broad, >1=scoped, 1=single.
	 *   4. No ids, no bulk signal, agent-supplied count:
	 *      - count > 20 → broad
	 *      - count > 1  → scoped
	 *      - count == 1 → single (accepted here because no conflicting bulk signal)
	 *   5. Fallback: single.
	 *
	 * @param string            $ability_lower
	 * @param array<int,string> $ability_segments
	 * @param array             $input
	 * @param int               $count
	 * @return string  'single'|'scoped'|'broad'|'systemic'
	 */
	private static function resolve_blast_radius(
		string $ability_lower,
		array $ability_segments,
		array $input,
		int $count
	): string {
		// 1. Systemic signals: whole site / all users / all options.
		foreach ( self::SYSTEMIC_SEGMENTS as $signal ) {
			if ( false !== strpos( $ability_lower, $signal ) ) {
				return 'systemic';
			}
		}

		// 2. Bulk signals in ability name → always broad, regardless of count.
		foreach ( self::BULK_SEGMENTS as $bulk_seg ) {
			if ( in_array( $bulk_seg, $ability_segments, true ) ) {
				return 'broad';
			}
		}
		// Also catch hyphenated bulk patterns ('-all', 'all-') not caught by segment split.
		if (
			false !== strpos( $ability_lower, '-all' ) ||
			false !== strpos( $ability_lower, 'all-' )
		) {
			return 'broad';
		}

		// 3. ids array length is the most trustworthy count signal.
		if ( isset( $input['ids'] ) && is_array( $input['ids'] ) ) {
			$ids_count = count( $input['ids'] );
			if ( $ids_count > 20 ) {
				return 'broad';
			}
			if ( $ids_count > 1 ) {
				return 'scoped';
			}
			return 'single';
		}

		// 4. No ids array: use $count (which may come from agent-supplied 'count').
		//    Agent count may raise risk but never lower it.  At this point there is
		//    no conflicting bulk signal, so 'single' is acceptable when count == 1.
		if ( $count > 20 ) {
			return 'broad';
		}
		if ( $count > 1 ) {
			return 'scoped';
		}
		return 'single';
	}

	// ------------------------------------------------------------------
	// Axis: externality
	// ------------------------------------------------------------------

	/**
	 * Determine whether the action reaches beyond the controlled system.
	 *
	 * outbound: emit verb or ability contains outbound segment.
	 * internal: all other WordPress operations.
	 * physical: not produced (WordPress has no SCADA/robotics operations).
	 *
	 * @param array<int,string> $ability_segments
	 * @param string            $verb
	 * @return string  'internal'|'outbound'
	 */
	private static function resolve_externality( array $ability_segments, string $verb ): string {
		if ( 'emit' === $verb ) {
			return 'outbound';
		}
		foreach ( $ability_segments as $seg ) {
			if ( in_array( $seg, self::OUTBOUND_SEGMENTS, true ) ) {
				return 'outbound';
			}
		}
		return 'internal';
	}

	// ------------------------------------------------------------------
	// Target kind / ref
	// ------------------------------------------------------------------

	/**
	 * Best-effort target kind from the ability name segments.
	 *
	 * Falls back to 'resource' when unrecognized.
	 *
	 * @param array<int,string> $ability_segments
	 * @return string
	 */
	private static function infer_kind( array $ability_segments ): string {
		$kind_map = array(
			'post'    => 'post',
			'page'    => 'page',
			'comment' => 'comment',
			'option'  => 'option',
			'user'    => 'user',
			'media'   => 'media',
			'term'    => 'term',
			'plugin'  => 'plugin',
			'theme'   => 'theme',
			'menu'    => 'menu',
		);
		foreach ( $kind_map as $token => $kind ) {
			if ( in_array( $token, $ability_segments, true ) ) {
				return $kind;
			}
		}
		return 'resource';
	}

	/**
	 * Build a stable target.ref when count == 1 and an id is known.
	 *
	 * Returns null for bulk operations (ref would be ambiguous).
	 *
	 * @param array  $input
	 * @param int    $count
	 * @param string $kind
	 * @return string|null
	 */
	private static function infer_ref( array $input, int $count, string $kind ): ?string {
		if ( 1 !== $count ) {
			return null;
		}

		// ids array with one entry.
		if ( isset( $input['ids'] ) && is_array( $input['ids'] ) && 1 === count( $input['ids'] ) ) {
			$id = reset( $input['ids'] );
			if ( is_numeric( $id ) ) {
				return $kind . ':' . (int) $id;
			}
		}

		// Scalar id / post_id / user_id.
		foreach ( array( 'id', 'post_id', 'user_id', 'comment_id', 'term_id', 'object_id' ) as $key ) {
			if ( isset( $input[ $key ] ) && is_numeric( $input[ $key ] ) ) {
				return $kind . ':' . (int) $input[ $key ];
			}
		}

		return null;
	}

	// ------------------------------------------------------------------
	// Session ID (P2-10)
	// ------------------------------------------------------------------

	/**
	 * Resolve a stable, non-empty session_id for the current agent session.
	 *
	 * Strategy (ordered, first non-empty wins):
	 *   1. MCP session ID from the Mcp-Session-Id HTTP header
	 *      ($_SERVER['HTTP_MCP_SESSION_ID']). Allowlisted to [A-Za-z0-9\-_],
	 *      capped at 128 chars. Trust level: as strong as MCP transport auth
	 *      (mcp-adapter enforces session validation; see mcp-adapter transport
	 *      docs for session auth requirements).
	 *   2. WordPress session token from wp_get_session_token() — stable for
	 *      a logged-in browser/API session.
	 *   3. Authenticated user: wp_hash('reeflex-sess:' . $user->ID) — uses
	 *      WordPress's keyed hash (wp_hash uses AUTH_KEY + AUTH_SALT internally);
	 *      stable per user, no cookie-value component (P2-10).
	 *   4. Anon ephemeral fallback: fragmentation resistance is degraded for
	 *      unauthenticated callers, but the envelope remains valid.
	 *
	 * Stability requirement (SPEC §4.1 fragmentation resistance): the same
	 * session_id MUST be returned for every action within one agent session so
	 * that reeflex-core's cumulative ledger can bind across calls.
	 *
	 * @param WP_User|null $user  Current user object (may be anonymous).
	 * @return string  Non-empty string.
	 */
	private static function resolve_session_id( ?WP_User $user ): string {
		// 1. MCP session id: allowlist + cap (P2-10).
		if ( ! empty( $_SERVER['HTTP_MCP_SESSION_ID'] ) ) {
			$raw_sid = (string) $_SERVER['HTTP_MCP_SESSION_ID'];
			$mcp_sid = substr( preg_replace( '/[^A-Za-z0-9\-_]/', '', $raw_sid ), 0, 128 );
			if ( '' !== $mcp_sid ) {
				return 'mcp:' . $mcp_sid;
			}
		}

		// 2. WordPress auth session token (stable per login session).
		if ( function_exists( 'wp_get_session_token' ) ) {
			$token = wp_get_session_token();
			if ( $token ) {
				return 'wpsess:' . $token;
			}
		}

		// 3. Stable hash for authenticated users via wp_hash() (P2-10).
		//    No cookie-value component: wp_hash uses AUTH_KEY + AUTH_SALT server-side.
		if ( $user && $user->exists() && $user->ID ) {
			return 'hash:' . wp_hash( 'reeflex-sess:' . $user->ID );
		}

		// 4. Anon ephemeral fallback.
		$ts = isset( $_SERVER['REQUEST_TIME'] ) ? (string) $_SERVER['REQUEST_TIME'] : (string) time();
		$ip = isset( $_SERVER['REMOTE_ADDR'] ) ? (string) $_SERVER['REMOTE_ADDR'] : '0.0.0.0';
		return 'anon:' . substr( hash( 'sha256', $ip . ':' . $ts ), 0, 24 );
	}

	// ------------------------------------------------------------------
	// Nonce
	// ------------------------------------------------------------------

	/**
	 * Generate a unique nonce for replay protection.
	 *
	 * Uses wp_generate_uuid4() when available (WP 4.7+), falling back to a
	 * sha256 hash seeded from high-resolution time so each call (even within
	 * the same second) produces a different value.
	 *
	 * The engine rejects a repeated nonce as a replay → HTTP 400.
	 *
	 * @param string $session_id
	 * @param string $timestamp
	 * @param string $ability
	 * @param int    $count
	 * @return string  32–64 hex chars; globally unique per call.
	 */
	private static function make_nonce(
		string $session_id,
		string $timestamp,
		string $ability,
		int $count
	): string {
		if ( function_exists( 'wp_generate_uuid4' ) ) {
			// UUID4 is cryptographically random; uniqueness is guaranteed.
			return str_replace( '-', '', wp_generate_uuid4() );
		}

		// Fallback: hash of context + microseconds.
		$hires = function_exists( 'hrtime' ) ? (string) hrtime( true ) : (string) microtime( true );
		$raw   = $session_id . ':' . $timestamp . ':' . $ability . ':' . $count . ':' . $hires;
		return hash( 'sha256', $raw );
	}
}
