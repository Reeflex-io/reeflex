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
 *     bulk delete (count ≥ 20)                  -> irreversible (mirrors adapter.py)
 *     delete of a TRASHABLE kind (post, page,
 *       revision, comment; media only when
 *       MEDIA_TRASH is on)                      -> recoverable
 *     ...but broad/systemic                     -> irreversible (an action cannot
 *                                                  be site-wide AND undoable)
 *     delete of any other kind (user, term,
 *       option, meta, plugin, theme, table)     -> irreversible (WordPress has
 *                                                  no undo for these)
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
 *   blast_radius: derived per SPEC §4.2 from the shape of the AFFECTED SET.
 *     Applied in order, first match wins:
 *       1. container claim (declared reeflex_scope, or a SYSTEMIC_SEGMENTS
 *          name signal)                        -> systemic
 *       2. affected set NOT enumerated -- declared 'predicate', or no ids
 *          array in $input                     -> broad
 *       3. affected set enumerated -- count( $input['ids'] ) decides:
 *            >= BROAD_MIN (20)                 -> broad
 *            2 .. 19                           -> scoped
 *            1                                 -> single
 *
 *     RFX-131 changed two things here, and both are SPEC §4.2 MUSTs:
 *       - "no ids" was 'single'; it is now 'broad'. Absence of an enumeration is
 *         a predicate over an unknown-size set -- the BROADEST signal available,
 *         not the narrowest. `core/truncate-postmeta` (a table wipe, matching no
 *         substring in either list) used to normalize to irreversible+single and
 *         ALLOW in production.
 *       - BULK_SEGMENTS no longer raises above an enumeration. Where $input holds
 *         a real list of affected ids, its cardinality is authoritative: an
 *         enumeration is evidence, a name is not. `delete-all-revisions-of-post`
 *         with ids=[7] used to read 'broad' off the substring "all-".
 *
 *     An agent-supplied 'count' is NOT an enumeration and no longer affects this
 *     axis at all (it still sets magnitude.count, where core's budgets validate
 *     it). Under the old rule it was the only thing standing between "no ids" and
 *     'single', which is precisely why "no ids" defaulting to 'single' was
 *     load-bearing and wrong.
 *
 *   externality:
 *     emit verb / outbound signals           -> outbound
 *     everything else                        -> internal
 *     physical (none in WP)                  -> n/a (never produced)
 *
 *   ability refinement for security-governing options (RFX-219):
 *     `core/update-option` is ONE ability covering every setting WordPress has,
 *     so disabling two-factor auth and renaming the site produced identical
 *     envelopes outside `params` — and `params` is an open bag no rule may
 *     match. For the options listed in SECURITY_OPTION_FAMILIES the reported
 *     ability becomes `<ability>/<family>/<option_name>`, e.g.
 *     `core/update-option/mfa/two_factor_enabled`. The family word is what a
 *     rule reads; the option name is what the human resolving the hold reads.
 *     REPORTED ONLY: the verb, all three axes, the target kind and the count
 *     are still derived from the ability WordPress registered, so an
 *     agent-supplied option name cannot move an axis. See refine_ability().
 *
 *   approval (HIL Phase 2 — SPEC §5.1):
 *     Schema is {present, hold_id} — matches core's validation contract exactly
 *     (holds.py / decide.py in reeflex-core). present:true is emitted ONLY when
 *     this normalize() call is happening inside a server-verified hold
 *     resubmission driven by Reeflex_Gate::resubmit_hold(); the caller passes the
 *     hold_id explicitly as a trusted parameter — it is NEVER read from
 *     agent-supplied $input. Everything else about the envelope (action, axes,
 *     magnitude, target, agent identity) is built exactly as it would be for a
 *     fresh call on the same ability+input, which is what lets core's
 *     action-hash binding match.
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

	// ------------------------------------------------------------------
	// Security-governing options (RFX-219).
	// ------------------------------------------------------------------

	/**
	 * WordPress option names whose VALUE governs who may act, how an identity is
	 * proved, or what code runs — mapped to the family word that says which.
	 *
	 * WHY THIS EXISTS AT ALL. `core/update-option` is one ability covering every
	 * setting WordPress has. Measured on a real core: disabling two-factor auth
	 * and renaming the site produce byte-identical envelopes outside `params`
	 * (same ability, same verb, same three axes, same target kind, ref null on
	 * both) and therefore the same verdict — `allow` / `default_allow`. The
	 * option name is the whole difference between them and it never left
	 * `params`, which SPEC §2 defines as an open backend-specific bag that no
	 * rule may pattern-match. So core cannot derive this. The adapter is the only
	 * layer that knows `two_factor_enabled` is not `blogname`.
	 *
	 * WHY THE FAMILY WORD AND NOT A BOOLEAN. The family is spliced into
	 * `action.ability` (see refine_ability()), and core's authority rule reads
	 * `action.ability` — tokenised, whole-token, never substring. The words below
	 * are drawn from THAT rule's own vocabulary (`role`, `membership` name who may
	 * act; `mfa` names how identity is proved; `plugin`, `theme`, `cron` name what
	 * code runs). A word outside it would be an honest label that no rule can
	 * read, which is what the first draft of this ticket proposed and what
	 * measurement rejected: `core/update-security-option` tokenises to
	 * {core, update, security, option} and `security` is in none of the lists.
	 *
	 * WHY `action.ability` AND NOT `target.ref`. Two measurements, not a
	 * preference. (1) The audit record carries `action.{namespace, verb, ability,
	 * environment, target_system}` and does NOT carry `target.ref` or `params` —
	 * so a ref would be invisible to the auditor, and the option name would still
	 * be missing from the one artefact an Art.14 reader gets. (2) `target.ref`
	 * has an established meaning for the other adapters (a filesystem path for
	 * reeflex-claude, matched by prefix against declared production assets), and
	 * minting a new ref shape for options would reach a rule this ticket has no
	 * business changing.
	 *
	 * WHAT THIS IS NOT. It is not a boundary and it cannot be complete: an option
	 * a plugin invents tomorrow is not in it, and an agent that writes such an
	 * option is not seen. It is a FLOOR, and the property that makes an admittedly
	 * incomplete list safe to ship is that it is RAISE-ONLY — a name in this list
	 * can turn an `allow` into a hold and can never do the reverse, so being wrong
	 * costs an approval prompt and never a missed refusal.
	 *
	 * Operators extend it through the `reeflex_security_option_families` filter,
	 * which is additive only (see security_option_families()).
	 *
	 * @var array<string,string>  lowercase option name => family word
	 */
	private const SECURITY_OPTION_FAMILIES = array(
		// -- how an identity is proved ---------------------------------
		'two_factor_enabled'   => 'mfa',
		'two_factor_forced'    => 'mfa',
		'two_factor_providers' => 'mfa',
		'wp_2fa_settings'      => 'mfa',

		// -- who may act -----------------------------------------------
		// `default_role` decides what every self-registered account becomes;
		// `users_can_register` decides whether there are any. Neither is a
		// cosmetic setting and both read as one in the envelope today.
		'default_role'         => 'role',
		'users_can_register'   => 'membership',

		// -- what code runs --------------------------------------------
		// Writing `active_plugins` activates PHP. Writing `template` or
		// `stylesheet` switches which theme's PHP runs. Writing `cron` schedules
		// it. All three are ordinary option writes to WordPress.
		'active_plugins'       => 'plugin',
		'template'             => 'theme',
		'stylesheet'           => 'theme',
		'cron'                 => 'cron',
	);

	/**
	 * Option-name suffixes that carry a family regardless of the table prefix.
	 *
	 * WordPress stores the role definitions under `{$table_prefix}user_roles`, so
	 * the literal name is `wp_user_roles` on a default install and something else
	 * on every install that changed the prefix. An exact-name map fails OPEN on
	 * exactly the installs that hardened their prefix, which is the wrong
	 * population to miss.
	 *
	 * Matched as a plain suffix, with no word boundary, and that is the
	 * deliberate direction: a boundary would exclude `superuser_roles`, which is
	 * an authority-governing name by any reading, in exchange for precision this
	 * list does not need. The match is RAISE-ONLY — its whole cost when wrong is
	 * one approval prompt — so the loose form is the safe one.
	 *
	 * @var array<string,string>  lowercase suffix => family word
	 */
	private const SECURITY_OPTION_SUFFIXES = array(
		'user_roles' => 'role',
	);

	/**
	 * Input keys that may carry the name of the option being operated on.
	 *
	 * Read ONLY when the ability is itself an option operation (target kind
	 * `option`), so a generic `name` on some other ability is never mistaken for
	 * an option name.
	 *
	 * @var array<int,string>
	 */
	private const OPTION_NAME_KEYS = array( 'option_name', 'option', 'name' );

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
	 * Ability name segments (lowercase) that imply a bulk blast radius.
	 *
	 * NO LONGER READ BY resolve_blast_radius() (RFX-131 / SPEC §4.2): a name may
	 * make a container claim (step 1) but MUST NOT make a cardinality claim, and
	 * every case this list used to catch is now reached without it —
	 *   - with no ids array, step 2 already returns 'broad';
	 *   - with an ids array, the enumeration is authoritative and this list would
	 *     have raised above it, which §4.2 forbids.
	 * It is retained because resolve_reversibility() and infer_kind() still read
	 * bulk signals for their own purposes, where a name IS the available evidence.
	 *
	 * @var array<int,string>
	 */
	private const BULK_SEGMENTS = array(
		'bulk', 'batch', 'mass', 'every', 'all',
	);

	/**
	 * Cardinality at which an enumerated affected set becomes 'broad'.
	 *
	 * INCLUSIVE: exactly BROAD_MIN entities is 'broad'. Carried as `broad_min` in
	 * reeflex-spec/conformance/blast-radius.json, which is what caught the two
	 * reference adapters disagreeing here — this adapter used `> 20`, the Claude
	 * Code adapter `>= 20`, so a 20-entity delete was 'scoped' in WordPress and
	 * 'broad' in Claude Code (RFX-131). The conservative reading wins, and it also
	 * lines up with resolve_reversibility()'s own `$count >= 20` threshold, which
	 * this class previously contradicted one axis over.
	 */
	private const BROAD_MIN = 20;

	/**
	 * Accepted values for the registration-time scope declaration (SPEC §4.2).
	 *
	 * Supplied by the operator who REGISTERS the ability (via the `reeflex_scope`
	 * arg, captured in Reeflex_Gate::wrap_permission_callback exactly like
	 * `reeflex_verb`), never from agent-supplied $input. It exists for the two
	 * facts the call site cannot see: an action whose affected set is not the
	 * parameter it receives, and a container change carrying no name signal.
	 *
	 * @var array<int,string>
	 */
	private const SCOPE_DECLARATIONS = array( 'container', 'predicate', 'enumerated' );

	/**
	 * Object kinds for which WordPress genuinely provides an undo.
	 *
	 * This is the ONLY set for which a plain `delete` is `recoverable`. The
	 * previous rule was "delete verb -> recoverable (WP trash default)", which
	 * is true of post-type objects and comments and FALSE of everything else:
	 *
	 *   posts / pages / revisions   wp_trash_post()      -> trash EXISTS
	 *   comments                    wp_trash_comment()   -> trash EXISTS
	 *   users                       wp_delete_user()     -> NO user trash
	 *   terms                       wp_delete_term()     -> NO term trash
	 *   options / meta              delete_option()      -> no prior value kept
	 *   plugins / themes            delete_plugins()     -> files removed
	 *   tables                      $wpdb DROP/TRUNCATE  -> no WP layer at all
	 *
	 * Attachments are deliberately NOT in this list: wp_delete_attachment()
	 * only trashes when MEDIA_TRASH is defined true, and that is OFF by
	 * default, so by default the original file and every generated size are
	 * unlinked from disk. is_trashable_kind() reads the constant so a site that
	 * has opted in still gets `recoverable`.
	 *
	 * @var array<int,string>
	 */
	private const TRASHABLE_SEGMENTS = array(
		'post', 'posts', 'page', 'pages', 'revision', 'revisions',
		'comment', 'comments',
	);

	/**
	 * Object kinds that are trashable ONLY when MEDIA_TRASH is enabled.
	 *
	 * @var array<int,string>
	 */
	private const MEDIA_SEGMENTS = array(
		'attachment', 'attachments', 'media', 'upload', 'uploads', 'image', 'images',
	);

	/**
	 * Object kinds WordPress cannot restore. Checked BEFORE TRASHABLE_SEGMENTS
	 * so that the non-trashable kind wins when an ability names both:
	 * `meta/delete-post-meta` deletes META, not a post, and must not be called
	 * recoverable because the word "post" appears in it.
	 *
	 * @var array<int,string>
	 */
	private const NON_TRASHABLE_SEGMENTS = array(
		'user', 'users', 'usermeta',
		'term', 'terms', 'category', 'categories', 'tag', 'tags', 'taxonomy',
		'option', 'options', 'settings', 'setting',
		'meta', 'postmeta', 'commentmeta', 'termmeta',
		'plugin', 'plugins', 'theme', 'themes',
		'table', 'tables', 'db', 'database', 'schema',
		'role', 'roles', 'capability', 'capabilities',
		'site', 'sites', 'network', 'blog',
		'menu', 'menus', 'widget', 'widgets',
		'transient', 'transients', 'cache',
	);

	// ------------------------------------------------------------------
	// Public entry point
	// ------------------------------------------------------------------

	/**
	 * Normalize a WordPress ability call into an Action Envelope.
	 *
	 * Approval (HIL Phase 2 — SPEC §5.1):
	 *   approval.present is true ONLY when $approval_hold_id is non-empty, which
	 *   only happens when Reeflex_Gate::resubmit_hold() is re-running the exact
	 *   ability+input that originally produced the hold (see
	 *   Reeflex_Gate::$active_resubmission_hold_id). $approval_hold_id is a
	 *   trusted, adapter-supplied parameter — it is NEVER derived from
	 *   agent-supplied $input (an agent forging '_reeflex_approved' or similar in
	 *   $input has no effect; see the params sanitation below). Core independently
	 *   validates the hold (single-use, TTL-bound, action-hash-bound — SPEC §5.1)
	 *   before ever returning allow; this adapter asserts nothing beyond "here is
	 *   the hold_id a human resolved."
	 *
	 *   Agent identity override (LOCKED DECISION, HIL Phase 2 T1.2 — non-negotiable
	 *   per brief): on a resubmission the envelope MUST carry the ORIGINAL agent
	 *   identity (id, on_behalf_of, session_id) captured when the hold was first
	 *   created — the actor stays the actor. resubmit_hold() executes from
	 *   whatever WordPress request context triggers it (an OPERATOR surface —
	 *   wp-admin, CLI, Slack — never the original agent's own request), so
	 *   deriving identity from "the live request" at THAT point would silently
	 *   substitute the resolver/operator for the actor in on_behalf_of and
	 *   session_id. $agent_override, when supplied, is used verbatim instead of
	 *   the live wp_get_current_user() lookup. Null (the normal, non-resubmission
	 *   path) leaves behaviour unchanged: identity is derived from the live request.
	 *
	 * @param string      $ability            Namespaced ability name, e.g. 'core/delete-post'.
	 * @param array       $input              Input array passed to the ability's callback.
	 * @param string      $trusted_verb       Optional: registration-time verb override from $args
	 *                                        (set by ability author via reeflex_verb key). Empty = auto.
	 * @param string|null $approval_hold_id   Optional: set ONLY by Reeflex_Gate::resubmit_hold()
	 *                                        around the ability's re-run. Null/empty = normal
	 *                                        first submission (approval.present = false).
	 * @param array|null  $agent_override     Optional: {id, on_behalf_of, session_id} captured at
	 *                                        hold-creation time. Set ONLY by
	 *                                        Reeflex_Gate::resubmit_hold(). Null = derive identity
	 *                                        from the live request (normal path, unchanged).
	 * @param string      $trusted_scope      Optional: registration-time scope declaration from
	 *                                        $args (reeflex_scope key), one of
	 *                                        container|predicate|enumerated — SPEC §4.2. Like
	 *                                        $trusted_verb it is captured at REGISTRATION time and
	 *                                        is NEVER read from agent-supplied $input. Empty =
	 *                                        derive the shape from the call (RFX-131).
	 * @return array  A fully-populated Action Envelope (SPEC §2).
	 */
	public static function normalize(
		string $ability,
		array $input,
		string $trusted_verb = '',
		?string $approval_hold_id = null,
		?array $agent_override = null,
		string $trusted_scope = ''
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
				if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
					// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Intentional debug-gated diagnostic; the authoritative record is the JSONL audit log.
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
			}
		} else {
			$verb = $heuristic_verb;
		}

		// -- COUNT (magnitude) --------------------------------------------
		$count = self::resolve_count( $input );

		// -- AXES ---------------------------------------------------------
		// blast_radius is resolved FIRST because reversibility now cross-checks
		// it: an action this same normalizer prices `broad` or `systemic` must
		// never simultaneously be called `recoverable` (see below).
		//
		// MERGE NOTE (dev-3 round 039, #101 rebased onto #94 `0243ee1`): the
		// argument list is #94's — RFX-131 removed $ability_segments and $count
		// from resolve_blast_radius (a name may not make a cardinality claim, and
		// $count is agent-supplied) and added the registration-time
		// $trusted_scope. Only the ORDER of these two lines is #101's, which is
		// the part RFX-164 needs.
		$blast_radius  = self::resolve_blast_radius( $ability_lower, $input, $trusted_scope );
		$reversibility = self::resolve_reversibility( $ability_lower, $ability_segments, $verb, $input, $count, $blast_radius );
		$externality   = self::resolve_externality( $ability_segments, $verb );

		// -- TARGET -------------------------------------------------------
		$kind = self::infer_kind( $ability_segments );
		$ref  = self::infer_ref( $input, $count, $kind );

		// -- ABILITY REFINEMENT (RFX-219) ---------------------------------
		// Computed LAST, from the ORIGINAL ability, and used for NOTHING except
		// the string reported in action.ability. That ordering is load-bearing,
		// not tidiness: the verb table, the systemic/bulk blast-radius signals
		// and infer_kind() all read the ability name, and every family word this
		// splices in is also a word one of those tables knows. `role` is an
		// 'update' verb token; an option named `alloptions` would trip the
		// `all-`/`-all` systemic substring test. Deriving the axes from the
		// refined name would let the option name move an axis it has no business
		// moving, which is the RFX-131 defect in a new costume.
		$reported_ability = self::refine_ability( $ability, $kind, $input );

		// -- AGENT --------------------------------------------------------
		// LOCKED DECISION (HIL Phase 2 T1.2): when $agent_override is supplied
		// (resubmission path only), it is used verbatim — the ORIGINAL agent
		// identity is preserved so the actor stays the actor. Otherwise identity
		// is derived from the live WordPress request, exactly as before.
		if ( null !== $agent_override ) {
			$agent_id     = isset( $agent_override['id'] ) && is_string( $agent_override['id'] ) && '' !== $agent_override['id']
				? $agent_override['id']
				: Reeflex_Config::agent_id();
			$on_behalf_of = isset( $agent_override['on_behalf_of'] ) && is_string( $agent_override['on_behalf_of'] )
				? $agent_override['on_behalf_of']
				: 'user:anonymous';
			$session_id   = isset( $agent_override['session_id'] ) && is_string( $agent_override['session_id'] ) && '' !== $agent_override['session_id']
				? $agent_override['session_id']
				: self::resolve_session_id( null );
		} else {
			$agent_id = Reeflex_Config::agent_id();
			$user     = wp_get_current_user();
			// P2-12: use user ID (integer), not user_login (PII).
			$on_behalf_of = ( $user && $user->exists() && $user->ID )
				? 'user:' . $user->ID
				: 'user:anonymous';

			$session_id = self::resolve_session_id( $user );
		}

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

		// -- APPROVAL (HIL Phase 2 — SPEC §5.1) ---------------------------
		// present=true ONLY when $approval_hold_id was passed in by
		// Reeflex_Gate::resubmit_hold() — never from agent-supplied $input.
		// Schema is exactly {present, hold_id}; core needs nothing else.
		$approval = ( null !== $approval_hold_id && '' !== $approval_hold_id )
			? array(
				'present' => true,
				'hold_id' => $approval_hold_id,
			)
			: array(
				'present' => false,
				'hold_id' => null,
			);

		return array(
			'reeflex_version' => '0.1',
			'agent'           => array(
				'id'           => $agent_id,
				'on_behalf_of' => $on_behalf_of,
				'session_id'   => $session_id,
			),
			'action'          => array(
				'namespace' => 'wordpress',
				'verb'      => $verb,
				'ability'   => $reported_ability,
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
	 *   3. Delete verb with count ≥ 20 → irreversible (mirrors adapter.py large-bulk rule).
	 *   4. Delete verb, and WordPress HAS an undo for this object kind
	 *      (TRASHABLE_SEGMENTS; media only when MEDIA_TRASH is on) →
	 *      recoverable, UNLESS blast_radius is broad/systemic, in which case
	 *      irreversible (an action cannot be both site-wide and undoable).
	 *   5. Delete verb, object kind has no undo or is unrecognised →
	 *      irreversible (SPEC §2 conservative default). This replaces the old
	 *      "delete → recoverable (WP trash default)", which was true only of
	 *      post-type objects and comments.
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
		int $count,
		string $blast_radius = 'single'
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
				// Large bulk delete treated as irreversible (mirrors adapter.py:
				// "bulk delete >= 20 -> irreversible (treat large bulk as unrecoverable)").
				if ( $count >= 20 ) {
					return 'irreversible';
				}

				// A delete is only `recoverable` when WordPress actually HAS an
				// undo for the KIND of object being deleted (see
				// TRASHABLE_SEGMENTS). The previous rule returned `recoverable`
				// for every small delete on the strength of a "WP trash
				// default" that does not exist for users, terms, options, meta,
				// plugins, themes or tables.
				//
				// This is not cosmetic: `reversibility` is a hard precondition
				// of BOTH R2 (irreversible+broad+prod -> require_approval) and
				// R3 (irreversible+systemic+prod -> deny), so a wrong
				// `recoverable` here is the difference between a human seeing
				// the action and not.
				if ( self::is_trashable_kind( $ability_lower, $ability_segments ) ) {
					// SELF-CONTRADICTION GUARD. Restoring 20 posts one at a
					// time out of the trash is not what "recoverable" is
					// offering the reader of a decision, and an action this
					// same normalizer prices `broad`/`systemic` cannot honestly
					// be called undoable. Without this, the two axes that R2
					// and R3 conjoin can contradict each other inside one
					// envelope.
					if ( in_array( $blast_radius, array( 'broad', 'systemic' ), true ) ) {
						return 'irreversible';
					}
					return 'recoverable';
				}

				// SPEC §2: when the object kind offers no undo — or we do not
				// recognise it — the conservative answer is irreversible.
				return 'irreversible';

			case 'transact':
			case 'execute':
				// Payments and arbitrary executions: unknown outcome → irreversible.
				return 'irreversible';

			default:
				// SPEC §2: unknown reversibility → irreversible.
				return 'irreversible';
		}
	}

	/**
	 * Does WordPress provide an undo for the object kind this ability names?
	 *
	 * An explicit `trash` segment counts only when the underlying kind is
	 * itself trashable — `users/empty-trash` is not a recoverable operation
	 * just because the word "trash" appears in it.
	 *
	 * @param string            $ability_lower
	 * @param array<int,string> $ability_segments
	 * @return bool
	 */
	private static function is_trashable_kind( string $ability_lower, array $ability_segments ): bool {
		// A non-trashable kind named anywhere in the ability wins: an ability
		// that touches users or meta is not made recoverable by also saying
		// "post" (e.g. `meta/delete-post-meta`).
		foreach ( self::NON_TRASHABLE_SEGMENTS as $seg ) {
			if ( in_array( $seg, $ability_segments, true ) ) {
				return false;
			}
		}

		foreach ( self::MEDIA_SEGMENTS as $seg ) {
			if ( in_array( $seg, $ability_segments, true ) ) {
				return defined( 'MEDIA_TRASH' ) && MEDIA_TRASH;
			}
		}

		foreach ( self::TRASHABLE_SEGMENTS as $seg ) {
			if ( in_array( $seg, $ability_segments, true ) ) {
				return true;
			}
		}

		// Emptying the trash SPENDS the undo; it is never itself recoverable.
		// (Handled here rather than by the 'trash' substring, which used to
		// make `core/empty-trash` look recoverable.)
		return false;
	}

	// ------------------------------------------------------------------
	// Axis: blast_radius (P1-6)
	// ------------------------------------------------------------------

	/**
	 * Derive how much is affected, per SPEC §4.2.
	 *
	 * The axis is read off the SHAPE OF THE AFFECTED SET, not off the ability's
	 * name. Resolution order, first match wins:
	 *
	 *   1. CONTAINER — the target is the system's own structure or control plane
	 *      (schema, site-wide configuration, the access-control model) → systemic.
	 *      Reached by an explicit `reeflex_scope: 'container'` declaration, or by a
	 *      SYSTEMIC_SEGMENTS name signal. A name is allowed to make this claim
	 *      because it is a claim about KIND, made by whoever registered the
	 *      ability, and it can only raise.
	 *   2. PREDICATE — the affected set is described by a filter rather than
	 *      enumerated: `reeflex_scope: 'predicate'`, or no `ids` array at all
	 *      → broad. §4.2: an adapter that cannot enumerate the affected set MUST
	 *      NOT emit 'single' or 'scoped'.
	 *   3. ENUMERATED — count( $input['ids'] ) is authoritative:
	 *      >= BROAD_MIN → broad, 2..BROAD_MIN-1 → scoped, 1 → single. A name
	 *      signal MUST NOT raise above this: an enumeration is evidence, a name
	 *      is not.
	 *
	 * What changed in RFX-131 and why it is not a tuning tweak: "no ids" used to
	 * return 'single', so `core/truncate-postmeta` — a table wipe whose name
	 * matches nothing in either substring list — normalized to
	 * irreversible + single + production and was ALLOWED by R4's default. Absence
	 * of an enumeration is the broadest signal available, not the narrowest.
	 *
	 * $count is deliberately absent from this method now. It can be agent-supplied
	 * (infer_count reads $input['count']), and a caller-supplied number is not an
	 * enumeration. It still populates magnitude.count, where reeflex-core validates
	 * and budgets it.
	 *
	 * @param string $ability_lower  Lowercased ability name.
	 * @param array  $input          Ability input (agent-supplied).
	 * @param string $trusted_scope  Registration-time declaration; '' if none.
	 *                               NEVER read from $input.
	 * @return string  'single'|'scoped'|'broad'|'systemic'
	 */
	private static function resolve_blast_radius(
		string $ability_lower,
		array $input,
		string $trusted_scope = ''
	): string {
		$declared = in_array( $trusted_scope, self::SCOPE_DECLARATIONS, true )
			? $trusted_scope
			: '';

		// 1. CONTAINER → systemic.
		if ( 'container' === $declared ) {
			return 'systemic';
		}
		foreach ( self::SYSTEMIC_SEGMENTS as $signal ) {
			if ( false !== strpos( $ability_lower, $signal ) ) {
				return 'systemic';
			}
		}

		// 2. PREDICATE → broad. Either the ability says so, or there is no
		//    enumeration of affected entities in the call.
		//
		//    An EMPTY ids array counts as no enumeration, not as a small one. WP
		//    handlers routinely read an empty selection as "everything", and an
		//    agent that wants 'single' would otherwise just send `ids: []` —
		//    reintroducing the exact fail-open this method was rewritten to close.
		$has_enumeration = isset( $input['ids'] )
			&& is_array( $input['ids'] )
			&& count( $input['ids'] ) > 0;
		if ( 'predicate' === $declared || ! $has_enumeration ) {
			return 'broad';
		}

		// 3. ENUMERATED → cardinality decides. BROAD_MIN is inclusive.
		//    A 'declared' value of 'enumerated' lands here too; it asserts nothing
		//    beyond what the ids array already shows, which is the point of the
		//    monotonic rule — a declaration may raise, never lower.
		$ids_count = count( $input['ids'] );
		if ( $ids_count >= self::BROAD_MIN ) {
			return 'broad';
		}
		if ( $ids_count > 1 ) {
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
	// Ability refinement for security-governing options (RFX-219)
	// ------------------------------------------------------------------

	/**
	 * The option-family map, after the operator's additive filter.
	 *
	 * ADDITIVE ONLY, and for the same reason the trusted verb override is
	 * raise-only (NEW-3): a hook that can DELETE a built-in entry is a documented
	 * way to switch a control off from inside the audited system, and the
	 * governing principle at the top of this file is that nothing reachable from
	 * the site may lower risk. A filter may add option names and may not remove
	 * or overwrite the ones shipped here; an attempt to overwrite keeps the
	 * shipped family and logs under WP_DEBUG.
	 *
	 * Entries whose key or value is not a non-empty string are dropped rather
	 * than trusted.
	 *
	 * @return array<string,string>  lowercase option name => family word
	 */
	private static function security_option_families(): array {
		$shipped = self::SECURITY_OPTION_FAMILIES;

		if ( ! function_exists( 'apply_filters' ) ) {
			return $shipped;
		}

		$filtered = apply_filters( 'reeflex_security_option_families', $shipped );
		if ( ! is_array( $filtered ) ) {
			return $shipped;
		}

		$merged = $shipped;
		foreach ( $filtered as $name => $family ) {
			if ( ! is_string( $name ) || ! is_string( $family ) ) {
				continue;
			}
			$name   = strtolower( trim( $name ) );
			$family = strtolower( trim( $family ) );
			if ( '' === $name || '' === $family ) {
				continue;
			}
			if ( isset( $shipped[ $name ] ) ) {
				// Shipped entry: keep ours. Only complain if they differ.
				if ( $shipped[ $name ] !== $family && defined( 'WP_DEBUG' ) && WP_DEBUG ) {
					// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Intentional debug-gated diagnostic; the authoritative record is the JSONL audit log.
					error_log( sprintf(
						'[reeflex] RFX-219: reeflex_security_option_families tried to change shipped option "%s" from family "%s" to "%s" — IGNORED; the filter is additive only.',
						$name,
						$shipped[ $name ],
						$family
					) );
				}
				continue;
			}
			$merged[ $name ] = $family;
		}

		return $merged;
	}

	/**
	 * Read the name of the option this call operates on, if there is one.
	 *
	 * Normalisation is the security-relevant part. `update_option()` trims its
	 * option name, so ' two_factor_enabled' and 'two_factor_enabled' write the
	 * SAME row — an untrimmed lookup would let one leading space walk past the
	 * gate. Lowercasing is a separate, deliberately RAISE-ONLY choice: WordPress
	 * option names are case-sensitive, so 'Two_Factor_Enabled' is a different row
	 * and folding it here can only ever cause an extra hold, never a miss.
	 *
	 * @param array $input
	 * @return string|null  Normalised option name, or null if none is present.
	 */
	private static function resolve_option_name( array $input ): ?string {
		foreach ( self::OPTION_NAME_KEYS as $key ) {
			if ( ! isset( $input[ $key ] ) || ! is_string( $input[ $key ] ) ) {
				continue;
			}
			$name = strtolower( trim( $input[ $key ] ) );
			if ( '' !== $name ) {
				return $name;
			}
		}
		return null;
	}

	/**
	 * Which family, if any, a normalised option name belongs to.
	 *
	 * Exact name first, then the prefix-independent suffixes.
	 *
	 * @param string $option_name  Already normalised by resolve_option_name().
	 * @return string|null  Family word, or null.
	 */
	private static function match_option_family( string $option_name ): ?string {
		$families = self::security_option_families();
		if ( isset( $families[ $option_name ] ) ) {
			return $families[ $option_name ];
		}

		foreach ( self::SECURITY_OPTION_SUFFIXES as $suffix => $family ) {
			$at = strlen( $option_name ) - strlen( $suffix );
			if ( $at >= 0 && substr( $option_name, $at ) === $suffix ) {
				return $family;
			}
		}

		return null;
	}

	/**
	 * Splice the family word and the option name into the reported ability.
	 *
	 *     core/update-option  +  two_factor_enabled  ->  core/update-option/mfa/two_factor_enabled
	 *
	 * Both halves are load-bearing and they serve different readers:
	 *
	 *   - the FAMILY WORD is what a rule can read. Core's authority rule
	 *     tokenises `action.ability` on non-alphanumerics and matches whole
	 *     tokens, so `mfa` reaches its credential list. Without it the write is
	 *     indistinguishable from renaming the site.
	 *   - the OPTION NAME is what a HUMAN reads. The audit record carries the
	 *     ability and neither `params` nor `target.ref`, so if the option name is
	 *     not in this string it is in no artefact an approver or an auditor ever
	 *     sees — they would be asked to approve "an MFA change" with no way to
	 *     learn which one.
	 *
	 * The original ability is left as a literal PREFIX, so an operator's existing
	 * `core/update-option` grep, dashboard filter or rule still finds these rows.
	 * Nothing is renamed and nothing is hidden.
	 *
	 * Only abilities whose own target kind is `option` are considered, so a
	 * `name` key on some unrelated ability is never read as an option name.
	 *
	 * Applies to every verb, including `read`. That is deliberate: a read of a
	 * security option is worth naming in the record, and it cannot be held —
	 * core's authority rule is structurally `verb != "read"`, and R1 (read-only
	 * internal) still allows it. Pinned as a test rather than left to trust.
	 *
	 * @param string $ability  The ability name exactly as WordPress registered it.
	 * @param string $kind     Target kind from infer_kind().
	 * @param array  $input
	 * @return string  The ability to report, refined or unchanged.
	 */
	private static function refine_ability( string $ability, string $kind, array $input ): string {
		if ( 'option' !== $kind ) {
			return $ability;
		}

		$option_name = self::resolve_option_name( $input );
		if ( null === $option_name ) {
			return $ability;
		}

		$family = self::match_option_family( $option_name );
		if ( null === $family ) {
			return $ability;
		}

		return $ability . '/' . $family . '/' . $option_name;
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
	 *   2. WordPress session token from wp_get_session_token(), as a salted
	 *      SHA-256 derivation — stable per logged-in browser/API session, but
	 *      NEVER the raw token (auth material must not leave the site).
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
			$raw_sid = sanitize_text_field( wp_unslash( $_SERVER['HTTP_MCP_SESSION_ID'] ) );
			$mcp_sid = substr( preg_replace( '/[^A-Za-z0-9\-_]/', '', $raw_sid ), 0, 128 );
			if ( '' !== $mcp_sid ) {
				return 'mcp:' . $mcp_sid;
			}
		}

		// 2. WordPress auth session token, as a NON-REVERSIBLE derived id.
		// SECURITY: wp_get_session_token() is auth-cookie-derived secret material —
		// it must NEVER leave the site (it is transmitted to core and written to
		// the audit log). We send only a salted SHA-256 derivation: sessions still
		// correlate (same token -> same id, so the R5 cumulative-session ledger
		// binds), but the token cannot be recovered from the id, and wp_salt()
		// makes it un-precomputable.
		if ( function_exists( 'wp_get_session_token' ) ) {
			$token = wp_get_session_token();
			if ( $token ) {
				return 'wpsess:' . hash( 'sha256', $token . wp_salt( 'auth' ) );
			}
		}

		// 3. Stable hash for authenticated users via wp_hash() (P2-10).
		//    No cookie-value component: wp_hash uses AUTH_KEY + AUTH_SALT server-side.
		if ( $user && $user->exists() && $user->ID ) {
			return 'hash:' . wp_hash( 'reeflex-sess:' . $user->ID );
		}

		// 4. Anon ephemeral fallback.
		$ts = isset( $_SERVER['REQUEST_TIME'] ) ? (string) absint( wp_unslash( $_SERVER['REQUEST_TIME'] ) ) : (string) time();
		$ip = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '0.0.0.0';
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
