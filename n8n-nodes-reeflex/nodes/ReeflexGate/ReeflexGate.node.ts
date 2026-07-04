import type {
	IDataObject,
	IExecuteFunctions,
	IHttpRequestOptions,
	IN8nHttpFullResponse,
	INodeExecutionData,
	INodeType,
	INodeTypeDescription,
} from 'n8n-workflow';
import { NodeConnectionTypes, NodeOperationError } from 'n8n-workflow';
// NOTE: NodeApiError is intentionally NOT used here. This node captures the
// response body itself (via returnFullResponse + ignoreHttpStatusErrors) so
// it can extract a real Decision even from reeflex-core's fail-closed 500
// response, instead of losing that body to a thrown NodeApiError. Genuine
// unrecoverable errors (bad parameters) still use NodeOperationError below.

const REEFLEX_VERSION = '0.1';

/**
 * STUB nonce generator. This is sufficient for the current reeflex-core
 * skeleton, which does not yet cryptographically verify envelope replay
 * protection (see reeflex-spec/SPEC.md SS2, SS6). Upgrade path: once core
 * enforces nonce uniqueness, replace with a cryptographically strong
 * generator (e.g. Node's crypto.randomUUID()).
 */
function generateNonce(): string {
	return `${Date.now().toString(16)}-${Math.random().toString(16).slice(2)}`;
}

/**
 * Coerce an httpRequest response body to a plain object for safe field access.
 * n8n's helper (with `json: true`) already parses JSON bodies into objects,
 * but a non-JSON error body (e.g. a proxy's plaintext 502 page) can still show
 * up as a raw string here - this keeps that case from throwing a TypeError.
 */
function _asDataObject(body: unknown): IDataObject {
	if (body && typeof body === 'object' && !Array.isArray(body)) {
		return body as IDataObject;
	}
	if (typeof body === 'string' && body.trim().length > 0) {
		try {
			const parsed = JSON.parse(body) as unknown;
			if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
				return parsed as IDataObject;
			}
		} catch {
			// not JSON - fall through
		}
	}
	return {};
}

/**
 * Build a synthetic, fail-closed Decision shape (SPEC SS5) for cases where
 * reeflex-core did not hand back a usable decision at all: network failure,
 * or an HTTP error response with no `decision` field. Always routes to the
 * Denied output (see the ENFORCE step in execute()) - never "allow".
 */
function _failClosed(reason: string): IDataObject {
	return {
		decision: 'deny',
		reason: `Reeflex: ${reason} -- failing closed`,
		rule: 'n8n-nodes-reeflex/fail_closed',
		obligations: [],
		modulation: null,
	};
}

interface ReeflexAdditionalFields {
	onBehalfOf?: string;
	targetRef?: string;
}

/**
 * Reeflex Gate - a thin, zero-business-logic consumer of reeflex-core's
 * POST /v1/decide (see reeflex-spec/SPEC.md and reeflex-core/README.md).
 *
 * For every input item this node:
 *   1. Builds an Action Envelope (SPEC SS2) from the node parameters.
 *   2. Submits it to reeflex-core.
 *   3. Routes the item to one of three outputs based on the Decision:
 *      Allowed / Held for Approval / Denied.
 *
 * The node performs NO enforcement itself - it never calls the governed
 * backend, never resolves holds, and never retries. That is the operator's
 * downstream workflow (see /docs/guides/n8n.md at the repository root for the
 * zero-code Wait-node / webhook pattern for the human-in-the-loop leg).
 *
 * Fail-closed (Adapter Contract responsibility #3, SPEC SS6): if reeflex-core
 * is unreachable, times out, or returns a non-2xx response with no usable
 * decision embedded, this node UNCONDITIONALLY routes the item to Denied with
 * a synthetic fail-closed reason (`reeflex.rule = "n8n-nodes-reeflex/fail_closed"`)
 * - it never lets the action proceed as "allow", and it never crashes the
 * workflow over a core-communication failure (that would defeat the purpose
 * of having a Denied output to alert on). This mirrors reeflex-claude and
 * reeflex-wordpress. "Continue On Fail" still applies to this node's OWN
 * configuration errors (e.g. a missing required parameter), a different
 * error class from "core said no" / "core is unreachable".
 *
 * Audit (Adapter Contract responsibility #4): reeflex-core writes an audit
 * record for every /v1/decide call server-side (see reeflex-core README,
 * "Directory layout" -> audit/decisions.jsonl). This node does not duplicate
 * that audit trail.
 *
 * Obligations (SPEC SS5): the `obligations` array from the Decision is passed
 * through verbatim on the `reeflex` output field. This node does not itself
 * enforce specific obligations (e.g. `redact:pii`) - build that as downstream
 * workflow steps that branch on `{{$json.reeflex.obligations}}`.
 */
export class ReeflexGate implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'Reeflex Gate',
		name: 'reeflexGate',
		icon: 'file:reeflexGate.svg',
		group: ['transform'],
		version: 1,
		subtitle: '={{$parameter["verb"] + ": " + $parameter["ability"]}}',
		description:
			'Deterministic governance gate for AI-agent actions - calls reeflex-core POST /v1/decide',
		defaults: {
			name: 'Reeflex Gate',
		},
		inputs: [NodeConnectionTypes.Main],
		outputs: [NodeConnectionTypes.Main, NodeConnectionTypes.Main, NodeConnectionTypes.Main],
		outputNames: ['Allowed', 'Held for Approval', 'Denied'],
		credentials: [
			{
				name: 'reeflexApi',
				required: true,
			},
		],
		properties: [
			{
				displayName:
					'Reeflex Gate submits one Action Envelope per input item to reeflex-core and routes the item to Allowed, Held for Approval, or Denied. The axis defaults below (Irreversible / Systemic / Outbound) are deliberately the most restrictive, so an unconfigured node fails toward safety - set them to describe your actual action truthfully.',
				name: 'reeflexNotice',
				type: 'notice',
				default: '',
			},
			{
				displayName: 'Action / Ability',
				name: 'ability',
				type: 'string',
				required: true,
				default: '',
				placeholder: 'e.g. wordpress/delete-post',
				description: 'The backend-specific action identifier (Action Envelope action.ability). The part before the first "/" is used as action.namespace; falls back to "n8n" if there is no "/".',
			},
			{
				displayName: 'Verb',
				name: 'verb',
				type: 'options',
				options: [
					{
						name: 'Create',
						value: 'create',
						description: 'Add new state (e.g. INSERT, create-post)',
					},
					{
						name: 'Delete',
						value: 'delete',
						description: 'Remove state (e.g. DELETE, delete-post)',
					},
					{
						name: 'Emit',
						value: 'emit',
						description: 'Send to the outside world (e.g. send email, publish)',
					},
					{
						name: 'Execute',
						value: 'execute',
						description: 'Run, trigger, or deploy (e.g. kubectl apply, run job)',
					},
					{
						name: 'Read',
						value: 'read',
						description: 'Observe, no state change (e.g. SELECT, GetObject)',
					},
					{
						name: 'Transact',
						value: 'transact',
						description: 'Move money or commit an obligation (e.g. refund, payment)',
					},
					{
						name: 'Update',
						value: 'update',
						description: 'Modify existing state (e.g. UPDATE, edit-page)',
					},
				],
				default: 'read',
				description: 'The normalized verb for this action (Action Envelope action.verb)',
			},
			{
				displayName: 'Environment',
				name: 'environment',
				type: 'options',
				options: [
					{ name: 'Production', value: 'production' },
					{ name: 'Staging', value: 'staging' },
					{ name: 'Dev', value: 'dev' },
				],
				default: 'production',
				description: 'Which environment this action targets (Action Envelope target.environment). Defaults to Production, the safe-conservative choice - override explicitly for staging or dev runs.',
			},
			{
				displayName: 'Reversibility',
				name: 'reversibility',
				type: 'options',
				options: [
					{
						name: 'Reversible',
						value: 'reversible',
						description: 'Trivially undone (e.g. toggle a draft)',
					},
					{
						name: 'Recoverable',
						value: 'recoverable',
						description: 'Undone with effort or backup (e.g. soft-deleted row)',
					},
					{
						name: 'Irreversible',
						value: 'irreversible',
						description: 'Gone for good (e.g. hard delete, sent email, executed payment)',
					},
				],
				default: 'irreversible',
				description: 'Whether this action can be undone (Action Envelope axes.reversibility). Defaults to the safe-conservative value.',
			},
			{
				displayName: 'Blast Radius',
				name: 'blastRadius',
				type: 'options',
				options: [
					{ name: 'Single', value: 'single', description: 'Affects one entity' },
					{
						name: 'Broad',
						value: 'broad',
						description: 'Affects a large set - a whole table, bucket, or site',
					},
					{
						name: 'Systemic',
						value: 'systemic',
						description: 'Could affect the system itself - schema, infrastructure, or all users',
					},
				],
				default: 'systemic',
				description:
					'How much is affected (Action Envelope axes.blast_radius). Defaults to the safe-conservative value. The full Action Envelope spec also defines a "scoped" value between Single and Broad, not exposed here to keep this list short',
			},
			{
				displayName: 'Externality',
				name: 'externality',
				type: 'options',
				options: [
					{ name: 'Internal', value: 'internal', description: 'Stays inside the controlled system' },
					{
						name: 'Outbound',
						value: 'outbound',
						description: 'Reaches third parties - email, API, publish',
					},
				],
				default: 'outbound',
				description:
					'Whether this action reaches beyond the system (Action Envelope axes.externality). Defaults to the safe-conservative value. The full Action Envelope spec also defines a "physical" value for actions affecting the physical world, not exposed here',
			},
			{
				displayName: 'Count',
				name: 'count',
				type: 'number',
				typeOptions: {
					minValue: 1,
				},
				default: 1,
				description: 'How many entities this action affects (Action Envelope magnitude.count). reeflex-core uses this together with the per-session budget to detect fragmented bulk actions (SPEC SS4.1).',
			},
			{
				displayName: 'Target System',
				name: 'targetSystem',
				type: 'string',
				default: '',
				placeholder: 'e.g. wp-prod, billing-db, CRM',
				description: 'Free-text identifier of the system or service being acted on. Informational: sent as Action Envelope target.kind, not itself a decision axis.',
			},
			{
				displayName: 'Session ID',
				name: 'sessionId',
				type: 'string',
				required: true,
				default: '={{$execution.id}}',
				description: 'Stable identifier tying this action to a session (Action Envelope agent.session_id), required so reeflex-core can detect fragmented bulk actions across calls (SPEC SS4.1). Defaults to this workflow execution\'s ID.',
			},
			{
				displayName: 'Agent ID',
				name: 'agentId',
				type: 'string',
				required: true,
				default: 'agent:n8n',
				// eslint-disable-next-line n8n-nodes-base/node-param-description-miscased-id -- "agent.id" is a literal Action Envelope JSON field name (lowercase by SPEC), not prose.
				description: 'Identifier of the agent performing the action (Action Envelope agent.id)',
			},
			{
				displayName: 'Additional Fields',
				name: 'additionalFields',
				type: 'collection',
				placeholder: 'Add Field',
				default: {},
				options: [
					{
						displayName: 'On Behalf Of',
						name: 'onBehalfOf',
						type: 'string',
						default: '',
						placeholder: 'e.g. user:alice',
						description:
							'The authorized human principal this agent is acting for (Action Envelope agent.on_behalf_of)',
					},
					{
						displayName: 'Target Ref',
						name: 'targetRef',
						type: 'string',
						default: '',
						placeholder: 'e.g. post:1481',
						description: 'Stable identifier of the specific entity being acted on (Action Envelope target.ref). Leave empty for bulk actions.',
					},
				],
			},
		],
		usableAsTool: true,
	};

	async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
		const items = this.getInputData();

		const allowedItems: INodeExecutionData[] = [];
		const heldItems: INodeExecutionData[] = [];
		const deniedItems: INodeExecutionData[] = [];

		for (let itemIndex = 0; itemIndex < items.length; itemIndex++) {
			try {
				const ability = this.getNodeParameter('ability', itemIndex) as string;
				if (!ability) {
					throw new NodeOperationError(this.getNode(), 'Action / Ability is required', {
						itemIndex,
						description:
							'Enter the backend-specific action identifier, for example "wordpress/delete-post"',
					});
				}

				const verb = this.getNodeParameter('verb', itemIndex) as string;
				const environment = this.getNodeParameter('environment', itemIndex) as string;
				const reversibility = this.getNodeParameter('reversibility', itemIndex) as string;
				const blastRadius = this.getNodeParameter('blastRadius', itemIndex) as string;
				const externality = this.getNodeParameter('externality', itemIndex) as string;
				const count = this.getNodeParameter('count', itemIndex) as number;
				const targetSystem = this.getNodeParameter('targetSystem', itemIndex, '') as string;
				const sessionId = this.getNodeParameter('sessionId', itemIndex) as string;
				const agentId = this.getNodeParameter('agentId', itemIndex) as string;
				const additionalFields = this.getNodeParameter(
					'additionalFields',
					itemIndex,
					{},
				) as ReeflexAdditionalFields;

				if (!sessionId) {
					throw new NodeOperationError(
						this.getNode(),
						'Session ID is required for fragmentation-resistant governance (SPEC SS4.1)',
						{
							itemIndex,
							description:
								"Provide a stable session identifier - for example the default '={{$execution.id}}' expression",
						},
					);
				}

				const namespace = ability.includes('/') ? ability.split('/')[0] : 'n8n';

				const envelope: IDataObject = {
					reeflex_version: REEFLEX_VERSION,
					agent: {
						id: agentId,
						on_behalf_of: additionalFields.onBehalfOf || null,
						session_id: sessionId,
					},
					action: {
						namespace,
						verb,
						ability,
					},
					target: {
						kind: targetSystem || null,
						ref: additionalFields.targetRef || null,
						environment,
					},
					// Deliberately empty: this generic gate node does not know the
					// shape of the caller's backend action, and pass-through of raw
					// item data here would risk piping arbitrary/PII-bearing payload
					// content into reeflex-core's audit trail without the operator's
					// explicit intent (project-wide zero-PII-by-default posture).
					// UPGRADE: expose an opt-in "Additional Context (JSON)" field
					// under Additional Fields that merges into `context` (SPEC SS2
					// says context is "free passthrough for policy use") once a real
					// policy pack needs it.
					params: {},
					magnitude: {
						count,
					},
					axes: {
						reversibility,
						blast_radius: blastRadius,
						externality,
					},
					approval: {
						present: false,
						hold_id: null,
					},
					trajectory_ref: null,
					context: {},
					meta: {
						timestamp: new Date().toISOString(),
						nonce: generateNonce(),
						// STUB signature: core does not yet cryptographically verify
						// envelope signatures (SPEC SS2, SS6 - Vault-backed signing is
						// on core's roadmap). Upgrade path: once core ships real
						// verification, add a "Signing Key" field to the reeflexApi
						// credential and sign the canonical envelope bytes here.
						signature: 'ed25519:stub:n8n-nodes-reeflex',
					},
				};

				const credentials = await this.getCredentials('reeflexApi');
				const baseUrl = (credentials.coreUrl as string).replace(/\/+$/, '');

				const options: IHttpRequestOptions = {
					method: 'POST',
					url: `${baseUrl}/v1/decide`,
					body: envelope,
					json: true,
					skipSslCertificateValidation: credentials.ignoreSslIssues === true,
					// Read the status code ourselves instead of letting the HTTP helper
					// throw on non-2xx: reeflex-core's own contract (app/decide.py
					// `process()`) returns HTTP 500 WITH a usable {"decision":"deny",...}
					// body on internal errors (fail-closed-by-design on core's side too),
					// and mirrors reeflex-claude's enforce.py, which does the same
					// "try to parse a decision from an error body" step for cross-adapter
					// consistency. Genuine network failures (DNS, connection refused,
					// timeout - no HTTP response at all) still throw and are caught below.
					returnFullResponse: true,
					ignoreHttpStatusErrors: true,
				};

				let decision: IDataObject;
				try {
					const response = (await this.helpers.httpRequestWithAuthentication.call(
						this,
						'reeflexApi',
						options,
					)) as IN8nHttpFullResponse;

					const body = _asDataObject(response.body);

					if (typeof body.decision === 'string') {
						// Covers the normal 200 path (allow / deny / require_approval /
						// frozen-deny) AND the 500 internal-error path, which also embeds
						// a real (fail-closed) decision - see decide.py `process()`.
						decision = body;
					} else {
						// No usable decision in the body (400 invalid_envelope, 401
						// unauthorized, 404/405/411/413, or an unrecognized shape).
						// Fail closed (Adapter Contract #3 ENFORCE, SPEC SS6): never let
						// the action proceed as "allow" when core did not hand back a
						// real decision.
						decision = _failClosed(
							`reeflex-core returned HTTP ${response.statusCode} without a decision` +
								(typeof body.error === 'string' ? `: ${body.error}` : '') +
								(typeof body.detail === 'string' ? ` (${body.detail})` : ''),
						);
					}
				} catch (error) {
					// Network-level failure: core unreachable, DNS failure, timeout, TLS
					// handshake failure, etc. - no HTTP response was ever received.
					decision = _failClosed(
						`reeflex-core unreachable: ${error instanceof Error ? error.message : String(error)}`,
					);
				}

				// Fail-closed-to-Denied is UNCONDITIONAL here (not gated behind
				// "Continue On Fail"): a governance gate that crashes the whole
				// workflow on a core outage defeats the purpose of having a Denied
				// output to alert on. This mirrors every other Reeflex adapter
				// (reeflex-claude, reeflex-wordpress): never silently allow, never
				// throw past the gate - always emit a definitive, auditable deny.
				// "Continue On Fail" still governs the outer catch below, which
				// covers this node's OWN configuration errors (e.g. missing Session
				// ID), a different error class from "core said no".
				// The original envelope is echoed back on every branch (not just
				// Denied) so that a downstream "resolve the hold, then resubmit"
				// flow (see /docs/guides/n8n.md, "the approval pattern") can take
				// `{{$json.reeflex.envelope}}`, set `approval.present = true` and
				// `approval.hold_id`, and POST it back to /v1/decide unmodified -
				// core's hash binding (SPEC "Approval object semantics") is over
				// action/axes/magnitude/target, so reusing this exact object
				// guarantees the hash matches.
				const outputItem: INodeExecutionData = {
					json: { ...items[itemIndex].json, reeflex: { ...decision, envelope } },
					pairedItem: { item: itemIndex },
				};

				if (decision.decision === 'allow') {
					allowedItems.push(outputItem);
				} else if (decision.decision === 'require_approval') {
					heldItems.push(outputItem);
				} else {
					// Covers 'deny' and any unexpected/unknown decision value - fail
					// closed rather than silently allowing (SPEC SS6).
					deniedItems.push(outputItem);
				}
			} catch (error) {
				if (this.continueOnFail()) {
					deniedItems.push({
						json: { ...items[itemIndex].json, error: error instanceof Error ? error.message : String(error) },
						pairedItem: { item: itemIndex },
					});
					continue;
				}
				throw error;
			}
		}

		return [allowedItems, heldItems, deniedItems];
	}
}
