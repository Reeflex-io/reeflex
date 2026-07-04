/**
 * Unit tests for the Reeflex Gate node, with a MOCKED reeflex-core.
 *
 * Deliberately imports NOTHING beyond the local source module and
 * `n8n-workflow` (types only, erased at compile time): no `node:test`,
 * no `node:assert`, no test-framework dependency. n8n's Cloud-compatibility
 * lint profile (`@n8n/community-nodes/no-restricted-imports`, enforced via
 * `n8n-node lint` with `"strict": true`) scans this whole package directory,
 * not just the published `dist/`, and flags any import outside its allowlist
 * - including Node's own built-in test/assert modules from a test-only file.
 * Editing `eslint.config.mjs` to exclude `test/` is explicitly blocked by
 * strict mode's "has been modified from the default configuration" check
 * (confirmed empirically: `npm run lint` refuses to run until the file is
 * byte-identical to the template). Zero non-source imports here is therefore
 * the actual fix, not a workaround - see PUBLISH.md section 1.
 *
 * Run with: npm test  (compiles via tsconfig.test.json, then runs the
 * compiled file directly with `node`; the file runs its own tests and exits
 * non-zero on any failure, so it composes with CI without a test-runner
 * dependency).
 */

import type {
	IDataObject,
	IExecuteFunctions,
	IHttpRequestOptions,
	IN8nHttpFullResponse,
	INode,
	INodeExecutionData,
} from 'n8n-workflow';

import { ReeflexGate } from '../nodes/ReeflexGate/ReeflexGate.node';

// ---------------------------------------------------------------------------
// Minimal hand-rolled test runner + assertions (see file header for why).
// ---------------------------------------------------------------------------

type TestFn = () => void | Promise<void>;
const tests: { name: string; fn: TestFn }[] = [];

function it(name: string, fn: TestFn): void {
	tests.push({ name, fn });
}

function assertEqual(actual: unknown, expected: unknown, message?: string): void {
	if (actual !== expected) {
		throw new Error(
			message ?? `Expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`,
		);
	}
}

function assertMatch(actual: unknown, pattern: RegExp, message?: string): void {
	const str = String(actual);
	if (!pattern.test(str)) {
		throw new Error(message ?? `Expected ${JSON.stringify(str)} to match ${pattern}`);
	}
}

async function assertRejects(fn: () => Promise<unknown>, pattern: RegExp): Promise<void> {
	try {
		await fn();
	} catch (error) {
		const msg = error instanceof Error ? error.message : String(error);
		if (!pattern.test(msg)) {
			throw new Error(`Expected rejection message to match ${pattern}, got: ${msg}`);
		}
		return;
	}
	throw new Error(`Expected the function to reject (matching ${pattern}), but it resolved`);
}

async function main(): Promise<void> {
	let pass = 0;
	let fail = 0;
	for (const t of tests) {
		try {
			await t.fn();
			pass += 1;
			console.log(`ok - ${t.name}`);
		} catch (error) {
			fail += 1;
			console.log(`NOT OK - ${t.name}`);
			console.log(`        ${error instanceof Error ? error.stack ?? error.message : String(error)}`);
		}
	}
	console.log(`\n${pass} passed, ${fail} failed, ${tests.length} total`);
	if (fail > 0) {
		process.exitCode = 1;
	}
}

// ---------------------------------------------------------------------------
// Test harness: a minimal IExecuteFunctions mock.
// ---------------------------------------------------------------------------

type ParamMap = Record<string, unknown>;

const DEFAULT_PARAMS: ParamMap = {
	ability: 'wordpress/delete-post',
	verb: 'delete',
	environment: 'production',
	reversibility: 'irreversible',
	blastRadius: 'systemic',
	externality: 'outbound',
	count: 1,
	targetSystem: 'wp-prod',
	sessionId: 'sess-test-1',
	agentId: 'agent:n8n-test',
	additionalFields: {},
};

const FAKE_NODE: INode = {
	id: 'test-node-id',
	name: 'Reeflex Gate',
	type: 'n8n-nodes-reeflex.reeflexGate',
	typeVersion: 1,
	position: [0, 0],
	parameters: {},
};

const FAKE_CREDENTIALS: IDataObject = {
	coreUrl: 'http://127.0.0.1:8080',
	apiToken: 'test-token',
	ignoreSslIssues: false,
};

interface HttpCall {
	credentialType: string;
	options: IHttpRequestOptions;
}

/**
 * Builds a fresh mock `this` context for ReeflexGate.execute(). Each test
 * supplies:
 *   - `items`: input items (defaults to a single empty-json item)
 *   - `params`: per-item parameter overrides (merged over DEFAULT_PARAMS)
 *   - `httpImpl`: the mocked httpRequestWithAuthentication behavior
 *   - `continueOnFail`: whether "Continue On Fail" is enabled
 * and returns both the mock context and a `calls` array capturing every
 * simulated HTTP call, so tests can assert on the outgoing Action Envelope.
 */
function makeMockExecuteFunctions(opts: {
	items?: INodeExecutionData[];
	params?: ParamMap[];
	httpImpl: (call: HttpCall) => Promise<IN8nHttpFullResponse>;
	continueOnFail?: boolean;
}): { ctx: IExecuteFunctions; calls: HttpCall[] } {
	const items = opts.items ?? [{ json: {} }];
	const paramsPerItem = opts.params ?? items.map(() => DEFAULT_PARAMS);
	const calls: HttpCall[] = [];

	const ctx = {
		getInputData(): INodeExecutionData[] {
			return items;
		},
		getNodeParameter(name: string, itemIndex: number, fallback?: unknown): unknown {
			const params = paramsPerItem[itemIndex] ?? {};
			if (Object.prototype.hasOwnProperty.call(params, name)) {
				return params[name];
			}
			return fallback;
		},
		async getCredentials(): Promise<IDataObject> {
			return FAKE_CREDENTIALS;
		},
		getNode(): INode {
			return FAKE_NODE;
		},
		continueOnFail(): boolean {
			return opts.continueOnFail ?? false;
		},
		helpers: {
			async httpRequestWithAuthentication(
				credentialType: string,
				options: IHttpRequestOptions,
			): Promise<IN8nHttpFullResponse> {
				const call = { credentialType, options };
				calls.push(call);
				return opts.httpImpl(call);
			},
		},
	} as unknown as IExecuteFunctions;

	return { ctx, calls };
}

function fullResponse(statusCode: number, body: IDataObject): IN8nHttpFullResponse {
	return {
		statusCode,
		body,
		headers: {},
		statusMessage: statusCode === 200 ? 'OK' : 'Error',
	} as IN8nHttpFullResponse;
}

function runExecute(ctx: IExecuteFunctions): Promise<INodeExecutionData[][]> {
	const node = new ReeflexGate();
	return node.execute.call(ctx as IExecuteFunctions);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

it('routes an "allow" decision to output 0 (Allowed)', async () => {
	const { ctx } = makeMockExecuteFunctions({
		httpImpl: async () =>
			fullResponse(200, {
				decision: 'allow',
				reason: 'read-only action',
				rule: 'reeflex.policy/read_only',
				obligations: [],
				modulation: null,
			}),
	});

	const [allowed, held, denied] = await runExecute(ctx);

	assertEqual(allowed.length, 1);
	assertEqual(held.length, 0);
	assertEqual(denied.length, 0);
	assertEqual((allowed[0].json.reeflex as IDataObject).decision, 'allow');
});

it('routes a "require_approval" decision to output 1 (Held for Approval) and preserves hold_id/expires_ts', async () => {
	const { ctx } = makeMockExecuteFunctions({
		httpImpl: async () =>
			fullResponse(200, {
				decision: 'require_approval',
				reason: 'irreversible bulk delete in production requires human approval',
				rule: 'reeflex.policy/irreversible_broad_prod',
				obligations: ['audit:full'],
				modulation: null,
				hold_id: 'a3f8c1d2e4b7',
				expires_ts: '2026-07-04T16:00:00Z',
			}),
	});

	const [allowed, held, denied] = await runExecute(ctx);

	assertEqual(allowed.length, 0);
	assertEqual(held.length, 1);
	assertEqual(denied.length, 0);
	const reeflex = held[0].json.reeflex as IDataObject;
	assertEqual(reeflex.decision, 'require_approval');
	assertEqual(reeflex.hold_id, 'a3f8c1d2e4b7');
	assertEqual(reeflex.expires_ts, '2026-07-04T16:00:00Z');
});

it('routes a "deny" decision to output 2 (Denied)', async () => {
	const { ctx } = makeMockExecuteFunctions({
		httpImpl: async () =>
			fullResponse(200, {
				decision: 'deny',
				reason: 'frozen by operator',
				rule: 'reeflex.policy/frozen',
				obligations: [],
				modulation: null,
			}),
	});

	const [allowed, held, denied] = await runExecute(ctx);

	assertEqual(allowed.length, 0);
	assertEqual(held.length, 0);
	assertEqual(denied.length, 1);
	assertEqual((denied[0].json.reeflex as IDataObject).rule, 'reeflex.policy/frozen');
});

it('fails closed to Denied (unconditionally, even without Continue On Fail) when core is unreachable', async () => {
	const { ctx } = makeMockExecuteFunctions({
		continueOnFail: false,
		httpImpl: async () => {
			throw new Error('connect ECONNREFUSED 127.0.0.1:8080');
		},
	});

	const [allowed, held, denied] = await runExecute(ctx);

	assertEqual(allowed.length, 0);
	assertEqual(held.length, 0);
	assertEqual(denied.length, 1);
	const reeflex = denied[0].json.reeflex as IDataObject;
	assertEqual(reeflex.decision, 'deny');
	assertEqual(reeflex.rule, 'n8n-nodes-reeflex/fail_closed');
	assertMatch(reeflex.reason, /unreachable/);
	assertMatch(reeflex.reason, /ECONNREFUSED/);
});

it('fails closed to Denied and preserves the real reason when core returns HTTP 500 with an embedded decision', async () => {
	// Mirrors reeflex-core app/decide.py `process()`: HTTP 500 -> internal
	// error -> deny, WITH a usable decision body (fail-closed on core's own
	// side too). The node must surface that real reason, not a synthetic one.
	const { ctx } = makeMockExecuteFunctions({
		httpImpl: async () =>
			fullResponse(500, {
				decision: 'deny',
				reason: 'internal error - failing closed',
				rule: 'reeflex.core/internal_error',
				obligations: [],
				modulation: null,
			}),
	});

	const [allowed, held, denied] = await runExecute(ctx);

	assertEqual(allowed.length, 0);
	assertEqual(held.length, 0);
	assertEqual(denied.length, 1);
	const reeflex = denied[0].json.reeflex as IDataObject;
	assertEqual(reeflex.decision, 'deny');
	assertEqual(reeflex.rule, 'reeflex.core/internal_error');
	assertEqual(reeflex.reason, 'internal error - failing closed');
});

it('fails closed to Denied with a synthetic reason when core returns HTTP 400 with no decision field', async () => {
	const { ctx } = makeMockExecuteFunctions({
		httpImpl: async () =>
			fullResponse(400, {
				error: 'invalid_envelope',
				detail: 'axes.reversibility missing',
			}),
	});

	const [allowed, , denied] = await runExecute(ctx);

	assertEqual(allowed.length, 0);
	assertEqual(denied.length, 1);
	const reeflex = denied[0].json.reeflex as IDataObject;
	assertEqual(reeflex.decision, 'deny');
	assertEqual(reeflex.rule, 'n8n-nodes-reeflex/fail_closed');
	assertMatch(reeflex.reason, /HTTP 400/);
	assertMatch(reeflex.reason, /invalid_envelope/);
	assertMatch(reeflex.reason, /axes\.reversibility missing/);
});

it('derives action.namespace from the part of Ability before the first "/"', async () => {
	const { ctx, calls } = makeMockExecuteFunctions({
		params: [{ ...DEFAULT_PARAMS, ability: 'postgres/delete-rows' }],
		httpImpl: async () =>
			fullResponse(200, { decision: 'allow', reason: 'ok', rule: 'x', obligations: [], modulation: null }),
	});

	await runExecute(ctx);

	assertEqual(calls.length, 1);
	const envelope = calls[0].options.body as IDataObject;
	const action = envelope.action as IDataObject;
	assertEqual(action.namespace, 'postgres');
	assertEqual(action.ability, 'postgres/delete-rows');
});

it('falls back action.namespace to "n8n" when Ability has no "/"', async () => {
	const { ctx, calls } = makeMockExecuteFunctions({
		params: [{ ...DEFAULT_PARAMS, ability: 'send-email' }],
		httpImpl: async () =>
			fullResponse(200, { decision: 'allow', reason: 'ok', rule: 'x', obligations: [], modulation: null }),
	});

	await runExecute(ctx);

	const envelope = calls[0].options.body as IDataObject;
	assertEqual((envelope.action as IDataObject).namespace, 'n8n');
});

it('sets all three axes and agent.session_id on the outgoing envelope (SPEC SS2/SS4.1)', async () => {
	const { ctx, calls } = makeMockExecuteFunctions({
		httpImpl: async () =>
			fullResponse(200, { decision: 'allow', reason: 'ok', rule: 'x', obligations: [], modulation: null }),
	});

	await runExecute(ctx);

	const envelope = calls[0].options.body as IDataObject;
	const axes = envelope.axes as IDataObject;
	assertEqual(axes.reversibility, 'irreversible');
	assertEqual(axes.blast_radius, 'systemic');
	assertEqual(axes.externality, 'outbound');
	assertEqual((envelope.agent as IDataObject).session_id, 'sess-test-1');
	assertEqual((envelope.approval as IDataObject).present, false);
});

it('sends skipSslCertificateValidation=true only when the credential opts out of TLS verification', async () => {
	const { ctx, calls } = makeMockExecuteFunctions({
		httpImpl: async () =>
			fullResponse(200, { decision: 'allow', reason: 'ok', rule: 'x', obligations: [], modulation: null }),
	});
	(ctx.getCredentials as unknown as () => Promise<IDataObject>) = async () => ({
		...FAKE_CREDENTIALS,
		ignoreSslIssues: true,
	});

	await runExecute(ctx);

	assertEqual(calls[0].options.skipSslCertificateValidation, true);
});

it("input validation > throws when Action / Ability is empty and Continue On Fail is off", async () => {
	const { ctx } = makeMockExecuteFunctions({
		params: [{ ...DEFAULT_PARAMS, ability: '' }],
		continueOnFail: false,
		httpImpl: async () => {
			throw new Error('should not be called');
		},
	});

	await assertRejects(() => runExecute(ctx), /Action \/ Ability is required/);
});

it('input validation > routes to Denied with a plain error (no reeflex key) when Ability is empty and Continue On Fail is on', async () => {
	const { ctx } = makeMockExecuteFunctions({
		params: [{ ...DEFAULT_PARAMS, ability: '' }],
		continueOnFail: true,
		httpImpl: async () => {
			throw new Error('should not be called');
		},
	});

	const [allowed, held, denied] = await runExecute(ctx);
	assertEqual(allowed.length, 0);
	assertEqual(held.length, 0);
	assertEqual(denied.length, 1);
	assertEqual(denied[0].json.reeflex, undefined);
	assertMatch(denied[0].json.error, /Action \/ Ability is required/);
});

it('input validation > throws when Session ID is empty (fragmentation-resistance requires a stable session id, SPEC SS4.1)', async () => {
	const { ctx } = makeMockExecuteFunctions({
		params: [{ ...DEFAULT_PARAMS, sessionId: '' }],
		continueOnFail: false,
		httpImpl: async () => {
			throw new Error('should not be called');
		},
	});

	await assertRejects(() => runExecute(ctx), /Session ID is required/);
});

it('processes multiple items independently, one call to core per item', async () => {
	const items: INodeExecutionData[] = [{ json: { row: 1 } }, { json: { row: 2 } }];
	const paramsPerItem: ParamMap[] = [
		{ ...DEFAULT_PARAMS, sessionId: 'sess-a' },
		{ ...DEFAULT_PARAMS, sessionId: 'sess-b' },
	];
	let call = 0;
	const { ctx, calls } = makeMockExecuteFunctions({
		items,
		params: paramsPerItem,
		httpImpl: async () => {
			call += 1;
			return call === 1
				? fullResponse(200, { decision: 'allow', reason: 'ok', rule: 'x', obligations: [], modulation: null })
				: fullResponse(200, { decision: 'deny', reason: 'no', rule: 'y', obligations: [], modulation: null });
		},
	});

	const [allowed, held, denied] = await runExecute(ctx);

	assertEqual(calls.length, 2);
	assertEqual(allowed.length, 1);
	assertEqual(held.length, 0);
	assertEqual(denied.length, 1);
	assertEqual(allowed[0].json.row, 1);
	assertEqual(denied[0].json.row, 2);
	assertEqual((calls[0].options.body as IDataObject & { agent: IDataObject }).agent.session_id, 'sess-a');
	assertEqual((calls[1].options.body as IDataObject & { agent: IDataObject }).agent.session_id, 'sess-b');
});

void main();
