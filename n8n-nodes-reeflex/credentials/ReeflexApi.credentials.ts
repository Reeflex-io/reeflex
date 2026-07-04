import type {
	IAuthenticateGeneric,
	ICredentialTestRequest,
	ICredentialType,
	Icon,
	INodeProperties,
} from 'n8n-workflow';

/**
 * Credential for reeflex-core (see ../../../reeflex-core/README.md).
 *
 * Test strategy: GET /v1/holds?limit=1. This is the read-only, side-effect-free
 * endpoint that shares the exact same Bearer auth as POST /v1/decide (see
 * reeflex-core README, "Holds API"), so a passing test genuinely validates both
 * reachability AND the token - not just that *some* URL responds. GET /healthz
 * is deliberately NOT used for the test because it is always unauthenticated
 * (reeflex-core README, HIL Phase 1 notes) and would pass even with a wrong
 * token, which would be a false-positive credential test.
 *
 * Requires reeflex-core v0.1.5+ (HIL Phase 1 - the Holds API).
 */
export class ReeflexApi implements ICredentialType {
	name = 'reeflexApi';

	displayName = 'Reeflex API';

	icon: Icon = 'file:../nodes/ReeflexGate/reeflexGate.svg';

	documentationUrl = 'https://github.com/Reeflex-io/reeflex/blob/main/reeflex-core/README.md';

	properties: INodeProperties[] = [
		{
			displayName: 'Core URL',
			name: 'coreUrl',
			type: 'string',
			default: 'http://127.0.0.1:8080',
			placeholder: 'e.g. https://core.example.com',
			description:
				'Base URL of your reeflex-core instance, with no trailing slash and no path. The node calls "<Core URL>/v1/decide"',
			required: true,
		},
		{
			displayName: 'API Token',
			name: 'apiToken',
			type: 'string',
			typeOptions: { password: true },
			default: '',
			description:
				"Bearer token for reeflex-core (the server's REEFLEX_AUTH_TOKEN environment variable). Leave empty only if the server has auth disabled (REEFLEX_AUTH_TOKEN unset)",
		},
		{
			displayName: 'Ignore SSL Issues (Insecure)',
			name: 'ignoreSslIssues',
			type: 'boolean',
			default: false,
			description:
				'Whether to accept invalid or self-signed TLS certificates when connecting to reeflex-core. Only enable this for trusted development or self-signed endpoints - it removes protection against man-in-the-middle attacks. Use at your own risk',
		},
	];

	authenticate: IAuthenticateGeneric = {
		type: 'generic',
		properties: {
			headers: {
				Authorization: '=Bearer {{$credentials.apiToken}}',
			},
		},
	};

	// NOTE: this test does not honor "Ignore SSL Issues" (n8n's credential test
	// request does not accept an expression for skipSslCertificateValidation in
	// the current @n8n/node-cli type surface). Against a self-signed Core URL,
	// this Test button may fail even though the node's actual POST /v1/decide
	// call at execution time correctly applies the setting. Upgrade path: revisit
	// once n8n exposes a typed way to parameterize test-request TLS behavior from
	// credential fields.
	test: ICredentialTestRequest = {
		request: {
			baseURL: '={{$credentials.coreUrl}}',
			url: '/v1/holds',
			method: 'GET',
			qs: {
				limit: 1,
			},
		},
	};
}
