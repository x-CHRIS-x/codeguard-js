/**
 * JSentinel Canonical Guidance Catalog (CommonJS Target for VS Code Extension)
 * 
 * Centralized remediation guidance catalog covering all 27 OWASP Top 10:2021 rules
 * and 5 multi-scenario variants. Provides educational rationale, risk analysis,
 * static analyzer limitations, explicit context checks, conditional approaches, and verification steps.
 * Examples are optional illustrations; architectural recommendations use text guidance.
 * 
 * Strict safety rules:
 * - Zero replacementCode, goodSnippet, bad, or deterministic flags.
 * - Max 2 conditional approaches per entry.
 * - Non-prescriptive, guidance-only advice.
 */

const GUIDANCE_DISCLAIMER =
  "Guidance only — not a drop-in replacement. Choose an approach that preserves your code's intended behavior.";

const EDUCATIONAL_DISCLAIMER = GUIDANCE_DISCLAIMER;

const FALLBACK_GUIDANCE = {
  guidanceId: 'UNKNOWN',
  ruleId: 'UNKNOWN',
  variant: null,
  title: 'Security Review Recommendation',
  category: 'General Security Practice',
  categoryUrl: 'https://owasp.org/',
  shortAction: 'If the flagged behavior handles untrusted or sensitive data, review the relevant project security controls.',
  recommendedAction: 'If the flagged behavior handles untrusted or sensitive data, review the relevant project security controls.',
  summary: 'If the flagged behavior handles untrusted or sensitive data, review the relevant project security controls.',
  contextCheck: 'What does the flagged code do, and which security requirement applies?',
  risk: 'An unclassified pattern needs review before its security impact can be established.',
  cannotInfer: 'JSentinel cannot determine application intent, runtime context or existing controls.',
  scope: 'cross-boundary',
  approaches: [
    'If the behavior is sensitive, trace its inputs and effects and review the relevant application security requirements.',
    'If the pattern is intentional and covered by existing controls, document the reason and verify those controls.'
  ],
  verifySteps: [
    'Confirm the flagged behavior satisfies the applicable security requirement.',
    'Test intended inputs and relevant invalid or untrusted inputs.'
  ],
  references: [
    {
      title: 'OWASP Top 10 Security Risks',
      url: 'https://owasp.org/www-project-top-ten/'
    }
  ],
  illustrativePattern: null
};

const guidanceCatalog = {
  // =========================================================================
  // A01:2021 - Broken Access Control
  // =========================================================================
  'OWASP-A01-001': {
    guidanceId: 'OWASP-A01-001',
    ruleId: 'OWASP-A01-001',
    variant: null,
    title: 'Open Redirect Navigation Target',
    category: 'A01:2021-Broken Access Control',
    categoryUrl: 'https://owasp.org/Top10/A01_2021-Broken_Access_Control/',
    shortAction: 'If navigation is internal, enforce the parsed origin and route policy; otherwise allow only approved destinations.',
    recommendedAction: 'If navigation is internal, enforce the parsed origin and route policy; otherwise allow only approved destinations.',
    summary: 'If navigation is internal, enforce the parsed origin and route policy; otherwise allow only approved destinations.',
    contextCheck: 'Should this destination stay inside the app, or can it use approved external sites?',
    risk: 'An attacker-controlled navigation target can send users to a phishing site under the appearance of a trusted link.',
    cannotInfer: 'JSentinel cannot identify intended routes, approved external origins, or existing destination checks.',
    scope: 'browser',
    approaches: [
      'For known internal destinations, map route identifiers to fixed paths. If accepting a path, parse it against the app origin, check the resulting origin and approved route, and navigate using that checked URL.',
      'For intentional external navigation, check the parsed scheme, origin and any required path restrictions against an explicit allowlist before using the checked URL.'
    ],
    verifySteps: [
      'Reject unauthorized absolute URLs, protocol-relative URLs, slash/backslash combinations, and encoded forms after the app\'s decoding steps.',
      'Confirm allowed routes, query parameters and external destinations still navigate as intended.'
    ],
    references: [
      { title: 'MDN URL Constructor', url: 'https://developer.mozilla.org/en-US/docs/Web/API/URL/URL' },
      { title: 'OWASP A01:2021 – Broken Access Control', url: 'https://owasp.org/Top10/A01_2021-Broken_Access_Control/' },
      { title: 'OWASP Unvalidated Redirects and Forwards Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html' }
    ],
    illustrativePattern: null
  },

  'OWASP-A01-002': {
    guidanceId: 'OWASP-A01-002',
    ruleId: 'OWASP-A01-002',
    variant: null,
    title: 'Client-Side Role Authorization Guard',
    category: 'A01:2021-Broken Access Control',
    categoryUrl: 'https://owasp.org/Top10/A01_2021-Broken_Access_Control/',
    shortAction: 'If this UI check protects sensitive operations, verify authorization on every corresponding server request.',
    recommendedAction: 'If this UI check protects sensitive operations, verify authorization on every corresponding server request.',
    summary: 'If this UI check protects sensitive operations, verify authorization on every corresponding server request.',
    contextCheck: 'Does the server already authorize the protected action independently of the UI?',
    risk: 'Users can change browser state or call an API directly to bypass client-side permission gates.',
    cannotInfer: 'JSentinel cannot inspect server authorization, resource ownership checks, or session permissions.',
    scope: 'cross-boundary',
    approaches: [
      'If the action needs protection, enforce server authorization for the current user and target resource on every request; keep the client check for presentation.',
      'If server authorization already exists, confirm it covers this action and resource before changing the UI guard.'
    ],
    verifySteps: [
      'Call the protected API without credentials and as a user lacking the required permission; confirm access is denied.',
      'Change client role state and resource identifiers; confirm server decisions remain correct.'
    ],
    references: [
      { title: 'OWASP A01:2021 – Broken Access Control', url: 'https://owasp.org/Top10/A01_2021-Broken_Access_Control/' },
      { title: 'OWASP Authorization Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html' }
    ],
    illustrativePattern: null
  },

  // =========================================================================
  // A02:2021 - Cryptographic Failures
  // =========================================================================
  'OWASP-A02-001': {
    guidanceId: 'OWASP-A02-001',
    ruleId: 'OWASP-A02-001',
    variant: null,
    title: 'Hardcoded Credentials in Source Code',
    category: 'A02:2021-Cryptographic Failures',
    categoryUrl: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
    shortAction: 'If this is a real exposed credential, revoke or rotate it and keep its replacement in server secret storage.',
    recommendedAction: 'If this is a real exposed credential, revoke or rotate it and keep its replacement in server secret storage.',
    summary: 'If this is a real exposed credential, revoke or rotate it and keep its replacement in server secret storage.',
    contextCheck: 'Is this an active credential, or an intentionally non-secret test value?',
    risk: 'Real credentials committed to source can be copied from repositories, history, logs or shipped client code.',
    cannotInfer: 'JSentinel cannot determine whether the value is valid, exposed, or used only as test data.',
    scope: 'server',
    approaches: [
      'For a real credential, revoke or rotate it with its issuer, remove it from source, and load the replacement from server runtime configuration or a secret manager.',
      'For a non-secret fixture, confirm it cannot authenticate to a real service and clearly identify it as test data.'
    ],
    verifySteps: [
      'For a real exposure, confirm the old credential no longer works and the replacement works with only required permissions.',
      'Check current source and client bundles for real secrets; assess history and other copies through the team\'s exposure response process.',
      'For fixtures, confirm they have no access to live accounts.'
    ],
    references: [
      { title: 'OWASP A02:2021 – Cryptographic Failures', url: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/' },
      { title: 'OWASP Secrets Management Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html' }
    ],
    illustrativePattern: null
  },

  'OWASP-A02-002': {
    guidanceId: 'OWASP-A02-002',
    ruleId: 'OWASP-A02-002',
    variant: null,
    title: 'Insecure Cookie Configuration',
    category: 'A02:2021-Cryptographic Failures',
    categoryUrl: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
    shortAction: 'For session cookies, have the server set HttpOnly, Secure and a SameSite policy that fits the authentication flow.',
    recommendedAction: 'For session cookies, have the server set HttpOnly, Secure and a SameSite policy that fits the authentication flow.',
    summary: 'For session cookies, have the server set HttpOnly, Secure and a SameSite policy that fits the authentication flow.',
    contextCheck: 'Is this an authentication cookie, and which cross-site flows must it support?',
    risk: 'Script-readable session cookies can be stolen through XSS; cookies sent over HTTP can be intercepted.',
    cannotInfer: 'JSentinel cannot inspect response headers or login flows; browser JavaScript cannot set HttpOnly cookies.',
    scope: 'cross-boundary',
    approaches: [
      'For session cookies, configure server session middleware or Set-Cookie headers with HttpOnly and Secure. Choose SameSite for the required cross-site flow and review CSRF protection for state-changing requests.',
      'For a non-sensitive cookie that scripts must read, retain required script access and choose transport and SameSite settings for that cookie\'s purpose.'
    ],
    verifySteps: [
      'Inspect the actual Set-Cookie response and confirm session values cannot be read through document.cookie.',
      'Test login, logout, external login callbacks and any required cross-site requests with the chosen SameSite policy.',
      'Confirm unauthorized cross-site state-changing requests are blocked by the application\'s CSRF controls.'
    ],
    references: [
      { title: 'OWASP Cross-Site Request Forgery Prevention', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html' },
      { title: 'MDN Set-Cookie Header Reference', url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie' },
      { title: 'OWASP Session Management Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html' }
    ],
    illustrativePattern: null
  },

  'OWASP-A02-003': {
    guidanceId: 'OWASP-A02-003',
    ruleId: 'OWASP-A02-003',
    variant: null,
    title: 'Insecure Pseudo-Random Number Generator',
    category: 'A02:2021-Cryptographic Failures',
    categoryUrl: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
    shortAction: 'If randomness protects a token or other security decision, use a cryptographic generator with the required format and entropy.',
    recommendedAction: 'If randomness protects a token or other security decision, use a cryptographic generator with the required format and entropy.',
    summary: 'If randomness protects a token or other security decision, use a cryptographic generator with the required format and entropy.',
    contextCheck: 'Does this random value protect a security decision, or only affect presentation?',
    risk: 'Math.random() is not designed for security; predictable values can undermine tokens or other security decisions.',
    cannotInfer: 'JSentinel cannot determine the value\'s purpose, required entropy, format, or runtime.',
    scope: 'browser',
    approaches: [
      'For security values, use Web Crypto in browsers or Node.js crypto on servers, with the length and format required by the protocol.',
      'For animation, sampling or other non-security behavior, keep ordinary randomness if its properties meet the application\'s needs.'
    ],
    verifySteps: [
      'Trace the value\'s uses to confirm whether unpredictability is a security requirement.',
      'For security values, verify the generator, output length and format meet the protocol\'s requirements in the target runtime.',
      'Confirm existing consumers accept the new format and non-security behavior still works.'
    ],
    references: [
      { title: 'MDN Web Crypto API', url: 'https://developer.mozilla.org/en-US/docs/Web/API/Window/crypto' },
      { title: 'OWASP Cryptographic Storage Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html' }
    ],
    illustrativePattern: '// If this browser feature needs an unpredictable UUID and that format fits its protocol.\n// crypto.randomUUID() requires a secure context; it does not fit every token format.\nconst identifier = crypto.randomUUID();'
  },

  'OWASP-A02-004': {
    guidanceId: 'OWASP-A02-004',
    ruleId: 'OWASP-A02-004',
    variant: null,
    title: 'Plaintext HTTP Endpoint Communication',
    category: 'A02:2021-Cryptographic Failures',
    categoryUrl: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
    shortAction: 'If the service supports TLS, use its verified HTTPS endpoint; otherwise coordinate the required service change.',
    recommendedAction: 'If the service supports TLS, use its verified HTTPS endpoint; otherwise coordinate the required service change.',
    summary: 'If the service supports TLS, use its verified HTTPS endpoint; otherwise coordinate the required service change.',
    contextCheck: 'Does this service support a valid TLS endpoint in the target environment?',
    risk: 'HTTP traffic can expose or allow alteration of request and response data in transit.',
    cannotInfer: 'JSentinel cannot verify TLS support, certificates, endpoint ports or deployment routing.',
    scope: 'cross-boundary',
    approaches: [
      'If HTTPS is supported, update configuration to the verified endpoint and send sensitive requests directly over HTTPS.',
      'If HTTPS is unavailable, coordinate TLS support with the service owner before migrating; moving a URL into configuration alone does not encrypt traffic.'
    ],
    verifySteps: [
      'Confirm the HTTPS endpoint has a valid certificate and supports the required API behavior.',
      'Check that sensitive requests start over HTTPS and that browser flows have no mixed-content failures.'
    ],
    references: [
      { title: 'OWASP Transport Layer Security Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html' },
      { title: 'MDN HTTPS Security', url: 'https://developer.mozilla.org/en-US/docs/Glossary/HTTPS' }
    ],
    illustrativePattern: null
  },

  'OWASP-A02-005': {
    guidanceId: 'OWASP-A02-005',
    ruleId: 'OWASP-A02-005',
    variant: null,
    title: 'Hardcoded Secret Patterns',
    category: 'A02:2021-Cryptographic Failures',
    categoryUrl: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
    shortAction: 'If this is a real secret, revoke or rotate it and move its replacement to server secret storage.',
    recommendedAction: 'If this is a real secret, revoke or rotate it and move its replacement to server secret storage.',
    summary: 'If this is a real secret, revoke or rotate it and move its replacement to server secret storage.',
    contextCheck: 'Is the matched value a real secret, an endpoint address, or non-secret test data?',
    risk: 'Real secrets in source or client bundles can grant unauthorized access; an address alone is not an authentication secret.',
    cannotInfer: 'JSentinel cannot establish the value\'s validity, sensitivity, exposure, or purpose.',
    scope: 'server',
    approaches: [
      'For real credentials, revoke or rotate exposed values, remove them from source, and load replacements from server runtime configuration or a secret manager.',
      'For endpoint addresses or fixtures, review their actual sensitivity and access controls; moving client configuration does not make it secret.'
    ],
    verifySteps: [
      'For real credentials, confirm old values are revoked and replacements authenticate correctly.',
      'Check current source and client output for secrets, and assess historical copies through the team\'s exposure response process.',
      'For addresses or fixtures, confirm the intended connectivity and that no live credential is embedded.'
    ],
    references: [
      { title: 'OWASP A02:2021 – Cryptographic Failures', url: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/' },
      { title: 'Vite Environment Variables & Modes', url: 'https://vite.dev/guide/env-and-mode' }
    ],
    illustrativePattern: null
  },

  'OWASP-A02-005:credential': {
    guidanceId: 'OWASP-A02-005:credential',
    ruleId: 'OWASP-A02-005',
    variant: 'credential',
    title: 'Hardcoded Credential or Token',
    category: 'A02:2021-Cryptographic Failures',
    categoryUrl: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
    shortAction: 'If this is a real exposed token or key, revoke or rotate it and use the appropriate server-managed credential flow.',
    recommendedAction: 'If this is a real exposed token or key, revoke or rotate it and use the appropriate server-managed credential flow.',
    summary: 'If this is a real exposed token or key, revoke or rotate it and use the appropriate server-managed credential flow.',
    contextCheck: 'Is this token or key usable against a real service, and has it been exposed?',
    risk: 'Hardcoded credentials, such as usable tokens and service keys, can give anyone who obtains the code access to protected services.',
    cannotInfer: 'JSentinel cannot verify credential validity or exposure; values injected into client bundles remain public.',
    scope: 'server',
    approaches: [
      'For service keys or signing secrets, revoke or rotate exposed values and store replacements in server runtime secret storage.',
      'For user access tokens, revoke exposed tokens and obtain short-lived tokens through the intended authentication flow instead of embedding a reusable value.'
    ],
    verifySteps: [
      'Confirm exposed credentials no longer authenticate and the intended authentication flow still works.',
      'Check client bundles and current source for reusable secrets; assess historical copies through the exposure response process.',
      'Verify replacements have only the permissions and lifetime required.'
    ],
    references: [
      { title: 'OWASP Secrets Management Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html' },
      { title: 'Vite Environment Variables & Modes', url: 'https://vite.dev/guide/env-and-mode' }
    ],
    illustrativePattern: null
  },

  'OWASP-A02-005:network-address': {
    guidanceId: 'OWASP-A02-005:network-address',
    ruleId: 'OWASP-A02-005',
    variant: 'network-address',
    title: 'Static Network IP Address Literal',
    category: 'A02:2021-Cryptographic Failures',
    categoryUrl: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
    shortAction: 'If the endpoint varies by deployment, move it to configuration and verify its transport and access controls.',
    recommendedAction: 'If the endpoint varies by deployment, move it to configuration and verify its transport and access controls.',
    summary: 'If the endpoint varies by deployment, move it to configuration and verify its transport and access controls.',
    contextCheck: 'Is this a deployment-specific endpoint, and does exposing its address matter?',
    risk: 'A hardcoded address can reveal infrastructure details or break when routing changes; hiding the address does not secure the service.',
    cannotInfer: 'JSentinel cannot determine network topology, address sensitivity, routing, or service access controls.',
    scope: 'cross-boundary',
    approaches: [
      'If the endpoint differs across deployments, configure it per environment and use a service hostname when appropriate for routing and TLS.',
      'If the address is intentionally fixed or public, retain it when required and verify authentication, authorization and encrypted transport independently.'
    ],
    verifySteps: [
      'Confirm the endpoint resolves and connects correctly in each supported environment.',
      'Verify intended authentication and TLS behavior; check client output if the address must not be exposed.'
    ],
    references: [
      { title: 'OWASP A02:2021 – Cryptographic Failures', url: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/' },
      { title: 'RFC 1918 Private Address Allocation', url: 'https://datatracker.ietf.org/doc/html/rfc1918' }
    ],
    illustrativePattern: null
  },

  'OWASP-A02-006': {
    guidanceId: 'OWASP-A02-006',
    ruleId: 'OWASP-A02-006',
    variant: null,
    title: 'Exposed API Key in Variable Declaration',
    category: 'A02:2021-Cryptographic Failures',
    categoryUrl: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
    shortAction: 'For an exposed secret key, revoke or rotate it and keep its replacement on the server; restrict public keys at the provider.',
    recommendedAction: 'For an exposed secret key, revoke or rotate it and keep its replacement on the server; restrict public keys at the provider.',
    summary: 'For an exposed secret key, revoke or rotate it and keep its replacement on the server; restrict public keys at the provider.',
    contextCheck: 'Is this a privileged secret key, or a provider-designated public client key?',
    risk: 'Privileged API keys exposed in source or client bundles can be extracted and used outside the application.',
    cannotInfer: 'JSentinel cannot determine the provider\'s key type, permissions, restrictions, or proxy architecture.',
    scope: 'cross-boundary',
    approaches: [
      'For privileged keys, revoke or rotate exposed values and keep replacements in server runtime secret storage. Authorize and constrain any backend proxy that uses them.',
      'For provider-designated public client keys, apply supported application, API and quota restrictions; build-time environment variables do not conceal bundled values.'
    ],
    verifySteps: [
      'For secret keys, confirm old values are revoked and no replacement secret appears in client bundles.',
      'For public keys, test provider restrictions and verify only required APIs and permissions are enabled.',
      'If a proxy is used, confirm its callers and forwarded operations are authorized.'
    ],
    references: [
      { title: 'Vite Environment Variables and Modes', url: 'https://vite.dev/guide/env-and-mode' },
      { title: 'OWASP Key Management Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html' },
      { title: 'OWASP A02:2021 – Cryptographic Failures', url: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/' }
    ],
    illustrativePattern: null
  },

  'OWASP-A02-007': {
    guidanceId: 'OWASP-A02-007',
    ruleId: 'OWASP-A02-007',
    variant: null,
    title: 'Sensitive Credentials in URL Query String',
    category: 'A02:2021-Cryptographic Failures',
    categoryUrl: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
    shortAction: 'If the API supports it, move credentials from URLs to its HTTPS authorization header or request-body contract.',
    recommendedAction: 'If the API supports it, move credentials from URLs to its HTTPS authorization header or request-body contract.',
    summary: 'If the API supports it, move credentials from URLs to its HTTPS authorization header or request-body contract.',
    contextCheck: 'Which credential transport does the receiving API actually support?',
    risk: 'Credentials in URLs can appear in history, logs, copied links or referrers, depending on the request and policy.',
    cannotInfer: 'JSentinel cannot determine the receiving API\'s contract, logging policies, or permitted authentication methods.',
    scope: 'cross-boundary',
    approaches: [
      'If the API supports headers or request bodies, use its documented credential mechanism over HTTPS and redact sensitive fields from logs.',
      'If a third-party contract requires a query credential, review supported alternatives with the provider and limit credential scope, lifetime and URL exposure.'
    ],
    verifySteps: [
      'Confirm the intended request still authenticates using the supported contract over HTTPS.',
      'Inspect request URLs and relevant logs for unintended credential exposure.',
      'If query credentials remain required, verify the documented restrictions and exposure controls.'
    ],
    references: [
      { title: 'OWASP REST Security Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html' },
      { title: 'RFC 6750 Bearer Token Usage', url: 'https://datatracker.ietf.org/doc/html/rfc6750' }
    ],
    illustrativePattern: null
  },

  // =========================================================================
  // A03:2021 - Injection
  // =========================================================================
  'OWASP-A03-001': {
    guidanceId: 'OWASP-A03-001',
    ruleId: 'OWASP-A03-001',
    variant: null,
    title: 'Dynamic Code Evaluation (eval)',
    category: 'A03:2021-Injection',
    categoryUrl: 'https://owasp.org/Top10/A03_2021-Injection/',
    shortAction: 'If the input represents data or a fixed operation, replace eval with the matching parser or explicit dispatch.',
    recommendedAction: 'If the input represents data or a fixed operation, replace eval with the matching parser or explicit dispatch.',
    summary: 'If the input represents data or a fixed operation, replace eval with the matching parser or explicit dispatch.',
    contextCheck: 'Is the evaluated string data, a property name, or an intentional expression language?',
    risk: 'Evaluating attacker-influenced JavaScript can run arbitrary code with the application\'s privileges.',
    cannotInfer: 'JSentinel cannot determine the input format, supported expressions, or intended evaluation behavior.',
    scope: 'browser',
    approaches: [
      'For JSON or property access, use JSON.parse with schema and error handling, or explicitly permitted property lookups, as appropriate to the input.',
      'For intentional formulas or operations, use fixed handlers or a restricted interpreter with documented language and resource limits; do not assume a parser is a security sandbox.'
    ],
    verifySteps: [
      'Confirm unsupported code cannot execute through user input and malformed input has a defined error path.',
      'Test representative valid data or expressions to preserve required behavior.'
    ],
    references: [
      { title: 'MDN eval() Reference and Security Risks', url: 'https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval' },
      { title: 'OWASP A03:2021 – Injection', url: 'https://owasp.org/Top10/A03_2021-Injection/' }
    ],
    illustrativePattern: null
  },

  'OWASP-A03-002': {
    guidanceId: 'OWASP-A03-002',
    ruleId: 'OWASP-A03-002',
    variant: null,
    title: 'String Code Execution in Timers',
    category: 'A03:2021-Injection',
    categoryUrl: 'https://owasp.org/Top10/A03_2021-Injection/',
    shortAction: 'If the timer is executing a code string, use a function callback that preserves its arguments, scope and timing.',
    recommendedAction: 'If the timer is executing a code string, use a function callback that preserves its arguments, scope and timing.',
    summary: 'If the timer is executing a code string, use a function callback that preserves its arguments, scope and timing.',
    contextCheck: 'Which callback, arguments and scheduling behavior should this timer preserve?',
    risk: 'String timer callbacks evaluate code and can execute attacker-controlled content included in the string.',
    cannotInfer: 'JSentinel cannot infer the intended captures, callback binding, delay, or timer lifecycle.',
    scope: 'browser',
    approaches: [
      'If a named function already performs the work, pass it as the callback and preserve any required binding and arguments.',
      'If arguments or surrounding state are needed, use a closure and deliberately choose whether values are captured now or read when the timer runs.'
    ],
    verifySteps: [
      'Confirm the callback receives the expected arguments and state at the intended time.',
      'Test repeat scheduling, cancellation and any required callback binding.'
    ],
    references: [
      { title: 'MDN setTimeout() Reference', url: 'https://developer.mozilla.org/en-US/docs/Web/API/setTimeout' },
      { title: 'OWASP A03:2021 – Injection', url: 'https://owasp.org/Top10/A03_2021-Injection/' }
    ],
    illustrativePattern: '// If this action should run once after one second using the current userId.\nconst scheduledUserId = userId;\nsetTimeout(() => {\n  processUserData(scheduledUserId);\n}, 1000);'
  },

  'OWASP-A03-003': {
    guidanceId: 'OWASP-A03-003',
    ruleId: 'OWASP-A03-003',
    variant: null,
    title: 'Unsafe Function Constructor Dynamic Code',
    category: 'A03:2021-Injection',
    categoryUrl: 'https://owasp.org/Top10/A03_2021-Injection/',
    shortAction: 'If operations are known, dispatch only explicit handlers; otherwise define and enforce a restricted expression language.',
    recommendedAction: 'If operations are known, dispatch only explicit handlers; otherwise define and enforce a restricted expression language.',
    summary: 'If operations are known, dispatch only explicit handlers; otherwise define and enforce a restricted expression language.',
    contextCheck: 'Can this behavior use fixed operations, or must users supply a restricted formula?',
    risk: 'The Function constructor compiles strings into JavaScript; attacker-influenced code can run with application privileges.',
    cannotInfer: 'JSentinel cannot determine the intended operations, formula language, or evaluation requirements.',
    scope: 'browser',
    approaches: [
      'For known operations, use a Map or an own-property-checked handler table and explicitly reject unknown names.',
      'For user formulas, select a maintained restricted interpreter, constrain its accessible operations and resources, and verify its security model.'
    ],
    verifySteps: [
      'Reject unknown names, including inherited property names such as constructor and toString.',
      'Confirm intended calculations work and arbitrary JavaScript is rejected.',
      'For formula interpreters, test invalid syntax and resource limits.'
    ],
    references: [
      { title: 'MDN JavaScript Prototype Pollution', url: 'https://developer.mozilla.org/en-US/docs/Web/Security/Attacks/Prototype_pollution' },
      { title: 'MDN Function Constructor Security Considerations', url: 'https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Function/Function' },
      { title: 'OWASP A03:2021 – Injection', url: 'https://owasp.org/Top10/A03_2021-Injection/' }
    ],
    illustrativePattern: '// If only the named add operation is supported; numeric arguments are shown literally.\nconst operations = new Map([["add", (a, b) => a + b]]);\nconst handler = operations.get(action);\nif (!handler) throw new Error("Unsupported operation");\nconst result = handler(2, 3);'
  },

  'OWASP-A03-004': {
    guidanceId: 'OWASP-A03-004',
    ruleId: 'OWASP-A03-004',
    variant: null,
    title: 'Dynamic innerHTML Template Literal',
    category: 'A03:2021-Injection',
    categoryUrl: 'https://owasp.org/Top10/A03_2021-Injection/',
    shortAction: 'If this is plain text, use textContent or DOM nodes; if it needs HTML, sanitize using the intended HTML policy.',
    recommendedAction: 'If this is plain text, use textContent or DOM nodes; if it needs HTML, sanitize using the intended HTML policy.',
    summary: 'If this is plain text, use textContent or DOM nodes; if it needs HTML, sanitize using the intended HTML policy.',
    contextCheck: 'Should the interpolated content display as plain text, or as intentional rich HTML?',
    risk: 'Untrusted values interpolated into HTML can introduce elements or event handlers that execute script.',
    cannotInfer: 'JSentinel cannot determine whether markup is intentional or how interpolated values were checked.',
    scope: 'browser',
    approaches: [
      'For text mixed with fixed layout, create the required DOM nodes and assign untrusted text with textContent.',
      'For intentional rich HTML, sanitize the complete markup with a maintained sanitizer and an explicit policy before insertion; do not modify it unsafely afterward.'
    ],
    verifySteps: [
      'Confirm HTML payloads with event handlers cannot execute in the rendered result.',
      'Verify plain text, special characters and any intentionally allowed formatting display correctly.'
    ],
    references: [
      { title: 'OWASP Cross-Site Scripting (XSS) Prevention Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html' },
      { title: 'DOMPurify Security Library', url: 'https://github.com/cure53/DOMPurify' }
    ],
    illustrativePattern: '// If the title should display the user name as plain text, without HTML formatting.\ncardTitle.textContent = userName;'
  },

  'OWASP-A03-005': {
    guidanceId: 'OWASP-A03-005',
    ruleId: 'OWASP-A03-005',
    variant: null,
    title: 'Function Return Assigned to innerHTML',
    category: 'A03:2021-Injection',
    categoryUrl: 'https://owasp.org/Top10/A03_2021-Injection/',
    shortAction: 'If the return value is text, use textContent; if it is HTML, confirm or apply the required sanitization policy.',
    recommendedAction: 'If the return value is text, use textContent; if it is HTML, confirm or apply the required sanitization policy.',
    summary: 'If the return value is text, use textContent; if it is HTML, confirm or apply the required sanitization policy.',
    contextCheck: 'Does the function return plain text, or HTML already covered by a reviewed sanitizer policy?',
    risk: 'Function output containing untrusted markup can execute script when inserted into innerHTML.',
    cannotInfer: 'JSentinel cannot trace every function return or verify existing sanitization across files.',
    scope: 'browser',
    approaches: [
      'If the function returns text, use textContent or text nodes at the insertion point.',
      'If the function returns intentional HTML, confirm its existing sanitization policy or sanitize before insertion with a maintained library; preserve only the required markup.'
    ],
    verifySteps: [
      'Trace input sources and confirm where the HTML policy is applied.',
      'Test event-handler payloads and valid content through the actual rendering path.'
    ],
    references: [
      { title: 'OWASP DOM-based XSS Prevention Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html' },
      { title: 'OWASP A03:2021 – Injection', url: 'https://owasp.org/Top10/A03_2021-Injection/' }
    ],
    illustrativePattern: '// If renderUserProfile returns plain text and no HTML formatting is required.\ncontainer.textContent = renderUserProfile(userData);'
  },

  'OWASP-A03-006': {
    guidanceId: 'OWASP-A03-006',
    ruleId: 'OWASP-A03-006',
    variant: null,
    title: 'Direct innerHTML Assignment',
    category: 'A03:2021-Injection',
    categoryUrl: 'https://owasp.org/Top10/A03_2021-Injection/',
    shortAction: 'If the value is plain text, use textContent; for required HTML, confirm a suitable sanitization policy.',
    recommendedAction: 'If the value is plain text, use textContent; for required HTML, confirm a suitable sanitization policy.',
    summary: 'If the value is plain text, use textContent; for required HTML, confirm a suitable sanitization policy.',
    contextCheck: 'Does the assigned value need HTML parsing, and can untrusted data reach it?',
    risk: 'innerHTML parses markup; attacker-influenced content can introduce executable event handlers or other unsafe elements.',
    cannotInfer: 'JSentinel cannot establish the value\'s trust level or whether existing controls make this insertion appropriate.',
    scope: 'browser',
    approaches: [
      'For plain text, use textContent or DOM text nodes so the value is not parsed as markup.',
      'For required HTML, confirm a maintained sanitizer and explicit allowed-HTML policy cover untrusted content before insertion.'
    ],
    verifySteps: [
      'Test event-handler payloads and special characters through the actual assignment.',
      'Confirm the chosen path preserves intended text or permitted formatting.'
    ],
    references: [
      { title: 'MDN Element.innerHTML Reference', url: 'https://developer.mozilla.org/en-US/docs/Web/API/Element/innerHTML' },
      { title: 'OWASP Cross-Site Scripting (XSS) Prevention Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html' }
    ],
    illustrativePattern: '// If this element should display the supplied value as plain text.\ncontentElement.textContent = untrustedInput;'
  },

  'OWASP-A03-007': {
    guidanceId: 'OWASP-A03-007',
    ruleId: 'OWASP-A03-007',
    variant: null,
    title: 'Document Stream Injection (document.write)',
    category: 'A03:2021-Injection',
    categoryUrl: 'https://owasp.org/Top10/A03_2021-Injection/',
    shortAction: 'If this writes page content, use DOM rendering; if it loads scripts, preserve the required loading and execution order.',
    recommendedAction: 'If this writes page content, use DOM rendering; if it loads scripts, preserve the required loading and execution order.',
    summary: 'If this writes page content, use DOM rendering; if it loads scripts, preserve the required loading and execution order.',
    contextCheck: 'Is document.write inserting content, or loading a script whose ordering matters?',
    risk: 'document.write can interpret untrusted markup and may replace the document or disrupt parsing depending on timing.',
    cannotInfer: 'JSentinel cannot determine document loading state, dependency order, or synchronous insertion requirements.',
    scope: 'browser',
    approaches: [
      'For page content, create DOM nodes and use textContent for text; sanitize intentional rich HTML under the application\'s policy.',
      'For script loading, use the platform or framework loader with approved script sources and explicitly preserve required execution order.'
    ],
    verifySteps: [
      'Test initial load and later updates without replacing the document or losing expected content.',
      'If scripts are involved, verify trusted sources, dependency ordering and load failures.',
      'Confirm untrusted content cannot introduce executable markup.'
    ],
    references: [
      { title: 'MDN document.write() Reference and Deprecation Warning', url: 'https://developer.mozilla.org/en-US/docs/Web/API/Document/write' },
      { title: 'OWASP A03:2021 – Injection', url: 'https://owasp.org/Top10/A03_2021-Injection/' }
    ],
    illustrativePattern: null
  },

  'OWASP-A03-008': {
    guidanceId: 'OWASP-A03-008',
    ruleId: 'OWASP-A03-008',
    variant: null,
    title: 'React dangerouslySetInnerHTML Property',
    category: 'A03:2021-Injection',
    categoryUrl: 'https://owasp.org/Top10/A03_2021-Injection/',
    shortAction: 'If this is text, render normal JSX children; use sanitized dangerouslySetInnerHTML only for intentional HTML.',
    recommendedAction: 'If this is text, render normal JSX children; use sanitized dangerouslySetInnerHTML only for intentional HTML.',
    summary: 'If this is text, render normal JSX children; use sanitized dangerouslySetInnerHTML only for intentional HTML.',
    contextCheck: 'Is this content plain text, or rich HTML that the React view intentionally supports?',
    risk: 'dangerouslySetInnerHTML bypasses normal string escaping and can execute unsafe markup supplied to __html.',
    cannotInfer: 'JSentinel cannot establish markup provenance or verify an existing HTML sanitization policy.',
    scope: 'browser',
    approaches: [
      'For plain text, render the value as a normal JSX child so React escapes it.',
      'For rich HTML, sanitize with a maintained library and the required allowed-HTML policy before setting __html; configure the sanitizer for the actual browser or server environment.'
    ],
    verifySteps: [
      'Test event-handler payloads through the React rendering path and confirm no script executes.',
      'Verify text and permitted formatting render correctly, including server rendering if used.'
    ],
    references: [
      { title: 'React Documentation: dangerouslySetInnerHTML', url: 'https://react.dev/reference/react-dom/components/common#dangerously-setting-the-inner-html' },
      { title: 'OWASP Cross-Site Scripting (XSS) Prevention Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html' }
    ],
    illustrativePattern: '// If this view displays the supplied content as plain text, without HTML formatting.\n<div>{userContent}</div>'
  },

  // =========================================================================
  // A05:2021 - Security Misconfiguration
  // =========================================================================
  'OWASP-A05-001': {
    guidanceId: 'OWASP-A05-001',
    ruleId: 'OWASP-A05-001',
    variant: null,
    title: 'Sensitive Variable Logging to Console',
    category: 'A05:2021-Security Misconfiguration',
    categoryUrl: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
    shortAction: 'If a logged value is sensitive, remove it or redact it before it reaches the logging destination.',
    recommendedAction: 'If a logged value is sensitive, remove it or redact it before it reaches the logging destination.',
    summary: 'If a logged value is sensitive, remove it or redact it before it reaches the logging destination.',
    contextCheck: 'Does the logged value contain a real secret or personal data in this environment?',
    risk: 'Passwords, tokens and personal data written to logs may become visible to console users or log-service readers.',
    cannotInfer: 'JSentinel cannot determine runtime value sensitivity, log access, retention, or downstream redaction.',
    scope: 'cross-boundary',
    approaches: [
      'If the value is unnecessary for diagnosis, log a non-sensitive event or outcome instead.',
      'If diagnostic fields are required, allowlist them and redact sensitive values before serialization and forwarding.'
    ],
    verifySteps: [
      'Inspect representative development and production output, including errors, for raw secrets.',
      'Confirm remaining events are useful and contain only approved fields.'
    ],
    references: [
      { title: 'OWASP Logging Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html' },
      { title: 'OWASP A05:2021 – Security Misconfiguration', url: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/' }
    ],
    illustrativePattern: null
  },

  'OWASP-A05-002': {
    guidanceId: 'OWASP-A05-002',
    ruleId: 'OWASP-A05-002',
    variant: null,
    title: 'Wildcard CORS Access-Control-Allow-Origin',
    category: 'A05:2021-Security Misconfiguration',
    categoryUrl: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
    shortAction: 'If responses need restricted browser access, configure explicit origins and the required credential policy.',
    recommendedAction: 'If responses need restricted browser access, configure explicit origins and the required credential policy.',
    summary: 'If responses need restricted browser access, configure explicit origins and the required credential policy.',
    contextCheck: 'Is this endpoint intentionally public, or should only specific browser origins read its responses?',
    risk: 'Wildcard CORS allows non-credentialed browser response sharing with any origin; CORS does not replace server authorization.',
    cannotInfer: 'JSentinel cannot determine whether responses are public or which origins and credential modes are required.',
    scope: 'server',
    approaches: [
      'For intentionally public non-credentialed resources, wildcard sharing may be appropriate; confirm the responses contain no private data.',
      'For restricted browser sharing, return only approved origins, configure credential handling, and vary cached responses by Origin when it changes the response headers. Authorize protected requests independently.'
    ],
    verifySteps: [
      'In a browser, test allowed and disallowed origins and the required credential mode; inspect actual responses and preflights where applicable.',
      'Confirm credentialed response sharing uses an explicit origin rather than wildcard.',
      'Confirm direct requests cannot bypass server authentication or authorization.'
    ],
    references: [
      { title: 'MDN Cross-Origin Resource Sharing (CORS)', url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS' },
      { title: 'OWASP HTML5 Security Cheat Sheet - CORS', url: 'https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#cross-origin-resource-sharing' }
    ],
    illustrativePattern: null
  },

  'OWASP-A05-003': {
    guidanceId: 'OWASP-A05-003',
    ruleId: 'OWASP-A05-003',
    variant: null,
    title: 'Sensitive Object Logging (req/session/user)',
    category: 'A05:2021-Security Misconfiguration',
    categoryUrl: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
    shortAction: 'If request, session or user objects contain sensitive data, log only an approved subset of fields.',
    recommendedAction: 'If request, session or user objects contain sensitive data, log only an approved subset of fields.',
    summary: 'If request, session or user objects contain sensitive data, log only an approved subset of fields.',
    contextCheck: 'Which fields are actually required for diagnostics, and which may contain sensitive data?',
    risk: 'Whole-object logging can expose nested credentials, cookies, tokens or personal data.',
    cannotInfer: 'JSentinel cannot inspect runtime object contents or verify downstream serializers and redaction.',
    scope: 'cross-boundary',
    approaches: [
      'For routine diagnostics, select only approved fields and avoid raw bodies, session objects and URLs containing sensitive values.',
      'If structured logging is needed, configure and test a serializer that allowlists or redacts fields before they reach any destination.'
    ],
    verifySteps: [
      'Inspect representative nested objects and error paths for unredacted secrets in log output.',
      'Confirm the selected fields meet diagnostic needs and the application\'s data policy.'
    ],
    references: [
      { title: 'OWASP Logging Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html' },
      { title: 'OWASP A05:2021 – Security Misconfiguration', url: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/' }
    ],
    illustrativePattern: null
  },

  'OWASP-A05-004': {
    guidanceId: 'OWASP-A05-004',
    ruleId: 'OWASP-A05-004',
    variant: null,
    title: 'Missing Express Security Header Middleware',
    category: 'A05:2021-Security Misconfiguration',
    categoryUrl: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
    shortAction: 'If deployed responses lack required protection, configure headers for the app\'s resources, framing and HTTPS needs.',
    recommendedAction: 'If deployed responses lack required protection, configure headers for the app\'s resources, framing and HTTPS needs.',
    summary: 'If deployed responses lack required protection, configure headers for the app\'s resources, framing and HTTPS needs.',
    contextCheck: 'Which security headers already reach users from Express, proxies or the CDN?',
    risk: 'Missing or unsuitable response headers can leave applications exposed to MIME sniffing, unwanted framing or unsafe resource loading.',
    cannotInfer: 'JSentinel cannot inspect deployed response headers or upstream proxy and CDN configuration.',
    scope: 'server',
    approaches: [
      'If Express owns the policy, configure Helmet or explicit middleware and tailor CSP, framing and HTTPS directives to the application\'s deployment.',
      'If a proxy or CDN owns the policy, verify its deployed headers and coverage before adding overlapping application settings.'
    ],
    verifySteps: [
      'Inspect actual deployed responses across relevant pages and routes for the intended header values.',
      'Verify scripts, assets and allowed embedding still work while unauthorized framing is blocked.',
      'Test development and production HTTPS behavior to avoid inappropriate redirects or resource upgrades.'
    ],
    references: [
      { title: 'Helmet.js Security Documentation', url: 'https://helmetjs.github.io/' },
      { title: 'OWASP Secure Headers Project', url: 'https://owasp.org/www-project-secure-headers/' }
    ],
    illustrativePattern: null
  },

  // =========================================================================
  // A06:2021 - Vulnerable and Outdated Components
  // =========================================================================
  'OWASP-A06-001': {
    guidanceId: 'OWASP-A06-001',
    ruleId: 'OWASP-A06-001',
    variant: null,
    title: 'Vulnerable and Outdated Component Import',
    category: 'A06:2021-Vulnerable and Outdated Components',
    categoryUrl: 'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/',
    shortAction: 'If the resolved dependency is affected or unsupported, update or replace it and test compatibility.',
    recommendedAction: 'If the resolved dependency is affected or unsupported, update or replace it and test compatibility.',
    summary: 'If the resolved dependency is affected or unsupported, update or replace it and test compatibility.',
    contextCheck: 'Which package version is resolved, and does a current advisory apply to its actual use?',
    risk: 'An affected dependency can expose the application to known flaws; an import alone does not establish a vulnerable version.',
    cannotInfer: 'JSentinel cannot determine installed versions or advisory applicability from this import alone.',
    scope: 'cross-boundary',
    approaches: [
      'If an advisory affects the resolved package, review the package manager\'s audit output and maintainer advisory, then update to an appropriate supported release.',
      'If the package is unsupported or has no suitable fix, assess a maintained replacement or native API that preserves the required behavior.'
    ],
    verifySteps: [
      'Check the lockfile, resolved dependency tree and relevant maintainer advisories.',
      'After the change, verify the applicable advisory is addressed and required behavior passes compatibility tests.'
    ],
    references: [
      { title: 'OWASP Vulnerable Dependency Management Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html' },
      { title: 'NIST National Vulnerability Database', url: 'https://nvd.nist.gov/' }
    ],
    illustrativePattern: null
  },

  'OWASP-A06-001:component-review': {
    guidanceId: 'OWASP-A06-001:component-review',
    ruleId: 'OWASP-A06-001',
    variant: 'component-review',
    title: 'Third-Party Component Advisory Review',
    category: 'A06:2021-Vulnerable and Outdated Components',
    categoryUrl: 'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/',
    shortAction: 'If the resolved package version is affected, select a supported fix or compatible replacement and verify the affected behavior.',
    recommendedAction: 'If the resolved package version is affected, select a supported fix or compatible replacement and verify the affected behavior.',
    summary: 'If the resolved package version is affected, select a supported fix or compatible replacement and verify the affected behavior.',
    contextCheck: 'Is the installed version affected by an advisory, and does the flagged usage meet its conditions?',
    risk: 'Historical package issues warrant review, but the import name does not prove the current application is exploitable.',
    cannotInfer: 'JSentinel cannot resolve dependency versions or evaluate advisory preconditions from this import.',
    scope: 'cross-boundary',
    approaches: [
      'If affected, use the lockfile and maintainer advisory to choose a fixed release, then review migration requirements.',
      'If replacement is necessary, compare the actual API semantics and security properties; native APIs are not interchangeable drop-in fixes.'
    ],
    verifySteps: [
      'Confirm the resolved version and relevant advisory conditions before and after the change.',
      'Run the applicable package audit and compatibility tests; assess remaining findings rather than assuming an empty audit proves safety.'
    ],
    references: [
      { title: 'OWASP Vulnerable Dependency Management Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html' },
      { title: 'NIST National Vulnerability Database', url: 'https://nvd.nist.gov/' }
    ],
    illustrativePattern: null
  },

  'OWASP-A06-001:express-headers': {
    guidanceId: 'OWASP-A06-001:express-headers',
    ruleId: 'OWASP-A06-001',
    variant: 'express-headers',
    title: 'Express Instance Missing Security Headers',
    category: 'A06:2021-Vulnerable and Outdated Components',
    categoryUrl: 'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/',
    shortAction: 'If deployed responses lack required headers, configure the responsible layer and verify application behavior.',
    recommendedAction: 'If deployed responses lack required headers, configure the responsible layer and verify application behavior.',
    summary: 'If deployed responses lack required headers, configure the responsible layer and verify application behavior.',
    contextCheck: 'Are the needed security headers supplied by Express or by the deployed infrastructure?',
    risk: 'A missing middleware call can signal incomplete header policy, but headers may already be supplied elsewhere.',
    cannotInfer: 'JSentinel cannot inspect proxy/CDN headers or determine the intended CSP, framing and HTTPS policy.',
    scope: 'server',
    approaches: [
      'If Express is responsible, configure Helmet or explicit header middleware for the actual resource, embedding and transport requirements.',
      'If infrastructure is responsible, verify the effective deployed policy and route coverage before duplicating it in Express.'
    ],
    verifySteps: [
      'Inspect deployed responses for the required header values across relevant HTML and API routes.',
      'Test legitimate assets and embedding, unauthorized framing, and development versus production HTTPS behavior.'
    ],
    references: [
      { title: 'Helmet.js Documentation', url: 'https://helmetjs.github.io/' },
      { title: 'Express Production Security Best Practices', url: 'https://expressjs.com/en/advanced/best-practice-security.html' }
    ],
    illustrativePattern: null
  },

  'OWASP-A06-001:dynamic-request-target': {
    guidanceId: 'OWASP-A06-001:dynamic-request-target',
    ruleId: 'OWASP-A06-001',
    variant: 'dynamic-request-target',
    title: 'Dynamic HTTP Client Request Target',
    category: 'A06:2021-Vulnerable and Outdated Components',
    categoryUrl: 'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/',
    shortAction: 'If input can change the destination, enforce the parsed target policy before sending the request.',
    recommendedAction: 'If input can change the destination, enforce the parsed target policy before sending the request.',
    summary: 'If input can change the destination, enforce the parsed target policy before sending the request.',
    contextCheck: 'Does this request run in the browser or on the server, and which destinations are allowed?',
    risk: 'Untrusted destinations can send requests or credentials to unintended hosts; server requests may also reach private services.',
    cannotInfer: 'JSentinel cannot determine runtime, approved destinations, redirects, or server network controls.',
    scope: 'cross-boundary',
    approaches: [
      'For known API routes, map identifiers to fixed URLs or validate the parsed scheme, origin and path. An Axios baseURL or new URL base alone does not constrain an absolute target.',
      'For server requests to user-selected URLs, enforce the destination policy across redirects and DNS/IP resolution, including relevant IPv4 and IPv6 private ranges, with network egress controls.'
    ],
    verifySteps: [
      'Test unauthorized absolute URLs, protocol-relative targets, slash/backslash combinations and valid API paths.',
      'For server requests, test redirects, DNS changes and blocked local/private IPv4 and IPv6 destinations.',
      'Confirm approved requests work and credentials are not forwarded to unauthorized targets.'
    ],
    references: [
      { title: 'Axios Request Configuration', url: 'https://axios-http.com/docs/req_config' },
      { title: 'OWASP Server-Side Request Forgery Prevention Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html' },
      { title: 'Axios Instance Config Documentation', url: 'https://axios-http.com/docs/instance' }
    ],
    illustrativePattern: null
  },

  // =========================================================================
  // A07:2021 - Identification and Authentication Failures
  // =========================================================================
  'OWASP-A07-001': {
    guidanceId: 'OWASP-A07-001',
    ruleId: 'OWASP-A07-001',
    variant: null,
    title: 'Insecure Token Storage in localStorage',
    category: 'A07:2021-Identification and Authentication Failures',
    categoryUrl: 'https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/',
    shortAction: 'If long-lived credentials are script-readable, assess a server-managed session or a shorter-lived token flow.',
    recommendedAction: 'If long-lived credentials are script-readable, assess a server-managed session or a shorter-lived token flow.',
    summary: 'If long-lived credentials are script-readable, assess a server-managed session or a shorter-lived token flow.',
    contextCheck: 'Can the authentication architecture use server-issued cookies, and which cross-site flows must work?',
    risk: 'XSS can access browser storage and act through the authenticated page; changing storage alone does not prevent XSS.',
    cannotInfer: 'JSentinel cannot determine API origin requirements, token lifetimes, refresh behavior or backend session support.',
    scope: 'cross-boundary',
    approaches: [
      'If server sessions fit the architecture, use HttpOnly and Secure cookies with a suitable SameSite policy and CSRF controls for state-changing requests.',
      'If script access tokens are required, assess short-lived in-memory tokens with a protected refresh flow; memory reduces persistence but does not prevent access by malicious running scripts.'
    ],
    verifySteps: [
      'Test login, refresh, logout, expiry and required cross-site flows after any storage change.',
      'For a cookie flow, verify cookie flags and CSRF protection on state-changing requests.',
      'Confirm long-lived credentials are absent from script-readable storage where the chosen design permits, and retain XSS defenses.'
    ],
    references: [
      { title: 'OWASP Cross-Site Request Forgery Prevention', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html' },
      { title: 'OWASP HTML5 Security Cheat Sheet - Local Storage', url: 'https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#local-storage' },
      { title: 'MDN Web Storage API Security', url: 'https://developer.mozilla.org/en-US/docs/Web/API/Web_Storage_API' }
    ],
    illustrativePattern: null
  },

  // =========================================================================
  // A08:2021 - Software and Data Integrity Failures
  // =========================================================================
  'OWASP-A08-001': {
    guidanceId: 'OWASP-A08-001',
    ruleId: 'OWASP-A08-001',
    variant: null,
    title: 'Unsafe JSON Deserialization Without Validation',
    category: 'A08:2021-Software and Data Integrity Failures',
    categoryUrl: 'https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/',
    shortAction: 'If parsed data is untrusted, validate its expected shape and handle parse or validation failures before use.',
    recommendedAction: 'If parsed data is untrusted, validate its expected shape and handle parse or validation failures before use.',
    summary: 'If parsed data is untrusted, validate its expected shape and handle parse or validation failures before use.',
    contextCheck: 'What shape should this data have, and is it already validated before sensitive use?',
    risk: 'Unexpected parsed values can cause errors or unsafe downstream decisions; JSON.parse alone does not pollute prototypes.',
    cannotInfer: 'JSentinel cannot determine the intended schema or validation performed elsewhere in the data flow.',
    scope: 'browser',
    approaches: [
      'If no suitable validation exists, use a schema validator or explicit checks for expected types and permitted fields, with separate handling for malformed JSON and invalid data.',
      'If validation already exists, confirm it covers this input before use and review any later dynamic property assignments or merges.'
    ],
    verifySteps: [
      'Test malformed JSON, null, arrays, wrong types and unexpected fields against the expected contract.',
      'Confirm valid data works and invalid data cannot reach sensitive processing.',
      'Where large untrusted payloads are accepted, verify an input-size limit before parsing.'
    ],
    references: [
      { title: 'MDN JavaScript Prototype Pollution', url: 'https://developer.mozilla.org/en-US/docs/Web/Security/Attacks/Prototype_pollution' },
      { title: 'OWASP Deserialization Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html' },
      { title: 'OWASP A08:2021 – Software and Data Integrity Failures', url: 'https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/' }
    ],
    illustrativePattern: null
  },

  'OWASP-A08-002': {
    guidanceId: 'OWASP-A08-002',
    ruleId: 'OWASP-A08-002',
    variant: null,
    title: 'Prototype Mutation and Pollution',
    category: 'A08:2021-Software and Data Integrity Failures',
    categoryUrl: 'https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/',
    shortAction: 'If untrusted keys reach object updates, restrict them and use a suitable map or dictionary structure.',
    recommendedAction: 'If untrusted keys reach object updates, restrict them and use a suitable map or dictionary structure.',
    summary: 'If untrusted keys reach object updates, restrict them and use a suitable map or dictionary structure.',
    contextCheck: 'Is this an intentional prototype extension, or can untrusted keys reach the mutation?',
    risk: 'Unsafe dynamic keys can alter an object\'s prototype or shared prototypes, changing inherited values and security decisions.',
    cannotInfer: 'JSentinel cannot determine mutation intent, key provenance, or the affected inheritance chain.',
    scope: 'browser',
    approaches: [
      'For untrusted dictionaries, use Map entries or null-prototype objects and validate allowed keys; Map entries do not use object-property lookup.',
      'For intentional prototype extension, review the affected prototype and compatibility requirements, and keep untrusted property paths away from it.'
    ],
    verifySteps: [
      'Send __proto__ and constructor.prototype payloads through the real update path; confirm target and shared prototypes remain as intended.',
      'Confirm legitimate keys and any intentional inheritance behavior still work.'
    ],
    references: [
      { title: 'MDN JavaScript Prototype Pollution', url: 'https://developer.mozilla.org/en-US/docs/Web/Security/Attacks/Prototype_pollution' },
      { title: 'MDN Object.prototype.__proto__', url: 'https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/proto' },
      { title: 'OWASP Prototype Pollution Prevention', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html' }
    ],
    illustrativePattern: null
  },

  'OWASP-A08-003': {
    guidanceId: 'OWASP-A08-003',
    ruleId: 'OWASP-A08-003',
    variant: null,
    title: 'Dynamic Object Merging (Object.assign)',
    category: 'A08:2021-Software and Data Integrity Failures',
    categoryUrl: 'https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/',
    shortAction: 'If data is untrusted, validate and copy only permitted fields into the intended target shape.',
    recommendedAction: 'If data is untrusted, validate and copy only permitted fields into the intended target shape.',
    summary: 'If data is untrusted, validate and copy only permitted fields into the intended target shape.',
    contextCheck: 'Which fields may this input change, and must the result preserve a particular object shape?',
    risk: 'Untrusted merges can overwrite protected fields; Object.assign can also invoke prototype setters, unlike object spread.',
    cannotInfer: 'JSentinel cannot determine the permitted fields, nested merge policy, or required target inheritance.',
    scope: 'browser',
    approaches: [
      'If only known fields are allowed, validate their own values and types and construct the target explicitly; a null-prototype target may suit a plain dictionary.',
      'If nested merging is required, validate the full permitted schema and use a reviewed merge policy that rejects dangerous property paths; copying extra fields remains a risk even with spread.'
    ],
    verifySteps: [
      'Test unexpected fields, wrong types and prototype-related payloads through the actual merge path.',
      'Confirm protected fields and target/shared prototypes remain unchanged while valid permitted values are retained.'
    ],
    references: [
      { title: 'MDN JavaScript Prototype Pollution', url: 'https://developer.mozilla.org/en-US/docs/Web/Security/Attacks/Prototype_pollution' },
      { title: 'MDN Object.assign() Reference', url: 'https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/assign' },
      { title: 'OWASP Prototype Pollution Prevention', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html' }
    ],
    illustrativePattern: '// If parsed JSON may provide a string name for a new dictionary; other fields are ignored.\nif (untrustedData === null || typeof untrustedData !== "object" ||\n    Array.isArray(untrustedData) || !Object.hasOwn(untrustedData, "name") ||\n    typeof untrustedData.name !== "string") {\n  throw new TypeError("Expected an object with a string name");\n}\nconst target = Object.create(null);\ntarget.name = untrustedData.name;'
  },

  // =========================================================================
  // A10:2021 - Server-Side Request Forgery (SSRF)
  // =========================================================================
  'OWASP-A10-001': {
    guidanceId: 'OWASP-A10-001',
    ruleId: 'OWASP-A10-001',
    variant: null,
    title: 'Server-Side Request Forgery (SSRF)',
    category: 'A10:2021-Server-Side Request Forgery (SSRF)',
    categoryUrl: 'https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/',
    shortAction: 'For server requests influenced by input, enforce a destination policy throughout URL resolution and redirects.',
    recommendedAction: 'For server requests influenced by input, enforce a destination policy throughout URL resolution and redirects.',
    summary: 'For server requests influenced by input, enforce a destination policy throughout URL resolution and redirects.',
    contextCheck: 'Does this run on a server, and are destinations fixed or intentionally user-selected?',
    risk: 'User-controlled server requests can reach unintended external hosts, internal services or cloud metadata endpoints.',
    cannotInfer: 'JSentinel cannot inspect server network boundaries, DNS behavior, redirect policy or approved destinations.',
    scope: 'server',
    approaches: [
      'For known services, map identifiers to fixed approved destinations or enforce parsed scheme, host and port checks; disable redirects or revalidate each hop, and enforce DNS/IP and network egress policy.',
      'If arbitrary external destinations are required, use a reviewed outbound-request policy covering URL parsing, redirects, resolved IPv4/IPv6 addresses and DNS changes, backed by egress restrictions.'
    ],
    verifySteps: [
      'Reject disallowed schemes, destinations and redirects, including local/private IPv4 and IPv6 and metadata addresses as required by policy.',
      'Test allowed hostnames that redirect or resolve to blocked addresses, including DNS changes between validation and connection.',
      'Confirm approved HTTPS destinations and any explicitly allowed internal services still work.'
    ],
    references: [
      { title: 'OWASP Server-Side Request Forgery Prevention Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html' },
      { title: 'OWASP A10:2021 – Server-Side Request Forgery (SSRF)', url: 'https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/' }
    ],
    illustrativePattern: null
  }
};

// Non-enumerable property for legacy __disclaimer lookups
Object.defineProperty(guidanceCatalog, '__disclaimer', {
  value: GUIDANCE_DISCLAIMER,
  enumerable: false,
  writable: false
});

/**
 * Retrieves the matching GuidanceRecord for a finding issue object or rule ID string.
 * Returns FALLBACK_GUIDANCE on null/undefined/unknown inputs.
 *
 * @param {Object|string} issue - Finding issue object or rule ID string
 * @returns {Object} Guidance record
 */
function getGuidance(issue) {
  const findRecord = (value) => {
    if (typeof value !== 'string') return null;
    const trimmed = value.trim();
    if (!trimmed) return null;

    const baseId = trimmed.split(':')[0].trim();
    for (const candidate of [trimmed, baseId]) {
      // Legacy metadata such as __disclaimer is not a GuidanceRecord.
      if (!Object.prototype.propertyIsEnumerable.call(guidanceCatalog, candidate)) continue;
      const record = guidanceCatalog[candidate];
      if (record && typeof record === 'object' && record.guidanceId === candidate) {
        return record;
      }
    }
    return null;
  };

  if (typeof issue === 'string') return findRecord(issue) || FALLBACK_GUIDANCE;
  if (issue && typeof issue === 'object') {
    return findRecord(issue.guidanceId) || findRecord(issue.id) || FALLBACK_GUIDANCE;
  }
  return FALLBACK_GUIDANCE;
}

/**
 * Returns all guidance records in the catalog as a key-value record map.
 *
 * @returns {Record<string, Object>}
 */
function getAllGuidance() {
  return { ...guidanceCatalog };
}

/**
 * Returns all guidance records associated with a specific base rule ID.
 *
 * @param {string} ruleId - Base rule ID (e.g. 'OWASP-A06-001')
 * @returns {Object[]} Array of matching guidance records
 */
function getGuidanceByRuleId(ruleId) {
  if (!ruleId || typeof ruleId !== 'string') return [];
  const trimmed = ruleId.trim();
  if (!trimmed) return [];
  return Object.values(guidanceCatalog).filter((record) => record && record.ruleId === trimmed);
}

module.exports = {
  guidanceCatalog,
  getGuidance,
  getAllGuidance,
  getGuidanceByRuleId,
  GUIDANCE_DISCLAIMER,
  EDUCATIONAL_DISCLAIMER,
  FALLBACK_GUIDANCE,
  default: guidanceCatalog
};
