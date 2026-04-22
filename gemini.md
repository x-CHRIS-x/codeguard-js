# Project Title

JSentinel: A Localized Static Analysis Tool for Detecting Latent Security Vulnerabilities for Web Developers


## What it is
A browser-based tool that analyzes JavaScript code for security vulnerabilities without sending any code to a server. Everything runs locally in the browser for privacy.

## CMO 25 Alignment
Falls under two CHED CMO 25 s.2015 suggested areas: Web Applications Development and IT Security Analysis, Planning and Implementation.

## Tech Stack
- React + Vite — UI framework
- Tailwind CSS — styling
- @babel/parser — parses JS into AST
- @babel/traverse — walks through AST nodes
- jsPDF — downloadable scan reports (planned)

## How it works
User uploads file/folder
→ Filter to .js .jsx .ts .tsx only
→ Ignore node_modules, dist, build, .git folders
→ Parse each file into AST using Babel
→ Run detection rules on AST nodes via Babel plugin visitors
→ Display results per file with line numbers and code snippets

## What is an AST
Abstract Syntax Tree — a universal representation of code structure. Babel converts raw JS code into a tree of typed nodes regardless of formatting or style. Use astexplorer.net to visualize nodes while writing rules.

## Scoring System
Uses a CVSS v3.1-inspired weighted penalty model on a 100-point scale.
Severity weights: CRITICAL = 20pts, HIGH = 10pts, MEDIUM = 5pts, LOW = 1pt.
Score = max(0, 100 - total weighted penalty across all issues in all scanned files.
Score display: green if > 80, orange if 50–80, red if below 50.

---

## Detection Rules — ALREADY IMPLEMENTED (13 rules across 7 categories)

### A1 - Injection
- OWASP-A1-001 (CRITICAL): eval() usage detected
- OWASP-A1-002 (HIGH): String arguments in setTimeout or setInterval (acts like eval)

### A2 - Broken Authentication
- OWASP-A2-001 (CRITICAL): Hardcoded passwords in variables or assignments
- OWASP-A2-002 (HIGH): Storing sensitive tokens (JWT, Auth) in localStorage
- OWASP-A2-003 (MEDIUM): Insecure cookies — missing HttpOnly or Secure flags, including template literal cookie assignments

### A3 - Sensitive Data Exposure
- OWASP-A3-001 (CRITICAL/MEDIUM): Hardcoded JWT tokens, AWS Access Keys, or non-local IP addresses in string literals

### A6 - Security Misconfiguration
- OWASP-A6-001 (MEDIUM): Sensitive variable names (token, key, secret, password) passed to console.log
- OWASP-A6-002 (HIGH): Permissive CORS policy — Access-Control-Allow-Origin set to wildcard *

### A7 - Cross-Site Scripting (XSS)
- OWASP-A7-001 (HIGH): Direct assignment to .innerHTML
- OWASP-A7-002 (CRITICAL): Use of document.write()
- OWASP-A7-003 (HIGH): React dangerouslySetInnerHTML attribute detected

### A8 - Software and Data Integrity Failures
- OWASP-A8-001 (LOW): General use of JSON.parse() — flagged for manual validation of untrusted input

### A9 - Vulnerable and Outdated Components
- OWASP-A9-001 (MEDIUM): Importing known risky libraries via import or require — serialize-javascript, markdown-it, js-yaml, node-fetch

---

## Detection Rules — TO BE IMPLEMENTED (14 new rules, target total: 27 rules across 9 categories)

### A1 - Injection (add 3 more)
- OWASP-A1-003 (CRITICAL): new Function() called with a string or template literal argument — same execution risk as eval()
  - Detect: NewExpression where callee name is 'Function' and first arg is StringLiteral or TemplateLiteral
- OWASP-A1-004 (HIGH): innerHTML assigned via a template literal containing a variable — likely XSS+injection vector
  - Detect: AssignmentExpression to .innerHTML where right side is a TemplateLiteral with Identifier expressions inside
- OWASP-A1-005 (HIGH): Result of a function call directly assigned to innerHTML — chained injection risk
  - Detect: AssignmentExpression where left is .innerHTML and right is a CallExpression

### A2 - Broken Authentication (add 2 more)
- OWASP-A2-004 (HIGH): Math.random() used to generate security-sensitive values
  - Detect: CallExpression to Math.random inside a VariableDeclarator where the variable name includes token, otp, secret, salt, or key
- OWASP-A2-005 (MEDIUM): Hardcoded http:// URLs — non-HTTPS connections transmit data in plaintext
  - Detect: StringLiteral starting with 'http://' assigned to a variable or passed as first argument to fetch or axios

### A3 - Sensitive Data Exposure (add 2 more)
- OWASP-A3-002 (CRITICAL): Hardcoded API key or secret in variable assignment
  - Detect: VariableDeclarator where variable name includes key, secret, token, or api and init is a StringLiteral longer than 8 characters
- OWASP-A3-003 (MEDIUM): Sensitive data embedded in URL query string
  - Detect: StringLiteral containing ?password=, ?token=, ?key=, or ?secret= substrings

### A5 - Broken Access Control (new category, add 2)
- OWASP-A5-001 (HIGH): window.location.href or location.replace() set to a variable — open redirect risk
  - Detect: AssignmentExpression where left is location.href or CallExpression to location.replace where argument is an Identifier or TemplateLiteral
- OWASP-A5-002 (MEDIUM): Client-side role check guarding sensitive logic — authorization enforced only in the browser
  - Detect: BinaryExpression or MemberExpression checking .role, .isAdmin, or .isAuthenticated inside an IfStatement condition

### A6 - Security Misconfiguration (add 2 more)
- OWASP-A6-003 (MEDIUM): Logging potentially sensitive objects to console — req, user, session, credentials, config
  - Detect: CallExpression to console.* where any argument is an Identifier matching those names
- OWASP-A6-004 (LOW): Express app imported but helmet middleware not imported anywhere in the file
  - Detect: ImportDeclaration for 'express' present in file but no ImportDeclaration or require() for 'helmet' found

### A8 - Software and Data Integrity Failures (add 2 more)
- OWASP-A8-002 (HIGH): Prototype pollution — direct assignment to __proto__ or constructor.prototype
  - Detect: AssignmentExpression where left side property name is __proto__ or the chain accesses .constructor.prototype
- OWASP-A8-003 (MEDIUM): Object.assign() with a user-controlled second argument — potential pollution vector
  - Detect: CallExpression to Object.assign where first arg is an ObjectExpression and second arg is an Identifier

### A9 - Vulnerable and Outdated Components (expand existing rule, no new rule ID)
- Expand the riskyLibs list in knownVulns.js to also include:
  lodash (prototype pollution — CVE-2019-10744)
  axios (SSRF risk if URL is user-controlled)
  jsonwebtoken (alg:none and weak secret vulnerabilities)
  express (flag for missing security middleware)
  mongoose (NoSQL injection if queries built from user input)
  vm2 (sandbox escape vulnerabilities)

### A10 - Server-Side Request Forgery (new category, add 1)
- OWASP-A10-001 (HIGH): fetch() or axios.get/post called with a variable or template literal URL — user-controlled request target
  - Detect: CallExpression to fetch, axios.get, or axios.post where first argument is an Identifier or TemplateLiteral (not a plain StringLiteral)

---

## File Upload Handling
- Supports single file upload, folder upload via webkitdirectory, and drag-and-drop
- Auto filters to .js .jsx .ts .tsx only
- Ignores node_modules, dist, build, and hidden dot folders
- Warning shown in header and upload section for projects with 50+ files

## Edge Cases Handled
- Syntax errors → errorRecovery: true in Babel parserOpts — partial AST generated instead of hard throw
- Partially broken files → partial scan completed, hasError flag surfaced in UI with amber warning banner
- Completely unreadable files → success: false returned, parse error state shown in viewer
- Per-rule errors → caught individually, remaining rules still execute, hasError flagged

## Limitations for your paper
- Does not catch indirect or obfuscated calls such as: let e = eval; e("x")
- Does not perform dynamic or runtime analysis
- Best results on syntactically valid JavaScript
- Large projects with 50+ JS files may be slower due to sequential per-file per-rule scanning
- SQL injection detection is limited to string patterns passed to known query functions — full SQL parsing is out of scope
- Extension to server-side languages such as PHP is identified as future work

## Scoring Model Citation
The weighted penalty scoring is inspired by CVSS v3.1 severity band definitions (FIRST, 2019) and the OWASP Risk Rating Methodology's recommendation to weight factors rather than treating all findings equally (OWASP, 2021).

## Problem framing for the paper
Vulnerabilities in student code come from multiple causes: lack of security knowledge, forgetting best practices, AI-assisted vibe coding, copying insecure tutorials, time pressure, and overconfidence. JSentinel addresses all of these regardless of cause.