/**
 * A1 - Injection Rules
 * Targets: eval(), dynamic setTimeout, dynamic setInterval
 */
export const injectionRules = [
  {
    name: "eval-detection",
    id: "OWASP-A1-001",
    severity: "CRITICAL",
    message: "Use of eval() detected. This allows execution of arbitrary strings and is highly vulnerable to injection attacks.",
    owasp: "A1:2021-Broken Access Control (Injection)",
    visitor: (issues) => ({
      CallExpression(path) {
        // Path can be null if not using traverse directly, but transform provides it
        if (path.node && path.node.callee && path.node.callee.name === 'eval') {
          issues.push({
            id: "OWASP-A1-001",
            severity: "CRITICAL",
            line: path.node.loc?.start?.line || 'unknown',
            column: path.node.loc?.start?.column || 'unknown',
            message: "Dangerous use of eval()",
            suggestion: "Use JSON.parse() or access object properties directly instead of eval()."
          });
        }
      }
    })
  }
];
