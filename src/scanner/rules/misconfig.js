/**
 * A6 - Security Misconfiguration
 * Targets: console.log of sensitive data, permissive CORS headers
 */
export const misconfigRules = [
  {
    name: "console-log-secrets",
    id: "OWASP-A6-001",
    severity: "MEDIUM",
    message: "Logging sensitive variables to the console can expose secrets in production environments.",
    owasp: "A6:2021-Security Misconfiguration",
    visitor: (issues) => ({
      CallExpression(path) {
        const callee = path.node.callee;
        if (callee.type === 'MemberExpression' && callee.object.name === 'console') {
          // Check what is being logged
          path.node.arguments.forEach(arg => {
            if (arg.type === 'Identifier') {
              const argName = arg.name.toLowerCase();
              if (argName.includes('password') || argName.includes('token') || argName.includes('secret') || argName.includes('key')) {
                issues.push({
                  id: "OWASP-A6-001",
                  severity: "MEDIUM",
                  line: path.node.loc?.start?.line || 'unknown',
                  column: path.node.loc?.start?.column || 'unknown',
                  message: `Sensitive variable '${arg.name}' logged to console`,
                  suggestion: "Remove console.log statements containing sensitive data before deploying to production."
                });
              }
            }
          });
        }
      }
    })
  },
  {
    name: "cors-wildcard",
    id: "OWASP-A6-002",
    severity: "HIGH",
    message: "Permissive CORS policy detected (Access-Control-Allow-Origin: *).",
    owasp: "A6:2021-Security Misconfiguration",
    visitor: (issues) => ({
      CallExpression(path) {
        const callee = path.node.callee;
        // Looking for res.setHeader('Access-Control-Allow-Origin', '*')
        if (callee.type === 'MemberExpression' && (callee.property.name === 'setHeader' || callee.property.name === 'header')) {
          const args = path.node.arguments;
          if (args.length === 2 && args[0].type === 'StringLiteral' && args[1].type === 'StringLiteral') {
            if (args[0].value.toLowerCase() === 'access-control-allow-origin' && args[1].value === '*') {
              issues.push({
                id: "OWASP-A6-002",
                severity: "HIGH",
                line: path.node.loc?.start?.line || 'unknown',
                column: path.node.loc?.start?.column || 'unknown',
                message: "Wildcard (*) used in Access-Control-Allow-Origin header",
                suggestion: "Specify exact trusted domains instead of using a wildcard to prevent unauthorized cross-origin requests."
              });
            }
          }
        }
      }
    })
  }
];
