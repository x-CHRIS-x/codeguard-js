/**
 * A8 - Software and Data Integrity Failures (Deserialization)
 * Targets: Unsafe JSON.parse()
 */
export const deserializationRules = [
  {
    name: "unsafe-json-parse",
    id: "OWASP-A8-001",
    severity: "LOW",
    message: "Use of JSON.parse() detected. Ensure the input string is validated and comes from a trusted source.",
    owasp: "A8:2021-Software and Data Integrity Failures",
    visitor: (issues) => ({
      CallExpression(path) {
        const callee = path.node.callee;
        if (callee.type === 'MemberExpression' && callee.object.name === 'JSON' && callee.property.name === 'parse') {
          issues.push({
            id: "OWASP-A8-001",
            severity: "LOW",
            line: path.node.loc?.start?.line || 'unknown',
            column: path.node.loc?.start?.column || 'unknown',
            message: "JSON.parse() usage detected",
            suggestion: "If the input comes from an untrusted user, validate the structure of the resulting object immediately."
          });
        }
      }
    })
  }
];
