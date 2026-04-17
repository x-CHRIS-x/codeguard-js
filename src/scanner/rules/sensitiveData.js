/**
 * A3 - Sensitive Data Exposure Rules
 * Targets: Hardcoded API keys, IPs, AWS Keys, JWTs in strings
 */
export const sensitiveDataRules = [
  {
    name: "hardcoded-secret-patterns",
    id: "OWASP-A3-001",
    severity: "CRITICAL",
    message: "Potential sensitive data or secret key hardcoded in string.",
    owasp: "A3:2021-Sensitive Data Exposure",
    visitor: (issues) => ({
      StringLiteral(path) {
        const val = path.node.value;
        // Basic Regex Patterns for common secrets
        const jwtPattern = /^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*$/;
        const awsKeyPattern = /(?:AKIA|A3T|AGPA|AIDA|AROA|AIPA|AQCA|AMZA|AWA|A2A)[A-Z0-9]{16}/;
        const ipPattern = /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/;

        let type = null;
        if (val.startsWith('eyJ') && jwtPattern.test(val)) type = "JWT Token";
        else if (awsKeyPattern.test(val)) type = "AWS Access Key";
        else if (ipPattern.test(val) && val !== '127.0.0.1' && val !== '0.0.0.0') type = "IP Address";

        if (type) {
          issues.push({
            id: "OWASP-A3-001",
            severity: type === "IP Address" ? "MEDIUM" : "CRITICAL",
            line: path.node.loc?.start?.line || 'unknown',
            column: path.node.loc?.start?.column || 'unknown',
            message: `Hardcoded ${type} detected in string.`,
            suggestion: `Never hardcode ${type}s. Use environment variables (e.g., process.env or import.meta.env).`
          });
        }
      }
    })
  }
];
