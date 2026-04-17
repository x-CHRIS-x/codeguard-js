import { parseToAST } from './babelParser';
import * as Babel from '@babel/standalone';

/**
 * Main scanning engine that coordinates file parsing and rule execution.
 * 
 * @param {File} file - Browser File object.
 * @param {Array} rules - Array of security rule objects.
 * @returns {Promise<Object>} - Results including AST and any vulnerabilities.
 */
export const scanFile = async (file, rules) => {
  try {
    const code = await file.text();
    const ast = parseToAST(code, file.name);
    const issues = [];

    // Correctly find traverse in @babel/standalone
    const traverse = Babel.traverse || (Babel.packages ? Babel.packages.traverse : null);
    
    if (traverse) {
      rules.forEach(rule => {
        // rules is an array of rule objects, each with a visitor function
        // the visitor function takes the issues array to populate it
        traverse(ast, rule.visitor(issues));
      });
    } else {
      console.warn("Babel.traverse not found in standalone package. Attempting fallback via transform...");
      
      // Fallback: If direct traverse is missing, use Babel.transform with a custom plugin
      // for each rule to achieve the same effect
      rules.forEach(rule => {
        Babel.transform(code, {
          ast: true,
          code: false,
          filename: file.name,
          plugins: [() => ({ visitor: rule.visitor(issues) })]
        });
      });
    }

    return {
      fileName: file.webkitRelativePath || file.name,
      issues,
      success: true
    };
  } catch (error) {
    console.error("Scanner Error:", error);
    return {
      fileName: file.webkitRelativePath || file.name,
      error: error.message,
      success: false
    };
  }
};
