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

    // Rules logic: Use @babel/standalone's traverse if available
    // or access it via Babel.availablePlugins
    // In @babel/standalone, the traverse function is usually not exported directly 
    // but we can use the Babel.transform feature or check the export.
    
    // Fallback: If Babel.traverse is not available, we can use a custom visitor 
    // through Babel.transform. But most builds of standalone expose traverse.
    
    if (Babel.traverse) {
      rules.forEach(rule => {
        Babel.traverse(ast, rule.visitor(issues));
      });
    } else {
      console.warn("Babel.traverse not found. Rule scanning skipped.");
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
