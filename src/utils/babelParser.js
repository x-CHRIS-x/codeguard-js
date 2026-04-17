import * as parser from '@babel/parser';

/**
 * Parses JavaScript/TypeScript code into an Abstract Syntax Tree (AST).
 * Handles JSX, TypeScript, and modern JavaScript features.
 * 
 * @param {string} code - Raw source code as text.
 * @param {string} fileName - File name to determine if it's TS or JS.
 * @returns {Object} - Babel AST object.
 */
export const parseToAST = (code, fileName) => {
  const isTypeScript = fileName.endsWith('.ts') || fileName.endsWith('.tsx');
  const isJSX = fileName.endsWith('.jsx') || fileName.endsWith('.tsx');

  try {
    return parser.parse(code, {
      sourceType: 'module',
      plugins: [
        isJSX ? 'jsx' : null,
        isTypeScript ? 'typescript' : null,
        'optionalChaining',
        'nullishCoalescingOperator',
        'dynamicImport',
        'classProperties',
        'decorators-legacy',
      ].filter(Boolean),
      errorRecovery: true, // Allows partial scans of broken files
    });
  } catch (error) {
    console.error(`Error parsing ${fileName}:`, error.message);
    throw new Error(`Failed to parse ${fileName}: ${error.message}`);
  }
};
