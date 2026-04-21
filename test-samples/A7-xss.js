// A7 - Cross-Site Scripting (XSS)
const name = new URLSearchParams(window.location.search).get('name');

// 1. Direct innerHTML (High Risk)
document.getElementById('welcome').innerHTML = "Hello, " + name;

// 2. document.write (High Risk)
document.write("<p>Current user: " + name + "</p>");

// 3. dangerouslySetInnerHTML in React/JSX (High Risk)
const MyComponent = ({ unsafeContent }) => {
  return <div dangerouslySetInnerHTML={{ __html: unsafeContent }} />;
};

// 4. Safe alternative
document.getElementById('safe').textContent = "Safe: " + name;
