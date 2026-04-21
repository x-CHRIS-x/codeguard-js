// A1 - Injection Vulnerabilities
const userInput = "console.log('pwned')";

// Dangerous eval()
eval(userInput);

// Dangerous setTimeout with string
setTimeout("alert('Hacked!')", 1000);

// Dangerous setInterval with string
setInterval("console.log('Injected')", 5000);

// Safe setTimeout
setTimeout(() => {
  console.log("Safe callback");
}, 1000);
