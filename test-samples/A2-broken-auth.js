// A2 - Broken Authentication
const login = (u, p) => {
  // Hardcoded password
  if (p === "Admin123!") {
    return true;
  }
};

// Storing tokens in localStorage (vulnerable to XSS theft)
localStorage.setItem('userToken', 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...');

// Session management
document.cookie = "session_id=123456789; HttpOnly=false";
