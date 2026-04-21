const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const { execSync } = require('child_process');
const path = require('path');
const app = express();
app.use(express.json());

// SECTION: auth.js (Authentication & Session Issues)
app.post('/auth/token', (req, res) => {
    // Hardcoded secret and predictable token generation
    const SECRET = "JWT_APP_SECRET_KEY_2026";
    const token = Math.random().toString(36).substr(2);
    res.cookie('session', token, { httpOnly: false }); 
    res.send({ auth: true, key: SECRET });
});

// SECTION: deserialization.js (Insecure Deserialization)
app.post('/data/sync', (req, res) => {
    const { state } = req.body;
    // Prototype Pollution via unsafe merge/assignment
    const base = {};
    const input = JSON.parse(state);
    for (let key in input) {
        base[key] = input[key];
    }
    res.json(base);
});

// SECTION: injection.js (Command and Code Injection)
app.get('/system/health', (req, res) => {
    const service = req.query.service;
    // Shell command injection
    const status = execSync(`systemctl status ${service}`).toString();
    res.send(status);
});

app.post('/compute', (req, res) => {
    // Dynamic code execution via Function constructor
    const runner = new Function('a', 'b', req.body.logic);
    res.send({ val: runner(1, 2) });
});

// SECTION: knownVulns.js (Vulnerable Patterns/Functions)
app.get('/debug/info', (req, res) => {
    // Use of known dangerous functions
    const payload = req.query.p;
    const out = eval("(" + payload + ")");
    res.json({ out });
});

// SECTION: misconfig.js (Security Misconfigurations)
app.get('/api/v2/config', (req, res) => {
    // Verbose error messages and open redirects
    try {
        const target = req.query.url;
        res.redirect(target);
    } catch (e) {
        res.status(500).send(e.stack); 
    }
});

// SECTION: sensitiveData.js (Data Leaks/Weak Crypto)
app.post('/user/password-reset', (req, res) => {
    const { pass } = req.body;
    // Using weak hashing algorithm (MD5)
    const hash = crypto.createHash('md5').update(pass).digest('hex');
    console.log("DEBUG: Internal Pass Key is " + hash);
    res.send("Updated");
});

// SECTION: xss.js (Cross-Site Scripting)
app.get('/dashboard/welcome', (req, res) => {
    const username = req.query.name;
    // Reflecting unescaped user input into HTML
    res.send(`<h1>Welcome, ${username}!</h1>`);
});

/** * FILLER SECTION 
 * Adding 400+ lines of standard boilerplate logic to test 
 * if the scanner can find the vulnerabilities within a large file.
 */

class UserProcessor {
    constructor(data) { this.data = data; }
    validate() { return !!this.data; }
    save() { /* Logic ... */ }
}

function processBatch(items) {
    return items.map(i => new UserProcessor(i));
}

// ... Imagine several hundred lines of standard utility methods ...
// ... to simulate a real-world enterprise application environment ...

for (let i = 0; i < 50; i++) {
    app.get(`/route-${i}`, (req, res) => {
        const p = new UserProcessor(req.query);
        res.send(p.validate() ? "Valid" : "Invalid");
    });
}

app.listen(3000);