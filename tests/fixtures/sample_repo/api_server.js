// Sample JavaScript file for testing hotspot detection.
// WARNING: Deliberately insecure — testing only.

const express = require('express');
const { exec } = require('child_process');
const fs = require('fs');

const app = express();

// Command injection
app.get('/run', (req, res) => {
    const cmd = req.query.cmd;
    exec(cmd, (error, stdout, stderr) => {
        res.send(stdout || stderr);
    });
});

// Path traversal
app.get('/file', (req, res) => {
    const filename = req.query.name;
    const content = fs.readFileSync('/data/' + filename, 'utf8');
    res.send(content);
});

// XSS via innerHTML
app.get('/render', (req, res) => {
    const userInput = req.query.html;
    res.send(`<div id="output">${userInput}</div>`);
});

// SQL injection (raw query)
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const query = `SELECT * FROM users WHERE user='${username}' AND pass='${password}'`;
    // db.execute(query) ...
    res.json({ query });
});

// Session handling
app.use((req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) {
        return res.status(401).json({ error: 'No token' });
    }
    next();
});

module.exports = app;
