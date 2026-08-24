const express = require('express');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(session({
    secret: 'change-me-in-production',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }   // HTTP only for local testing
}));

// ----- Database setup -----
const db = new sqlite3.Database('./users.db');

app.get('/setup', (req, res) => {
    db.serialize(() => {
        db.run("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)");
        db.run("INSERT OR IGNORE INTO users (username, password) VALUES ('admin', 'admin123')");
        db.run("INSERT OR IGNORE INTO users (username, password) VALUES ('alice', 'password')");
        db.run("INSERT OR IGNORE INTO users (username, password) VALUES ('bob', '123456')");
    });
    res.send('Database ready! <a href="/">Go to login</a>');
});

// ----- Login page -----
app.get('/', (req, res) => {
    if (req.session.user) return res.redirect('/dashboard');
    res.send(`
        <h2>Login</h2>
        <form method="POST" action="/login">
            Username: <input type="text" name="username"><br>
            Password: <input type="password" name="password"><br>
            <input type="submit" value="Login">
        </form>
    `);
});

// ----- Login handler (VULNERABLE to SQL injection) -----
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    // ❌ Direct string interpolation – classic SQL injection
    const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;

    db.get(query, (err, row) => {
        if (row) {
            req.session.user = row.username;
            res.redirect('/dashboard');
        } else {
            res.send('Invalid credentials. <a href="/">Try again</a>');
        }
    });
});

// ----- Dashboard (VULNERABLE to reflected XSS) -----
app.get('/dashboard', (req, res) => {
    if (!req.session.user) return res.redirect('/');

    let searchResults = '';
    if (req.query.q) {
        // ❌ Unescaped user input – XSS payloads will execute
        searchResults = `Results for: ${req.query.q}`;
    }

    res.send(`
        <h2>Welcome, ${req.session.user}!</h2>
        <form method="GET" action="/dashboard">
            Search transactions: <input type="text" name="q">
            <input type="submit" value="Search">
        </form>
        <div>${searchResults}</div>
        <p><a href="/admin">Admin Panel</a></p>
        <p><a href="/logout">Logout</a></p>
    `);
});

// ----- Admin panel (VULNERABLE – no authentication check) -----
app.get('/admin', (req, res) => {
    // ❌ Anyone can access this – no session verification
    res.send(`
        <h1>Admin Area</h1>
        <p>Super secret data: FLAG{admin_panel_exposed}</p>
        <a href="/dashboard">Back</a>
    `);
});

// ----- Logout -----
app.get('/logout', (req, res) => {
    req.session.destroy(() => res.redirect('/'));
});

// ----- Start server -----
app.listen(3000, () => {
    console.log('🔥 Vulnerable app running at http://localhost:3000');
    console.log('👉 Visit /setup first to create the database');
});
