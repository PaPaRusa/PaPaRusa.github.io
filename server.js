const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const sqlite3 = require("sqlite3").verbose();
const cors = require("cors");
require("dotenv").config();

const app = express();
const path = require('path');
app.use(express.static(path.join(__dirname, 'public')));

app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const SECRET_KEY = process.env.JWT_SECRET || "supersecretkey";

// Database setup
const db = new sqlite3.Database("database.sqlite");
db.serialize(() => {
    db.run("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, email TEXT UNIQUE, password TEXT)");
});

// Register endpoint
app.post("/register", async (req, res) => {
    const { email, password } = req.body;
    
    if (!email || !password) {
        return res.status(400).json({ error: "Email and password are required" });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        db.run("INSERT INTO users (email, password) VALUES (?, ?)", [email, hashedPassword], function (err) {
            if (err) {
                return res.status(400).json({ error: "Email already registered" });
            }
            res.status(201).json({ message: "User registered successfully" });
        });
    } catch (error) {
        res.status(500).json({ error: "Registration failed" });
    }
});

// Login endpoint
app.post("/login", (req, res) => {
    const { email, password } = req.body;
    db.get("SELECT * FROM users WHERE email = ?", [email], async (err, user) => {
        if (err || !user) {
            return res.status(400).json({ error: "Invalid credentials" });
        }

        const isValid = await bcrypt.compare(password, user.password);
        if (!isValid) {
            return res.status(400).json({ error: "Invalid credentials" });
        }

        const token = jwt.sign({ id: user.id, email: user.email }, SECRET_KEY, { expiresIn: "1h" });
        res.json({ token });
    });
});

// Middleware to verify JWT
function authenticateToken(req, res, next) {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

// Protected API for starting phishing test
app.post("/api/start-phishing-test", authenticateToken, (req, res) => {
    const { email } = req.body;
    if (!email) {
        return res.status(400).json({ error: "Target email is required" });
    }

    // Placeholder response - Replace with email sending logic
    res.json({ message: "Phishing test initiated successfully!" });
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
