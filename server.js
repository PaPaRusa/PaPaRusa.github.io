const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const sqlite3 = require("sqlite3").verbose();
const cors = require("cors");
const nodemailer = require("nodemailer");
require("dotenv").config();

const app = express();
const path = require("path");
app.use(express.json());
app.use(cors());
app.use(express.static(path.join(__dirname, "public")));

app.get("*", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "index.html"));
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
    db.get("SELECT id, email, username, password FROM users WHERE email = ?", [email], async (err, user) => {
        if (err || !user) {
            return res.status(400).json({ error: "Invalid credentials" });
        }

        const isValid = await bcrypt.compare(password, user.password);
        if (!isValid) {
            return res.status(400).json({ error: "Invalid credentials" });
        }

        const token = jwt.sign({ id: user.id, email: user.email }, SECRET_KEY, { expiresIn: "1h" });

        if (user.username) {
            res.json({ token, username: user.username }); // ✅ Send actual username
        } else {
            res.json({ token, username: "Guest" }); // Fallback if no username found
        }
    });
});


function authenticateToken(req, res, next) {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];

    if (!token) return res.status(401).json({ error: "Access denied. No token provided." });

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.status(403).json({ error: "Invalid token." });
        req.user = user;
        next();
    });
}


// Protected API for sending phishing test email
app.post("/api/send-test-email", authenticateToken, async (req, res) => {
    const { testerEmail, testEmail } = req.body;

    if (!testerEmail || !testEmail) {
        return res.status(400).json({ error: "Both emails are required" });
    }

    try {
        const transporter = nodemailer.createTransport({
            host: "smtp.gmail.com", // Or your email provider
            port: 465,
            secure: true,
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASS
            }
        });

        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: testEmail,
            subject: "Outlook Security Alert",
            html: `<img src='https://w7.pngwing.com/pngs/495/230/png-transparent-outlook-logo.png' alt='Outlook Logo'><br>
                   <p>Dear User,</p>
                   <p>All Hotmail customers have been upgraded to Outlook.com. Your Hotmail Account services have expired.</p>
                   <p>Due to our new system upgrade to Outlook. In order for it to remain active, follow the link below to Sign in and Re-activate your account:</p>
                   <a href="https://account.live.com">https://account.live.com</a>
                   <p>Thanks,<br>The Microsoft account team</p>`
        };

        await transporter.sendMail(mailOptions);

        // Send a notification email to the tester
        const notificationOptions = {
            from: process.env.EMAIL_USER,
            to: testerEmail,
            subject: "Phishing Test Notification",
            text: `A phishing test email was sent to ${testEmail}. Monitor their response.`
        };

        await transporter.sendMail(notificationOptions);
        res.status(200).json({ message: "Test email sent and notification delivered!" });

    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Failed to send email" });
    }
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
