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

const SECRET_KEY = process.env.JWT_SECRET || "supersecretkey";

// Database setup
const db = new sqlite3.Database("database.sqlite");

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT, 
        email TEXT UNIQUE NOT NULL, 
        username TEXT UNIQUE NOT NULL, 
        password TEXT NOT NULL
    )`);
});

// ** Register API **
app.post("/register", async (req, res) => {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
        return res.status(400).json({ error: "All fields are required" });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        db.run("INSERT INTO users (email, username, password) VALUES (?, ?, ?)", [email, username, hashedPassword], function (err) {
            if (err) {
                return res.status(400).json({ error: "Email or username already registered" });
            }
            res.status(201).json({ message: "User registered successfully" });
        });
    } catch (error) {
        res.status(500).json({ error: "Registration failed" });
    }
});

// ** Login API **
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

        const token = jwt.sign({ id: user.id, email: user.email, username: user.username }, SECRET_KEY, { expiresIn: "1h" });

        res.json({ token, username: user.username });
    });
});

// ** Middleware to Verify JWT **
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

// ** Send Phishing Test Email API **
app.post("/api/send-test-email", authenticateToken, async (req, res) => {
    const { testerEmail, testEmail } = req.body;

    if (!testerEmail || !testEmail) {
        return res.status(400).json({ error: "Both emails are required" });
    }

    try {
        const transporter = nodemailer.createTransport({
            host: "smtp.gmail.com",
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
            subject: "Security Alert - Action Required",
            html: `
                <div style="font-family: Arial, sans-serif; padding: 20px; border: 1px solid #ddd;">
                    <h2 style="color: #0072c6;">Outlook Security Notice</h2>
                    <p>Dear User,</p>
                    <p>All Hotmail customers have been upgraded to Outlook.com. Your Hotmail account services have expired.</p>
                    <p>To continue using your account, please verify your account:</p>
                    <p><a href="https://account.live.com" style="color: #0072c6; font-weight: bold;">Verify Now</a></p>
                    <p>Thanks,</p>
                    <p>The Microsoft Account Team</p>
                </div>
            `
        };

        await transporter.sendMail(mailOptions);
        
        // Send notification email to tester
        const testerNotification = {
            from: process.env.EMAIL_USER,
            to: testerEmail,
            subject: "Phishing Test Sent Successfully",
            text: `Your phishing test email was successfully sent to ${testEmail}.`
        };
        await transporter.sendMail(testerNotification);

        res.status(200).json({ message: "Test email sent!" });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Failed to send email" });
    }
});

// ** Serve Index Page **
app.get("*", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "index.html"));
});

// ** Start Server **
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
