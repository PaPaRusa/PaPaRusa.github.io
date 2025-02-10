const express = require("express");
const path = require("path");
const fs = require("fs");
const cors = require("cors");
const nodemailer = require("nodemailer");
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors());

// Serve static files from the 'public' folder
app.use(express.static(path.join(__dirname, "public")));

// Route for homepage
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Route for subscribe page
app.get("/subscribe", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "subscribe.html"));
});

const adminEmail = "main@forti-phish.com";

const transporter = nodemailer.createTransport({
    host: "smtp.gmail.com",
    port: 465,
    secure: true, 
    auth: {
        user: process.env.GMAIL_USER,           
        pass: process.env.GMAIL_APP_PASSWORD    
    }
});


app.post("/api/start-phishing-test", async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ error: "Email is required" });
    }

    const trackingUrl = `https://forti-phish.com/track?email=${encodeURIComponent(email)}`;

    const mailOptions = {
    from: "no-reply@forti-phish.com", // 
    to: email,
    subject: "⚠️ Important: Account Verification Required",
    html: `
        <div style="font-family: Arial, sans-serif; padding: 20px; color: #333;">
            <h2 style="color: #D93025;">Action Required: Verify Your Account</h2>
            <p>We've detected unusual activity on your account. For your security, please verify your login to prevent account suspension.</p>
            <p>Failure to verify within 24 hours may result in restricted access.</p>
            <a href="${trackingUrl}" style="display: inline-block; background-color: #1A73E8; color: white; padding: 12px 20px; text-decoration: none; border-radius: 5px;">
                Verify My Account
            </a>
            <p style="font-size: 12px; color: gray; margin-top: 10px;">If you didn't request this, please ignore this email.</p>
        </div>
    `
};

    try {
        await transporter.sendMail(mailOptions);
        res.status(200).json({ message: "Phishing test email sent successfully!" });
    } catch (error) {
        console.error("Email sending failed:", error);
        res.status(500).json({ error: "Failed to send email" });
    }
});

app.get("/track", (req, res) => {
    const email = req.query.email;

    if (email) {
        const logEntry = `${email}-clicked`;
        const logFile = "log.txt";

        // Check if the user has already clicked the link
        const existingLog = fs.existsSync(logFile) ? fs.readFileSync(logFile, "utf8") : "";

        if (!existingLog.includes(logEntry)) {
            fs.appendFileSync(logFile, `${logEntry} at ${new Date().toISOString()}\n`);
            console.log(`${email} clicked the phishing link.`);

            // Send Notification to Admin
            const adminMailOptions = {
                from: "no-reply@forti-phish.com",
                to: "main@forti-phish.com",
                subject: "🚨 Phishing Test Alert!",
                text: `User ${email} clicked the phishing link at ${new Date().toISOString()}.`
            };

            transporter.sendMail(adminMailOptions, (error, info) => {
                if (error) {
                    console.error("Error sending notification:", error);
                } else {
                    console.log("Admin notified:", info.response);
                }
            });
        } else {
            console.log(`Duplicate click detected for ${email}, notification skipped.`);
        }
    }

    // Redirect to training page
    res.redirect("https://your-training-page.com");
});

// Catch-all route for undefined paths
app.use((req, res) => {
    res.status(404).send("404 Not Found");
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
