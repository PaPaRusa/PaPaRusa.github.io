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
        from: "no-reply@forti-phish.com",
        to: email,
        subject: "🚨 Security Alert - Verify Your Account",
        html: `<p>We detected unusual activity. Click <a href='${trackingUrl}'>here</a> to verify.</p>`
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
        const logEntry = `${email} clicked at ${new Date().toISOString()}\n`;
        fs.appendFileSync("log.txt", logEntry);
        console.log(logEntry);

        // Send Notification to Admin
        const adminMailOptions = {
            from: "no-reply@forti-phish.com",
            to: "main@forti-phish.com", // Admin email to receive notifications
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
    }

    // Redirect to the training page
    res.redirect("https://your-training-page.com");
});


// Catch-all route for undefined paths
app.use((req, res) => {
    res.status(404).send("404 Not Found");
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
