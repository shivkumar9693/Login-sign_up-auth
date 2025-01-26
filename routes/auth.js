const express = require("express");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const bcrypt = require("bcrypt");
const { body, validationResult } = require("express-validator");
const User = require("../models/User");
const { runInContext } = require("vm");

const router = express.Router();

// Middleware for Input Validation
const validateInput = (method) => {
  switch (method) {
    case "signup":
      return [
        body("email").isEmail().withMessage("Invalid email address"),
        body("password")
          .isLength({ min: 8 })
          .withMessage("Password must be at least 8 characters")
          .matches(/[A-Z]/)
          .withMessage("Password must contain at least one uppercase letter")
          .matches(/[a-z]/)
          .withMessage("Password must contain at least one lowercase letter")
          .matches(/[0-9]/)
          .withMessage("Password must contain at least one number")
          .matches(/[\W_]/)
          .withMessage("Password must contain at least one special character"),
      ];
    case "forgot-password":
      return [
        body("email").isEmail().withMessage("Invalid email address"),
      ];
    default:
      return [];
  }
};
//
router.get("/", (req, res) => {
    res.render("home");
  });
// Signup Page
router.get("/signup", (req, res) => {
  res.render("signup");
});

router.post("/signup", validateInput("signup"), async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).send(errors.array().map(err => err.msg).join(", "));
  }

  const { email, password } = req.body;

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).send("Email already exists");

    const user = new User({ email, password });
    await user.save();
    res.redirect("/login");
  } catch (err) {
    res.status(500).send("Server error");
  }
});

// Login Page
router.get("/login", (req, res) => {
  res.render("login");
});

router.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).send("Invalid email or password");

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) return res.status(400).send("Invalid email or password");

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: "1h" });
    res.cookie("auth_token", token, { httpOnly: true, secure: true });
    res.send("Login successful");
  } catch (err) {
    res.status(500).send("Server error");
  }
});

// Forgot Password Page
router.get("/forgot-password", (req, res) => {
  res.render("forgot-password");
});

router.post("/forgot-password", validateInput("forgot-password"), async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).send(errors.array().map(err => err.msg).join(", "));
  }

  const { email } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).send("User not found");

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: "15m" });
    user.resetToken = token;
    user.resetTokenExpiration = Date.now() + 15 * 60 * 1000; // 15 minutes
    await user.save();

    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Password Reset",
      text: `Reset your password using this link: http://localhost:${process.env.PORT}/reset-password?token=${token}`,
    };

    transporter.sendMail(mailOptions, (err, info) => {
      if (err) return res.status(500).send("Error sending email");
      res.send("Password reset email sent");
    });
  } catch (err) {
    res.status(500).send("Server error");
  }
});

// Reset Password Page
router.get("/reset-password", (req, res) => {
  const { token } = req.query;
  res.render("reset-password", { token });
});

router.post("/reset-password", async (req, res) => {
  const { token, password } = req.body;

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId);

    if (!user || user.resetToken !== token || user.resetTokenExpiration < Date.now()) {
      return res.status(400).send("Invalid or expired token");
    }

    const hashedPassword = await bcrypt.hash(password, 10); // Hash the new password
    user.password = hashedPassword;
    user.resetToken = undefined;
    user.resetTokenExpiration = undefined;
    await user.save();
    res.redirect("/login");
  } catch (err) {
    console.error(err);
    res.status(500).send("Error resetting password");
  }
});

module.exports = router;