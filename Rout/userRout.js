import express from "express";
import {
  registerUser,
  loginUser,
  verifyUser,
  requestPasswordReset,
  resetPassword,
} from "../controler/Usercont.js";
import rateLimit from "express-rate-limit";
import auth from "../Midleware/authmidleware.js";

const router = express.Router();

// Rate limiter for reset password requests
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // limit each IP to 5 requests per windowMs
  message: {
    message: "Too many requests from this IP, please try again later.",
    success: false,
  },
});

// ✅ ROUTES

// Register new user
router.post("/register", registerUser);

// Login user (❌ remove auth middleware — user is not logged in yet)
router.post("/login", auth, loginUser);

// Verify JWT and return user
router.get("/verify", auth, verifyUser);

// Request password reset
router.post("/request-reset-password", apiLimiter, requestPasswordReset);

// Reset password
router.post("/reset-password", resetPassword);

export default router;
