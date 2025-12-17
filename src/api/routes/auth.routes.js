const express = require("express");
const debug = require('debug')('easyinjection:api:auth');
const passport = require("passport");
const auth = require("../middleware/auth.middleware");
const {
  createSessionData,
} = require("../middleware/session-tracker.middleware");
const router = express.Router();

router.get("/verify", auth, async (req, res) => {
  try {
    res.json({
      message: "Token válido",
      user: req.user,
    });
  } catch (error) {
    res.status(500).json({
      error: "Error interno del servidor",
    });
  }
});

router.get("/me", auth, async (req, res) => {
  try {
    const { User } = require("../../models/user/user.model");
    const userDoc = await User.Model.findById(req.user._id).select(
      "-contrasena_hash -token_verificacion"
    );

    if (!userDoc) {
      return res.status(404).json({
        error: "Usuario no encontrado",
      });
    }

    const user = User.fromMongoose(userDoc);
    res.json({
      user: user.toDTO()
    });
  } catch (error) {
    debug('ERROR en GET /api/auth/me:', error);
    debug('Error message:', error.message);
    debug('Error stack:', error.stack);
    debug('User ID:', req.user?._id);
    res.status(500).json({
      error: "Error interno del servidor",
    });
  }
});

router.get(
  "/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
    prompt: "select_account",
  })
);

router.get(
  "/google/callback",
  passport.authenticate("google", { session: false }),
  async (req, res) => {
    try {
      const crypto = require('crypto');
      const sessionId = crypto.randomBytes(32).toString('hex');
      
      // Generate refresh token
      const refreshToken = req.user.generateRefreshToken();
      const hashedRefreshToken = req.user.hashRefreshToken(refreshToken);
      
      const sessionData = {
        ...createSessionData(req, sessionId),
        refreshToken: hashedRefreshToken
      };

      if (!req.user.activeSessions) {
        req.user.activeSessions = [];
      }

      req.user.activeSessions = req.user.activeSessions.filter(session => 
        !(session.device === sessionData.device && 
          session.browser === sessionData.browser &&
          session.ip === sessionData.ip)
      );

      req.user.activeSessions.push(sessionData);

      if (req.user.activeSessions.length > 5) {
        req.user.activeSessions.sort((a, b) => 
          new Date(b.createdAt) - new Date(a.createdAt)
        );
        req.user.activeSessions = req.user.activeSessions.slice(0, 5);
      }

      await req.user.save();
      
      // Generate short-lived JWT (15 minutes)
      const token = req.user.generateAuthToken(sessionId);
      
      res.cookie('auth_token', token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: 15 * 60 * 1000 // 15 minutes
      });
      
      res.cookie('refresh_token', refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
      });
      
      res.redirect(`${process.env.FRONTEND_URL}/dashboard`);
    } catch (error) {
      debug('ERROR en GET /api/auth/google/callback:', error);
      debug('Error message:', error.message);
      debug('Error stack:', error.stack);
      res.redirect("/login?error=internal_server_error");
    }
  }
);

module.exports = router;
