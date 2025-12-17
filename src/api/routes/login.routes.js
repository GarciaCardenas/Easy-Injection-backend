const express = require('express');
const debug = require('debug')('easyinjection:api:login');
const bcrypt = require('bcrypt');
const { User } = require('../../models/user/user.model');
const router = express.Router();

const { createSessionData } = require('../middleware/session-tracker.middleware');

router.post('/', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        if (!email || !password) {
            return res.status(400).json({ 
                error: 'Email y contraseña son requeridos' 
            });
        }

        const userDoc = await User.Model.findOne({ email: email });
        if (!userDoc) {
            return res.status(401).json({ 
                error: 'Credenciales inválidas' 
            });
        }

        const user = User.fromMongoose(userDoc);

        if (!user.email_verificado) {
            return res.status(401).json({ 
                error: 'Por favor verifica tu email antes de iniciar sesión' 
            });
        }

        if (user.estado_cuenta !== 'activo') {
            return res.status(401).json({ 
                error: 'Tu cuenta no está activa. Contacta al administrador.' 
            });
        }

        const validPassword = await bcrypt.compare(password, user.contrasena_hash);
        if (!validPassword) {
            return res.status(401).json({ 
                error: 'Credenciales inválidas' 
            });
        }

        user.updateLogin();
        
        // Limpiar sesiones antiguas sin sessionId (migración)
        if (user.activeSessions && user.activeSessions.length > 0) {
            const validSessions = user.activeSessions.filter(s => s.sessionId);
            if (validSessions.length < user.activeSessions.length) {
                user.clearSessionsOnly();
                validSessions.forEach(s => user.addSession(s));
                debug('Sesiones antiguas sin sessionId limpiadas');
            }
        }
        
        // Generate unique sessionId
        const crypto = require('crypto');
        const sessionId = crypto.randomBytes(32).toString('hex');
        
        // Generate refresh token
        const refreshToken = user.generateRefreshToken();
        const hashedRefreshToken = user.hashRefreshToken(refreshToken);
        
        const sessionData = {
            ...createSessionData(req, sessionId),
            refreshToken: hashedRefreshToken
        };
        user.addSession(sessionData);
        
        // Generate short-lived JWT (15 minutes)
        const token = user.generateAuthToken(sessionId);

        if (user.getActiveSessionCount() > 5) {
            const sortedSessions = [...user.activeSessions].sort((a, b) => 
                new Date(b.lastActivity) - new Date(a.lastActivity)
            );
            user.clearSessionsOnly();
            sortedSessions.slice(0, 5).forEach(s => user.addSession(s));
        }
        
        await user.save();

        // Set short-lived JWT cookie (15 minutes)
        res.cookie('auth_token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax',
            maxAge: 15 * 60 * 1000 // 15 minutes
        });

        // Set long-lived refresh token cookie (7 days)
        res.cookie('refresh_token', refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax',
            maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
        });

        res.json({
            message: 'Login exitoso',
            user: user.toDTO()
        });

    } catch (error) {
        debug('ERROR en POST /api/login:', error);
        debug('Error message:', error.message);
        debug('Error stack:', error.stack);
        debug('Email:', req.body?.email);
        console.error('Error en login:', error);
        res.status(500).json({ 
            error: 'Error interno del servidor',
            details: error.message 
        });
    }
});

module.exports = router;
