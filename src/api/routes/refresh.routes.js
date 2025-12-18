const express = require('express');
const debug = require('debug')('easyinjection:api:refresh');
const jwt = require('jsonwebtoken');
const config = require('config');
const { User } = require('../../models/user/user.model');
const router = express.Router();

/**
 * Endpoint para refrescar el JWT usando el refresh token
 * POST /api/auth/refresh
 */
router.post('/', async (req, res) => {
    try {
        const refreshToken = req.cookies.refresh_token;
        const oldJwt = req.cookies.auth_token;

        if (!refreshToken) {
            debug('Refresh token no proporcionado');
            return res.status(401).json({ 
                error: 'Refresh token no proporcionado' 
            });
        }

        if (!oldJwt) {
            debug('JWT antiguo no encontrado');
            return res.status(401).json({ 
                error: 'JWT no encontrado' 
            });
        }

        // Decodificar el JWT antiguo sin verificar expiración (puede estar expirado)
        // Esto es válido para refresh porque verificamos el refresh token
        let decoded;
        try {
            // Primero intentar verificar normalmente
            try {
                decoded = jwt.verify(oldJwt, config.get('jwtPrivateKey'));
            } catch (verifyErr) {
                // Si falla por expiración, decodificar sin verificar
                if (verifyErr.name === 'TokenExpiredError') {
                    decoded = jwt.decode(oldJwt);
                    debug('JWT expirado pero válido para refresh');
                } else {
                    throw verifyErr;
                }
            }
        } catch (err) {
            debug('Error decodificando JWT:', err);
            return res.status(401).json({ 
                error: 'JWT inválido' 
            });
        }

        if (!decoded || !decoded._id || !decoded.sessionId) {
            debug('JWT no contiene información necesaria');
            return res.status(401).json({ 
                error: 'JWT inválido' 
            });
        }

        // Buscar el usuario
        const userDoc = await User.Model.findById(decoded._id);
        if (!userDoc) {
            debug('Usuario no encontrado');
            return res.status(401).json({ 
                error: 'Usuario no encontrado' 
            });
        }

        const user = User.fromMongoose(userDoc);

        // Verificar que el tokenVersion coincida
        if (decoded.tokenVersion !== user.tokenVersion) {
            debug('Token version mismatch. Usuario: %d, JWT: %d', user.tokenVersion, decoded.tokenVersion);
            // Limpiar cookies
            res.clearCookie('auth_token');
            res.clearCookie('refresh_token');
            return res.status(401).json({ 
                error: 'Token ha sido revocado',
                revoked: true
            });
        }

        // Verificar el refresh token
        const isValidRefreshToken = user.verifyRefreshToken(refreshToken, decoded.sessionId);
        if (!isValidRefreshToken) {
            debug('Refresh token inválido para sessionId: %s', decoded.sessionId);
            res.clearCookie('auth_token');
            res.clearCookie('refresh_token');
            return res.status(401).json({ 
                error: 'Refresh token inválido' 
            });
        }

        // Generar nuevo refresh token (rotación)
        const newRefreshToken = user.generateRefreshToken();
        user.updateRefreshToken(decoded.sessionId, newRefreshToken);

        // Actualizar última actividad de la sesión
        const session = user.activeSessions.find(s => s.sessionId === decoded.sessionId);
        if (session) {
            session.lastActivity = new Date();
        }

        await user.save();

        // Generar nuevo JWT de 15 minutos
        const newJwt = user.generateAuthToken(decoded.sessionId);

        // Enviar nuevas cookies
        res.cookie('auth_token', newJwt, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax',
            maxAge: 15 * 60 * 1000 // 15 minutes
        });

        res.cookie('refresh_token', newRefreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax',
            maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
        });

        debug('Token refrescado exitosamente para usuario: %s', user.username);

        res.json({
            message: 'Token refrescado exitosamente',
            user: user.toDTO()
        });

    } catch (error) {
        debug('ERROR en POST /api/auth/refresh:', error);
        console.error('Error en refresh:', error);
        res.status(500).json({ 
            error: 'Error interno del servidor',
            details: error.message 
        });
    }
});

module.exports = router;
