const jwt = require('jsonwebtoken');
const config = require('config');
const { User } = require('../../models/user/user.model');

module.exports = async function (req, res, next) {
    const token = req.cookies.auth_token;
    
    if (!token) {
        return res.status(401).json({ 
            error: 'Acceso denegado. No se proporcionó un token de autenticación.' 
        });
    }

    try {
        const decoded = jwt.verify(token, config.get('jwtPrivateKey'));
        
        const userDoc = await User.Model.findById(decoded._id);
        if (!userDoc) {
            return res.status(401).json({ 
                error: 'Token inválido. Usuario no encontrado.' 
            });
        }

        const user = User.fromMongoose(userDoc);

        // Verify token version matches current user token version (global revocation)
        if (decoded.tokenVersion !== user.tokenVersion) {
            return res.status(401).json({ 
                error: 'Token inválido. La sesión ha sido cerrada globalmente.' 
            });
        }

        // Verify sessionId exists in activeSessions (per-session revocation)
        // Only check if JWT has sessionId (new sessions), skip for old sessions during migration
        if (decoded.sessionId) {
            const sessionExists = user.activeSessions.some(s => s.sessionId === decoded.sessionId);
            if (!sessionExists) {
                return res.status(401).json({ 
                    error: 'Token inválido. Esta sesión ha sido cerrada.' 
                });
            }
        } else {
            // Old JWT without sessionId - still valid but will be migrated on next login
            debug('Token antiguo sin sessionId detectado para usuario: %s', decoded._id);
        }

        if (user.estado_cuenta !== 'activo') {
            return res.status(401).json({ 
                error: 'Cuenta inactiva.' 
            });
        }
        
        req.user = decoded;
        next();
    } catch (ex) {
        res.status(400).json({ 
            error: 'Token inválido.' 
        });
    }
};
