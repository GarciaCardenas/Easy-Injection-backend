const express = require('express');
const debug = require('debug')('easyinjection:api:user');
const bcrypt = require('bcrypt');
const auth = require('../middleware/auth.middleware');
const { User } = require('../../models/user/user.model');
const router = express.Router();

function validatePasswordStrength(password, email, username) {
    const minLength = 8;
    const hasUpperCase = /[A-Z]/.test(password);
    const hasLowerCase = /[a-z]/.test(password);
    const hasNumber = /\d/.test(password);
    const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);
    
    if (password.length < minLength) {
        return { valid: false, message: 'La contraseña debe tener al menos 8 caracteres' };
    }
    if (!hasUpperCase) {
        return { valid: false, message: 'La contraseña debe incluir al menos una letra mayúscula' };
    }
    if (!hasLowerCase) {
        return { valid: false, message: 'La contraseña debe incluir al menos una letra minúscula' };
    }
    if (!hasNumber) {
        return { valid: false, message: 'La contraseña debe incluir al menos un número' };
    }
    if (!hasSpecialChar) {
        return { valid: false, message: 'La contraseña debe incluir al menos un carácter especial' };
    }

    // Validar que la contraseña no sea igual al email (case insensitive)
    if (email && password.toLowerCase() === email.toLowerCase()) {
        return { valid: false, message: 'La contraseña no puede ser igual a tu correo electrónico' };
    }

    // Validar que la contraseña no sea igual al username (case insensitive)
    if (username && password.toLowerCase() === username.toLowerCase()) {
        return { valid: false, message: 'La contraseña no puede ser igual a tu nombre de usuario' };
    }

    // Validar que la contraseña no contenga el email o username
    if (email && password.toLowerCase().includes(email.toLowerCase())) {
        return { valid: false, message: 'La contraseña no puede contener tu correo electrónico' };
    }

    if (username && password.toLowerCase().includes(username.toLowerCase())) {
        return { valid: false, message: 'La contraseña no puede contener tu nombre de usuario' };
    }

    // Detectar secuencias numéricas predecibles
    const numericSequences = [
        '012', '123', '234', '345', '456', '567', '678', '789', '890',
        '987', '876', '765', '654', '543', '432', '321', '210',
        '111', '222', '333', '444', '555', '666', '777', '888', '999', '000'
    ];

    const passwordLower = password.toLowerCase();
    for (const sequence of numericSequences) {
        if (password.includes(sequence)) {
            return { valid: false, message: 'La contraseña no puede contener secuencias numéricas predecibles (ej: 123, 987, 111)' };
        }
    }

    // Detectar secuencias alfabéticas predecibles
    const alphabeticSequences = [
        'abc', 'bcd', 'cde', 'def', 'efg', 'fgh', 'ghi', 'hij', 'ijk', 'jkl', 'klm', 'lmn', 'mno', 'nop', 'opq', 'pqr', 'qrs', 'rst', 'stu', 'tuv', 'uvw', 'vwx', 'wxy', 'xyz',
        'zyx', 'yxw', 'xwv', 'wvu', 'vut', 'uts', 'tsr', 'srq', 'rqp', 'qpo', 'pon', 'onm', 'nml', 'mlk', 'lkj', 'kji', 'jih', 'ihg', 'hgf', 'gfe', 'fed', 'edc', 'dcb', 'cba',
        'aaa', 'bbb', 'ccc', 'ddd', 'eee', 'fff', 'ggg', 'hhh', 'iii', 'jjj', 'kkk', 'lll', 'mmm', 'nnn', 'ooo', 'ppp', 'qqq', 'rrr', 'sss', 'ttt', 'uuu', 'vvv', 'www', 'xxx', 'yyy', 'zzz'
    ];

    for (const sequence of alphabeticSequences) {
        if (passwordLower.includes(sequence)) {
            return { valid: false, message: 'La contraseña no puede contener secuencias alfabéticas predecibles (ej: abc, xyz, aaa)' };
        }
    }

    // Detectar patrones de teclado comunes
    const keyboardPatterns = [
        'qwerty', 'qwertz', 'azerty', 'asdfgh', 'zxcvbn', 'qweasd', 'asdzxc'
    ];

    for (const pattern of keyboardPatterns) {
        if (passwordLower.includes(pattern)) {
            return { valid: false, message: 'La contraseña no puede contener patrones de teclado predecibles (ej: qwerty, asdfgh)' };
        }
    }

    return { valid: true };
}

router.get('/profile', auth, async (req, res) => {
    try {
        const { User } = require('../../models/user/user.model');
        const userDoc = await User.Model.findById(req.user._id).select('-contrasena_hash -token_verificacion');
        
        if (!userDoc) {
            return res.status(404).json({ 
                error: 'Usuario no encontrado' 
            });
        }

        const user = User.fromMongoose(userDoc);
        const dto = user.toDTO();
        
        console.log('User DTO:', {
            fechaRegistro: dto.fechaRegistro,
            ultimoLogin: dto.ultimoLogin,
            rawUserDoc: {
                fecha_registro: userDoc.fecha_registro,
                ultimo_login: userDoc.ultimo_login
            }
        });
        
        res.json({
            user: dto
        });
    } catch (error) {
        debug('ERROR en GET /api/user/profile:', error);
        debug('Error message:', error.message);
        debug('Error stack:', error.stack);
        debug('User ID:', req.user?._id);
        console.error('Error en GET /api/user/profile:', error);
        res.status(500).json({ 
            error: 'Error interno del servidor',
            details: error.message
        });
    }
});

router.put('/profile', auth, async (req, res) => {
    try {
        const { User } = require('../../models/user/user.model');
        const { username, email, avatarId } = req.body;

        if (!username || !email) {
            return res.status(400).json({
                error: 'Username y email son requeridos'
            });
        }

        const existingUser = await User.Model.findOne({ 
            username: username,
            _id: { $ne: req.user._id }
        });

        if (existingUser) {
            return res.status(400).json({
                error: 'El nombre de usuario ya está en uso'
            });
        }

        const existingEmail = await User.Model.findOne({ 
            email: email,
            _id: { $ne: req.user._id }
        });

        if (existingEmail) {
            return res.status(400).json({
                error: 'El email ya está en uso'
            });
        }

        const userDoc = await User.Model.findById(req.user._id);
        const user = User.fromMongoose(userDoc);
        
        user.username = username;
        user.email = email;
        if (avatarId) {
            user.setAvatar(avatarId);
        }

        await user.save();

        res.json({
            message: 'Perfil actualizado exitosamente',
            user: user.toDTO()
        });
    } catch (error) {
        debug('ERROR en PUT /api/user/profile:', error);
        debug('Error message:', error.message);
        debug('Error stack:', error.stack);
        debug('User ID:', req.user?._id);
        res.status(500).json({ 
            error: 'Error interno del servidor' 
        });
    }
});

router.put('/password', auth, async (req, res) => {
    try {
        const { User } = require('../../models/user/user.model');
        const { currentPassword, newPassword } = req.body;

        if (!currentPassword || !newPassword) {
            return res.status(400).json({
                error: 'Contraseña actual y nueva contraseña son requeridas'
            });
        }

        const userDoc = await User.Model.findById(req.user._id);
        if (!userDoc) {
            return res.status(404).json({
                error: 'Usuario no encontrado'
            });
        }

        const user = User.fromMongoose(userDoc);

        // Validar contraseña actual
        const isCurrentPasswordValid = await bcrypt.compare(currentPassword, user.contrasena_hash);
        if (!isCurrentPasswordValid) {
            return res.status(400).json({
                error: 'La contraseña actual es incorrecta'
            });
        }

        // Validar fortaleza de la nueva contraseña
        const passwordValidation = validatePasswordStrength(newPassword, user.email, user.username);
        if (!passwordValidation.valid) {
            return res.status(400).json({ 
                error: passwordValidation.message 
            });
        }

        // Validar que la nueva contraseña no sea la misma que la anterior
        const isSamePassword = await bcrypt.compare(newPassword, user.contrasena_hash);
        if (isSamePassword) {
            return res.status(400).json({ 
                error: 'La nueva contraseña debe ser diferente a la contraseña anterior' 
            });
        }

        const saltRounds = 10;
        const newPasswordHash = await bcrypt.hash(newPassword, saltRounds);

        user.contrasena_hash = newPasswordHash;

        await user.save();

        res.json({
            message: 'Contraseña actualizada exitosamente'
        });
    } catch (error) {
        debug('ERROR en PUT /api/user/password:', error);
        debug('Error message:', error.message);
        debug('Error stack:', error.stack);
        debug('User ID:', req.user?._id);
        res.status(500).json({ 
            error: 'Error interno del servidor' 
        });
    }
});

router.post('/logout', auth, async (req, res) => {
    try {
        const sessionId = req.user.sessionId;
        
        if (sessionId) {
            const userDoc = await User.Model.findById(req.user._id);
            const user = User.fromMongoose(userDoc);
            
            // Remove the current session
            user.removeSession(sessionId);
            await user.save();
        }
        
        res.clearCookie('auth_token', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax'
        });
        
        res.clearCookie('refresh_token', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax'
        });
        
        res.json({
            message: 'Sesión cerrada exitosamente'
        });
    } catch (error) {
        debug('ERROR en POST /api/user/logout:', error);
        debug('Error message:', error.message);
        debug('User ID:', req.user?._id);
        res.status(500).json({ 
            error: 'Error interno del servidor' 
        });
    }
});

router.get('/sessions', auth, async (req, res) => {
    try {
        const sessions = [
            {
                id: 's1',
                device: 'PC',
                browser: 'Chrome',
                location: 'Ciudad de México',
                lastActive: 'Activo ahora',
                isCurrent: true
            }
        ];

        res.json({
            sessions: sessions
        });
    } catch (error) {
        debug('ERROR en GET /api/user/sessions:', error);
        debug('Error message:', error.message);
        debug('Error stack:', error.stack);
        debug('User ID:', req.user?._id);
        res.status(500).json({ 
            error: 'Error interno del servidor' 
        });
    }
});

router.delete('/sessions/:sessionId', auth, async (req, res) => {
    try {
        const { sessionId } = req.params;
        
        res.json({
            message: 'Sesión cerrada exitosamente'
        });
    } catch (error) {
        debug('ERROR en DELETE /api/user/sessions/:sessionId:', error);
        debug('Error message:', error.message);
        debug('Session ID:', req.params.sessionId);
        debug('User ID:', req.user?._id);
        res.status(500).json({ 
            error: 'Error interno del servidor' 
        });
    }
});

router.delete('/sessions', auth, async (req, res) => {
    try {
        res.json({
            message: 'Todas las sesiones cerradas exitosamente'
        });
    } catch (error) {
        debug('ERROR en DELETE /api/user/sessions:', error);
        debug('Error message:', error.message);
        debug('User ID:', req.user?._id);
        res.status(500).json({ 
            error: 'Error interno del servidor' 
        });
    }
});

router.get('/statistics', auth, async (req, res) => {
  try {
    const { Scan } = require('../../models/scan/scan.model');
    const { Vulnerability } = require('../../models/scan/vulnerability.model');
    
    const scansCount = await Scan.Model.countDocuments({ usuario_id: req.user._id });
    
    const scans = await Scan.Model.find({ usuario_id: req.user._id });
    const scanIds = scans.map(scan => scan._id);
    const vulnerabilitiesCount = await Vulnerability.Model.countDocuments({ 
      escaneo_id: { $in: scanIds } 
    });
    
    const bestScan = await Scan.Model.findOne({ usuario_id: req.user._id })
      .sort({ 'puntuacion.puntuacion_final': -1 })
      .limit(1);
    
    const statistics = {
      scansPerformed: scansCount,
      vulnerabilitiesDetected: vulnerabilitiesCount,
      bestScore: bestScan?.puntuacion?.puntuacion_final || 0,
      bestScanAlias: bestScan?.alias || 'N/A'
    };
    
    res.json(statistics);
  } catch (error) {
    debug('ERROR en GET /api/user/statistics:', error);
    debug('Error message:', error.message);
    debug('Error stack:', error.stack);
    debug('User ID:', req.user?._id);
    console.error('Error en /api/user/statistics:', error);
    res.status(500).json({ error: 'Error interno del servidor', details: error.message });
  }
});

router.delete('/account', auth, async (req, res) => {
  try {
    const { password } = req.body;
    
    const userDoc = await User.Model.findById(req.user._id);
    const user = User.fromMongoose(userDoc);
    const validPassword = await bcrypt.compare(password, user.contrasena_hash);
    
    if (!validPassword) {
      return res.status(401).json({ error: 'Contraseña incorrecta' });
    }
    
    const { Scan } = require('../../models/scan/scan.model');
    await Scan.Model.deleteMany({ usuario_id: req.user._id });
    
    const { Activity } = require('../../models/user/activity.model');
    await Activity.Model.deleteMany({ user_id: req.user._id });
    
    const { Notification } = require('../../models/user/notification.model');
    await Notification.Model.deleteMany({ user_id: req.user._id });
    
    await User.Model.findByIdAndDelete(req.user._id);
    
    res.json({ message: 'Tu cuenta ha sido eliminada exitosamente' });
  } catch (error) {
    debug('ERROR en DELETE /api/user/account:', error);
    debug('Error message:', error.message);
    debug('Error stack:', error.stack);
    debug('User ID:', req.user?._id);
    console.error('Error en /api/user/account DELETE:', error);
    res.status(500).json({ error: 'Error interno del servidor', details: error.message });
    }
});

module.exports = router;
