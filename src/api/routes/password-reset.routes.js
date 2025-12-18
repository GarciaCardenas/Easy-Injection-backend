const express = require('express');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const debug = require('debug')('easyinjection:api:password-reset');
const { User } = require('../../models/user/user.model');
const emailService = require('../../services/email.service');
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

router.post('/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;
        
        debug('Forgot password request for email:', email);
        
        if (!email) {
            return res.status(400).json({ 
                error: 'El correo electrónico es requerido' 
            });
        }

        const userDoc = await User.Model.findOne({ email: email.toLowerCase() });
        
        if (!userDoc) {
            debug('User not found for email:', email);
            return res.status(200).json({ 
                message: 'Si el correo existe, recibirás un enlace de recuperación' 
            });
        }

        const user = User.fromMongoose(userDoc);
        const resetToken = crypto.randomBytes(32).toString('hex');
        user.setPasswordResetToken(resetToken, 1);
        
        await user.save();
        
        debug('Reset token generated for user:', user.email);

        const resetUrl = `${process.env.BASE_URL_FRONTEND}/reset-password?token=${resetToken}`;
        
        const emailHtml = `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <div style="background: linear-gradient(135deg, #e53966 0%, #d62d5a 100%); padding: 30px; text-align: center;">
                    <h1 style="color: white; margin: 0;">Restablecer Contraseña</h1>
                </div>
                <div style="padding: 30px; background: #f9fafb;">
                    <p style="font-size: 16px; color: #111827;">Hola <strong>${user.username}</strong>,</p>
                    <p style="font-size: 15px; color: #6b7280; line-height: 1.6;">
                        Recibimos una solicitud para restablecer la contraseña de tu cuenta en EasyInjection.
                    </p>
                    <p style="font-size: 15px; color: #6b7280; line-height: 1.6;">
                        Haz clic en el siguiente botón para crear una nueva contraseña:
                    </p>
                    <div style="text-align: center; margin: 30px 0;">
                        <a href="${resetUrl}" 
                           style="background: linear-gradient(135deg, #e53966 0%, #d62d5a 100%); 
                                  color: white; 
                                  padding: 14px 32px; 
                                  text-decoration: none; 
                                  border-radius: 8px; 
                                  font-weight: 600;
                                  display: inline-block;">
                            Restablecer Contraseña
                        </a>
                    </div>
                    <p style="font-size: 13px; color: #9ca3af; line-height: 1.6;">
                        O copia y pega este enlace en tu navegador:
                    </p>
                    <p style="font-size: 13px; color: #6b7280; word-break: break-all; background: white; padding: 12px; border-radius: 6px;">
                        ${resetUrl}
                    </p>
                    <div style="margin-top: 30px; padding: 16px; background: #fef3c7; border-left: 4px solid #f59e0b; border-radius: 6px;">
                        <p style="margin: 0; font-size: 14px; color: #92400e;">
                            <strong> Importante:</strong> Este enlace expirará en 1 hora.
                        </p>
                    </div>
                    <p style="font-size: 14px; color: #6b7280; margin-top: 20px;">
                        Si no solicitaste restablecer tu contraseña, puedes ignorar este correo de forma segura.
                    </p>
                </div>
                <div style="background: #111827; padding: 20px; text-align: center;">
                    <p style="color: #9ca3af; font-size: 13px; margin: 0;">
                        © ${new Date().getFullYear()} EasyInjection. Todos los derechos reservados.
                    </p>
                </div>
            </div>
        `;

        await emailService.sendEmail({
            to: user.email,
            subject: 'Restablecer tu contraseña - EasyInjection',
            html: emailHtml
        });

        res.json({ 
            message: 'Si el correo existe, recibirás un enlace de recuperación' 
        });

    } catch (error) {
        res.status(500).json({ 
            error: 'Error interno del servidor' 
        });
    }
});

router.get('/validate-token/:token', async (req, res) => {
    try {
        const { token } = req.params;
        
        debug('Validating token:', { tokenLength: token?.length });
        
        if (!token) {
            return res.status(400).json({ 
                error: 'Token es requerido' 
            });
        }

        const user = await User.Model.findOne({
            passwordResetToken: token,
            passwordResetExpires: { $gt: Date.now() }
        });

        debug('Token validation result:', { found: !!user, email: user?.email });

        if (!user) {
            return res.status(400).json({ 
                error: 'Token inválido o expirado' 
            });
        }

        res.json({ 
            valid: true,
            email: user.email,
            username: user.username
        });

    } catch (error) {
        debug('Error in validate-token:', error);
        res.status(500).json({ 
            error: 'Error interno del servidor' 
        });
    }
});

router.post('/reset-password', async (req, res) => {
    try {
        const { token, newPassword } = req.body;
        
        debug('Reset password request received', { tokenLength: token?.length });
        
        if (!token || !newPassword) {
            return res.status(400).json({ 
                error: 'Token y nueva contraseña son requeridos' 
            });
        }

        // Usar el modelo Mongoose directamente para la consulta y actualización
        const userDoc = await User.Model.findOne({
            passwordResetToken: token,
            passwordResetExpires: { $gt: Date.now() }
        });

        debug('User found:', { 
            found: !!userDoc, 
            email: userDoc?.email,
            hasToken: !!userDoc?.passwordResetToken,
            tokenExpires: userDoc?.passwordResetExpires 
        });

        if (!userDoc) {
            return res.status(400).json({ 
                error: 'Token inválido o expirado' 
            });
        }

        // Validación de fortaleza de contraseña con email y username del usuario
        const passwordValidation = validatePasswordStrength(newPassword, userDoc.email, userDoc.username);
        if (!passwordValidation.valid) {
            debug('Password validation failed:', passwordValidation.message);
            return res.status(400).json({ 
                error: passwordValidation.message 
            });
        }

        // Validar que la nueva contraseña no sea la misma que la anterior
        const isSamePassword = await bcrypt.compare(newPassword, userDoc.contrasena_hash);
        if (isSamePassword) {
            debug('New password is same as old password');
            return res.status(400).json({ 
                error: 'La nueva contraseña debe ser diferente a la contraseña anterior' 
            });
        }

        debug('Before clearing token:', {
            tokenBefore: userDoc.passwordResetToken,
            expiresBefore: userDoc.passwordResetExpires
        });

        // Actualizar contraseña y eliminar tokens
        const salt = await bcrypt.genSalt(10);
        userDoc.contrasena_hash = await bcrypt.hash(newPassword, salt);
        userDoc.passwordResetToken = undefined;
        userDoc.passwordResetExpires = undefined;
        
        await userDoc.save();

        debug('After saving:', {
            tokenAfter: userDoc.passwordResetToken,
            expiresAfter: userDoc.passwordResetExpires
        });

        // Verificar que realmente se eliminó
        const verifyUser = await User.Model.findOne({ email: userDoc.email });
        debug('Verification after save:', {
            tokenInDb: verifyUser.passwordResetToken,
            expiresInDb: verifyUser.passwordResetExpires
        });

        const emailHtml = `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <div style="background: linear-gradient(135deg, #10b981 0%, #059669 100%); padding: 30px; text-align: center;">
                    <h1 style="color: white; margin: 0;">✓ Contraseña Actualizada</h1>
                </div>
                <div style="padding: 30px; background: #f9fafb;">
                    <p style="font-size: 16px; color: #111827;">Hola <strong>${userDoc.username}</strong>,</p>
                    <p style="font-size: 15px; color: #6b7280; line-height: 1.6;">
                        Tu contraseña ha sido restablecida exitosamente.
                    </p>
                    <p style="font-size: 15px; color: #6b7280; line-height: 1.6;">
                        Ya puedes iniciar sesión con tu nueva contraseña.
                    </p>
                    <div style="margin-top: 30px; padding: 16px; background: #fef2f2; border-left: 4px solid #ef4444; border-radius: 6px;">
                        <p style="margin: 0; font-size: 14px; color: #991b1b;">
                            <strong>🔒 Seguridad:</strong> Si no realizaste este cambio, contacta con soporte inmediatamente.
                        </p>
                    </div>
                </div>
                <div style="background: #111827; padding: 20px; text-align: center;">
                    <p style="color: #9ca3af; font-size: 13px; margin: 0;">
                        © ${new Date().getFullYear()} EasyInjection. Todos los derechos reservados.
                    </p>
                </div>
            </div>
        `;

        await emailService.sendEmail({
            to: userDoc.email,
            subject: 'Contraseña restablecida - EasyInjection',
            html: emailHtml
        });

        res.json({ 
            message: 'Contraseña restablecida exitosamente' 
        });

    } catch (error) {
        debug('Error in reset-password:', error);
        res.status(500).json({ 
            error: 'Error interno del servidor' 
        });
    }
});

module.exports = router;

