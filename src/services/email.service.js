const nodemailer = require("nodemailer");
const debug = require('debug')('easyinjection:email');
const config = require("config");

class EmailService {
  constructor() {
    this.transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: config.get("email.user"),
        pass: config.get("email.password"),
      },
    });
  }

  async sendVerificationEmail(email, username, verificationToken) {
    const verificationUrl = `${config.get(
      "baseUrlFrontend"
    )}verify-success?token=${verificationToken}`;

    const mailOptions = {
      from: config.get("email.user"),
      to: email,
      subject: "Verifica tu cuenta - EasyInjection",
      html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h2 style="color: #333; text-align: center;">¡Bienvenido a EasyInjection!</h2>
                    <p>Hola <strong>${username}</strong>,</p>
                    <p>Gracias por registrarte en EasyInjection. Para completar tu registro, necesitas verificar tu dirección de email.</p>
                    
                    <div style="text-align: center; margin: 30px 0;">
                        <a href="${verificationUrl}" 
                           style="background-color: #D63D6C; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">
                            Verificar Email
                        </a>
                    </div>
                    
                    <p>O copia y pega este enlace en tu navegador:</p>
                    <p style="word-break: break-all; color: #007bff;">${verificationUrl}</p>
                    
                    <p>Este enlace expirará en 24 horas por seguridad.</p>
                    
                    <p>Si no creaste esta cuenta, puedes ignorar este email.</p>
                    
                    <hr style="margin: 30px 0; border: none; border-top: 1px solid #eee;">
                    <p style="color: #666; font-size: 12px; text-align: center;">
                        EasyInjection - Entender las vulnerabilidades de inyección nunca fue tan fácil.
                    </p>
                </div>
            `,
    };

    try {
      await this.transporter.sendMail(mailOptions);
      return true;
    } catch (error) {
      debug('ERROR enviando email de reset password:', error);
      debug('Error message:', error.message);
      debug('Error stack:', error.stack);
      debug('To:', email);
      return false;
    }
  }

  async sendEmail({ to, subject, html }) {
    const mailOptions = {
      from: config.get("email.user"),
      to,
      subject,
      html,
    };

    try {
      await this.transporter.sendMail(mailOptions);
      return true;
    } catch (error) {
      debug('ERROR enviando email genérico:', error);
      debug('Error message:', error.message);
      debug('Error stack:', error.stack);
      debug('To:', to);
      debug('Subject:', subject);
      throw error;
    }
  }
}

module.exports = new EmailService();
