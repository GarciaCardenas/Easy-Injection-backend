const Joi = require('joi');
const mongoose = require('mongoose');
const debug = require('debug')('easyinjection:models:authtype');
const BaseModel = require('../base/BaseModel');
const { buildObject } = require('../base/ModelHelpers');

const authTypeSchema = new mongoose.Schema({
    nombre: { 
        type: String, 
        enum: ['usuario_password', 'token', 'oauth2', 'apikey'], 
        required: true, 
        unique: true 
    },
    descripcion: { type: String, maxlength: 255 }
});

const AuthTypeModel = mongoose.models.AuthType || mongoose.model('AuthType', authTypeSchema);

class AuthType extends BaseModel {
    #nombre;
    #descripcion;

    constructor(data = {}) {
        super(data);
        const plainData = data && typeof data.toObject === 'function' ? data.toObject() : data;
        
        this.#nombre = plainData.nombre;
        this.#descripcion = plainData.descripcion;
    }

    get nombre() { return this.#nombre; }
    get descripcion() { return this.#descripcion; }

    // Métodos de dominio
    getDisplayName() {
        const names = {
            'usuario_password': 'Usuario y Contraseña',
            'token': 'Token de Autenticación',
            'oauth2': 'OAuth 2.0',
            'apikey': 'API Key'
        };
        return names[this.#nombre] || this.#nombre;
    }

    static createEmpty() {
        return new AuthType({ nombre: 'usuario_password', descripcion: '' });
    }

    static validate(authType) {
        const schema = Joi.object({
            nombre: Joi.string().valid('usuario_password', 'token', 'oauth2', 'apikey').required(),
            descripcion: Joi.string().max(255)
        });

        return schema.validate(authType);
    }

    static get Model() {
        return AuthTypeModel;
    }

    static get debug() {
        return debug;
    }

    toObject() {
        return buildObject(this, ['nombre', 'descripcion']);
    }

    toString() {
        return `[${this.getDisplayName()}] ${this.#descripcion || 'Sin descripción'}`;
    }
}

function validateAuthType(auth) {
    return AuthType.validate(auth);
}

exports.AuthType = AuthType;
exports.validate = validateAuthType;
