const Joi = require('joi');
const mongoose = require('mongoose');
const debug = require('debug')('easyinjection:models:gestordb');
const BaseModel = require('../base/BaseModel');
const { buildObject } = require('../base/ModelHelpers');

const gestorBDSchema = new mongoose.Schema({
    nombre: { 
        type: String, 
        enum: ['dalfox', 'sqlmap', 'zap', 'otros'], 
        required: true, 
        unique: true 
    },
    descripcion: { type: String, maxlength: 255 }
});

const GestorBDModel = mongoose.models.GestorBD || mongoose.model('GestorBD', gestorBDSchema);

class GestorBD extends BaseModel {
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
    getFullName() {
        const names = {
            'dalfox': 'Dalfox (XSS Scanner)',
            'sqlmap': 'SQLMap (SQL Injection)',
            'zap': 'OWASP ZAP',
            'otros': 'Otros Gestores'
        };
        return names[this.#nombre] || this.#nombre;
    }

    static createEmpty() {
        return new GestorBD({ nombre: 'sqlmap', descripcion: '' });
    }

    static validate(gestor) {
        const schema = Joi.object({
            nombre: Joi.string().valid('dalfox', 'sqlmap', 'zap', 'otros').required(),
            descripcion: Joi.string().max(255)
        });

        return schema.validate(gestor);
    }

    static get Model() {
        return GestorBDModel;
    }

    static get debug() {
        return debug;
    }

    toObject() {
        return buildObject(this, ['nombre', 'descripcion']);
    }

    toString() {
        return `[${this.getFullName()}] ${this.#descripcion || 'Sin descripción'}`;
    }
}

function validateGestorBD(gestor) {
    return GestorBD.validate(gestor);
}

exports.GestorBD = GestorBD;
exports.DbManager = GestorBD;
exports.validate = validateGestorBD;
