const Joi = require('joi');
const mongoose = require('mongoose');
const debug = require('debug')('easyinjection:models:severity');
const BaseModel = require('../base/BaseModel');
const { buildObject } = require('../base/ModelHelpers');

// Schema de niveles de severidad
const severityLevelSchema = new mongoose.Schema({
    nombre: { 
        type: String, 
        enum: ['Baja', 'Media', 'Alta', 'Crítica'], 
        required: true, 
        unique: true 
    },
    descripcion: { type: String, maxlength: 255 }
});

const SeverityLevelModel = mongoose.models.SeverityLevel || mongoose.model('SeverityLevel', severityLevelSchema);

/**
 * Clase de dominio SeverityLevel con encapsulamiento OOP
 * Representa un nivel de severidad de vulnerabilidad
 */
class SeverityLevel extends BaseModel {
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
    isCritical() {
        return this.#nombre === 'Crítica';
    }

    // Factory Methods
    static createEmpty() {
        return new SeverityLevel({ nombre: 'Baja', descripcion: '' });
    }

    static validate(level) {
        const schema = Joi.object({
            nombre: Joi.string().valid('Baja', 'Media', 'Alta', 'Crítica').required(),
            descripcion: Joi.string().max(255)
        });

        return schema.validate(level);
    }

    static get Model() {
        return SeverityLevelModel;
    }

    static get debug() {
        return debug;
    }

    toObject() {
        return buildObject(this, ['nombre', 'descripcion']);
    }

    toString() {
        return `[${this.#nombre}] ${this.#descripcion || 'Sin descripción'}`;
    }
}

function validateSeverityLevel(level) {
    return SeverityLevel.validate(level);
}

exports.SeverityLevel = SeverityLevel;
exports.validate = validateSeverityLevel;
