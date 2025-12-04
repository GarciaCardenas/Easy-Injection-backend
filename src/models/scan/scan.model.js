const Joi = require('joi');
const mongoose = require('mongoose');
const debug = require('debug')('easyinjection:models:scan');
const BaseModel = require('../base/BaseModel');
const { buildObject } = require('../base/ModelHelpers');
const { ScanFlags, UserAnswer, Score } = require('../value-objects/scan-value-objects');

const userAnswerSchema = new mongoose.Schema({
    pregunta_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Question', required: true },
    respuesta_seleccionada_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Answer', required: true },
    es_correcta: { type: Boolean, required: true },
    puntos_obtenidos: { type: Number, default: 0 }
});

const scanSchema = new mongoose.Schema({
    usuario_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    alias: { type: String, maxlength: 150, required: true },
    url: { type: String, maxlength: 255, required: true },

    flags: {
        xss: { type: Boolean, default: false },
        sqli: { type: Boolean, default: false }
    },

    tipo_autenticacion: { 
        type: mongoose.Schema.Types.ObjectId, 
        ref: 'AuthType' 
    },

    credenciales: {
        usuario_login: { type: String, maxlength: 100 },
        password_login: { type: String, maxlength: 255 }
    },

    estado: { 
        type: String, 
        enum: ['pendiente', 'en_progreso', 'finalizado', 'error'], 
        default: 'pendiente' 
    },

    gestor: { 
        type: mongoose.Schema.Types.ObjectId, 
        ref: 'GestorBD' 
    },

    fecha_inicio: { type: Date, default: Date.now },
    fecha_fin: { type: Date },
    cookie: { type: String, maxlength: 255 },

    vulnerabilidades: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Vulnerability' }],

    respuestas_usuario: [userAnswerSchema],
    puntuacion: {
        puntos_cuestionario: { type: Number, default: 0 },
        total_puntos_cuestionario: { type: Number, default: 0 },
        vulnerabilidades_encontradas: { type: Number, default: 0 },
        puntuacion_final: { type: Number, default: 0 },
        calificacion: { type: String, enum: ['Excelente', 'Bueno', 'Regular', 'Deficiente', 'Crítico'], default: 'Regular' }
    }
});

const ScanModel = mongoose.models.Scan || mongoose.model('Scan', scanSchema);

class Scan extends BaseModel {
    #usuario_id; #alias; #url; #flags; #tipo_autenticacion; #estado; #gestor;
    #fecha_inicio; #fecha_fin; #cookie; #vulnerabilidades; #respuestas_usuario; #puntuacion;

    constructor(data = {}) {
        super(data);
        const plainData = data && typeof data.toObject === 'function' ? data.toObject() : data;
        this.#usuario_id = plainData.usuario_id;
        this.#alias = plainData.alias;
        this.#url = plainData.url;
        this.#flags = new ScanFlags(plainData.flags || {});
        this.#tipo_autenticacion = plainData.tipo_autenticacion;
        this.#estado = plainData.estado || 'pendiente';
        this.#gestor = plainData.gestor;
        this.#fecha_inicio = plainData.fecha_inicio;
        this.#fecha_fin = plainData.fecha_fin;
        this.#cookie = plainData.cookie;
        this.#vulnerabilidades = plainData.vulnerabilidades || [];
        this.#respuestas_usuario = (plainData.respuestas_usuario || []).map(ua => new UserAnswer(ua));
        this.#puntuacion = new Score(plainData.puntuacion || {});
    }

    get usuario_id() { return this.#usuario_id; }
    get alias() { return this.#alias; }
    get url() { return this.#url; }
    get flags() { return this.#flags; }
    get tipo_autenticacion() { return this.#tipo_autenticacion; }

    get estado() { return this.#estado; }
    set estado(value) {
        const validStates = ['pendiente', 'en_progreso', 'finalizado', 'error'];
        if (!validStates.includes(value)) throw new Error(`Estado inválido: ${value}`);
        this.#estado = value;
    }

    get gestor() { return this.#gestor; }
    get fecha_inicio() { return this.#fecha_inicio; }
    set fecha_inicio(value) { this.#fecha_inicio = value; }

    get fecha_fin() { return this.#fecha_fin; }
    set fecha_fin(value) { this.#fecha_fin = value; }

    get cookie() { return this.#cookie; }
    get vulnerabilidades() { return this.#vulnerabilidades; }
    set vulnerabilidades(value) { this.#vulnerabilidades = value || []; }

    get respuestas_usuario() { return this.#respuestas_usuario; }
    set respuestas_usuario(value) { this.#respuestas_usuario = (value || []).map(ua => new UserAnswer(ua)); }

    get puntuacion() { return this.#puntuacion; }
    set puntuacion(value) { this.#puntuacion = new Score(value); }

    getDuration() {
        if (!this.#fecha_fin || !this.#fecha_inicio) return null;
        return Math.floor((new Date(this.#fecha_fin) - new Date(this.#fecha_inicio)) / 1000);
    }

    getVulnerabilityCount() { return this.#vulnerabilidades.length; }

    calculateScore() {
        debug('calculateScore: calculating final score with 60/40 formula');
        return this.#puntuacion.calculateFinalScore();
    }

    static createEmpty(usuarioId) {
        return new Scan({
            usuario_id: usuarioId, alias: '', url: '', flags: ScanFlags.createEmpty().toObject(),
            estado: 'pendiente',
            vulnerabilidades: [], respuestas_usuario: [], puntuacion: Score.createEmpty().toObject()
        });
    }

    static validate(scan) {
        return Joi.object({
            usuario_id: Joi.string().required(),
            alias: Joi.string().max(150).required(),
            url: Joi.string().uri().max(255).required(),
            flags: Joi.object({ xss: Joi.boolean(), sqli: Joi.boolean() }),
            tipo_autenticacion: Joi.string(),
            credenciales: Joi.object({ usuario_login: Joi.string().max(100), password_login: Joi.string().max(255) }),
            estado: Joi.string().valid('pendiente', 'en_progreso', 'finalizado', 'error'),
            gestor: Joi.string(),
            cookie: Joi.string().max(255),
            vulnerabilidades: Joi.array().items(Joi.string()),
            respuestas_usuario: Joi.array(),
            puntuacion: Joi.object()
        }).validate(scan);
    }

    static get Model() { return ScanModel; }
    static get debug() { return debug; }

    toObject() { return buildObject(this, ['usuario_id', 'alias', 'url', 'flags', 'tipo_autenticacion', 'estado', 'gestor', 'fecha_inicio', 'fecha_fin', 'cookie', 'vulnerabilidades', 'respuestas_usuario', 'puntuacion']); }

    toDTO() {
        return {
            _id: this._id,
            id: this._id, 
            usuarioId: this.#usuario_id,
            usuario_id: this.#usuario_id,
            alias: this.#alias, 
            url: this.#url,
            flags: this.#flags.toObject(), 
            estado: this.#estado, 
            fecha_inicio: this.#fecha_inicio,
            fechaInicio: this.#fecha_inicio,
            fecha_fin: this.#fecha_fin,
            fechaFin: this.#fecha_fin, 
            duracion: this.getDuration(), 
            vulnerabilidades: this.getVulnerabilityCount(),
            puntuacion: {
                puntos_cuestionario: this.#puntuacion.puntos_cuestionario,
                total_puntos_cuestionario: this.#puntuacion.total_puntos_cuestionario,
                vulnerabilidades_encontradas: this.#puntuacion.vulnerabilidades_encontradas,
                puntuacion_final: this.#puntuacion.puntuacion_final,
                calificacion: this.#puntuacion.calificacion
            },
            quizPercentage: this.#puntuacion.getQuizPercentage()
        };
    }

    toString() { return `[${this.#estado.toUpperCase()}] ${this.#alias}: ${this.#url} (${this.getVulnerabilityCount()} vulns)`; }
}

function validateScan(scan) {
    return Scan.validate(scan);
}

exports.Scan = Scan;
exports.validate = validateScan;
