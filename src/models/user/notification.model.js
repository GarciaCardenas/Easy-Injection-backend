const mongoose = require("mongoose");
const Joi = require('joi');
const debug = require('debug')('easyinjection:models:notification');
const BaseModel = require('../base/BaseModel');
const { buildObject } = require('../base/ModelHelpers');
const Schema = mongoose.Schema;

const notificationSchema = new Schema({
    user_id: {
        type: Schema.Types.ObjectId,
        ref: "User",
        required: true
    },
    tipo: {
        type: String,
        enum: ["scan_completed", "vulnerability_detected", "resource_available"],
        required: true
    },
    titulo: {
        type: String,
        required: true
    },
    mensaje: {
        type: String,
        required: true
    },
    relatedId: {
        type: Schema.Types.ObjectId,
    },
    leido: {
        type: Boolean,
        default: false
    },
    fecha: {
        type: Date,
        default: Date.now
    }
});

const NotificationModel = mongoose.models.Notification || mongoose.model("Notification", notificationSchema);

class Notification extends BaseModel {
    #user_id; #tipo; #titulo; #mensaje; #relatedId; #leido; #fecha;

    constructor(data = {}) {
        super(data);
        const plainData = data && typeof data.toObject === 'function' ? data.toObject() : data;
        this.#user_id = plainData.user_id;
        this.#tipo = plainData.tipo;
        this.#titulo = plainData.titulo;
        this.#mensaje = plainData.mensaje;
        this.#relatedId = plainData.relatedId;
        this.#leido = plainData.leido !== undefined ? plainData.leido : false;
        this.#fecha = plainData.fecha || new Date();
        debug('Notificación creada: [%s] %s', this.#tipo, this.#titulo);
    }

    get user_id() { return this.#user_id; }
    get tipo() { return this.#tipo; }
    get titulo() { return this.#titulo; }
    get mensaje() { return this.#mensaje; }
    get relatedId() { return this.#relatedId; }
    get leido() { return this.#leido; }
    get fecha() { return this.#fecha; }

    markAsRead() {
        debug('Marcando notificación como leída: %s', this._id);
        this.#leido = true;
    }
    
    markAsUnread() {
        debug('Marcando notificación como no leída: %s', this._id);
        this.#leido = false;
    }
    
    isRead() { return this.#leido === true; }
    isUnread() { return this.#leido === false; }
    
    isRecent() {
        const daysSinceCreated = (new Date() - new Date(this.#fecha)) / (1000 * 60 * 60 * 24);
        return daysSinceCreated < 7;
    }
    
    getAge() {
        return Math.floor((new Date() - new Date(this.#fecha)) / (1000 * 60 * 60 * 24));
    }

    getDisplayType() {
        const typeMap = {
            'scan_completed': 'Escaneo Completado',
            'vulnerability_detected': 'Vulnerabilidad Detectada',
            'resource_available': 'Recurso Disponible'
        };
        return typeMap[this.#tipo] || this.#tipo;
    }

    static create(userId, tipo, titulo, mensaje, relatedId = null) {
        debug('Creando nueva notificación para usuario %s: [%s] %s', userId, tipo, titulo);
        return new Notification({ user_id: userId, tipo, titulo, mensaje, relatedId, leido: false });
    }

    static validate(notification) {
        return Joi.object({
            user_id: Joi.string().required(),
            tipo: Joi.string().valid('scan_completed', 'vulnerability_detected', 'resource_available').required(),
            titulo: Joi.string().required(),
            mensaje: Joi.string().required(),
            relatedId: Joi.string(),
            leido: Joi.boolean(),
            fecha: Joi.date()
        }).validate(notification);
    }

    static get Model() { return NotificationModel; }
    static get debug() { return debug; }

    toObject() {
        return buildObject(this, ['user_id', 'tipo', 'titulo', 'mensaje', 'relatedId', 'leido', 'fecha']);
    }
    
    toDTO() {
        return {
            id: this._id,
            userId: this.#user_id,
            type: this.#tipo,
            title: this.#titulo,
            message: this.#mensaje,
            relatedId: this.#relatedId,
            read: this.#leido,
            date: this.#fecha,
            isRecent: this.isRecent(),
            displayType: this.getDisplayType()
        };
    }
    
    toString() { return `[${this.#tipo}] ${this.#titulo}: ${this.#mensaje.substring(0, 50)}...`; }
}

function validateNotification(notification) {
    return Notification.validate(notification);
}

exports.Notification = Notification;
exports.validate = validateNotification;