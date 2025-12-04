const Joi = require('joi');
const mongoose = require('mongoose');
const debug = require('debug')('easyinjection:models:report');
const BaseModel = require('../base/BaseModel');
const { buildObject } = require('../base/ModelHelpers');

const reportSchema = new mongoose.Schema({
    escaneo_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Scan', required: true },
    fecha_generado: { type: Date, default: Date.now },
    resumen: { 
        total_vulnerabilidades: { type: Number, default: 0 }, 
        criticas: { type: Number, default: 0 },
        altas: { type: Number, default: 0 }, 
        medias: { type: Number, default: 0 }, 
        bajas: { type: Number, default: 0 } 
    }
});

const ReportModel = mongoose.models.Report || mongoose.model('Report', reportSchema);

class Report extends BaseModel {
    #escaneo_id;
    #fecha_generado;
    #resumen;

    constructor(data = {}) {
        super(data);
        const plainData = data && typeof data.toObject === 'function' ? data.toObject() : data;
        this.#escaneo_id = plainData.escaneo_id;
        this.#fecha_generado = plainData.fecha_generado;
        
        // Handle both nested resumen object and flat structure
        if (plainData.resumen) {
            this.#resumen = {
                total_vulnerabilidades: plainData.resumen.total_vulnerabilidades || 0,
                criticas: plainData.resumen.criticas || 0,
                altas: plainData.resumen.altas || 0,
                medias: plainData.resumen.medias || 0,
                bajas: plainData.resumen.bajas || 0
            };
        } else {
            this.#resumen = {
                total_vulnerabilidades: plainData.total_vulnerabilidades || 0,
                criticas: plainData.criticas || 0,
                altas: plainData.altas || 0,
                medias: plainData.medias || 0,
                bajas: plainData.bajas || 0
            };
        }
    }

    get escaneo_id() { return this.#escaneo_id; }
    get fecha_generado() { return this.#fecha_generado; }
    get resumen() { return this.#resumen; }
    
    // Direct getters for backward compatibility
    get total_vulnerabilidades() { return this.#resumen.total_vulnerabilidades; }
    get criticas() { return this.#resumen.criticas; }
    get altas() { return this.#resumen.altas; }
    get medias() { return this.#resumen.medias; }
    get bajas() { return this.#resumen.bajas; }

    static createEmpty(escaneoId) {
        return new Report({ 
            escaneo_id: escaneoId, 
            fecha_generado: new Date(), 
            resumen: {
                total_vulnerabilidades: 0,
                criticas: 0,
                altas: 0,
                medias: 0,
                bajas: 0
            }
        });
    }

    static fromVulnerabilities(escaneoId, vulnerabilidades) {
        const summary = {
            total_vulnerabilidades: vulnerabilidades.length,
            criticas: 0,
            altas: 0,
            medias: 0,
            bajas: 0
        };

        vulnerabilidades.forEach(v => {
            const nivel = v.nivel_severidad || v.nivel_severidad_id?.nombre || 'Baja';
            if (nivel === 'Crítica') summary.criticas++;
            else if (nivel === 'Alta') summary.altas++;
            else if (nivel === 'Media') summary.medias++;
            else if (nivel === 'Baja') summary.bajas++;
        });

        return new Report({ 
            escaneo_id: escaneoId, 
            fecha_generado: new Date(), 
            resumen: summary 
        });
    }

    static validate(report) {
        return Joi.object({
            escaneo_id: Joi.string().required(),
            fecha_generado: Joi.date(),
            resumen: Joi.object({
                total_vulnerabilidades: Joi.number().min(0),
                criticas: Joi.number().min(0),
                altas: Joi.number().min(0),
                medias: Joi.number().min(0),
                bajas: Joi.number().min(0)
            })
        }).validate(report);
    }

    static get Model() { return ReportModel; }
    static get debug() { return debug; }

    toObject() { 
        return buildObject(this, ['escaneo_id', 'fecha_generado', 'resumen']); 
    }
    
    toString() { 
        return `[REPORT] Escaneo ${this.#escaneo_id}: ${this.#resumen.total_vulnerabilidades} vulns (${this.#resumen.criticas} críticas)`; 
    }
}

function validateReport(report) {
    return Report.validate(report);
}

exports.Report = Report;
exports.validate = validateReport;
