const Joi = require('joi');
const mongoose = require('mongoose');
const debug = require('debug')('easyinjection:models:answer');
const BaseModel = require('../base/BaseModel');
const { buildObject } = require('../base/ModelHelpers');

const answerSchema = new mongoose.Schema({
    pregunta_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Question', required: true },
    texto_respuesta: { type: String, required: true },
    es_correcta: { type: Boolean, default: false }
});

const AnswerModel = mongoose.models.Answer || mongoose.model('Answer', answerSchema);

class Answer extends BaseModel {
    #pregunta_id; #texto_respuesta; #es_correcta;

    constructor(data = {}) {
        super(data);
        const plainData = data && typeof data.toObject === 'function' ? data.toObject() : data;
        this.#pregunta_id = plainData.pregunta_id;
        this.#texto_respuesta = plainData.texto_respuesta;
        this.#es_correcta = plainData.es_correcta !== undefined ? plainData.es_correcta : false;
    }

    get pregunta_id() { return this.#pregunta_id; }
    get texto_respuesta() { return this.#texto_respuesta; }
    get es_correcta() { return this.#es_correcta; }

    getDisplayText() { return this.#texto_respuesta; }

    static createEmpty(preguntaId) { return new Answer({ pregunta_id: preguntaId, texto_respuesta: '', es_correcta: false }); }

    static validate(answer) {
        return Joi.object({
            pregunta_id: Joi.string().required(),
            texto_respuesta: Joi.string().required(),
            es_correcta: Joi.boolean()
        }).validate(answer);
    }

    static get Model() { return AnswerModel; }
    static get debug() { return debug; }

    toObject() { return buildObject(this, ['pregunta_id', 'texto_respuesta', 'es_correcta']); }
    toDTO() { return { 
        _id: this._id,
        id: this._id, 
        pregunta_id: this.#pregunta_id,
        preguntaId: this.#pregunta_id, 
        texto_respuesta: this.#texto_respuesta,
        texto: this.#texto_respuesta, 
        es_correcta: this.#es_correcta,
        esCorrecta: this.#es_correcta, 
        displayText: this.getDisplayText() 
    }; }
    toString() { return `${this.#es_correcta ? '✓' : '✗'} ${this.#texto_respuesta}`; }
}

function validateAnswer(answer) {
    return Answer.validate(answer);
}

exports.Answer = Answer;
exports.validate = validateAnswer;
