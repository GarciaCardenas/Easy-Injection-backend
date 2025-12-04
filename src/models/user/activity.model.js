const mongoose = require("mongoose");
const Joi = require('joi');
const debug = require('debug')('easyinjection:models:activity');
const BaseModel = require('../base/BaseModel');
const { buildObject } = require('../base/ModelHelpers');
const Schema = mongoose.Schema;

const activitySchema = new Schema({
  user_id: {
    type: Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  type: {
    type: String,
    enum: ["scan_completed", "resource_available"],
    required: true,
  },
  title: {
    type: String,
    required: true,
  },
  description: {
    type: String,
    required: true,
  },
  relatedId: {
    type: Schema.Types.ObjectId,
  },
  date: {
    type: Date,
    default: Date.now,
  },
  read: {
    type: Boolean,
    default: false,
  }
});

const ActivityModel = mongoose.models.Activity || mongoose.model("Activity", activitySchema);

class Activity extends BaseModel {
  #user_id; #type; #title; #description; #relatedId; #date; #read;

  constructor(data = {}) {
    super(data);
    const plainData = data && typeof data.toObject === 'function' ? data.toObject() : data;
    this.#user_id = plainData.user_id;
    this.#type = plainData.type;
    this.#title = plainData.title;
    this.#description = plainData.description;
    this.#relatedId = plainData.relatedId;
    this.#date = plainData.date || new Date();
    this.#read = plainData.read !== undefined ? plainData.read : false;
    debug('Activity creada: %s - %s', this.#type, this.#title);
  }

  get user_id() { return this.#user_id; }
  get type() { return this.#type; }
  get title() { return this.#title; }
  get description() { return this.#description; }
  get relatedId() { return this.#relatedId; }
  get date() { return this.#date; }
  get read() { return this.#read; }
  
  isRecent() {
    const daysSinceCreated = (new Date() - new Date(this.#date)) / (1000 * 60 * 60 * 24);
    return daysSinceCreated < 7;
  }

  getDisplayType() {
    const typeMap = {
      'scan_completed': 'Escaneo Completado',
      'resource_available': 'Recurso Disponible'
    };
    return typeMap[this.#type] || this.#type;
  }

  static validate(activity) {
    return Joi.object({
      user_id: Joi.string().required(),
      type: Joi.string().valid('scan_completed', 'resource_available').required(),
      title: Joi.string().required(),
      description: Joi.string().required(),
      relatedId: Joi.string(),
      date: Joi.date(),
      read: Joi.boolean()
    }).validate(activity);
  }

  static get Model() { return ActivityModel; }
  static get debug() { return debug; }

  toObject() {
    return buildObject(this, ['user_id', 'type', 'title', 'description', 'relatedId', 'date', 'read']);
  }
  
  toDTO() {
    return {
      id: this._id,
      userId: this.#user_id,
      type: this.#type,
      title: this.#title,
      description: this.#description,
      relatedId: this.#relatedId,
      date: this.#date,
      read: this.#read,
      isRecent: this.isRecent(),
      displayType: this.getDisplayType()
    };
  }
  
  toString() { return `[${this.#type}] ${this.#title} - ${this.#date.toLocaleDateString()}`; }
}

function validateActivity(activity) {
  return Activity.validate(activity);
}

exports.Activity = Activity;
exports.validate = validateActivity;
