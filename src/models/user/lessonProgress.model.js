const mongoose = require('mongoose');
const Joi = require('joi');
const debug = require('debug')('easyinjection:models:lessonProgress');
const BaseModel = require('../base/BaseModel');
const { buildObject } = require('../base/ModelHelpers');

// Value Object para LessonEntry
class LessonEntry {
  #lessonId; #status; #firstViewedAt; #lastViewedAt; #completedAt; #viewCount;

  constructor(data = {}) {
    this.#lessonId = data.lessonId;
    this.#status = data.status || 'not_started';
    this.#firstViewedAt = data.firstViewedAt || null;
    this.#lastViewedAt = data.lastViewedAt || null;
    this.#completedAt = data.completedAt || null;
    this.#viewCount = data.viewCount || 0;
  }

  get lessonId() { return this.#lessonId; }
  get status() { return this.#status; }
  get firstViewedAt() { return this.#firstViewedAt; }
  get lastViewedAt() { return this.#lastViewedAt; }
  get completedAt() { return this.#completedAt; }
  get viewCount() { return this.#viewCount; }

  isViewed() { return this.#status === 'viewed'; }
  isCompleted() { return this.#status === 'completed'; }

  markViewed(now = new Date()) {
    if (!this.#firstViewedAt) this.#firstViewedAt = now;
    this.#lastViewedAt = now;
    this.#viewCount++;
    if (this.#status === 'not_started') this.#status = 'viewed';
    return this;
  }

  markCompleted(now = new Date()) {
    if (!this.#firstViewedAt) this.#firstViewedAt = now;
    this.#lastViewedAt = now;
    this.#completedAt = now;
    this.#status = 'completed';
    return this;
  }

  toObject() {
    return {
      lessonId: this.#lessonId,
      status: this.#status,
      firstViewedAt: this.#firstViewedAt,
      lastViewedAt: this.#lastViewedAt,
      completedAt: this.#completedAt,
      viewCount: this.#viewCount
    };
  }
}

const lessonEntrySchema = new mongoose.Schema({
  lessonId: { type: String, required: true },
  status: { type: String, enum: ['not_started', 'viewed', 'completed'], default: 'not_started' },
  firstViewedAt: { type: Date, default: null },
  lastViewedAt: { type: Date, default: null },
  completedAt: { type: Date, default: null },
  viewCount: { type: Number, default: 0 }
}, { _id: false });

const lessonProgressSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, unique: true },
  lessons: { type: [lessonEntrySchema], default: [] },
  lastActivity: { type: Date, default: Date.now }
}, { timestamps: true });

const LessonProgressModel = mongoose.models.LessonProgress || mongoose.model('LessonProgress', lessonProgressSchema);

class LessonProgress extends BaseModel {
  #userId; #lessons; #lastActivity; #createdAt; #updatedAt;

  constructor(data = {}) {
    super(data);
    const plainData = data && typeof data.toObject === 'function' ? data.toObject() : data;
    this.#userId = plainData.userId;
    this.#lessons = (plainData.lessons || []).map(l => new LessonEntry(l));
    this.#lastActivity = plainData.lastActivity || new Date();
    this.#createdAt = plainData.createdAt;
    this.#updatedAt = plainData.updatedAt;
    debug('LessonProgress creado para usuario: %s con %d lecciones', this.#userId, this.#lessons.length);
  }

  get userId() { return this.#userId; }
  get lessons() { return [...this.#lessons]; }
  get lastActivity() { return this.#lastActivity; }
  get createdAt() { return this.#createdAt; }
  get updatedAt() { return this.#updatedAt; }

  findLesson(lessonId) {
    return this.#lessons.find(l => l.lessonId === lessonId);
  }

  addOrUpdateLesson(lessonEntry) {
    const index = this.#lessons.findIndex(l => l.lessonId === lessonEntry.lessonId);
    if (index === -1) {
      this.#lessons.push(lessonEntry);
    } else {
      this.#lessons[index] = lessonEntry;
    }
    this.#lastActivity = new Date();
  }

  getViewedLessons() {
    return this.#lessons.filter(l => l.isViewed()).map(l => l.lessonId);
  }

  getCompletedLessons() {
    return this.#lessons.filter(l => l.isCompleted()).map(l => l.lessonId);
  }

  getNotStartedLessons(allLessonIds) {
    const startedIds = this.#lessons.map(l => l.lessonId);
    return allLessonIds.filter(id => !startedIds.includes(id));
  }

  static async getUserProgress(userId) {
    debug('Obteniendo progreso para usuario: %s', userId);
    let doc = await this.Model.findOne({ userId });
    if (!doc) {
      debug('Creando nuevo progreso para usuario: %s', userId);
      doc = await this.Model.create({ userId, lessons: [] });
    }
    return this.fromMongoose(doc);
  }

  static async markLessonViewed(userId, lessonId) {
    debug('Marcando lecci\u00f3n %s como vista para usuario: %s', lessonId, userId);
    const progress = await this.getUserProgress(userId);
    let lesson = progress.findLesson(lessonId);
    
    if (!lesson) {
      lesson = new LessonEntry({ lessonId });
    }
    
    lesson.markViewed();
    progress.addOrUpdateLesson(lesson);
    await progress.save();
    return progress;
  }

  static async markLessonCompleted(userId, lessonId) {
    debug('Marcando lecci\u00f3n %s como completada para usuario: %s', lessonId, userId);
    const progress = await this.getUserProgress(userId);
    let lesson = progress.findLesson(lessonId);
    
    if (!lesson) {
      lesson = new LessonEntry({ lessonId });
    }
    
    lesson.markCompleted();
    progress.addOrUpdateLesson(lesson);
    await progress.save();
    return progress;
  }

  static async getProgressStats(userId, lessonIds = null) {
    debug('Obteniendo estad\u00edsticas de progreso para usuario: %s', userId);
    const progress = await this.getUserProgress(userId);
    
    const viewed = progress.getViewedLessons();
    const completed = progress.getCompletedLessons();
    const notStarted = lessonIds ? progress.getNotStartedLessons(lessonIds) : [];
    
    return {
      viewedLessons: viewed,
      completedLessons: completed,
      notStartedLessons: notStarted,
      viewedCount: viewed.length,
      completedCount: completed.length,
      notStartedCount: notStarted.length,
      totalLessons: lessonIds ? lessonIds.length : progress.lessons.length,
      hasStartedAny: progress.lessons.length > 0,
      lastActivity: progress.lastActivity
    };
  }

  static async getLessonDetails(userId, lessonId) {
    debug('Obteniendo detalles de lecci\u00f3n %s para usuario: %s', lessonId, userId);
    const progress = await this.getUserProgress(userId);
    const lesson = progress.findLesson(lessonId);
    
    if (!lesson) {
      return {
        lessonId,
        status: 'not_started',
        firstViewedAt: null,
        lastViewedAt: null,
        completedAt: null,
        viewCount: 0
      };
    }
    
    return lesson.toObject();
  }

  static validate(lessonProgress) {
    return Joi.object({
      userId: Joi.string().required(),
      lessons: Joi.array().items(Joi.object({
        lessonId: Joi.string().required(),
        status: Joi.string().valid('not_started', 'viewed', 'completed'),
        firstViewedAt: Joi.date().allow(null),
        lastViewedAt: Joi.date().allow(null),
        completedAt: Joi.date().allow(null),
        viewCount: Joi.number().min(0)
      })),
      lastActivity: Joi.date()
    }).validate(lessonProgress);
  }

  static get Model() { return LessonProgressModel; }
  static get debug() { return debug; }

  toObject() {
    return {
      ...buildObject(this, ['userId', 'lastActivity', 'createdAt', 'updatedAt']),
      lessons: this.#lessons.map(l => l.toObject())
    };
  }

  toDTO() {
    return {
      id: this._id,
      userId: this.#userId,
      lessons: this.#lessons.map(l => l.toObject()),
      lastActivity: this.#lastActivity,
      viewedCount: this.getViewedLessons().length,
      completedCount: this.getCompletedLessons().length,
      totalLessons: this.#lessons.length
    };
  }

  toString() {
    return `LessonProgress[user=${this.#userId}, lessons=${this.#lessons.length}]`;
  }
}

function validateLessonProgress(lessonProgress) {
  return LessonProgress.validate(lessonProgress);
}

exports.LessonProgress = LessonProgress;
exports.LessonEntry = LessonEntry;
exports.validate = validateLessonProgress;
