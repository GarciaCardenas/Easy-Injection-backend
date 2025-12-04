// Base Models & Helpers
const BaseModel = require('./base/BaseModel');
const ModelHelpers = require('./base/ModelHelpers');

// Value Objects
const { Profile } = require('./value-objects/user-value-objects');
const { ScanFlags, UserAnswer, Score } = require('./value-objects/scan-value-objects');

// User Models
const { User, validate: validateUser } = require('./user/user.model');
const { Activity, validate: validateActivity } = require('./user/activity.model');
const { Notification, validate: validateNotification } = require('./user/notification.model');
const { LessonProgress, LessonEntry, validate: validateLessonProgress } = require('./user/lessonProgress.model');

// Scan Models
const { Scan, validate: validateScan } = require('./scan/scan.model');
const { Vulnerability, validate: validateVulnerability } = require('./scan/vulnerability.model');
const { Report, validate: validateReport } = require('./scan/report.model');

// Quiz Models
const { Question, validate: validateQuestion } = require('./quiz/question.model');
const { Answer, validate: validateAnswer } = require('./quiz/answer.model');

// Catalog Models
const { AuthType, validate: validateAuthType } = require('./catalog/auth-type.model');
const { GestorBD, validate: validateGestorBD } = require('./catalog/db-manager.model');
const { VulnerabilityType, validate: validateVulnerabilityType } = require('./catalog/vulnerability-type.model');
const { SeverityLevel, validate: validateSeverityLevel } = require('./catalog/severity-level.model');

module.exports = {
    // Base
    BaseModel,
    ModelHelpers,

    // Value Objects
    Profile,
    ScanFlags,
    UserAnswer,
    Score,
    LessonEntry,

    // User Models
    User,
    validateUser,
    Activity,
    validateActivity,
    Notification,
    validateNotification,
    LessonProgress,
    validateLessonProgress,

    // Scan Models
    Scan,
    validateScan,
    Vulnerability,
    validateVulnerability,
    Report,
    validateReport,

    // Quiz Models
    Question,
    validateQuestion,
    Answer,
    validateAnswer,

    // Catalog Models
    AuthType,
    validateAuthType,
    GestorBD,
    validateGestorBD,
    DbManager: GestorBD, // Alias para compatibilidad
    validateDbManager: validateGestorBD, // Alias para compatibilidad
    VulnerabilityType,
    validateVulnerabilityType,
    SeverityLevel,
    validateSeverityLevel
};


