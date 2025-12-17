const { Question } = require('../../models/quiz/question.model');
const { Answer } = require('../../models/quiz/answer.model');
const crypto = require('crypto');
const debug = require('debug')('easyinjection:scan:questions');

class QuestionHandler {
    constructor(emitter, logger, askedPhases = []) {
        this.emitter = emitter;
        this.logger = logger;
        this.isPaused = false;
        this.pauseResolver = null;
        this.questionAttempts = new Map(); // Rastrear intentos por pregunta
        this.askedPhases = new Set(askedPhases); // Rastrear fases cuyas preguntas ya se hicieron
    }

    // Función para obtener un índice aleatorio criptográficamente seguro
    getSecureRandomIndex(max) {
        const randomBytes = crypto.randomBytes(4);
        const randomNumber = randomBytes.readUInt32BE(0);
        return randomNumber % max;
    }

    // Función para mezclar un array de forma segura (Fisher-Yates shuffle)
    secureShuffleArray(array) {
        const shuffled = [...array];
        for (let i = shuffled.length - 1; i > 0; i--) {
            const j = this.getSecureRandomIndex(i + 1);
            [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
        }
        return shuffled;
    }

    async waitIfPaused() {
        while (this.isPaused) {
            await new Promise(resolve => {
                this.pauseResolver = resolve;
            });
        }
    }

    async getRandomQuestionByPhase(phase) {
        try {
            let questions = await Question.Model.find({ fase: phase });
            
            if (questions.length === 0) {
                if (phase.startsWith('sqli-')) {
                    questions = await Question.Model.find({ fase: 'sqli' });
                } else if (phase.startsWith('xss-')) {
                    questions = await Question.Model.find({ fase: 'xss' });
                }
            }
            
            if (questions.length === 0) {
                this.logger.addLog(`No se encontraron preguntas para la fase: ${phase}`, 'warning');
                return null;
            }
            
            const randomIndex = this.getSecureRandomIndex(questions.length);
            const question = questions[randomIndex];
            
            const answers = await Answer.Model.find({ pregunta_id: question._id }).sort({ es_correcta: -1 });
            
            if (answers.length === 0) {
                this.logger.addLog(`No se encontraron respuestas para la pregunta: ${question.texto_pregunta}`, 'warning');
                return null;
            }
            
            const correctAnswerIndex = answers.findIndex(a => a.es_correcta === true);
            
            const shuffledAnswers = this.secureShuffleArray(answers);
            const shuffledCorrectIndex = shuffledAnswers.findIndex(a => a.es_correcta === true);
            
            return {
                phase: phase,
                question: question.texto_pregunta,
                options: shuffledAnswers.map(a => a.texto_respuesta),
                correctAnswer: shuffledCorrectIndex,
                points: question.puntos,
                questionId: question._id,
                answerIds: shuffledAnswers.map(a => a._id)
            };
        } catch (error) {
            debug('ERROR en getRandomQuestionByPhase:', error);
            debug('Error message:', error.message);
            debug('Error stack:', error.stack);
            this.logger.addLog(`Error obteniendo pregunta de la base de datos: ${error.message}`, 'error');
            return null;
        }
    }

    async askQuestion(questionData = null, phase = null) {
        // Check if question from this phase was already asked
        if (phase && this.askedPhases.has(phase)) {
            this.logger.addLog(`Pregunta de la fase '${phase}' ya fue contestada previamente, omitiendo...`, 'info');
            return;
        }
        
        this.isPaused = true;
        this.logger.addLog('⏸ Escaneo pausado - Pregunta teórica', 'info');
        
        let questionToAsk;
        
        if (questionData) {
            questionToAsk = questionData;
        } else if (phase) {
            questionToAsk = await this.getRandomQuestionByPhase(phase);
            if (!questionToAsk) {
                this.logger.addLog('No se pudo obtener pregunta de la base de datos', 'error');
                this.isPaused = false;
                return;
            }
        } else {
            this.logger.addLog('Error: Debe proporcionar questionData o phase', 'error');
            this.isPaused = false;
            return;
        }
        
        // Inicializar contador de intentos para esta pregunta
        const questionKey = questionToAsk.questionId.toString();
        if (!this.questionAttempts.has(questionKey)) {
            this.questionAttempts.set(questionKey, 0);
        }
        
        return new Promise((resolve) => {
            this.emitter.emit('question:asked', questionToAsk);
            
            const answerHandler = (answer) => {
                // Incrementar contador de intentos
                const currentAttempts = this.questionAttempts.get(questionKey) + 1;
                this.questionAttempts.set(questionKey, currentAttempts);
                
                const isCorrect = answer.selectedAnswer === questionToAsk.correctAnswer;
                
                // Calcular puntos como porcentaje del valor de la pregunta
                let pointsEarned = 0;
                if (isCorrect) {
                    const questionValue = questionToAsk.points || 10;
                    if (currentAttempts === 1) {
                        pointsEarned = questionValue; // 100%
                    } else if (currentAttempts === 2) {
                        pointsEarned = Math.round(questionValue * 0.8); // 80%
                    } else {
                        pointsEarned = Math.round(questionValue * 0.2); // 20%
                    }
                }
                
                this.emitter.emit('question:result', {
                    ...questionToAsk,
                    userAnswer: answer.selectedAnswer,
                    correct: isCorrect,
                    pointsEarned: pointsEarned,
                    attempts: currentAttempts
                });
                
                // Save ALL attempts to DB immediately (whether correct or incorrect)
                this.saveAttemptToDb(questionToAsk, answer.selectedAnswer, isCorrect, currentAttempts, pointsEarned).catch(err => {
                    this.logger.addLog(`Error guardando intento: ${err.message}`, 'warning');
                });
                
                if (isCorrect) {
                    // Mark phase as asked when question is answered correctly
                    if (phase) {
                        this.askedPhases.add(phase);
                    }
                    this.logger.addLog(`✓ Respuesta correcta en el intento ${currentAttempts}! Puntos obtenidos: ${pointsEarned}. Continuando escaneo...`, 'success');
                    this.isPaused = false;
                    
                    this.emitter.off('question:answered', answerHandler);
                    
                    if (this.pauseResolver) {
                        this.pauseResolver();
                        this.pauseResolver = null;
                    }
                    
                    resolve();
                } else {
                    this.logger.addLog(`✗ Respuesta incorrecta (intento ${currentAttempts}). Esperando la respuesta correcta...`, 'warning');
                }
            };
            
            this.emitter.on('question:answered', answerHandler);
        });
    }

    answerQuestion(answer) {
        this.emitter.emit('question:answered', answer);
    }

    isCurrentlyPaused() {
        return this.isPaused;
    }

    async saveAttemptToDb(questionData, userAnswerIndex, isCorrect, currentAttempts, pointsEarned) {
        try {
            const Scan = require('../../models/scan/scan.model').Scan;
            const answerId = questionData.answerIds[userAnswerIndex];
            const questionId = questionData.questionId;
            
            // Try to add answer to existing question atomically
            const updateResult = await Scan.Model.updateOne(
                { 
                    _id: this.emitter.scanId,
                    'respuestas_usuario.pregunta_id': questionId
                },
                { 
                    $push: { 
                        'respuestas_usuario.$.respuestas_seleccionadas': answerId 
                    },
                    ...(isCorrect && { 
                        $set: { 
                            'respuestas_usuario.$.puntos_obtenidos': pointsEarned 
                        } 
                    })
                }
            );
            
            // If no existing entry was found, create new one
            if (updateResult.matchedCount === 0) {
                await Scan.Model.updateOne(
                    { _id: this.emitter.scanId },
                    { 
                        $push: { 
                            respuestas_usuario: {
                                pregunta_id: questionId,
                                respuestas_seleccionadas: [answerId],
                                puntos_obtenidos: isCorrect ? pointsEarned : 0
                            }
                        }
                    }
                );
            }
            
            debug(`Intento ${currentAttempts} guardado en BD`);
        } catch (error) {
            debug('ERROR en saveAttemptToDb:', error);
            debug('Error message:', error.message);
            debug('Error stack:', error.stack);
            debug('ScanId:', this.emitter.scanId);
            this.logger.addLog(`Error en saveAttemptToDb: ${error.message}`, 'warning');
        }
    }
}

module.exports = QuestionHandler;

