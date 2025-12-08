const { Question } = require('../../models/quiz/question.model');
const { Answer } = require('../../models/quiz/answer.model');

class QuestionHandler {
    constructor(emitter, logger) {
        this.emitter = emitter;
        this.logger = logger;
        this.isPaused = false;
        this.pauseResolver = null;
        this.questionAttempts = new Map(); // Rastrear intentos por pregunta
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
            
            const randomIndex = Math.floor(Math.random() * questions.length);
            const question = questions[randomIndex];
            
            const answers = await Answer.Model.find({ pregunta_id: question._id }).sort({ es_correcta: -1 });
            
            if (answers.length === 0) {
                this.logger.addLog(`No se encontraron respuestas para la pregunta: ${question.texto_pregunta}`, 'warning');
                return null;
            }
            
            const correctAnswerIndex = answers.findIndex(a => a.es_correcta === true);
            
            const shuffledAnswers = [...answers].sort(() => Math.random() - 0.5);
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
            this.logger.addLog(`Error obteniendo pregunta de la base de datos: ${error.message}`, 'error');
            return null;
        }
    }

    async askQuestion(questionData = null, phase = null) {
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
                
                if (isCorrect) {
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
}

module.exports = QuestionHandler;

