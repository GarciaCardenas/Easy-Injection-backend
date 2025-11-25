const socketIO = require('socket.io');
const ScanOrchestrator = require('./scan/scan-orchestrator.service');
const { Scan } = require('../models/scan/scan.model');
const { User } = require('../models/user/user.model');
const { Vulnerability } = require('../models/scan/vulnerability.model');
const { VulnerabilityType } = require('../models/catalog/vulnerability-type.model');
const { SeverityLevel } = require('../models/catalog/severity-level.model');
const { Question } = require('../models/quiz/question.model');
const { Answer } = require('../models/quiz/answer.model');
const { Notification } = require('../models/user/notification.model');
const jwt = require('jsonwebtoken');
const config = require('config');

class SocketService {
    constructor() {
        this.io = null;
        this.activeScans = new Map();
    }

    initialize(server) {
        this.io = socketIO(server, {
            cors: {
                origin: process.env.FRONTEND_URL || 'http://localhost:4200',
                methods: ['GET', 'POST'],
                credentials: true
            }
        });

        this.io.use((socket, next) => {
            const token = socket.handshake.auth.token;
            
            if (!token) {
                return next(new Error('Authentication error: No token provided'));
            }

            try {
                const decoded = jwt.verify(token, config.get('jwtPrivateKey'));
                socket.userId = decoded._id;
                next();
            } catch (error) {
                next(new Error('Authentication error: Invalid token'));
            }
        });

        this.io.on('connection', (socket) => {

            socket.on('scan:join', async (data) => {
                const { scanId } = data;
                
                try {
                    const scan = await Scan.findById(scanId);
                    if (!scan) {
                        return socket.emit('error', { message: 'Scan not found' });
                    }
                    
                    if (scan.usuario_id.toString() !== socket.userId) {
                        return socket.emit('error', { message: 'Unauthorized' });
                    }

                    socket.join(`scan:${scanId}`);

                    const orchestrator = this.activeScans.get(scanId);
                    if (orchestrator) {
                        socket.emit('scan:status', orchestrator.getStatus());
                    }
                } catch (error) {
                    socket.emit('error', { message: 'Error joining scan room' });
                }
            });

            socket.on('scan:start', async (data) => {
                const { scanId, config: scanConfig } = data;

                try {
                    const scan = await Scan.findById(scanId);
                    if (!scan || scan.usuario_id.toString() !== socket.userId) {
                        return socket.emit('error', { message: 'Unauthorized or scan not found' });
                    }

                    if (this.activeScans.has(scanId)) {
                        return socket.emit('error', { message: 'Scan already running' });
                    }

                    const orchestrator = new ScanOrchestrator(scanId, scanConfig);
                    this.activeScans.set(scanId, orchestrator);

                    this.setupOrchestratorListeners(orchestrator, scanId);

                    this.io.to(`scan:${scanId}`).emit('scan:status', orchestrator.getStatus());

                    scan.estado = 'en_progreso';
                    scan.fecha_inicio = new Date();
                    await scan.save();

                    orchestrator.start().catch(error => {
                        this.io.to(`scan:${scanId}`).emit('scan:error', { 
                            message: error.message 
                        });
                    });

                    socket.emit('scan:started', { scanId });
                } catch (error) {
                    socket.emit('error', { message: 'Error starting scan' });
                }
            });

            socket.on('question:answer', (data) => {
                const { scanId, selectedAnswer } = data;
                const orchestrator = this.activeScans.get(scanId);
                
                if (orchestrator) {
                    orchestrator.answerQuestion({ selectedAnswer });
                }
            });

            socket.on('scan:pause', async (data) => {
                const { scanId } = data;
                const orchestrator = this.activeScans.get(scanId);
                
                if (!orchestrator) {
                    return socket.emit('error', { message: 'Scan not found' });
                }

                try {
                    const scan = await Scan.findById(scanId);
                    if (!scan || scan.usuario_id.toString() !== socket.userId) {
                        return socket.emit('error', { message: 'Unauthorized' });
                    }
                } catch (error) {
                    return socket.emit('error', { message: 'Error verifying scan' });
                }

                orchestrator.pause();
                this.io.to(`scan:${scanId}`).emit('scan:paused', { scanId });
            });

            socket.on('scan:resume', async (data) => {
                const { scanId } = data;
                const orchestrator = this.activeScans.get(scanId);
                
                if (!orchestrator) {
                    return socket.emit('error', { message: 'Scan not found' });
                }

                try {
                    const scan = await Scan.findById(scanId);
                    if (!scan || scan.usuario_id.toString() !== socket.userId) {
                        return socket.emit('error', { message: 'Unauthorized' });
                    }
                } catch (error) {
                    return socket.emit('error', { message: 'Error verifying scan' });
                }

                orchestrator.resume();
                this.io.to(`scan:${scanId}`).emit('scan:resumed', { scanId });
            });

            socket.on('scan:stop', async (data) => {
                const { scanId } = data;
                const orchestrator = this.activeScans.get(scanId);
                
                if (!orchestrator) {
                    return socket.emit('error', { message: 'Scan not found' });
                }

                try {
                    const scan = await Scan.findById(scanId);
                    if (!scan || scan.usuario_id.toString() !== socket.userId) {
                        return socket.emit('error', { message: 'Unauthorized' });
                    }

                    scan.estado = 'detenido';
                    scan.fecha_fin = new Date();
                    await scan.save();
                } catch (error) {
                }

                orchestrator.stop();
                this.activeScans.delete(scanId);
                this.io.to(`scan:${scanId}`).emit('scan:stopped', { scanId });
            });

            socket.on('scan:leave', (data) => {
                const { scanId } = data;
                socket.leave(`scan:${scanId}`);
            });

            socket.on('disconnect', () => {
            });
        });

    }

    setupOrchestratorListeners(orchestrator, scanId) {
        const room = `scan:${scanId}`;

        orchestrator.on('phase:started', (data) => {
            this.io.to(room).emit('phase:started', data);
        });

        orchestrator.on('phase:completed', (data) => {
            this.io.to(room).emit('phase:completed', data);
        });

        orchestrator.on('subphase:started', (data) => {
            this.io.to(room).emit('subphase:started', data);
        });

        orchestrator.on('subphase:completed', (data) => {
            this.io.to(room).emit('subphase:completed', data);
        });

        orchestrator.on('log:added', (logEntry) => {
            this.io.to(room).emit('log:added', logEntry);
        });

        orchestrator.on('endpoint:discovered', (endpoint) => {
            this.io.to(room).emit('endpoint:discovered', endpoint);
        });

        orchestrator.on('parameter:discovered', (parameter) => {
            this.io.to(room).emit('parameter:discovered', parameter);
        });

        orchestrator.on('vulnerability:found', (vulnerability) => {
            this.io.to(room).emit('vulnerability:found', vulnerability);
        });

        orchestrator.on('question:asked', (question) => {
            this.io.to(room).emit('question:asked', question);
        });

        orchestrator.on('question:result', (result) => {
            this.io.to(room).emit('question:result', result);
        });

        orchestrator.on('scan:paused', (data) => {
            this.io.to(room).emit('scan:paused', data);
        });

        orchestrator.on('scan:resumed', (data) => {
            this.io.to(room).emit('scan:resumed', data);
        });

        orchestrator.on('scan:stopped', (data) => {
            this.io.to(room).emit('scan:stopped', data);
        });

        orchestrator.on('scan:completed', async (data) => {
            try {
                const scan = await Scan.findById(scanId);
                if (!scan) {
                    return;
                }

                const savedVulnerabilityIds = await this.saveVulnerabilities(scanId, data.vulnerabilities || []);
                
                const savedAnswers = await this.saveQuestionAnswers(scanId, data.questionResults || []);
                
                // Calcular estadísticas de intentos
                const totalIntentos = savedAnswers.length;
                const intentosCorrectos = savedAnswers.filter(ans => ans.es_correcta).length;
                const intentosIncorrectos = totalIntentos - intentosCorrectos;
                
                // Calcular preguntas únicas
                const uniqueQuestionIds = new Set();
                let totalQuizPoints = 0;
                
                for (const ans of savedAnswers) {
                    const questionIdStr = ans.pregunta_id.toString();
                    if (!uniqueQuestionIds.has(questionIdStr)) {
                        uniqueQuestionIds.add(questionIdStr);
                        try {
                            const question = await Question.findById(ans.pregunta_id);
                            if (question) {
                                totalQuizPoints += question.puntos;
                            }
                        } catch (err) {
                        }
                    }
                }
                
                const totalPreguntas = uniqueQuestionIds.size;
                const preguntasCorrectas = new Set(
                    savedAnswers.filter(ans => ans.es_correcta).map(ans => ans.pregunta_id.toString())
                ).size;
                const preguntasIncorrectas = totalPreguntas - preguntasCorrectas;
                
                // Calcular puntos obtenidos (solo de los intentos correctos)
                const quizPoints = savedAnswers
                    .filter(ans => ans.es_correcta)
                    .reduce((sum, ans) => sum + (ans.puntos_obtenidos || 0), 0);
                
                scan.estado = 'finalizado';
                scan.fecha_fin = new Date();
                scan.vulnerabilidades = savedVulnerabilityIds;
                scan.respuestas_usuario = savedAnswers;
                scan.puntuacion = {
                    puntos_cuestionario: quizPoints,
                    total_puntos_cuestionario: totalQuizPoints || 100,
                    vulnerabilidades_encontradas: savedVulnerabilityIds.length,
                    total_intentos: totalIntentos,
                    intentos_correctos: intentosCorrectos,
                    intentos_incorrectos: intentosIncorrectos,
                    total_preguntas: totalPreguntas,
                    preguntas_correctas: preguntasCorrectas,
                    preguntas_incorrectas: preguntasIncorrectas
                };
                
                scan.calculateScore();
                
                await scan.save();


                try {
                    const notification = new Notification({
                        user_id: scan.usuario_id,
                        tipo: 'scan_completed',
                        titulo: 'Escaneo completado',
                        mensaje: `Tu escaneo "${scan.alias}" ha finalizado con una puntuación de ${scan.puntuacion.puntuacion_final}`,
                        relatedId: scan._id,
                        leido: false
                    });
                    await notification.save();
                } catch (notifError) {
                }

                try {
                    const { Activity } = require('../models/user/activity.model');
                    const activity = new Activity({
                        user_id: scan.usuario_id,
                        type: 'scan_completed',
                        title: 'Escaneo completado',
                        description: `El escaneo "${scan.alias}" ha finalizado con una puntuación de ${scan.puntuacion.puntuacion_final}`,
                        relatedId: scan._id,
                        read: false
                    });
                    await activity.save();
                } catch (activityError) {
                }

                this.io.to(room).emit('scan:completed', data);
                
                this.activeScans.delete(scanId);
            } catch (error) {
                this.io.to(room).emit('scan:error', { message: 'Error guardando el escaneo: ' + error.message });
            }
        });

        orchestrator.on('scan:error', async (data) => {
            try {
                const scan = await Scan.findById(scanId);
                if (scan) {
                    scan.estado = 'error';
                    await scan.save();
                }

                this.io.to(room).emit('scan:error', data);
                this.activeScans.delete(scanId);
            } catch (error) {
            }
        });
    }

    getScanStatus(scanId) {
        const orchestrator = this.activeScans.get(scanId);
        return orchestrator ? orchestrator.getStatus() : null;
    }

    isScanning(scanId) {
        return this.activeScans.has(scanId);
    }

    async saveVulnerabilities(scanId, vulnerabilities) {
        const savedIds = [];

        for (const vuln of vulnerabilities) {
            try {
                let typeName = vuln.type;
                if (typeName === 'SQLi') typeName = 'SQLi';
                else if (typeName === 'XSS') typeName = 'XSS';
                
                let vulnerabilityType = await VulnerabilityType.findOne({ nombre: typeName });
                if (!vulnerabilityType) {
                    vulnerabilityType = new VulnerabilityType({
                        nombre: typeName,
                        descripcion: `Vulnerabilidad de tipo ${typeName}`
                    });
                    await vulnerabilityType.save();
                }
                const severityMap = {
                    'critical': 'Crítica',
                    'high': 'Alta',
                    'medium': 'Media',
                    'low': 'Baja',
                    'critica': 'Crítica',
                    'alta': 'Alta',
                    'media': 'Media',
                    'baja': 'Baja'
                };
                
                const severityName = severityMap[vuln.severity?.toLowerCase()] || 'Media';
                let severityLevel = await SeverityLevel.findOne({ nombre: severityName });
                if (!severityLevel) {
                    severityLevel = new SeverityLevel({
                        nombre: severityName,
                        descripcion: `Nivel de severidad ${severityName}`
                    });
                    await severityLevel.save();
                }

                const vulnerability = new Vulnerability({
                    escaneo_id: scanId,
                    tipo_id: vulnerabilityType._id,
                    nivel_severidad_id: severityLevel._id,
                    parametro_afectado: vuln.parameter || null,
                    url_afectada: vuln.endpoint || null,
                    descripcion: vuln.description || `Vulnerabilidad ${typeName} detectada`,
                    sugerencia: this._getVulnerabilitySuggestion(typeName),
                    referencia: null
                });

                await vulnerability.save();
                savedIds.push(vulnerability._id);
            } catch (error) {
            }
        }

        return savedIds;
    }

    async saveQuestionAnswers(scanId, questionResults) {
        const savedAnswers = [];

        // Guardar TODOS los intentos (correctos e incorrectos)
        for (const result of questionResults) {
            try {
                let question;
                let savedAnswerIds = [];
                
                if (result.questionId) {
                    question = await Question.findById(result.questionId);
                    if (!question) {
                        continue;
                    }
                    
                    if (result.answerIds && result.answerIds.length > 0) {
                        savedAnswerIds = result.answerIds;
                    } else {
                        const answerOptions = result.options || [];
                        for (const optionText of answerOptions) {
                            const answer = await Answer.findOne({ 
                                pregunta_id: question._id,
                                texto_respuesta: optionText
                            });
                            if (answer) {
                                savedAnswerIds.push(answer._id);
                            }
                        }
                    }
                } else {
                    question = await Question.findOne({ texto_pregunta: result.question });
                    if (!question) {
                        let dificultad = 'facil';
                        if (result.points > 15) dificultad = 'dificil';
                        else if (result.points > 10) dificultad = 'media';

                        question = new Question({
                            texto_pregunta: result.question,
                            dificultad: dificultad,
                            puntos: result.points || 10,
                            fase: result.phase || 'init'
                        });
                        await question.save();
                    }

                    const answerOptions = result.options || [];
                    
                    for (let i = 0; i < answerOptions.length; i++) {
                        let answer = await Answer.findOne({ 
                            pregunta_id: question._id,
                            texto_respuesta: answerOptions[i]
                        });
                        
                        if (!answer) {
                            answer = new Answer({
                                pregunta_id: question._id,
                                texto_respuesta: answerOptions[i],
                                es_correcta: i === result.correctAnswer
                            });
                            await answer.save();
                        }
                        
                        savedAnswerIds.push(answer._id);
                    }
                }

                const selectedAnswerIndex = result.userAnswer !== undefined ? result.userAnswer : -1;
                const respuesta_seleccionada_id = savedAnswerIds[selectedAnswerIndex] || savedAnswerIds[0];

                // Sistema de puntos por intentos: 1er intento=100%, 2do=80%, 3ro+=20% del valor de la pregunta
                const puntos = result.pointsEarned || 0;
                const intentos = result.attempts || 1;
                
                const userAnswer = {
                    pregunta_id: question._id,
                    respuesta_seleccionada_id: respuesta_seleccionada_id,
                    es_correcta: result.correct || false,
                    puntos_obtenidos: puntos,
                    numero_intentos: intentos
                };

                savedAnswers.push(userAnswer);
            } catch (error) {
            }
        }

        return savedAnswers;
    }

    _getVulnerabilitySuggestion(type) {
        const suggestions = {
            'SQLi': 'Utilice consultas preparadas (prepared statements) o parámetros parametrizados para prevenir inyecciones SQL. Valide y sanitice toda la entrada del usuario.',
            'XSS': 'Implemente validación de entrada y escapado de salida. Use Content Security Policy (CSP) y considere sanitizar el contenido HTML antes de mostrarlo.',
            'CSRF': 'Implemente tokens CSRF (tokens sincronizadores) y verifique el origen de las peticiones.',
            'XXE': 'Deshabilite el procesamiento de entidades externas XML. Use procesadores XML seguros que no procesen DTDs externos.',
            'SSTI': 'Evite usar motores de plantillas que evalúen código arbitrario. Use motores de plantillas seguros o sanitice las plantillas.'
        };
        return suggestions[type] || 'Revise y corrija la vulnerabilidad siguiendo las mejores prácticas de seguridad.';
    }
}

const socketService = new SocketService();

module.exports = socketService;
