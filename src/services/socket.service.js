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
                    const scan = await Scan.Model.findById(scanId);
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
                    const scan = await Scan.Model.findById(scanId);
                    if (!scan || scan.usuario_id.toString() !== socket.userId) {
                        return socket.emit('error', { message: 'Unauthorized or scan not found' });
                    }

                    if (this.activeScans.has(scanId)) {
                        return socket.emit('error', { message: 'Scan already running' });
                    }

                    // Load previous state if resuming
                    const previousState = scan.estado === 'en_progreso' && scan.current_phase ? {
                        current_phase: scan.current_phase,
                        current_subphase: scan.current_subphase || null,
                        completed_phases: scan.completed_phases || [],
                        completed_subphases: scan.completed_subphases || [],
                        discovered_endpoints: scan.discovered_endpoints || [],
                        discovered_parameters: scan.discovered_parameters || [],
                        tested_endpoints_sqli: scan.tested_endpoints_sqli || [],
                        tested_endpoints_xss: scan.tested_endpoints_xss || [],
                        asked_phases: scan.asked_phases || []
                    } : null;

                    const orchestrator = new ScanOrchestrator(scanId, scanConfig, previousState);
                    this.activeScans.set(scanId, orchestrator);

                    this.setupOrchestratorListeners(orchestrator, scanId);

                    this.io.to(`scan:${scanId}`).emit('scan:status', orchestrator.getStatus());

                    scan.estado = 'en_progreso';
                    if (!previousState) {
                        scan.fecha_inicio = new Date();
                    }
                    await scan.save();

                    orchestrator.start().catch(error => {
                        this.io.to(`scan:${scanId}`).emit('scan:error', { 
                            message: error.message 
                        });
                    });

                    socket.emit('scan:started', { scanId, isResuming: !!previousState });
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
                    const scan = await Scan.Model.findById(scanId);
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
                    const scan = await Scan.Model.findById(scanId);
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
                    const scan = await Scan.Model.findById(scanId);
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
                const scan = await Scan.Model.findById(scanId)
                    .populate('respuestas_usuario.pregunta_id')
                    .populate('respuestas_usuario.respuestas_seleccionadas');
                if (!scan) {
                    return;
                }

                // Vulnerabilities are already saved individually during scan by saveVulnerabilityToDb
                // Just get the IDs that are already in the scan document
                const savedVulnerabilityIds = scan.vulnerabilidades || [];
                
                // All answers are already saved individually during scan by saveAttemptToDb
                // No need to call saveQuestionAnswers - just use what's in the database
                const allAnswers = scan.respuestas_usuario;
                
                // Helper function to check if question was answered correctly
                const isAnsweredCorrectly = (respuestas_seleccionadas) => {
                    if (!respuestas_seleccionadas || respuestas_seleccionadas.length === 0) return false;
                    const lastAnswer = respuestas_seleccionadas[respuestas_seleccionadas.length - 1];
                    return lastAnswer.es_correcta === true;
                };
                
                // Calcular estadísticas de intentos
                const totalIntentos = allAnswers.reduce((sum, ans) => sum + ans.respuestas_seleccionadas.length, 0);
                const intentosCorrectos = allAnswers.reduce((sum, ans) => {
                    return sum + ans.respuestas_seleccionadas.filter(r => r.es_correcta).length;
                }, 0);
                const intentosIncorrectos = totalIntentos - intentosCorrectos;
                
                // Calcular preguntas únicas
                const uniqueQuestionIds = new Set();
                let totalQuizPoints = 0;
                
                for (const ans of allAnswers) {
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
                const preguntasCorrectas = allAnswers.filter(ans => 
                    isAnsweredCorrectly(ans.respuestas_seleccionadas)
                ).length;
                const preguntasIncorrectas = totalPreguntas - preguntasCorrectas;
                
                // Calcular puntos obtenidos
                const quizPoints = allAnswers.reduce((sum, ans) => sum + (ans.puntos_obtenidos || 0), 0);
                
                scan.estado = 'finalizado';
                scan.fecha_fin = new Date();
                // vulnerabilidades ya están guardadas en scan.vulnerabilidades por saveVulnerabilityToDb
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
                
                // Calcular puntuación final (60/40 formula)
                let quizScore = 0;
                if (totalQuizPoints > 0) {
                    const porcentajeCuestionario = quizPoints / totalQuizPoints;
                    quizScore = porcentajeCuestionario * 60;
                }
                
                const penalizacionVulnerabilidades = savedVulnerabilityIds.length * 5;
                let vulnerabilityScore = 40;
                let penalizacionExcedente = 0;
                
                if (penalizacionVulnerabilidades > 40) {
                    vulnerabilityScore = 0;
                    penalizacionExcedente = penalizacionVulnerabilidades - 40;
                } else {
                    vulnerabilityScore = 40 - penalizacionVulnerabilidades;
                }
                
                const puntuacionFinal = Math.max(0, Math.round(quizScore - penalizacionExcedente + vulnerabilityScore));
                
                let calificacion = 'Crítico';
                if (puntuacionFinal >= 90) {
                    calificacion = 'Excelente';
                } else if (puntuacionFinal >= 75) {
                    calificacion = 'Bueno';
                } else if (puntuacionFinal >= 60) {
                    calificacion = 'Regular';
                } else if (puntuacionFinal >= 40) {
                    calificacion = 'Deficiente';
                }
                
                scan.puntuacion.puntuacion_final = puntuacionFinal;
                scan.puntuacion.calificacion = calificacion;
                
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
                const scan = await Scan.Model.findById(scanId);
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
}

const socketService = new SocketService();

module.exports = socketService;
