const socketIO = require('socket.io');
const debug = require('debug')('easyinjection:socket');
const ScanOrchestrator = require('./scan/scan-orchestrator.service');
const { Scan } = require('../models/scan/scan.model');
const { Question } = require('../models/quiz/question.model');
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
            const cookieParser = require('cookie-parser');
            const cookieString = socket.handshake.headers.cookie || '';
            const cookies = {};
            
            // Parse cookies manually
            cookieString.split(';').forEach(cookie => {
                const [key, value] = cookie.trim().split('=');
                if (key && value) {
                    cookies[key] = decodeURIComponent(value);
                }
            });
            
            const token = cookies.auth_token;
            
            if (!token) {
                return next(new Error('Authentication error: No token provided'));
            }

            try {
                const decoded = jwt.verify(token, config.get('jwtPrivateKey'));
                socket.userId = decoded._id;
                next();
            } catch (error) {
                debug('ERROR en JWT authentication:', error);
                debug('Error message:', error.message);
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
                    debug('ERROR en scan:join:', error);
                    debug('Error message:', error.message);
                    debug('ScanId:', scanId);
                    socket.emit('error', { message: 'Error joining scan room' });
                }
            });

            socket.on('scan:start', async (data) => {
                debug('=== SCAN:START EVENT ===');
                debug('Data recibida:', JSON.stringify(data));
                const { scanId, config: scanConfig } = data;
                debug('ScanId:', scanId);
                debug('Config:', JSON.stringify(scanConfig));

                try {
                    debug('Buscando scan en BD...');
                    const scan = await Scan.Model.findById(scanId);
                    debug('Scan encontrado:', scan ? 'SI' : 'NO');
                    if (scan) {
                        debug('Scan estado:', scan.estado);
                        debug('Scan usuario_id:', scan.usuario_id);
                        debug('Socket userId:', socket.userId);
                    }
                    if (!scan || scan.usuario_id.toString() !== socket.userId) {
                        debug('ERROR: Unauthorized or scan not found');
                        return socket.emit('error', { message: 'Unauthorized or scan not found' });
                    }

                    debug('Verificando si scan ya está activo...');
                    if (this.activeScans.has(scanId)) {
                        const existingOrchestrator = this.activeScans.get(scanId);
                        
                        // Si el scan está pausado o en_progreso en BD, permitir reanudar limpiando el viejo
                        if (scan.estado === 'pendiente' || scan.estado === 'en_progreso') {
                            debug('Scan encontrado en memoria pero con estado ' + scan.estado + ', limpiando orchestrator viejo...');
                            
                            // Detener auto-save del viejo
                            if (existingOrchestrator.stopAutoSave) {
                                existingOrchestrator.stopAutoSave();
                            }
                            
                            // Matar procesos activos
                            if (existingOrchestrator.killAllProcesses) {
                                existingOrchestrator.killAllProcesses();
                            }
                            
                            // Limpiar de memoria
                            this.activeScans.delete(scanId);
                            debug('Orchestrator viejo limpiado, permitiendo reanudar');
                        } else {
                            debug('ERROR: Scan already running y no está pausado (pendiente)');
                            return socket.emit('error', { message: 'Scan already running' });
                        }
                    }

                    debug('Cargando estado previo...');

                    // Load previous state if resuming
                    const previousState = scan.estado === 'pendiente' && scan.current_phase ? {
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
                    debug('Estado previo:', previousState ? 'SI' : 'NO');
                    if (previousState) {
                        debug('Estado previo detalles:', JSON.stringify(previousState));
                    }

                    debug('Creando ScanOrchestrator...');
                    const orchestrator = new ScanOrchestrator(scanId, scanConfig, previousState);
                    debug('ScanOrchestrator creado exitosamente');
                    
                    this.activeScans.set(scanId, orchestrator);
                    debug('Orchestrator agregado a activeScans');

                    debug('Configurando listeners del orchestrator...');
                    this.setupOrchestratorListeners(orchestrator, scanId);
                    debug('Listeners configurados');

                    debug('Emitiendo scan:status...');
                    this.io.to(`scan:${scanId}`).emit('scan:status', orchestrator.getStatus());

                    debug('Guardando estado del scan en BD...');
                    scan.estado = 'pendiente';
                    if (!previousState) {
                        scan.fecha_inicio = new Date();
                    }
                    await scan.save();
                    debug('Estado guardado en BD');

                    debug('Iniciando orchestrator.start()...');
                    orchestrator.start().catch(error => {
                        debug('ERROR en orchestrator.start():', error);
                        debug('Error message:', error.message);
                        debug('Error stack:', error.stack);
                        this.io.to(`scan:${scanId}`).emit('scan:error', { 
                            message: error.message 
                        });
                    });
                    debug('orchestrator.start() lanzado (async)');

                    socket.emit('scan:started', { scanId, isResuming: !!previousState });
                } catch (error) {
                    debug('ERROR EN SCAN:START HANDLER:', error);
                    debug('Error message:', error.message);
                    debug('Error stack:', error.stack);
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
                    debug('ERROR verificando scan en pause:', error);
                    debug('Error message:', error.message);
                    debug('ScanId:', scanId);
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
                    debug('ERROR verificando scan en resume:', error);
                    debug('Error message:', error.message);
                    debug('ScanId:', scanId);
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
                    debug('ERROR guardando estado detenido:', error);
                    debug('Error message:', error.message);
                    debug('ScanId:', scanId);
                }

                orchestrator.stop();
                this.activeScans.delete(scanId);
                this.io.to(`scan:${scanId}`).emit('scan:stopped', { scanId });
            });

            socket.on('scan:leave', (data) => {
                const { scanId } = data;
                socket.leave(`scan:${scanId}`);
            });

            socket.on('disconnect', async () => {
                debug(`Socket ${socket.id} disconnected`);
                
                // Buscar qué scan estaba asociado a este socket
                let disconnectedScanId = null;
                for (const [scanId, orchestrator] of this.activeScans.entries()) {
                    // Verificar si este socket está en el room del scan
                    const socketRooms = Array.from(socket.rooms);
                    if (socketRooms.includes(`scan:${scanId}`)) {
                        disconnectedScanId = scanId;
                        break;
                    }
                }
                
                if (disconnectedScanId) {
                    const orchestrator = this.activeScans.get(disconnectedScanId);
                    if (orchestrator) {
                        try {
                            debug(`Suspendiendo scan ${disconnectedScanId} por desconexión...`);
                            
                            // Guardar progreso actual
                            await orchestrator.saveProgress();
                            
                            // Detener auto-save
                            if (orchestrator.stopAutoSave) {
                                orchestrator.stopAutoSave();
                            }
                            
                            // Matar procesos activos (sqlmap, dalfox)
                            if (orchestrator.killAllProcesses) {
                                orchestrator.killAllProcesses();
                            }
                            
                            // Actualizar estado a pausado (pendiente) en BD
                            await Scan.Model.findByIdAndUpdate(disconnectedScanId, {
                                estado: 'pendiente'
                            });
                            
                            // Limpiar de memoria
                            this.activeScans.delete(disconnectedScanId);
                            
                            debug(`Scan ${disconnectedScanId} suspendido exitosamente`);
                        } catch (error) {
                            debug(`Error al suspender scan ${disconnectedScanId}:`, error);
                            debug('Error stack:', error.stack);
                        }
                    }
                }
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
                            debug('ERROR obteniendo pregunta para puntuación:', err);
                            debug('Pregunta ID:', ans.pregunta_id);
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
                
                // Obtener vulnerabilidades con detalles de severidad para calcular puntuación
                const { Vulnerability } = require('../models/scan/vulnerability.model');
                const { Score } = require('../models/value-objects/scan-value-objects');
                const vulnerabilities = await Vulnerability.Model.find({ escaneo_id: scan._id })
                    .populate('nivel_severidad_id', 'nivel');
                
                // Convertir scan.puntuacion a instancia de Score para usar calculateFinalScore
                const scoreInstance = new Score(scan.puntuacion);
                const puntuacionFinal = scoreInstance.calculateFinalScore(vulnerabilities);
                
                scan.puntuacion.puntuacion_final = puntuacionFinal;
                scan.puntuacion.calificacion = scoreInstance.calificacion;
                
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
                    debug('ERROR guardando notificación:', notifError);
                    debug('Error message:', notifError.message);
                    debug('Usuario ID:', scan.usuario_id);
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
                    debug('ERROR guardando actividad:', activityError);
                    debug('Error message:', activityError.message);
                    debug('Usuario ID:', scan.usuario_id);
                }

                this.io.to(room).emit('scan:completed', data);
                
                this.activeScans.delete(scanId);
            } catch (error) {
                debug('ERROR en scan:completed handler:', error);
                debug('Error message:', error.message);
                debug('Error stack:', error.stack);
                debug('ScanId:', scanId);
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

                // Enviar error con formato esperado por el frontend: { message: string }
                this.io.to(room).emit('scan:error', { 
                    message: data.error || 'Error desconocido en el escaneo' 
                });
                this.activeScans.delete(scanId);
            } catch (error) {
                debug('ERROR en scan:error handler:', error);
                debug('Error message:', error.message);
                debug('ScanId:', scanId);
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
