const mongoose = require('mongoose');
const { MongoMemoryServer } = require('mongodb-memory-server');
const io = require('socket.io-client');

jest.mock('config', () => ({
    get: jest.fn((key) => {
        if (key === 'sqlmap.path') return '/usr/bin/sqlmap';
        if (key === 'dalfox.path') return '/usr/bin/dalfox';
        return null;
    }),
    has: jest.fn((key) => {
        return key === 'sqlmap.path' || key === 'dalfox.path';
    })
}));

const { User } = require('../../models/user/user.model');
const { Scan } = require('../../models/scan/scan.model');
const { Vulnerability } = require('../../models/scan/vulnerability.model');
const { Question } = require('../../models/quiz/question.model');
const { Answer } = require('../../models/quiz/answer.model');
const { VulnerabilityType } = require('../../models/catalog/vulnerability-type.model');
const { SeverityLevel } = require('../../models/catalog/severity-level.model');
const ScanOrchestrator = require('../../services/scan/scan-orchestrator.service');

describe('PRUEBAS CRÍTICAS DE INTEGRACIÓN', () => {
    let mongoServer;
    let testUser;
    let clientSocket;

    beforeAll(async () => {
        mongoServer = await MongoMemoryServer.create();
        await mongoose.connect(mongoServer.getUri());

        clientSocket = io('http://localhost:3000', {
            reconnection: false,
            timeout: 5000
        });
    });

    afterAll(async () => {
        if (clientSocket && clientSocket.connected) {
            clientSocket.disconnect();
        }
        await mongoose.disconnect();
        await mongoServer.stop();
    });

    beforeEach(async () => {
        const collections = mongoose.connection.collections;
        for (const key in collections) {
            await collections[key].deleteMany({});
        }

        testUser = await User.Model.create({
            username: 'testuser',
            email: 'test@example.com',
            contrasena_hash: 'hashedPassword123',
            email_verificado: true
        });
    });

    describe('PI-001: Flujo de Escaneo End-to-End', () => {
        test('Debe crear escaneo, asociarlo a usuario y calcular puntuación final', async () => {
            const questions = [];
            for (let i = 0; i < 5; i++) {
                const q = await Question.Model.create({
                    texto_pregunta: `Pregunta crítica ${i + 1}`,
                    dificultad: 'media',
                    puntos: 10,
                    fase: ['init', 'discovery', 'sqli', 'xss', 'parameters'][i]
                });
                
                await Answer.Model.create([
                    { pregunta_id: q._id, texto_respuesta: 'Correcta', es_correcta: true },
                    { pregunta_id: q._id, texto_respuesta: 'Incorrecta', es_correcta: false }
                ]);
                
                questions.push(q);
            }

            const scan = await Scan.create({
                usuario_id: testUser._id,
                alias: 'Escaneo Crítico',
                url: 'http://testphp.vulnweb.com',
                flags: { xss: true, sqli: true },
                respuestas_usuario: [
                    { pregunta_id: questions[0]._id, respuestas_seleccionadas: [answers[0]._id], puntos_obtenidos: 10 },
                    { pregunta_id: questions[1]._id, respuestas_seleccionadas: [answers[1]._id, answers[2]._id], puntos_obtenidos: 8 },
                    { pregunta_id: questions[2]._id, respuestas_seleccionadas: [answers[3]._id], puntos_obtenidos: 10 },
                    { pregunta_id: questions[3]._id, respuestas_seleccionadas: [answers[4]._id, answers[5]._id, answers[6]._id], puntos_obtenidos: 2 },
                    { pregunta_id: questions[4]._id, respuestas_seleccionadas: [answers[7]._id], puntos_obtenidos: 10 }
                ],
                puntuacion: {
                    puntos_cuestionario: 40,
                    total_puntos_cuestionario: 50,
                    vulnerabilidades_encontradas: 2
                }
            });

            scan.calculateScore();
            await scan.save();

            const savedScan = await Scan.Model.findById(scan._id).populate('usuario_id');
            
            expect(savedScan).toBeDefined();
            expect(savedScan.usuario_id.email).toBe('test@example.com');
            expect(savedScan.respuestas_usuario).toHaveLength(5);
            expect(savedScan.puntuacion.puntuacion_final).toBeDefined();
            expect(savedScan.puntuacion.puntuacion_final).toBeGreaterThan(0);
            expect(savedScan.estado).toBe('pendiente');
            expect(savedScan.puntuacion.puntuacion_final).toBe(78);
        });
    });

    describe('PI-002: Sistema de 5 Preguntas Aleatorias', () => {
        test('Debe cargar exactamente 5 preguntas y calcular puntos por intentos', async () => {
            const phases = ['init', 'discovery', 'sqli', 'xss', 'parameters'];
            for (let i = 0; i < 10; i++) {
                await Question.Model.create({
                    texto_pregunta: `Pregunta ${i + 1}`,
                    dificultad: 'media',
                    puntos: 10,
                    fase: phases[i % 5]
                });
            }

            const questions = await Question.Model.aggregate([{ $sample: { size: 5 } }]);
            expect(questions).toHaveLength(5);
            const puntosPorIntento = [
                { intentos: 1, esperado: 10 },
                { intentos: 2, esperado: 8 },
                { intentos: 3, esperado: 2 }
            ];

            puntosPorIntento.forEach(({ intentos, esperado }) => {
                let puntos = 10;
                if (intentos === 2) puntos = 8;
                else if (intentos >= 3) puntos = 2;
                
                expect(puntos).toBe(esperado);
            });
        });
    });

    describe('PI-003: Integridad de Base de Datos', () => {
        test('Debe mantener relaciones entre Usuario-Escaneo-Vulnerabilidades', async () => {
            const vulnType = await VulnerabilityType.Model.create({
                nombre: 'SQLi',
                descripcion: 'SQL Injection'
            });

            const severityLevel = await SeverityLevel.Model.create({
                nombre: 'Alta',
                descripcion: 'Severidad Alta'
            });

            const scan = await Scan.create({
                usuario_id: testUser._id,
                alias: 'Test Scan',
                url: 'http://testphp.vulnweb.com',
                flags: { xss: true, sqli: true }
            });

            const vulns = await Vulnerability.Model.create([
                {
                    escaneo_id: scan._id,
                    tipo_id: vulnType._id,
                    nivel_severidad_id: severityLevel._id,
                    url_afectada: 'http://testphp.vulnweb.com/artists.php?artist=1',
                    parametro_afectado: 'id',
                    descripcion: 'Vulnerabilidad 1'
                },
                {
                    escaneo_id: scan._id,
                    tipo_id: vulnType._id,
                    nivel_severidad_id: severityLevel._id,
                    url_afectada: 'http://testphp.vulnweb.com/listproducts.php?cat=1',
                    parametro_afectado: 'name',
                    descripcion: 'Vulnerabilidad 2'
                }
            ]);

            scan.vulnerabilidades = vulns.map(v => v._id);
            scan.estado = 'finalizado';
            await scan.save();

            const savedScan = await Scan.Model.findById(scan._id)
                .populate('usuario_id')
                .populate('vulnerabilidades');

            expect(savedScan.usuario_id._id.toString()).toBe(testUser._id.toString());
            expect(savedScan.vulnerabilidades).toHaveLength(2);
            expect(savedScan.estado).toBe('finalizado');
        });
    });

    describe('PI-004: Inicialización del Motor de Escaneo', () => {
        test('Debe inicializar el orquestador con configuración válida', () => {
            const config = {
                url: 'http://testphp.vulnweb.com',
                flags: { xss: true, sqli: true },
                depth: 1,
                timeout: 30
            };

            const orchestrator = new ScanOrchestrator('test-scan-001', config);

            expect(orchestrator).toBeDefined();
            expect(orchestrator.config.url).toBe('http://testphp.vulnweb.com');
            expect(orchestrator.config.flags.xss).toBe(true);
            expect(orchestrator.config.flags.sqli).toBe(true);
            expect(orchestrator.logger).toBeDefined();
            expect(orchestrator.questionHandler).toBeDefined();
            expect(orchestrator.isStopped).toBe(false);
        });

        test('Debe rechazar configuración inválida', () => {
            expect(() => {
                new ScanOrchestrator('test-scan-002', {});
            }).toThrow();

            expect(() => {
                new ScanOrchestrator('test-scan-003', { url: '' });
            }).toThrow();
        });
    });

    describe('PI-005: Control de Escaneo (Pausar/Reanudar/Detener)', () => {
        test('Debe poder controlar el flujo del escaneo', () => {
            const config = {
                url: 'http://testphp.vulnweb.com',
                flags: { xss: true, sqli: true }
            };

            const orchestrator = new ScanOrchestrator('test-scan-004', config);

            orchestrator.pause();
            expect(orchestrator.isPaused).toBe(true);

            orchestrator.resume();
            expect(orchestrator.isPaused).toBe(false);

            orchestrator.stop();
            expect(orchestrator.isStopped).toBe(true);
        });
    });

    describe('PI-006: Prevención de Usuarios Duplicados', () => {
        test('Debe prevenir correos duplicados', async () => {
            await User.Model.create({
                username: 'usuario1',
                email: 'duplicado@example.com',
                contrasena_hash: 'pass123',
                email_verificado: true
            });
            await expect(
                User.Model.create({
                    username: 'usuario2',
                    email: 'duplicado@example.com',
                    contrasena_hash: 'pass456',
                    email_verificado: true
                })
            ).rejects.toThrow();
        });
    });

    describe('PI-007: Cálculo de Puntuación Final', () => {
        test('Debe calcular correctamente con fórmula 60/40 (cuestionario/vulnerabilidades)', async () => {
            const scan1 = await Scan.create({
                usuario_id: testUser._id,
                alias: 'Perfect Score',
                url: 'http://testphp.vulnweb.com',
                flags: { xss: true, sqli: true },
                puntuacion: {
                    puntos_cuestionario: 50,
                    total_puntos_cuestionario: 50,
                    vulnerabilidades_encontradas: 0
                }
            });
            scan1.calculateScore();
            expect(scan1.puntuacion.puntuacion_final).toBe(100);
            expect(scan1.puntuacion.calificacion).toBe('Excelente');
            const scan2 = await Scan.create({
                usuario_id: testUser._id,
                alias: 'With Vulns',
                url: 'http://demo.testfire.net',
                flags: { xss: true, sqli: true },
                puntuacion: {
                    puntos_cuestionario: 38,
                    total_puntos_cuestionario: 50,
                    vulnerabilidades_encontradas: 3
                }
            });
            scan2.calculateScore();
            expect(scan2.puntuacion.puntuacion_final).toBe(71);
            expect(scan2.puntuacion.calificacion).toBe('Regular');
            const scan3 = await Scan.create({
                usuario_id: testUser._id,
                alias: 'Many Vulns',
                url: 'http://testhtml5.vulnweb.com',
                flags: { xss: true, sqli: true },
                puntuacion: {
                    puntos_cuestionario: 10,
                    total_puntos_cuestionario: 50,
                    vulnerabilidades_encontradas: 15
                }
            });
            scan3.calculateScore();
            expect(scan3.puntuacion.puntuacion_final).toBe(12);
            expect(scan3.puntuacion.calificacion).toBe('Crítico');
        });
    });

    describe('PI-008: Motor de Escaneo - Vulnerabilidades', () => {
        test('Debe agregar y prevenir vulnerabilidades duplicadas', () => {
            const config = {
                url: 'http://testphp.vulnweb.com',
                flags: { xss: true, sqli: true }
            };

            const orchestrator = new ScanOrchestrator('test-scan-vulns', config);
            orchestrator.addVulnerability({
                type: 'SQLi',
                url: 'http://testphp.vulnweb.com/artists.php?artist=1',
                parameter: 'id',
                payload: "' OR '1'='1"
            });

            expect(orchestrator.vulnerabilities).toHaveLength(1);

            orchestrator.addVulnerability({
                type: 'SQLi',
                url: 'http://testphp.vulnweb.com/artists.php?artist=1',
                parameter: 'id',
                payload: "' OR '1'='1"
            });

            expect(orchestrator.vulnerabilities).toHaveLength(1);
            orchestrator.addVulnerability({
                type: 'XSS',
                url: 'http://testphp.vulnweb.com/AJAX/index.php',
                parameter: 'q',
                payload: '<script>alert(1)</script>'
            });

            expect(orchestrator.vulnerabilities).toHaveLength(2);
        });
    });

    describe('PI-009: Motor de Escaneo - Estadísticas', () => {
        test('Debe actualizar estadísticas correctamente durante el escaneo', () => {
            const config = {
                url: 'http://testphp.vulnweb.com',
                flags: { xss: true, sqli: true }
            };

            const orchestrator = new ScanOrchestrator('test-scan-stats', config);
            expect(orchestrator.stats.totalRequests).toBe(0);
            expect(orchestrator.stats.vulnerabilitiesFound).toBe(0);
            expect(orchestrator.stats.endpointsDiscovered).toBe(0);

            orchestrator.stats.totalRequests = 50;
            orchestrator.stats.endpointsDiscovered = 10;
            orchestrator.addVulnerability({
                type: 'SQLi',
                url: 'http://testphp.vulnweb.com/listproducts.php?cat=1',
                parameter: 'id'
            });

            expect(orchestrator.stats.totalRequests).toBe(50);
            expect(orchestrator.stats.endpointsDiscovered).toBe(10);
            expect(orchestrator.vulnerabilities.length).toBeGreaterThan(0);
        });
    });

    describe('PI-010: Performance - Índices de BD', () => {
        test('Debe tener índices en campos de búsqueda frecuente', async () => {
            const userIndexes = await User.Model.collection.getIndexes();
            const scanIndexes = await Scan.Model.collection.getIndexes();
            expect(userIndexes).toBeDefined();
            expect(scanIndexes).toBeDefined();
            expect(Object.keys(userIndexes).length).toBeGreaterThan(1);
            expect(Object.keys(scanIndexes).length).toBeGreaterThan(0);
        });
    });

    describe('PI-011: Performance - Búsqueda de Usuarios', () => {
        test('Debe buscar usuarios por email eficientemente', async () => {
            await User.Model.insertMany([
                { username: 'user1', email: 'user1@example.com', contrasena_hash: 'pass123', email_verificado: true },
                { username: 'user2', email: 'user2@example.com', contrasena_hash: 'pass123', email_verificado: true },
                { username: 'user3', email: 'user3@example.com', contrasena_hash: 'pass123', email_verificado: true }
            ]);

            const startTime = Date.now();
            const user = await User.Model.findOne({ email: 'user2@example.com' });
            const endTime = Date.now();

            expect(user).toBeDefined();
            expect(user.email).toBe('user2@example.com');
            expect(endTime - startTime).toBeLessThan(100);
        });
    });

    describe('PI-012: Base de Datos - Preguntas y Respuestas', () => {
        test('Debe crear pregunta con múltiples respuestas y validar correctas', async () => {
            const question = await Question.Model.create({
                texto_pregunta: '¿Qué es SQL Injection?',
                dificultad: 'media',
                puntos: 15,
                fase: 'sqli'
            });

            const answers = await Answer.Model.create([
                {
                    pregunta_id: question._id,
                    texto_respuesta: 'Es una vulnerabilidad de seguridad',
                    es_correcta: true
                },
                {
                    pregunta_id: question._id,
                    texto_respuesta: 'Es un lenguaje de programación',
                    es_correcta: false
                },
                {
                    pregunta_id: question._id,
                    texto_respuesta: 'Es un tipo de base de datos',
                    es_correcta: false
                }
            ]);

            expect(answers).toHaveLength(3);
            expect(answers.filter(a => a.es_correcta)).toHaveLength(1);

            const foundAnswers = await Answer.Model.find({ pregunta_id: question._id });
            expect(foundAnswers).toHaveLength(3);
        });
    });

    describe('PI-013: Motor de Escaneo - Ejecutores SQLMap/Dalfox', () => {
        test('Debe inicializar ejecutores según flags activos', () => {
            const config1 = {
                url: 'http://testphp.vulnweb.com',
                flags: { xss: false, sqli: true }
            };
            const orch1 = new ScanOrchestrator('test-sqli', config1);
            expect(orch1.sqlmapExecutor).toBeDefined();

            const config2 = {
                url: 'http://testphp.vulnweb.com',
                flags: { xss: true, sqli: false }
            };
            const orch2 = new ScanOrchestrator('test-xss', config2);
            expect(orch2.dalfoxExecutor).toBeDefined();
            const config3 = {
                url: 'http://testphp.vulnweb.com',
                flags: { xss: true, sqli: true }
            };
            const orch3 = new ScanOrchestrator('test-both', config3);
            expect(orch3.sqlmapExecutor).toBeDefined();
            expect(orch3.dalfoxExecutor).toBeDefined();
        });
    });

    describe('PI-014: Motor de Escaneo - Sistema de Logs', () => {
        test('Debe tener sistema de logging funcional', () => {
            const config = {
                url: 'http://testphp.vulnweb.com',
                flags: { xss: true, sqli: true }
            };

            const orchestrator = new ScanOrchestrator('test-logger', config);

            expect(orchestrator.logger).toBeDefined();
            expect(typeof orchestrator.logger.addLog).toBe('function');
            let logReceived = false;
            orchestrator.on('log:new', (log) => {
                logReceived = true;
            });

            expect(orchestrator.listenerCount('log:new')).toBeGreaterThan(0);
        });
    });

    describe('PI-015: Base de Datos - Conexión', () => {
        test('Debe conectar correctamente a MongoDB y tener modelos registrados', async () => {
            expect(mongoose.connection.readyState).toBe(1);
            const models = mongoose.modelNames();
            expect(models).toContain('User');
            expect(models).toContain('Scan');
            expect(models).toContain('Vulnerability');
            expect(models).toContain('Question');
            expect(models).toContain('Answer');
        });
    });

    describe('PI-016: Frontend - Socket.IO', () => {
        test('Debe tener cliente Socket.IO disponible y validar estructura de escaneo', async () => {
            expect(clientSocket).toBeDefined();
            const scan = await Scan.create({
                usuario_id: testUser._id,
                alias: 'Socket Test',
                url: 'http://testphp.vulnweb.com',
                flags: { xss: false, sqli: true }
            });

            expect(scan._id).toBeDefined();
            expect(scan.url).toBe('http://testphp.vulnweb.com');
            expect(scan.estado).toBe('pendiente');
            expect(scan.usuario_id.toString()).toBe(testUser._id.toString());

            expect(typeof clientSocket.on).toBe('function');
            expect(typeof clientSocket.emit).toBe('function');
        });
    });

    describe('PI-017: Base de Datos - Validación de Campos', () => {
        test('Debe validar campos requeridos en modelos críticos', async () => {
            await expect(
                User.Model.create({ username: 'test' })
            ).rejects.toThrow();

            await expect(
                Scan.Model.create({
                    usuario_id: testUser._id,
                    alias: 'Test'
                })
            ).rejects.toThrow();

            await expect(
                Question.Model.create({ texto_pregunta: 'Test' })
            ).rejects.toThrow();
        });
    });

    describe('PI-018: Motor de Escaneo - Question Handler', () => {
        test('Debe tener question handler para pausar escaneo', () => {
            const config = {
                url: 'http://testphp.vulnweb.com',
                flags: { xss: true, sqli: true }
            };

            const orchestrator = new ScanOrchestrator('test-qh', config);

            expect(orchestrator.questionHandler).toBeDefined();
            expect(typeof orchestrator.questionHandler.waitIfPaused).toBe('function');
            expect(orchestrator.isPaused).toBe(false);
        });
    });
});
