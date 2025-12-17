const EventEmitter = require('events');
const path = require('path');
const os = require('os');
const fs = require('fs');
const debug = require('debug')('easyinjection:scan:orchestrator');

const { validateAndNormalizeConfig } = require('./config-validator.service');
const Logger = require('./logger.service');
const QuestionHandler = require('./question-handler.service');
const SqlmapExecutor = require('./sqlmap-executor.service');
const DalfoxExecutor = require('./dalfox-executor.service');
const DiscoveryPhase = require('../phases/discovery.phase');
const SQLiPhase = require('../phases/sqli.phase');
const XSSPhase = require('../phases/xss.phase');
const { Scan } = require('../../models/scan/scan.model');
const { VulnerabilitySubtype } = require('../../models/catalog/vulnerability-subtype.model');

class ScanOrchestrator extends EventEmitter {
    constructor(scanId, scanConfig, previousState = null) {
        super();
        
        try {
            this.config = validateAndNormalizeConfig(scanConfig);
        } catch (error) {
            throw new Error(`Invalid configuration: ${error.message}`);
        }
        
        this.scanId = scanId;
        this.currentPhase = previousState?.current_phase || null;
        this.currentSubphase = previousState?.current_subphase || null;
        this.discoveredEndpoints = previousState?.discovered_endpoints || [];
        this.discoveredParameters = previousState?.discovered_parameters || [];
        this.vulnerabilities = [];
        this.questionResults = [];
        this.activeProcesses = new Map();
        this.isPaused = false;
        this.isStopped = false;
        this.completedPhases = previousState?.completed_phases || [];
        this.completedSubphases = previousState?.completed_subphases || [];
        this.testedEndpointsSqli = previousState?.tested_endpoints_sqli || [];
        this.testedEndpointsXss = previousState?.tested_endpoints_xss || [];
        this.askedPhases = previousState?.asked_phases || [];
        this.autoSaveInterval = null;
        
        this.stats = {
            totalRequests: 0,
            vulnerabilitiesFound: 0,
            endpointsDiscovered: previousState?.discovered_endpoints?.length || 0,
            parametersFound: previousState?.discovered_parameters?.length || 0
        };
        
        const outputDir = path.join(os.tmpdir(), 'easyinjection_scans', `scan_${scanId}`);
        if (!fs.existsSync(outputDir)) {
            fs.mkdirSync(outputDir, { recursive: true });
        }
        
        this.config.outputDir = outputDir;
        this.config.tmpDir = path.join(os.tmpdir(), 'easyinjection_sqlmap_tmp');
        
        this.logger = new Logger(this);
        this.questionHandler = new QuestionHandler(this, this.logger, this.askedPhases);
        
        this.sqlmapExecutor = new SqlmapExecutor(
            this.config,
            this.logger,
            this,
            this.activeProcesses
        );
        
        this.dalfoxExecutor = new DalfoxExecutor(
            this.config,
            this.logger,
            this,
            this.activeProcesses
        );
        
        this.on('endpoint:crawl-discovered', (data) => {
            if (this.discoveryPhase) {
                this.discoveryPhase.addEndpoint({
                    url: data.url,
                    method: data.method,
                    parameters: []
                });
            }
        });
        
        this.on('question:result', (result) => {
            this.questionResults.push(result);
        });
        
        this.phases = [
            { id: 'init', name: 'Inicialización', status: this.completedPhases.includes('init') ? 'completed' : 'pending' },
            { id: 'discovery', name: 'Descubrimiento de endpoints y parámetros', status: this.completedPhases.includes('discovery') ? 'completed' : 'pending' },
            { id: 'sqli', name: 'Pruebas SQL Injection', status: this.completedPhases.includes('sqli') ? 'completed' : 'pending', subphases: [
                { id: 'detection', name: 'Detección de vulnerabilidad', status: 'pending' },
                { id: 'fingerprint', name: 'Fingerprinting', status: 'pending' },
                { id: 'technique', name: 'Selección de técnica', status: 'pending' },
                { id: 'exploit', name: 'Explotación (POC)', status: 'pending' }
            ]},
            { id: 'xss', name: 'Pruebas XSS', status: this.completedPhases.includes('xss') ? 'completed' : 'pending', subphases: [
                { id: 'context', name: 'Análisis de contexto', status: 'pending' },
                { id: 'payload', name: 'Generación de payloads', status: 'pending' },
                { id: 'fuzzing', name: 'Motor de fuzzing', status: 'pending' }
            ]},
            { id: 'report', name: 'Generación de reporte', status: this.completedPhases.includes('report') ? 'completed' : 'pending' }
        ];
    }
    
    async start() {
        try {
            debug('=== INICIO DE ESCANEO ===');
            debug('ScanId:', this.scanId);
            debug('Config:', JSON.stringify(this.config));
            debug('Phases completed:', this.completedPhases);
            
            // Actualizar estado inmediatamente para detectar desconexiones
            debug('Actualizando estado a pendiente...');
            const scanUpdate = await Scan.Model.findByIdAndUpdate(this.scanId, { estado: 'pendiente' });
            debug('Estado actualizado:', scanUpdate ? 'OK' : 'FAILED');
            
            this.isStopped = false;
            this.isPaused = false;
            
            // Iniciar auto-save periódico
            debug('Iniciando auto-save periódico...');
            this.startAutoSave();
            debug('Auto-save iniciado');
            
            const isResuming = this.completedPhases.length > 0;
            debug('Es reanudación?', isResuming);
            if (isResuming) {
                this.logger.addLog('Reanudando escaneo desde fase guardada...', 'info');
                await this.loadExistingResults();
            }
            
            this.emit('scan:started', { scanId: this.scanId, isResuming });
            
            if (this.isStopped) return;
            if (!this.completedPhases.includes('init')) {
                await this.runPhase('init');
            } else {
                this.logger.addLog('Fase de inicialización ya completada, omitiendo...', 'info');
            }
            
            if (this.isStopped) return;
            if (!this.completedPhases.includes('discovery')) {
                await this.runPhase('discovery');
            } else {
                this.logger.addLog('Fase de descubrimiento ya completada, omitiendo...', 'info');
                this.stats.endpointsDiscovered = this.discoveredEndpoints.length;
                this.stats.parametersFound = this.discoveredParameters.length;
            }
            
            if (this.config.flags.sqli && !this.isStopped && !this.completedPhases.includes('sqli')) {
                await this.runPhase('sqli');
            }
            
            if (this.config.flags.xss && !this.isStopped && !this.completedPhases.includes('xss')) {
                await this.runPhase('xss');
            }
            
            if (!this.isStopped) {
                await this.waitForAllProcesses();
                await this.runPhase('report');
            }
            
            if (!this.isStopped) {
                this.stopAutoSave();
                this.emit('scan:completed', { 
                    scanId: this.scanId,
                    vulnerabilities: this.vulnerabilities,
                    questionResults: this.questionResults,
                    stats: this.stats
                });
            }
        } catch (error) {
            debug('ERROR CRÍTICO EN START:', error);
            debug('Error message:', error.message);
            debug('Error stack:', error.stack);
            if (!this.isStopped) {
                this.logger.addLog(`Error crítico: ${error.message}`, 'error');
                this.emit('scan:error', { scanId: this.scanId, error: error.message });
            }
            this.stopAutoSave();
            this.killAllProcesses();
            throw error;
        }
    }

    async waitForAllProcesses() {
        this.logger.addLog('Esperando que finalicen todos los procesos...', 'info');
        
        const maxWaitTime = 60000;
        const checkInterval = 1000;
        let elapsed = 0;
        
        while (this.activeProcesses.size > 0 && elapsed < maxWaitTime) {
            await this.sleep(checkInterval);
            elapsed += checkInterval;
        }
        
        if (this.activeProcesses.size > 0) {
            this.logger.addLog(`Advertencia: ${this.activeProcesses.size} proceso(s) aún activos después del tiempo máximo de espera`, 'warning');
        } else {
            this.logger.addLog('Todos los procesos han finalizado', 'success');
        }
    }
    
    killAllProcesses() {
        for (const [name, proc] of this.activeProcesses.entries()) {
            if (proc && !proc.killed) {
                this.logger.addLog(`Terminando proceso: ${name}`, 'warning');
                proc.kill('SIGTERM');
            }
        }
        this.activeProcesses.clear();
    }

    startAutoSave() {
        // Guardar progreso cada 15 segundos mientras el scan está activo
        this.autoSaveInterval = setInterval(() => {
            if (!this.isPaused && !this.isStopped) {
                this.saveProgress().catch(err => {
                    this.logger.addLog(`Error en auto-save: ${err.message}`, 'error');
                });
            }
        }, 15000);
    }

    stopAutoSave() {
        if (this.autoSaveInterval) {
            clearInterval(this.autoSaveInterval);
            this.autoSaveInterval = null;
        }
    }

    setCurrentSubphase(subphase) {
        // If subphase is null, mark the previous subphase as completed
        if (subphase === null && this.currentSubphase) {
            if (!this.completedSubphases.includes(this.currentSubphase)) {
                this.completedSubphases.push(this.currentSubphase);
            }
        }
        
        this.currentSubphase = subphase;
        // Auto-save progress when subphase changes
        this.saveProgress().catch(err => {
            this.logger.addLog(`Error guardando progreso de subfase: ${err.message}`, 'warning');
        });
    }

    async runPhase(phaseId) {
        if (this.isStopped) return;
        
        const phase = this.phases.find(p => p.id === phaseId);
        if (!phase) return;

        this.currentPhase = phaseId;
        this.currentSubphase = null;
        this.logger.setCurrentPhase(phaseId);
        phase.status = 'running';
        this.emit('phase:started', { phase: phaseId, name: phase.name });
        this.logger.addLog(`Iniciando fase: ${phase.name}`, 'info', phaseId);

        try {
            switch (phaseId) {
                case 'init':
                    await this.initializeScan();
                    break;
                case 'discovery':
                    const discoveryResult = await this.runDiscoveryPhase();
                    this.discoveredEndpoints = discoveryResult.endpoints;
                    this.discoveredParameters = discoveryResult.parameters;
                    this.stats.endpointsDiscovered = this.discoveredEndpoints.length;
                    this.stats.parametersFound = this.discoveredParameters.length;
                    break;
                case 'sqli':
                    await this.runSQLiPhase();
                    break;
                case 'xss':
                    await this.runXSSPhase();
                    break;
                case 'report':
                    await this.generateReport();
                    break;
            }
        } catch (error) {
            if (!this.isStopped) {
                phase.status = 'error';
                throw error;
            }
        }

        if (!this.isStopped) {
            phase.status = 'completed';
            this.completedPhases.push(phaseId);
            await this.saveProgress();
            this.emit('phase:completed', { phase: phaseId, name: phase.name });
            this.logger.addLog(`Fase completada: ${phase.name}`, 'success', phaseId);
        }
    }

    async saveProgress() {
        try {
            await Scan.Model.findByIdAndUpdate(
                this.scanId,
                {
                    $set: {
                        current_phase: this.currentPhase,
                        current_subphase: this.currentSubphase,
                        completed_phases: this.completedPhases,
                        completed_subphases: this.completedSubphases,
                        discovered_endpoints: this.discoveredEndpoints,
                        discovered_parameters: this.discoveredParameters,
                        tested_endpoints_sqli: this.testedEndpointsSqli,
                        tested_endpoints_xss: this.testedEndpointsXss,
                        asked_phases: Array.from(this.questionHandler.askedPhases)
                    }
                },
                { new: true, runValidators: false }
            );
            
            debug('Progreso guardado exitosamente');
        } catch (error) {
            this.logger.addLog(`Error guardando progreso: ${error.message}`, 'warning');
        }
    }

    async loadExistingResults() {
        try {
            const Vulnerability = require('../../models/scan/vulnerability.model').Vulnerability;
            
            const scanDoc = await Scan.Model.findById(this.scanId)
                .populate({
                    path: 'vulnerabilidades',
                    populate: [
                        {
                            path: 'tipo_id',
                            model: 'VulnerabilityType'
                        },
                        {
                            path: 'nivel_severidad_id',
                            model: 'SeverityLevel'
                        }
                    ]
                })
                .populate({
                    path: 'respuestas_usuario.pregunta_id',
                    model: 'Question'
                });
            
            if (scanDoc) {
                // Load existing vulnerabilities
                if (scanDoc.vulnerabilidades && scanDoc.vulnerabilidades.length > 0) {
                    this.vulnerabilities = scanDoc.vulnerabilidades.map(v => ({
                        type: v.tipo_id?.nombre || 'Unknown',
                        endpoint: v.url_afectada || '',
                        parameter: v.parametro_afectado || '',
                        description: v.descripcion || '',
                        severity: v.nivel_severidad_id?.nombre || 'Unknown',
                        poc: v.referencia || ''
                    }));
                    this.stats.vulnerabilitiesFound = this.vulnerabilities.length;
                    this.logger.addLog(`Cargadas ${this.vulnerabilities.length} vulnerabilidades existentes`, 'info');
                    
                    // Notify frontend about existing vulnerabilities
                    this.vulnerabilities.forEach(vuln => {
                        this.emit('vulnerability:found', vuln);
                    });
                    debug(`Notificadas ${this.vulnerabilities.length} vulnerabilidades al frontend`);
                }
                
                // Load existing question results
                if (scanDoc.respuestas_usuario && scanDoc.respuestas_usuario.length > 0) {
                    // Populate answers to check if correct
                    await scanDoc.populate('respuestas_usuario.respuestas_seleccionadas');
                    
                    this.questionResults = scanDoc.respuestas_usuario.map(ru => {
                        // Check if last answer is correct
                        const lastAnswer = ru.respuestas_seleccionadas && ru.respuestas_seleccionadas.length > 0 
                            ? ru.respuestas_seleccionadas[ru.respuestas_seleccionadas.length - 1]
                            : null;
                        const isCorrect = lastAnswer?.es_correcta || false;
                        
                        return {
                            questionId: ru.pregunta_id?._id,
                            question: ru.pregunta_id?.texto_pregunta || '',
                            correct: isCorrect,
                            pointsEarned: ru.puntos_obtenidos || 0
                        };
                    });
                    this.logger.addLog(`Cargadas ${this.questionResults.length} respuestas existentes`, 'info');
                    
                    // Notify frontend about existing question results for correct count
                    this.questionResults.forEach(result => {
                        this.emit('question:result', result);
                    });
                    debug(`Notificadas ${this.questionResults.length} respuestas al frontend`);
                }
            }
        } catch (error) {
            this.logger.addLog(`Error cargando resultados existentes: ${error.message}`, 'warning');
        }
    }

    async initializeScan() {
        await this.questionHandler.waitIfPaused();
        
        this.logger.addLog('Validando configuración del escaneo...', 'info');
        this.logger.addLog(`URL objetivo: ${this.config.url}`, 'info');
        this.logger.addLog(`Flags activas: SQLi=${this.config.flags.sqli}, XSS=${this.config.flags.xss}`, 'info');
        
        await this.sqlmapExecutor.checkAvailability();
        if (this.config.flags.xss) {
            await this.dalfoxExecutor.checkAvailability();
        }
        
        await this.questionHandler.waitIfPaused();
        
        await this.questionHandler.askQuestion(null, 'init');
        
        this.logger.addLog('Inicialización completada', 'success');
    }

    async runDiscoveryPhase() {
        const phase = new DiscoveryPhase(
            this.config,
            this.sqlmapExecutor,
            this.logger,
            this.questionHandler,
            this
        );
        return await phase.run();
    }

    async addVulnerability(vuln) {
        debug('=== addVulnerability LLAMADO ===');
        debug('Vulnerabilidad recibida:', JSON.stringify(vuln));
        debug('Vulnerabilidades actuales:', this.vulnerabilities.length);
        
        if (!this.vulnerabilities.some(v => 
            v.type === vuln.type && 
            v.endpoint === vuln.endpoint && 
            v.parameter === vuln.parameter
        )) {
            debug('Vulnerabilidad no duplicada, agregando...');
            this.vulnerabilities.push(vuln);
            this.stats.vulnerabilitiesFound++;
            this.logger.addLog(`Vulnerabilidad encontrada: ${vuln.type} en ${vuln.endpoint}`, 'success');
            
            // Emit event for frontend to display in real-time
            debug('Emitiendo evento vulnerability:found...');
            this.emit('vulnerability:found', vuln);
            
            // Save vulnerability to DB immediately and WAIT for it to complete
            debug('Iniciando guardado de vulnerabilidad en BD...');
            this.logger.addLog(`Iniciando guardado de vulnerabilidad en BD...`, 'info');
            try {
                await this.saveVulnerabilityToDb(vuln);
                debug('Vulnerabilidad guardada exitosamente en BD');
            } catch (err) {
                debug('ERROR EN saveVulnerabilityToDb:', err);
                debug('Error message:', err.message);
                debug('Error stack:', err.stack);
                this.logger.addLog(`ERROR CRÍTICO guardando vulnerabilidad: ${err.message}`, 'error');
                throw err; // Re-throw to propagate error to caller
            }
        } else {
            debug('Vulnerabilidad duplicada, ignorando');
            this.logger.addLog(`Vulnerabilidad duplicada ignorada: ${vuln.type} en ${vuln.endpoint}`, 'info');
        }
    }

    async saveVulnerabilityToDb(vuln) {
        const debug = require('debug')('easyinjection:scan:vulnerability-save');
        debug('=== INICIANDO GUARDADO DE VULNERABILIDAD ===');
        debug('Datos de vulnerabilidad recibidos: %O', vuln);
        debug('ScanId actual: %s', this.scanId);
        
        try {
            const Vulnerability = require('../../models/scan/vulnerability.model').Vulnerability;
            const VulnerabilityType = require('../../models/catalog/vulnerability-type.model').VulnerabilityType;
            const SeverityLevel = require('../../models/catalog/severity-level.model').SeverityLevel;
            // VulnerabilitySubtype ya está importado al inicio del archivo
            
            debug('Modelos cargados correctamente');
            
            // Map severity to Spanish names
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
            
            const mappedSeverity = severityMap[vuln.severity?.toLowerCase()] || 'Media';
            debug('Severidad mapeada: %s -> %s', vuln.severity, mappedSeverity);
            
            // Find type and severity IDs
            debug('Buscando tipo de vulnerabilidad: %s', vuln.type);
            const vulnType = await VulnerabilityType.Model.findOne({ nombre: vuln.type });
            debug('Tipo encontrado: %O', vulnType);
            
            debug('Buscando nivel de severidad: %s', mappedSeverity);
            const severityLevel = await SeverityLevel.Model.findOne({ nombre: mappedSeverity });
            debug('Severidad encontrada: %O', severityLevel);
            
            if (!vulnType || !severityLevel) {
                const msg = `No se encontró el tipo (${vulnType ? 'OK' : 'NULL'}) o nivel de severidad (${severityLevel ? 'OK' : 'NULL'})`;
                debug('ERROR: %s', msg);
                this.logger.addLog(msg, 'warning');
                return;
            }

            // Buscar el subtipo si se proporcionó
            let vulnSubtype = null;
            if (vuln.subtype) {
                debug('Buscando subtipo de vulnerabilidad: %s para tipo: %s', vuln.subtype, vuln.type);
                vulnSubtype = await VulnerabilitySubtype.Model.findOne({ 
                    tipo_id: vulnType._id,
                    nombre: vuln.subtype 
                });
                debug('Subtipo encontrado: %O', vulnSubtype);
                
                if (!vulnSubtype) {
                    debug('ADVERTENCIA: No se encontró el subtipo exacto "%s", buscando alternativas...', vuln.subtype);
                    // Si no se encuentra exactamente, intentar buscar por coincidencia parcial
                    const subtypes = await VulnerabilitySubtype.Model.find({ tipo_id: vulnType._id });
                    debug('Subtipos disponibles: %O', subtypes.map(s => s.nombre));
                    
                    // Para SQLi, buscar por la primera técnica si viene separado por comas
                    if (vuln.type === 'SQLi' && vuln.subtype.includes(',')) {
                        const firstTechnique = vuln.subtype.split(',')[0].trim();
                        debug('Buscando primera técnica: %s', firstTechnique);
                        vulnSubtype = await VulnerabilitySubtype.Model.findOne({ 
                            tipo_id: vulnType._id,
                            nombre: firstTechnique
                        });
                        debug('Subtipo encontrado con primera técnica: %O', vulnSubtype);
                    }
                }
            }
            
            // Create vulnerability document
            const vulnData = {
                escaneo_id: this.scanId,
                tipo_id: vulnType._id,
                subtipo_id: vulnSubtype ? vulnSubtype._id : null,
                nivel_severidad_id: severityLevel._id,
                parametro_afectado: vuln.parameter,
                url_afectada: vuln.endpoint,
                descripcion: vuln.description,
                sugerencia: this._getVulnerabilitySuggestion(vuln.type),
                referencia: vuln.poc || this._getVulnerabilityReferences(vuln.type)
            };
            
            debug('Datos para crear documento: %O', vulnData);
            const vulnerabilityDoc = new Vulnerability.Model(vulnData);
            debug('Documento creado, intentando guardar...');
            
            await vulnerabilityDoc.save();
            debug('¡Vulnerabilidad guardada exitosamente! ID: %s', vulnerabilityDoc._id);
            
            // Add to scan
            debug('Buscando documento de scan: %s', this.scanId);
            const scanDoc = await Scan.Model.findById(this.scanId);
            debug('Scan encontrado: %O', scanDoc ? { id: scanDoc._id, vulnerabilidades: scanDoc.vulnerabilidades } : 'NULL');
            
            if (scanDoc) {
                if (!scanDoc.vulnerabilidades.includes(vulnerabilityDoc._id)) {
                    debug('Agregando vulnerabilidad al array del scan...');
                    scanDoc.vulnerabilidades.push(vulnerabilityDoc._id);
                    await scanDoc.save();
                    debug('Scan actualizado con vulnerabilidad. Total vulnerabilidades: %d', scanDoc.vulnerabilidades.length);
                    this.logger.addLog(`Vulnerabilidad agregada al reporte. Total: ${scanDoc.vulnerabilidades.length}`, 'info');
                } else {
                    debug('Vulnerabilidad ya estaba en el array del scan');
                    this.logger.addLog('Vulnerabilidad ya existía en el scan', 'info');
                }
            } else {
                debug('ERROR: Scan no encontrado');
                this.logger.addLog('ERROR: Scan no encontrado al agregar vulnerabilidad', 'error');
            }
            
            debug('=== GUARDADO COMPLETADO EXITOSAMENTE ===');
        } catch (error) {
            debug('ERROR CAPTURADO: %s', error.message);
            debug('Stack trace: %s', error.stack);
            this.logger.addLog(`Error en saveVulnerabilityToDb: ${error.message}`, 'error');
            debug('ERROR COMPLETO AL GUARDAR VULNERABILIDAD:', error);
            debug('Error stack:', error.stack);
            throw error; // Re-lanzar para que se capture en el catch de addVulnerability
        }
    }

    _getVulnerabilitySuggestion(type) {
        const suggestions = {
            'SQLi': '• Utiliza consultas parametrizadas o prepared statements, ya sea de forma manual o mediante un ORM, los cuales generalmente incorporan medidas de seguridad por defecto. Este enfoque garantiza que la entrada del usuario sea procesada exclusivamente como datos y no como comandos SQL ejecutables.\n• Aplica reglas estrictas de listas blancas (whitelists) basadas en los requisitos específicos de cada campo. Por ejemplo, para un nombre de usuario, esto implicaría restringir la entrada a un conjunto definido de caracteres y una longitud permitida (por ejemplo, 3–20 caracteres alfanuméricos).\n• La cuenta de la base de datos utilizada por la aplicación debe operar con los mínimos privilegios necesarios, típicamente limitada a operaciones SELECT e INSERT sobre tablas específicas. Esta estrategia de contención limita el daño potencial si ocurriera un ataque exitoso de inyección.',
            'XSS': '• Codificación de Salida Contextual: Aplicar output encoding específico (HTML, Atributo, JavaScript, URL) en todos los datos de salida para neutralizar la carga útil antes de la renderización.\n• Validación Estricta de Entradas (Whitelisting): Implementar validación de lado del servidor utilizando listas blancas que definan qué caracteres, formatos y patrones son estrictamente permitidos.\n• Evitar Inyección Directa: Nunca insertar datos sin procesar en scripts, atributos de eventos (ej., onclick) o contextos que construyen HTML dinámicamente. Utilizar funciones seguras del DOM.\n• Content Security Policy (CSP): Configurar una política CSP que restrinja las fuentes de contenido y bloquee el código inline (\'unsafe-inline\').',
            'CSRF': 'Implemente tokens CSRF (tokens sincronizadores) y verifique el origen de las peticiones.',
            'XXE': 'Deshabilite el procesamiento de entidades externas XML. Use procesadores XML seguros que no procesen DTDs externos.',
            'SSTI': 'Evite usar motores de plantillas que evalúen código arbitrario. Use motores de plantillas seguros o sanitice las plantillas.'
        };
        return suggestions[type] || 'Revise y corrija la vulnerabilidad siguiendo las mejores prácticas de seguridad.';
    }

    _getVulnerabilityReferences(type) {
        const references = {
            'SQLi': 'OWASP - SQL Injection\nhttps://owasp.org/www-community/attacks/SQL_Injection\n\nOWASP - Query Parametrization Cheat Sheet\nhttps://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html\n\nOWASP - Input Validation Cheat Sheet\nhttps://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html',
            'XSS': 'OWASP – Cross Site Scripting Prevention Cheat Sheet\nhttps://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html\n\nOWASP – Content Security Policy Cheat Sheet\nhttps://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html'
        };
        return references[type] || null;
    }

    async runSQLiPhase() {
        const phase = new SQLiPhase(
            this.config,
            this.sqlmapExecutor,
            this.logger,
            this.questionHandler,
            this.discoveredParameters,
            this.vulnerabilities,
            this.stats,
            this
        );
        await phase.run();
    }

    async runXSSPhase() {
        const phase = new XSSPhase(
            this.config,
            this.dalfoxExecutor,
            this.logger,
            this.questionHandler,
            this.discoveredParameters,
            this.vulnerabilities,
            this.stats,
            this
        );
        await phase.run();
    }

    markEndpointTestedForSqli(endpoint) {
        const endpointKey = `${endpoint.method}:${endpoint.url}`;
        if (!this.testedEndpointsSqli.includes(endpointKey)) {
            this.testedEndpointsSqli.push(endpointKey);
        }
    }

    markEndpointTestedForXss(endpoint) {
        const endpointKey = `${endpoint.method}:${endpoint.url}`;
        if (!this.testedEndpointsXss.includes(endpointKey)) {
            this.testedEndpointsXss.push(endpointKey);
        }
    }

    isEndpointTestedForSqli(endpoint) {
        const endpointKey = `${endpoint.method}:${endpoint.url}`;
        return this.testedEndpointsSqli.includes(endpointKey);
    }

    isEndpointTestedForXss(endpoint) {
        const endpointKey = `${endpoint.method}:${endpoint.url}`;
        return this.testedEndpointsXss.includes(endpointKey);
    }

    async generateReport() {
        this.logger.addLog('Generando reporte...', 'info');
        await this.sleep(1500);
        this.logger.addLog(`Vulnerabilidades encontradas: ${this.stats.vulnerabilitiesFound}`, 'info');
        this.logger.addLog(`Endpoints analizados: ${this.stats.endpointsDiscovered}`, 'info');
        this.logger.addLog(`Parámetros testeados: ${this.stats.parametersFound}`, 'info');
        await this.sleep(1000);
        this.logger.addLog('Reporte generado exitosamente', 'success');
    }

    answerQuestion(answer) {
        this.questionHandler.answerQuestion(answer);
    }

    pause() {
        if (this.isStopped) return;
        
        this.stopAutoSave();
        this.isPaused = true;
        this.questionHandler.isPaused = true;
        
        // Save progress when pausing
        this.saveProgress().catch(err => {
            this.logger.addLog(`Error guardando progreso al pausar: ${err.message}`, 'warning');
        });
        
        // Actualizar estado a pausado en BD
        Scan.Model.findByIdAndUpdate(this.scanId, { estado: 'pendiente' }).catch(err => {
            debug('Error actualizando estado a pausado (pendiente):', err);
        });
        
        this.logger.addLog('Escaneo pausado por el usuario', 'warning');
        this.emit('scan:paused', { scanId: this.scanId });
    }

    resume() {
        if (this.isStopped) return;
        
        this.isPaused = false;
        this.questionHandler.isPaused = false;
        this.startAutoSave();
        if (this.questionHandler.pauseResolver) {
            this.questionHandler.pauseResolver();
            this.questionHandler.pauseResolver = null;
        }
        this.logger.addLog('Escaneo reanudado', 'info');
        this.emit('scan:resumed', { scanId: this.scanId });
    }

    stop() {
        if (this.isStopped) return;
        
        this.stopAutoSave();
        
        // Save progress before stopping
        this.saveProgress().catch(err => {
            this.logger.addLog(`Error guardando progreso al detener: ${err.message}`, 'warning');
        });
        
        this.isStopped = true;
        this.isPaused = false;
        this.questionHandler.isPaused = false;
        if (this.questionHandler.pauseResolver) {
            this.questionHandler.pauseResolver();
            this.questionHandler.pauseResolver = null;
        }
        
        this.logger.addLog('Escaneo detenido por el usuario', 'warning');
        this.killAllProcesses();
        this.emit('scan:stopped', { scanId: this.scanId });
    }

    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    getStatus() {
        return {
            scanId: this.scanId,
            currentPhase: this.currentPhase,
            currentSubphase: this.currentSubphase,
            isPaused: this.questionHandler.isCurrentlyPaused(),
            phases: this.phases,
            completedPhases: this.completedPhases,
            completedSubphases: this.completedSubphases,
            askedPhases: Array.from(this.questionHandler.askedPhases),
            discoveredEndpoints: this.discoveredEndpoints,
            vulnerabilities: this.vulnerabilities,
            questionResults: this.questionResults,
            stats: this.stats,
            logs: this.logger.getRecentLogs(50)
        };
    }
}

module.exports = ScanOrchestrator;
