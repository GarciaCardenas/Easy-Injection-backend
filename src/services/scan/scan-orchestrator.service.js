const EventEmitter = require('events');
const path = require('path');
const os = require('os');
const fs = require('fs');

const { validateAndNormalizeConfig } = require('./config-validator.service');
const Logger = require('./logger.service');
const QuestionHandler = require('./question-handler.service');
const SqlmapExecutor = require('./sqlmap-executor.service');
const DalfoxExecutor = require('./dalfox-executor.service');
const DiscoveryPhase = require('../phases/discovery.phase');
const SQLiPhase = require('../phases/sqli.phase');
const XSSPhase = require('../phases/xss.phase');

class ScanOrchestrator extends EventEmitter {
    constructor(scanId, scanConfig) {
        super();
        
        try {
            this.config = validateAndNormalizeConfig(scanConfig);
        } catch (error) {
            throw new Error(`Invalid configuration: ${error.message}`);
        }
        
        this.scanId = scanId;
        this.currentPhase = null;
        this.discoveredEndpoints = [];
        this.discoveredParameters = [];
        this.vulnerabilities = [];
        this.questionResults = [];
        this.activeProcesses = new Map();
        this.isPaused = false;
        this.isStopped = false;
        
        this.stats = {
            totalRequests: 0,
            vulnerabilitiesFound: 0,
            endpointsDiscovered: 0,
            parametersFound: 0
        };
        
        const outputDir = path.join(os.tmpdir(), 'easyinjection_scans', `scan_${scanId}`);
        if (!fs.existsSync(outputDir)) {
            fs.mkdirSync(outputDir, { recursive: true });
        }
        
        this.config.outputDir = outputDir;
        this.config.tmpDir = path.join(os.tmpdir(), 'easyinjection_sqlmap_tmp');
        
        this.logger = new Logger(this);
        this.questionHandler = new QuestionHandler(this, this.logger);
        
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
            { id: 'init', name: 'Inicialización', status: 'pending' },
            { id: 'discovery', name: 'Descubrimiento de endpoints y parámetros', status: 'pending' },
            { id: 'sqli', name: 'Pruebas SQL Injection', status: 'pending', subphases: [
                { id: 'detection', name: 'Detección de vulnerabilidad', status: 'pending' },
                { id: 'fingerprint', name: 'Fingerprinting', status: 'pending' },
                { id: 'technique', name: 'Selección de técnica', status: 'pending' },
                { id: 'exploit', name: 'Explotación (POC)', status: 'pending' }
            ]},
            { id: 'xss', name: 'Pruebas XSS', status: 'pending', subphases: [
                { id: 'context', name: 'Análisis de contexto', status: 'pending' },
                { id: 'payload', name: 'Generación de payloads', status: 'pending' },
                { id: 'fuzzing', name: 'Motor de fuzzing', status: 'pending' }
            ]},
            { id: 'report', name: 'Generación de reporte', status: 'pending' }
        ];
    }
    
    async start() {
        try {
            this.isStopped = false;
            this.isPaused = false;
            this.emit('scan:started', { scanId: this.scanId });
            
            if (this.isStopped) return;
            await this.runPhase('init');
            
            if (this.isStopped) return;
            await this.runPhase('discovery');
            
            if (this.config.flags.sqli && !this.isStopped) {
                await this.runPhase('sqli');
            }
            
            if (this.config.flags.xss && !this.isStopped) {
                await this.runPhase('xss');
            }
            
            if (!this.isStopped) {
                await this.waitForAllProcesses();
                await this.runPhase('report');
            }
            
            if (!this.isStopped) {
                this.emit('scan:completed', { 
                    scanId: this.scanId,
                    vulnerabilities: this.vulnerabilities,
                    questionResults: this.questionResults,
                    stats: this.stats
                });
            }
        } catch (error) {
            if (!this.isStopped) {
                this.logger.addLog(`Error crítico: ${error.message}`, 'error');
                this.emit('scan:error', { scanId: this.scanId, error: error.message });
            }
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

    async runPhase(phaseId) {
        if (this.isStopped) return;
        
        const phase = this.phases.find(p => p.id === phaseId);
        if (!phase) return;

        this.currentPhase = phaseId;
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
            this.emit('phase:completed', { phase: phaseId, name: phase.name });
            this.logger.addLog(`Fase completada: ${phase.name}`, 'success', phaseId);
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

    addVulnerability(vuln) {
        if (!this.vulnerabilities.some(v => 
            v.type === vuln.type && 
            v.endpoint === vuln.endpoint && 
            v.parameter === vuln.parameter
        )) {
            this.vulnerabilities.push(vuln);
            this.stats.vulnerabilitiesFound++;
            this.emit('vulnerability:found', vuln);
            this.logger.addLog(`Vulnerabilidad encontrada: ${vuln.type} en ${vuln.endpoint}`, 'success');
        }
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

    async generateReport() {
        await this.sleep(1500);
        this.logger.addLog('Generating final report...', 'info');
        this.logger.addLog(`Vulnerabilities found: ${this.stats.vulnerabilitiesFound}`, 'info');
        this.logger.addLog(`Endpoints analyzed: ${this.stats.endpointsDiscovered}`, 'info');
        this.logger.addLog(`Parameters tested: ${this.stats.parametersFound}`, 'info');
        await this.sleep(1000);
        this.logger.addLog('Report generated successfully', 'success');
    }

    answerQuestion(answer) {
        this.questionHandler.answerQuestion(answer);
    }

    pause() {
        if (this.isStopped) return;
        
        this.isPaused = true;
        this.questionHandler.isPaused = true;
        this.logger.addLog('Escaneo pausado por el usuario', 'warning');
        this.emit('scan:paused', { scanId: this.scanId });
    }

    resume() {
        if (this.isStopped) return;
        
        this.isPaused = false;
        this.questionHandler.isPaused = false;
        if (this.questionHandler.pauseResolver) {
            this.questionHandler.pauseResolver();
            this.questionHandler.pauseResolver = null;
        }
        this.logger.addLog('Escaneo reanudado', 'info');
        this.emit('scan:resumed', { scanId: this.scanId });
    }

    stop() {
        if (this.isStopped) return;
        
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
            isPaused: this.questionHandler.isCurrentlyPaused(),
            phases: this.phases,
            discoveredEndpoints: this.discoveredEndpoints,
            vulnerabilities: this.vulnerabilities,
            questionResults: this.questionResults,
            stats: this.stats,
            logs: this.logger.getRecentLogs(50)
        };
    }
}

module.exports = ScanOrchestrator;
