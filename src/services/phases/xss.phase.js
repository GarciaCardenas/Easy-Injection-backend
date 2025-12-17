const debug = require('debug')('easyinjection:scan:xss-phase');

class XSSPhase {
    constructor(config, dalfoxExecutor, logger, questionHandler, discoveredParameters, vulnerabilities, stats, emitter) {
        this.config = config;
        this.dalfoxExecutor = dalfoxExecutor;
        this.logger = logger;
        this.questionHandler = questionHandler;
        this.discoveredParameters = discoveredParameters;
        this.vulnerabilities = vulnerabilities;
        this.stats = stats;
        this.emitter = emitter;
    }

    async run() {
        const subphases = ['context', 'payload', 'fuzzing'];
        
        for (const subphaseId of subphases) {
            const subphaseFullId = `xss-${subphaseId}`;
            
            // Skip if subphase already completed
            if (this.emitter.completedSubphases && this.emitter.completedSubphases.includes(subphaseFullId)) {
                this.logger.addLog(`Subfase ${subphaseFullId} ya completada, omitiendo...`, 'info');
                continue;
            }
            
            await this.runSubphase(subphaseId);
        }
    }

    async runSubphase(subphaseId) {
        const subphases = {
            context: { name: 'Análisis de contexto', handler: () => this.analyzeXSSContext() },
            payload: { name: 'Generación de payloads', handler: () => this.generateXSSPayloads() },
            fuzzing: { name: 'Motor de fuzzing', handler: () => this.runXSSFuzzing() }
        };

        const subphase = subphases[subphaseId];
        if (!subphase) return;

        const subphaseFullId = `xss-${subphaseId}`;
        
        // Update current subphase in orchestrator
        if (this.emitter.setCurrentSubphase) {
            this.emitter.setCurrentSubphase(subphaseFullId);
        }
        
        this.logger.setCurrentPhase(subphaseFullId);
        this.logger.addLog(`XSS - ${subphase.name}`, 'info', subphaseFullId);
        this.emitter.emit('subphase:started', { 
            phase: 'xss', 
            subphase: subphaseId, 
            name: subphase.name 
        });

        await subphase.handler();

        this.emitter.emit('subphase:completed', { 
            phase: 'xss', 
            subphase: subphaseId, 
            name: subphase.name 
        });
        
        // Clear current subphase after completion
        if (this.emitter.setCurrentSubphase) {
            this.emitter.setCurrentSubphase(null);
        }
        
        this.logger.setCurrentPhase('xss');
    }

    async analyzeXSSContext() {
        await this.questionHandler.waitIfPaused();
        
        await this.questionHandler.askQuestion(null, 'xss-context');
        
        await this.questionHandler.waitIfPaused();

        this.logger.addLog('Analizando contextos de inyección con Dalfox...', 'info');
        this.logger.addLog('Preparando análisis de contextos HTML, JS y atributos...', 'info');
    }

    async generateXSSPayloads() {
        await this.questionHandler.waitIfPaused();
        
        this.logger.addLog('Generando payloads XSS con Dalfox...', 'info');
        this.logger.addLog('Payloads adaptados para múltiples contextos', 'info');
    }

    async runXSSFuzzing() {
        await this.questionHandler.waitIfPaused();
        
        await this.questionHandler.askQuestion(null, 'xss-fuzzing');
        
        await this.questionHandler.waitIfPaused();

        const testableParams = this.discoveredParameters.filter(p => p.testable);
        
        if (testableParams.length === 0) {
            this.logger.addLog('No hay parámetros para testear XSS', 'warning');
            return;
        }
        
        const testedUrls = new Set();
        
        for (const param of testableParams) {
            await this.questionHandler.waitIfPaused();
            
            if (!testedUrls.has(param.endpoint)) {
                testedUrls.add(param.endpoint);
                
                // Check if this endpoint was already tested
                const endpointObj = { method: 'GET', url: param.endpoint };
                if (this.emitter.isEndpointTestedForXss && this.emitter.isEndpointTestedForXss(endpointObj)) {
                    this.logger.addLog(`Omitiendo ${param.endpoint} - ya fue testeado para XSS`, 'info');
                    continue;
                }
                
                this.logger.addLog(`Fuzzing XSS en ${param.endpoint}`, 'info');
                
                try {
                    debug('Llamando a dalfoxExecutor.scanUrl con callback...');
                    debug('Endpoint:', param.endpoint);
                    debug('Callback definido?', true);
                    
                    await this.dalfoxExecutor.scanUrl(param.endpoint, async (vuln) => {
                        debug('[CALLBACK XSS] Vulnerabilidad recibida en callback');
                        debug('[CALLBACK XSS] Vulnerabilidad:', JSON.stringify(vuln));
                        debug('[CALLBACK XSS] this.emitter existe?', !!this.emitter);
                        debug('[CALLBACK XSS] this.emitter.addVulnerability existe?', !!(this.emitter && this.emitter.addVulnerability));
                        
                        debug(`[XSS] Vulnerabilidad detectada:`);
                        debug(`  - Endpoint: ${vuln.endpoint}`);
                        debug(`  - Parámetro: ${vuln.parameter}`);
                        debug(`  - Severidad: ${vuln.severity}`);
                        debug(`  - Descripción: ${vuln.description}`);
                        
                        // Call orchestrator's addVulnerability directly and WAIT for it
                        debug('[CALLBACK XSS] Llamando a this.emitter.addVulnerability...');
                        await this.emitter.addVulnerability(vuln);
                        debug('[CALLBACK XSS] addVulnerability ejecutado');
                    });
                    
                    debug('dalfoxExecutor.scanUrl completado');
                    
                    // Mark endpoint as tested AFTER scanUrl completes (including all callbacks)
                    if (this.emitter.markEndpointTestedForXss) {
                        this.emitter.markEndpointTestedForXss(endpointObj);
                    }
                } catch (error) {
                    this.logger.addLog(`Error en fuzzing XSS: ${error.message}`, 'warning');
                }
            }
        }
    }
}

module.exports = XSSPhase;

