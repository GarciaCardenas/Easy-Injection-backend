class SQLiPhase {
    constructor(config, sqlmapExecutor, logger, questionHandler, discoveredParameters, vulnerabilities, stats, emitter) {
        this.config = config;
        this.sqlmapExecutor = sqlmapExecutor;
        this.logger = logger;
        this.questionHandler = questionHandler;
        this.discoveredParameters = discoveredParameters;
        this.vulnerabilities = vulnerabilities;
        this.stats = stats;
        this.emitter = emitter;
    }

    async run() {
        const subphases = ['detection', 'fingerprint', 'technique', 'exploit'];
        
        for (const subphaseId of subphases) {
            const subphaseFullId = `sqli-${subphaseId}`;
            
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
            detection: { name: 'Detección de vulnerabilidad', handler: () => this.detectSQLi() },
            fingerprint: { name: 'Fingerprinting', handler: () => this.fingerprintDatabase() },
            technique: { name: 'Selección de técnica', handler: () => this.selectTechnique() },
            exploit: { name: 'Explotación (POC)', handler: () => this.exploitSQLi() }
        };

        const subphase = subphases[subphaseId];
        if (!subphase) return;

        const subphaseFullId = `sqli-${subphaseId}`;
        
        // Update current subphase in orchestrator
        if (this.emitter.setCurrentSubphase) {
            this.emitter.setCurrentSubphase(subphaseFullId);
        }
        
        this.logger.setCurrentPhase(subphaseFullId);
        this.logger.addLog(`SQLi - ${subphase.name}`, 'info', subphaseFullId);
        this.emitter.emit('subphase:started', { 
            phase: 'sqli', 
            subphase: subphaseId, 
            name: subphase.name 
        });

        await subphase.handler();

        this.emitter.emit('subphase:completed', { 
            phase: 'sqli', 
            subphase: subphaseId, 
            name: subphase.name 
        });
        
        // Clear current subphase after completion
        if (this.emitter.setCurrentSubphase) {
            this.emitter.setCurrentSubphase(null);
        }
        
        this.logger.setCurrentPhase('sqli');
    }

    async detectSQLi() {
        await this.questionHandler.waitIfPaused();
        
        await this.questionHandler.askQuestion(null, 'sqli-detection');
        
        await this.questionHandler.waitIfPaused();

        const testableParams = this.discoveredParameters.filter(p => p.testable);
        
        if (testableParams.length === 0) {
            this.logger.addLog('No hay parámetros para testear', 'warning');
            return;
        }

        const paramsByEndpoint = new Map();
        for (const param of testableParams) {
            if (!paramsByEndpoint.has(param.endpoint)) {
                paramsByEndpoint.set(param.endpoint, []);
            }
            paramsByEndpoint.get(param.endpoint).push(param);
        }

        this.logger.addLog(`Testeando SQLi en ${paramsByEndpoint.size} endpoint(s) con ${testableParams.length} parámetro(s) total`, 'info');

        for (const [endpoint, params] of paramsByEndpoint.entries()) {
            await this.questionHandler.waitIfPaused();
            
            // Check if this endpoint was already tested
            const endpointObj = { method: 'GET', url: endpoint }; // Assuming GET, adjust if needed
            if (this.emitter.isEndpointTestedForSqli && this.emitter.isEndpointTestedForSqli(endpointObj)) {
                this.logger.addLog(`Omitiendo ${endpoint} - ya fue testeado para SQLi`, 'info');
                continue;
            }
            
            this.logger.addLog(`Testeando SQLi en ${endpoint} con parámetros: ${params.map(p => p.name).join(', ')}`, 'info');
            
            try {
                await this.sqlmapExecutor.testEndpoint(endpoint, params, 'detection', (vuln) => {
                    // Call orchestrator's addVulnerability directly
                    this.emitter.addVulnerability(vuln);
                });
                
                // Mark endpoint as tested
                if (this.emitter.markEndpointTestedForSqli) {
                    this.emitter.markEndpointTestedForSqli(endpointObj);
                }
            } catch (error) {
                this.logger.addLog(`Error testeando endpoint ${endpoint}: ${error.message}`, 'warning');
            }
        }
    }

    async fingerprintDatabase() {
        await this.questionHandler.waitIfPaused();
        
        await this.questionHandler.askQuestion(null, 'sqli-fingerprint');
        
        await this.questionHandler.waitIfPaused();

        this.logger.addLog('Ejecutando fingerprinting de la base de datos...', 'info');
        
        // Buscar un parámetro vulnerable de SQLi
        const sqlVuln = this.vulnerabilities.find(v => v.type === 'SQLi');
        
        if (!sqlVuln) {
            this.logger.addLog('No hay vulnerabilidades SQLi detectadas para fingerprinting', 'info');
            return;
        }
        
        // Buscar el parámetro correspondiente en discoveredParameters
        const param = this.discoveredParameters.find(p => 
            p.endpoint === sqlVuln.endpoint && p.name === sqlVuln.parameter
        );
        
        if (!param) {
            this.logger.addLog(`No se encontró información del parámetro vulnerable ${sqlVuln.parameter}`, 'warning');
            return;
        }
        
        this.logger.addLog(`Ejecutando fingerprinting en ${param.endpoint} (parámetro: ${param.name})`, 'info');
        
        try {
            await this.sqlmapExecutor.testParameter(param, 'fingerprint');
        } catch (error) {
            this.logger.addLog(`Error en fingerprinting: ${error.message}`, 'warning');
        }
    }

    async selectTechnique() {
        await this.questionHandler.waitIfPaused();
        
        this.logger.addLog('Analizando técnicas de inyección detectadas...', 'info');
        
        const techniques = [];
        for (const vuln of this.vulnerabilities.filter(v => v.type === 'SQLi')) {
            if (vuln.description.match(/boolean/i)) techniques.push('Boolean-based blind');
            if (vuln.description.match(/union/i)) techniques.push('UNION query');
            if (vuln.description.match(/time/i)) techniques.push('Time-based blind');
            if (vuln.description.match(/error/i)) techniques.push('Error-based');
        }
        
        const uniqueTechniques = [...new Set(techniques)];
        
        if (uniqueTechniques.length > 0) {
            this.logger.addLog(`Técnicas disponibles: ${techniques.join(', ')}`, 'info');
            this.logger.addLog(`Técnica óptima: ${uniqueTechniques[0]}`, 'success');
        } else {
            this.logger.addLog('No se detectaron técnicas específicas', 'info');
        }
    }

    async exploitSQLi() {
        await this.questionHandler.waitIfPaused();
        
        await this.questionHandler.askQuestion(null, 'sqli-exploit');
        
        await this.questionHandler.waitIfPaused();

        if (!this.config.enableExploitation) {
            this.logger.addLog('⚠ Explotación deshabilitada por configuración (modo seguro)', 'warning');
            this.logger.addLog('Solo se genera Proof of Concept teórico', 'info');
            return;
        }

        this.logger.addLog('Generando POC (Proof of Concept) - Solo lectura', 'info');
        
        // Buscar un parámetro vulnerable de SQLi
        const sqlVuln = this.vulnerabilities.find(v => v.type === 'SQLi');
        
        if (!sqlVuln) {
            this.logger.addLog('No hay vulnerabilidades SQLi detectadas para explotar', 'info');
            return;
        }
        
        // Buscar el parámetro correspondiente en discoveredParameters
        const param = this.discoveredParameters.find(p => 
            p.endpoint === sqlVuln.endpoint && p.name === sqlVuln.parameter
        );
        
        if (!param) {
            this.logger.addLog(`No se encontró información del parámetro vulnerable ${sqlVuln.parameter}`, 'warning');
            return;
        }
        
        this.logger.addLog(`Generando POC en ${param.endpoint} (parámetro: ${param.name})`, 'info');
        
        try {
            await this.sqlmapExecutor.testParameter(param, 'exploit');
            this.logger.addLog('POC completado - Información básica extraída', 'success');
        } catch (error) {
            this.logger.addLog(`Error en explotación: ${error.message}`, 'warning');
        }
    }
}

module.exports = SQLiPhase;

