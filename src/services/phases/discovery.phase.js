const fs = require('fs');
const path = require('path');

class DiscoveryPhase {
    constructor(config, sqlmapExecutor, logger, questionHandler, emitter) {
        this.config = config;
        this.sqlmapExecutor = sqlmapExecutor;
        this.logger = logger;
        this.questionHandler = questionHandler;
        this.emitter = emitter;
        this.discoveredEndpoints = [];
        this.discoveredParameters = [];
    }

    async run() {
        await this.questionHandler.waitIfPaused();
        await this.questionHandler.askQuestion(null, 'discovery');
        await this.questionHandler.waitIfPaused();

        const crawlerFinishedHandler = (data) => {
            this.processCrawlResults(data).catch(error => {
                this.logger.addLog(`Error procesando resultados: ${error.message}`, 'error');
            });
        };
        
        this.emitter.once('crawler:finished', crawlerFinishedHandler);

        try {
            await this.sqlmapExecutor.runCrawl();
            
            if (this.discoveredEndpoints.length === 0 && this.discoveredParameters.length === 0) {
                await new Promise(resolve => setTimeout(resolve, 5000));
                
                let csvPath = null;
                for (let attempt = 0; attempt < 3; attempt++) {
                    csvPath = await this.sqlmapExecutor.findCrawlCsv(this.sqlmapExecutor.tmpDir);
                    if (csvPath) {
                        await this.processCrawlResults({ csvPath });
                        break;
                    }
                    await new Promise(resolve => setTimeout(resolve, 2000));
                }
                
                if (!csvPath) {
                    this.logger.addLog('⚠ No se pudo encontrar el CSV después de múltiples intentos', 'warning');
                }
            }
            
            if (this.discoveredEndpoints.length === 0) {
                this.logger.addLog('No se encontraron endpoints adicionales, usando URL base', 'info');
                const baseEndpoint = {
                    url: this.config.url,
                    method: 'GET',
                    parameters: []
                };
                this.addEndpoint(baseEndpoint);
            }
            
            this.logger.addLog(`✓ Descubrimiento completado: ${this.discoveredEndpoints.length} endpoint(s) y ${this.discoveredParameters.length} parámetro(s)`, 'success');
        } catch (error) {
            this.logger.addLog(`Error en descubrimiento: ${error.message}`, 'error');
            const baseEndpoint = {
                url: this.config.url,
                method: 'GET',
                parameters: []
            };
            this.addEndpoint(baseEndpoint);
        } finally {
            this.emitter.removeListener('crawler:finished', crawlerFinishedHandler);
        }

        return {
            endpoints: this.discoveredEndpoints,
            parameters: this.discoveredParameters
        };
    }

    async processCrawlResults(data) {
        const { csvPath } = data;
        
        if (!csvPath || !fs.existsSync(csvPath)) {
            this.logger.addLog('⚠ CSV de crawling no encontrado', 'warning');
            return;
        }

        try {
            const result = await this.sqlmapExecutor.processCrawlCsvToEndpointsAndParams(csvPath);
            
            const targetsResult = await this.sqlmapExecutor._processCrawlCsvToTargets(csvPath);
            
            for (const endpoint of result.endpoints) {
                this.addEndpoint(endpoint);
            }
            
            for (const param of result.parameters) {
                this.addParameter(param);
            }
            
            console.log(`✓ Procesados ${result.endpoints.length} endpoint(s) y ${result.parameters.length} parámetro(s) del CSV`, 'success');
            
            if (targetsResult) {
                console.log(`✓ Archivos targets.txt generados: ${targetsResult.getCount} GET, ${targetsResult.postCount} POST`, 'debug');
            }
        } catch (error) {
            console.log(`Error procesando CSV: ${error.message}`, 'error');
            throw error;
        }
    }

    addEndpoint(endpoint) {
        if (!this.discoveredEndpoints.some(e => e.url === endpoint.url && e.method === endpoint.method)) {
            this.discoveredEndpoints.push(endpoint);
            
            if (this.emitter) {
                this.emitter.emit('endpoint:discovered', endpoint);
            }
            
            this.logger.addLog(`Endpoint descubierto: ${endpoint.method} ${endpoint.url}`, 'success');
            return true;
        }
        return false;
    }

    addParameter(param) {
        if (!this.discoveredParameters.some(p => 
            p.endpoint === param.endpoint && p.name === param.name
        )) {
            this.discoveredParameters.push(param);
            
            if (this.emitter) {
                this.emitter.emit('parameter:discovered', param);
            }
            
            return true;
        }
        return false;
    }
}

module.exports = DiscoveryPhase;
