const { spawn } = require('child_process');
const debug = require('debug')('easyinjection:scan:dalfox');

class DalfoxExecutor {
    constructor(config, logger, emitter, activeProcesses) {
        this.config = config;
        this.logger = logger;
        this.emitter = emitter;
        this.activeProcesses = activeProcesses;
        
        this.toolConfig = {
            path: config.dalfoxPath || 'dalfox',
            commonArgs: ['--format', 'json', '--silence', '--no-color', '--skip-bav'],
            workers: config.dalfoxWorkers || 10,
            delay: config.dalfoxDelay || 0,
            timeout: config.timeout || 30
        };
    }

    async checkAvailability() {
        try {
            await this.runCommand(['version'], 5000);
            this.logger.addLog(`✓ dalfox disponible`, 'success');
            return true;
        } catch (error) {
            this.logger.addLog(`⚠ dalfox no encontrado. Instala con: go install github.com/hahwul/dalfox/v2@latest`, 'warning');
            return false;
        }
    }

    async scanUrl(url, onVulnerabilityFound) {
        const args = [
            'url',
            url,
            ...this.toolConfig.commonArgs,
            '--worker', this.toolConfig.workers.toString()
        ];

        if (this.toolConfig.delay > 0) {
            args.push('--delay', this.toolConfig.delay.toString());
        }

        if (this.config.headers) {
            for (const [key, value] of Object.entries(this.config.headers)) {
                args.push('--header', `${key}: ${value}`);
            }
        }

        if (this.config.customHeaders) {
            const headers = this.config.customHeaders.split('\n').filter(h => h.trim());
            headers.forEach(header => {
                args.push('--header', header.trim());
            });
        }

        this.logger.addLog(`Ejecutando: dalfox ${args.join(' ')}`, 'debug', null, true);

        return new Promise((resolve) => {
            const proc = spawn(this.toolConfig.path, args);
            const processKey = `dalfox-${url}`;
            this.activeProcesses.set(processKey, proc);

            let jsonBuffer = '';
            let processedVulnerabilities = new Set();
            let callbackPromises = []; // Track async callbacks

            let streamBuffer = '';

            proc.stdout.on('data', (data) => {
                const chunk = data.toString();
                process.stdout.write(`[dalfox stdout] ${chunk}`);
                streamBuffer += chunk;

                const objects = [];
                let depth = 0;
                let startIdx = -1;
                for (let i = 0; i < streamBuffer.length; i++) {
                    const ch = streamBuffer[i];
                    if (ch === '{') {
                        if (depth === 0) startIdx = i;
                        depth++;
                    } else if (ch === '}') {
                        depth--;
                        if (depth === 0 && startIdx !== -1) {
                            const objStr = streamBuffer.slice(startIdx, i + 1);
                            objects.push(objStr);
                            startIdx = -1;
                        }
                    }
                }

                if (objects.length > 0) {
                    const lastObj = objects[objects.length - 1];
                    const lastPos = streamBuffer.indexOf(lastObj) + lastObj.length;
                    streamBuffer = streamBuffer.slice(lastPos);
                }


                for (const [i, objText] of objects.entries()) {
                    const trimmed = objText.trim();
                    try {
                        const result = JSON.parse(trimmed);
                        debug('JSON parseado:', result);
                        debug('Tipo de resultado:', result.type);
                        
                        if (result.type === 'V' || result.type === 'POC' || result.type === 'VULN') {
                            debug('Vulnerabilidad detectada! Tipo:', result.type);
                            const vulnKey = `${result.param || 'unknown'}-${result.payload || 'unknown'}`;
                            debug('Clave de vulnerabilidad:', vulnKey);
                            
                            if (!processedVulnerabilities.has(vulnKey)) {
                                debug('Vulnerabilidad nueva, procesando...');
                                processedVulnerabilities.add(vulnKey);
                                const callbackResult = this._parseOutput(result, onVulnerabilityFound);
                                if (callbackResult && callbackResult.then) {
                                    callbackPromises.push(callbackResult);
                                }
                            } else {
                                debug('Vulnerabilidad duplicada, ignorando');
                            }
                        } else {
                            debug('Tipo de resultado no es vulnerabilidad:', result.type);
                        }
                    } catch (parseErr) {
                        debug('Error parseando JSON:', parseErr.message);
                    }
                }
            });

            proc.stderr.on('data', (data) => {
                const error = data.toString();
                
                process.stderr.write(`[dalfox stderr] ${error}`);
                
                const errorTrimmed = error.trim();
                
                if (!errorTrimmed) {
                    return;
                }
                
                if (errorTrimmed.includes('Loopback') || 
                    errorTrimmed.includes('could not unmarshal event') ||
                    errorTrimmed.includes('IPAddressSpace') ||
                    errorTrimmed.includes('unknown IPAddressSpace value')) {
                    return;
                }
                
                if (errorTrimmed.includes('ERROR:') || errorTrimmed.includes('FATAL:')) {
                    if (!errorTrimmed.match(/Loopback|IPAddressSpace|unmarshal/i)) {
                        this.logger.addLog(`dalfox stderr: ${errorTrimmed}`, 'warning');
                    } else {
                    }
                } else {
                    this.logger.addLog(`dalfox stderr: ${errorTrimmed}`, 'debug', null, true);
                }
            });

            proc.on('close', async (code) => {
                this.activeProcesses.delete(processKey);

                if (jsonBuffer.trim()) {
                    try {
                        const trimmed = jsonBuffer.trim();
                        if (trimmed.startsWith('{') && this._isVulnerabilityJson(trimmed)) {
                            const result = JSON.parse(trimmed);
                            if (result.type === 'V' || result.type === 'POC' || result.type === 'VULN') {
                                const vulnKey = `${result.param || 'unknown'}-${result.payload || 'unknown'}`;
                                if (!processedVulnerabilities.has(vulnKey)) {
                                    processedVulnerabilities.add(vulnKey);
                                    const callbackResult = this._parseOutput(result, onVulnerabilityFound);
                                    if (callbackResult && callbackResult.then) {
                                        callbackPromises.push(callbackResult);
                                    }
                                } else {
                                }
                            } else {
                            }
                        } else {
                        }
                    } catch (finalParseErr) {
                    }
                } else {
                }
                
                // Wait for all async callbacks to complete before resolving
                debug(`Esperando ${callbackPromises.length} callbacks asíncronos...`);
                await Promise.all(callbackPromises);
                debug('Todos los callbacks completados');
                
                resolve();
            });

            proc.on('error', (error) => {
                this.activeProcesses.delete(processKey);
                this.logger.addLog(`Error ejecutando dalfox: ${error.message}`, 'error');
                resolve();
            });

            setTimeout(() => {
                if (this.activeProcesses.has(processKey)) {
                    proc.kill('SIGTERM');
                    this.logger.addLog(`Timeout en fuzzing XSS para ${url}`, 'warning');
                    resolve();
                }
            }, this.toolConfig.timeout * 1000);
        });
    }

    _isVulnerabilityJson(line) {
        if (!line.startsWith('{')) return false;
        const match = /"type"\s*:\s*"(V|POC|VULN)"/.test(line);
        return match;
    }

    _cleanEndpointUrl(url) {
        try {
            // Eliminar parámetros de query string
            const urlObj = new URL(url);
            return `${urlObj.protocol}//${urlObj.host}${urlObj.pathname}`;
        } catch (e) {
            // Si no es una URL válida, intentar remover todo después de '?'
            const questionMarkIndex = url.indexOf('?');
            if (questionMarkIndex !== -1) {
                return url.substring(0, questionMarkIndex);
            }
            return url;
        }
    }

    _parseOutput(result, onVulnerabilityFound) {
        const vulnType = result.type;
        
        debug('_parseOutput llamado con resultado tipo:', vulnType);
        debug('Resultado completo:', JSON.stringify(result));

        if (vulnType === 'V' || vulnType === 'POC' || vulnType === 'VULN') {
            debug('Es una vulnerabilidad confirmada, procesando...');
            let endpoint = 'unknown';
            
            if (result.data) {
                if (typeof result.data === 'string') {
                    endpoint = result.data;
                } else if (typeof result.data === 'object' && result.data.url) {
                    endpoint = result.data.url;
                } else if (typeof result.data === 'object' && result.data.target) {
                    endpoint = result.data.target;
                }
            }
            
            if (endpoint === 'unknown' && result.url) {
                endpoint = result.url;
            }
            
            if (endpoint === 'unknown') {
                const jsonStr = JSON.stringify(result);
                const urlMatch = jsonStr.match(/https?:\/\/[^\s"]+/);
                if (urlMatch) {
                    endpoint = urlMatch[0];
                }
            }
            
            // Limpiar endpoint para mostrar solo la URL base sin parámetros
            const cleanEndpoint = this._cleanEndpointUrl(endpoint);
            
            const param = result.param || result.data?.param || 'unknown';
            const payload = result.payload || result.data?.payload || 'detected';
            const injectType = result.inject_type || result.data?.inject_type || '';
            const method = result.method || result.data?.method || 'GET';
            
            // Traducir el tipo de XSS
            const xssTypeInfo = this._translateXSSType(injectType);
            const xssTypeSpanish = xssTypeInfo.context || 'Cross-Site Scripting';
            const paramMethod = xssTypeInfo.method || (method === 'POST' ? 'POST' : 'GET');
            
            debug('xssTypeInfo:', xssTypeInfo);
            debug('xssTypeSpanish:', xssTypeSpanish);
            debug('paramMethod:', paramMethod);
            
            // Construir descripción según el nuevo formato usando el endpoint limpio
            let description = `El endpoint ${cleanEndpoint} presenta una vulnerabilidad Cross-Site Scripting (XSS) de tipo ${xssTypeSpanish}, debido a una sanitización insuficiente de los datos proporcionados por el usuario. Durante el análisis se comprobó que el parámetro ${param} de tipo ${paramMethod} acepta contenido malicioso que posteriormente es reflejado o almacenado en la aplicación, permitiendo la ejecución arbitraria de JavaScript en el navegador.\n\n`;
            
            description += `La validación y neutralización del contenido no confiable es insuficiente, lo que permite al atacante ejecutar código arbitrario JavaScript y potencialmente realizar ataques del lado del cliente, incluyendo secuestro de sesiones de usuario, redirección maliciosa o manipulación del DOM. Dalfox identificó el punto de inyección, y la siguiente prueba de concepto confirma la vulnerabilidad:\n\n`;
            
            description += `Prueba de concepto (PoC):\n${payload}`;

            const vuln = {
                type: 'XSS',
                severity: this._mapSeverity(result.severity || 'medium'),
                endpoint: cleanEndpoint,
                parameter: param,
                description: description,
                payload: payload,
                xssType: xssTypeSpanish,
                subtype: xssTypeInfo.context, // Usar el contexto como subtipo
                method: paramMethod
            };

            this.logger.addLog(`✓ XSS detectado: ${cleanEndpoint} - Parámetro: ${param}`, 'success');
            this.logger.addLog(`  Tipo: ${xssTypeSpanish} | Severidad: ${vuln.severity} | Método: ${paramMethod}`, 'info');
            this.logger.addLog(`  Payload: ${payload.substring(0, 50)}${payload.length > 50 ? '...' : ''}`, 'info');

            debug('=== VULNERABILIDAD XSS DETECTADA ===');
            debug('Vulnerabilidad parseada:', JSON.stringify(vuln));
            debug('onVulnerabilityFound existe?', !!onVulnerabilityFound);
            debug('onVulnerabilityFound tipo:', typeof onVulnerabilityFound);

            if (onVulnerabilityFound) {
                try {
                    debug('Llamando a onVulnerabilityFound callback...');
                    const result = onVulnerabilityFound(vuln);
                    debug('Callback ejecutado exitosamente');
                    // Return the result in case it's a promise
                    return result;
                } catch (cbErr) {
                    debug('ERROR EN CALLBACK onVulnerabilityFound:', cbErr);
                    debug('Error message:', cbErr.message);
                    debug('Error stack:', cbErr.stack);
                }
            } else {
                debug('WARNING: onVulnerabilityFound es null/undefined, no se puede notificar vulnerabilidad');
            }
        } else if (result.type === 'GREP' || result.type === 'INFO') {
            if (result.message && !result.message.match(/Loopback|IPAddressSpace/i)) {
                this.logger.addLog(result.message, 'debug', null, true);
            }
        } else {
        }
    }

    _translateXSSType(injectType) {
        // Si viene en formato [inHTML-URL] o [inJS-single-FORM]
        let cleanType = injectType.replace(/[\[\]]/g, '').trim();
        
        // Separar el contexto del método
        const parts = cleanType.split('-');
        let context = '';
        let method = '';
        
        // Detectar el prefijo (inHTML, inJS, inATTR)
        const prefix = parts[0];
        
        // Simplificado a solo 3 categorías
        if (prefix === 'inHTML') {
            context = 'Inyección en contenido HTML';
        } else if (prefix === 'inJS') {
            context = 'Inyección en contenido JavaScript';
        } else if (prefix === 'inATTR') {
            context = 'Inyección en atributo HTML';
        } else {
            context = 'Cross-Site Scripting';
        }
        
        // Extraer método si existe (URL o FORM)
        if (parts.length >= 2) {
            const lastPart = parts[parts.length - 1];
            if (lastPart === 'URL' || lastPart === 'FORM') {
                method = lastPart;
            }
        }
        
        return { context, method };
    }

    _mapSeverity(dalfoxSeverity) {
        const severity = dalfoxSeverity.toLowerCase();
        if (severity.includes('critical') || severity.includes('high')) {
            return 'high';
        } else if (severity.includes('medium')) {
            return 'medium';
        } else {
            return 'low';
        }
    }

    async runCommand(args, timeout = 30000) {
        return new Promise((resolve, reject) => {
            const proc = spawn(this.toolConfig.path, args);
            const timer = setTimeout(() => {
                try { proc.kill(); } catch (e) {}
                reject(new Error('Command timeout'));
            }, timeout);

            proc.on('close', (code) => {
                clearTimeout(timer);
                if (code === 0) resolve();
                else reject(new Error(`Command failed with code ${code}`));
            });

            proc.on('error', (error) => {
                clearTimeout(timer);
                reject(error);
            });
        });
    }
}

module.exports = DalfoxExecutor;
