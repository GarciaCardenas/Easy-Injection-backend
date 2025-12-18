const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');
const debug = require('debug')('easyinjection:scan:sqlmap');
const os = require('os');

class SqlmapExecutor {
    constructor(config, logger, emitter, activeProcesses) {
        this.config = config;
        this.logger = logger;
        this.emitter = emitter;
        this.activeProcesses = activeProcesses;
        
        this.toolConfig = {
            path: config.sqlmapPath || 'sqlmap',
            commonArgs: [
                '--batch',
                '--random-agent'
            ],
            crawlDepth: config.crawlDepth || 2,
            level: config.level || 1,
            risk: config.risk || 1,
            threads: config.threads || 1,
            timeout: config.timeout || 90
        };

        this.tmpDir = config.tmpDir || path.join(os.tmpdir(), 'easyinjection_sqlmap_tmp');
        this.outputDir = config.outputDir || null;
        this.reportedVulnerabilities = new Set(); // Track vulnerabilidades ya reportadas
    }

    async checkAvailability() {
        try {
            const result = await this.runCommand(['--version'], 5000);
            this.logger.addLog(`✓ sqlmap disponible: ${result.stdout?.slice(0,14)}`, 'success');
            return true;
        } catch (error) {
            debug('ERROR en checkAvailability:', error);
            debug('Error message:', error.message);
            debug('Tool path:', this.toolConfig.path);
            this.logger.addLog(`⚠ sqlmap no encontrado. Asegúrate de que está instalado y en PATH`, 'warning');
            this.logger.addLog(`Ruta esperada: ${this.toolConfig.path}`, 'info');
            this.logger.addLog(`Detalles: ${error.message}`, 'error');
            if (error.stdout) this.logger.addLog(`stdout: ${error.stdout}`, 'debug');
            if (error.stderr) this.logger.addLog(`stderr: ${error.stderr}`, 'debug');
            return false;
        }
    }

    async _gracefulKill(proc, gracePeriod = 300) {
        try {
            proc.kill('SIGTERM');
            await new Promise(resolve => setTimeout(resolve, gracePeriod));
            
            if (!proc.killed && proc.exitCode === null) {
                proc.kill('SIGKILL');
                this.logger.addLog('Forzando terminación del proceso sqlmap', 'debug');
            }
        } catch (error) {
            debug('ERROR en _gracefulKill:', error);
            debug('Error message:', error.message);
            this.logger.addLog(`Error al terminar proceso: ${error.message}`, 'warning');
        }
    }

    _buildAnswersArg() {
        const answers = [
            'do you want to check for the existence of site\'s sitemap(.xml)=N',
            'do you want to normalize crawling results=Y',
            'do you want to store crawling results to a temporary file for eventual further processing with other tools=Y',
            'Do you want to skip further tests involving it?=n'
        ];
        return `--answers="${answers.join(',')}"`;
    }

    async runCrawl() {
        if (!fs.existsSync(this.tmpDir)) {
            fs.mkdirSync(this.tmpDir, { recursive: true });
        }

        const args = [
            '-u', this.config.url,
            '--crawl', this.toolConfig.crawlDepth.toString(),
            this._buildAnswersArg(),
            '--forms',
            ...this.toolConfig.commonArgs,
            '--threads', this.toolConfig.threads.toString(),
            '--tmp-dir', this.tmpDir,
            '-v', '1'
        ];

        this._addDbmsAndHeaders(args);

        // Log detallado solo en consola del servidor
        debug('\n[SQLmap Crawl] ===== COMANDO CRAWL =====');
        debug('[SQLmap Crawl] URL:', this.config.url);
        debug('[SQLmap Crawl] Profundidad:', this.toolConfig.crawlDepth);
        debug('[SQLmap Crawl] tmp-dir:', this.tmpDir);
        debug('[SQLmap Crawl] Args completos:', args);
        debug('[SQLmap Crawl] ====================================\n');

        return new Promise(async (resolve, reject) => {
            const { executable, args: spawnArgs, spawnOpts } = this.getSpawnCommandForTool(this.toolConfig.path, args);
            
            debug('[SQLmap Crawl Spawn] Ejecutable:', executable);
            debug('[SQLmap Crawl Spawn] Argumentos:', spawnArgs);
            debug('[SQLmap Crawl Spawn] Comando completo:', executable, spawnArgs.join(' '), '\n');
            const proc = spawn(executable, spawnArgs, spawnOpts);
            this.activeProcesses.set('sqlmap-crawl', proc);

            let buffer = '';
            let crawlFinished = false;
            let timeoutTimer = null;
            const finishPattern = /\[?\d{2}:\d{2}:\d{2}\]?.*\[INFO\]\s+found a total of \d+ targets/i;

            const processCrawlResults = async () => {
                if (crawlFinished) return;
                crawlFinished = true;

                if (timeoutTimer) {
                    clearTimeout(timeoutTimer);
                    timeoutTimer = null;
                }

                try {
                    await new Promise(resolve => setTimeout(resolve, 5000));

                    let csvPath = null;
                    for (let attempt = 0; attempt < 3; attempt++) {
                        csvPath = await this.findCrawlCsv(this.tmpDir);
                        if (csvPath) break;
                        await new Promise(resolve => setTimeout(resolve, 2000));
                    }
                    
                    if (!csvPath) {
                        this.logger.addLog(`⚠ No se encontró CSV de crawling en tmp-dir: ${this.tmpDir}`, 'warning');
                        this.emitter.emit('crawler:failed', { reason: 'CSV not found' });
                        resolve();
                        return;
                    }

                    this.emitter.emit('crawler:finished', { csvPath });
                    resolve();
                } catch (error) {
                    debug('ERROR procesando resultados del crawl:', error);
                    debug('Error message:', error.message);
                    debug('Error stack:', error.stack);
                    this.logger.addLog(`Error procesando resultados del crawl: ${error.message}`, 'error');
                    this.emitter.emit('crawler:failed', { reason: error.message });
                    reject(error);
                }
            };

            proc.stdout.on('data', (data) => {
                const output = data.toString();
                // Solo en consola del servidor
                debug(`[sqlmap crawl stdout] ${output}`);
                
                buffer += output;
                const lines = buffer.split('\n');
                buffer = lines.pop() || '';

                for (const line of lines) {
                    if (finishPattern.test(line) && !crawlFinished) {
                        this.logger.addLog('✓ Crawling completado, procesando resultados...', 'success');
                        setTimeout(() => {
                            this._gracefulKill(proc).then(() => processCrawlResults());
                        }, 1000);
                    }
                }
            });

            proc.stderr.on('data', (data) => {
                const error = data.toString();
                // Solo en consola del servidor
                debug(`[sqlmap crawl stderr] ${error}`);
            });

            proc.on('close', async (code) => {
                this.activeProcesses.delete('sqlmap-crawl');
                if (crawlFinished) return;

                if (code === 0 || code === null) {
                    await processCrawlResults();
                } else if (!crawlFinished) {
                    reject(new Error(`sqlmap crawl exited with code ${code}`));
                }
            });

            proc.on('error', (error) => {
                this.activeProcesses.delete('sqlmap-crawl');
                if (timeoutTimer) clearTimeout(timeoutTimer);
                reject(new Error(`Failed to start sqlmap: ${error.message}`));
            });

            timeoutTimer = setTimeout(async () => {
                if (this.activeProcesses.has('sqlmap-crawl') && !crawlFinished) {
                    await this._gracefulKill(proc);
                    this.logger.addLog(`Timeout de crawling alcanzado (${this.toolConfig.timeout} segundos), intentando procesar resultados...`, 'warning');
                    await processCrawlResults();
                }
            }, this.toolConfig.timeout * 1000);
        });
    }
    
    async findCrawlCsv(tmpDir) {
        try {
            if (!fs.existsSync(tmpDir)) {
                this.logger.addLog(`tmp-dir no existe: ${tmpDir}`, 'debug');
                return null;
            }

            const files = [];
            
            const searchDir = (dir, depth = 0) => {
                try {
                    if (depth > 5) return;
                    
                    const entries = fs.readdirSync(dir, { withFileTypes: true });
                    
                    for (const entry of entries) {
                        const fullPath = path.join(dir, entry.name);
                        
                        try {
                            if (entry.isDirectory()) {
                                searchDir(fullPath, depth + 1);
                            } else if (entry.isFile() && entry.name.endsWith('.csv')) {
                                const stats = fs.statSync(fullPath);
                                const oneHourAgo = Date.now() - (60 * 60 * 1000);
                                if (stats.mtime.getTime() > oneHourAgo) {
                                    files.push({ path: fullPath, mtime: stats.mtime });
                                }
                            }
                        } catch (entryError) {
                            debug('ERROR en searchDir entry processing:', entryError);
                            debug('Entry error:', entryError.message);
                            continue;
                        }
                    }
                } catch (error) {
                    debug('ERROR en searchDir:', error);
                    debug('Error message:', error.message);
                    debug('Dir:', dir);
                    this.logger.addLog(`Error buscando CSV en ${dir}: ${error.message}`, 'debug');
                }
            };

            searchDir(tmpDir);

            if (files.length === 0) {
                this.logger.addLog(`No se encontraron archivos CSV en ${tmpDir}`, 'debug');
                return null;
            }

            files.sort((a, b) => b.mtime - a.mtime);
            const selectedFile = files[0].path;
            return selectedFile;
        } catch (error) {
            debug('ERROR en findLatestCrawlCsv:', error);
            debug('Error message:', error.message);
            debug('Error stack:', error.stack);
            this.logger.addLog(`Error buscando CSV: ${error.message}`, 'error');
            return null;
        }
    }

    async processCrawlCsvToEndpointsAndParams(csvPath) {
        try {
            if (!fs.existsSync(csvPath)) {
                throw new Error(`CSV file not found: ${csvPath}`);
            }

            const csvContent = fs.readFileSync(csvPath, 'utf-8');
            const lines = csvContent.split('\n').map(l => l.trim()).filter(l => l);

            if (lines.length < 2) {
                throw new Error('CSV file has no data rows');
            }

            const dataLines = lines.slice(1);
            const endpoints = [];
            const parameters = [];
            const endpointMap = new Map();

            for (const line of dataLines) {
                const firstCommaIndex = line.indexOf(',');
                
                let url, method, postData;
                
                if (firstCommaIndex === -1) {
                    url = line.trim();
                    method = 'GET';
                    postData = null;
                } else {
                    url = line.substring(0, firstCommaIndex).trim();
                    postData = line.substring(firstCommaIndex + 1).trim();
                    method = postData ? 'POST' : 'GET';
                }

                if (!url) {
                    continue;
                }

                const urlParams = this._extractUrlParams(url);
                
                const postParams = postData ? this._extractPostParams(postData) : [];

                const allParams = [...urlParams, ...postParams];
                
                const endpointKey = `${method}:${url}`;
                
                if (!endpointMap.has(endpointKey)) {
                    const endpoint = {
                        url,
                        method,
                        parameters: allParams,
                        postData: postData || null
                    };
                    
                    endpoints.push(endpoint);
                    endpointMap.set(endpointKey, endpoint);
                    
                    for (const paramName of allParams) {
                        parameters.push({
                            endpoint: url,
                            name: paramName,
                            type: method === 'GET' ? 'query' : 'body',
                            postData: postData || null,
                            testable: true
                        });
                    }
                } else {
                    const existingEndpoint = endpointMap.get(endpointKey);
                    for (const paramName of allParams) {
                        if (!existingEndpoint.parameters.includes(paramName)) {
                            existingEndpoint.parameters.push(paramName);
                            parameters.push({
                                endpoint: url,
                                name: paramName,
                                type: method === 'GET' ? 'query' : 'body',
                                postData: postData || null,
                                testable: true
                            });
                        }
                    }
                    if (postData && !existingEndpoint.postData) {
                        existingEndpoint.postData = postData;
                    }
                }
            }

            return {
                endpoints,
                parameters
            };
        } catch (error) {
            debug('ERROR en processCrawlCsvToEndpointsAndParams:', error);
            debug('Error message:', error.message);
            debug('Error stack:', error.stack);
            debug('CSV path:', csvPath);
            this.logger.addLog(`Error procesando CSV: ${error.message}`, 'error');
            throw error;
        }
    }

    async _processCrawlCsvToTargets(csvPath) {
        const result = await this.processCrawlCsvToEndpointsAndParams(csvPath);
        
        const outputDir = this.outputDir || path.join(os.tmpdir(), 'easyinjection_scans');
        if (!fs.existsSync(outputDir)) {
            fs.mkdirSync(outputDir, { recursive: true });
        }

        const getTargets = [];
        const postTargets = [];

        for (const endpoint of result.endpoints) {
            if (endpoint.method === 'GET') {
                getTargets.push(endpoint.url);
            } else {
                const postData = endpoint.postData || endpoint.parameters.map(p => `${p}=`).join('&');
                postTargets.push(`${endpoint.url}|||${postData}`);
            }
        }

        const getTargetsPath = path.join(outputDir, 'get_targets.txt');
        fs.writeFileSync(getTargetsPath, getTargets.join('\n') + (getTargets.length > 0 ? '\n' : ''), 'utf-8');
        debug(`✓ get_targets.txt generado: ${getTargets.length} targets`);

        const postTargetsPath = path.join(outputDir, 'post_targets.txt');
        fs.writeFileSync(postTargetsPath, postTargets.join('\n') + (postTargets.length > 0 ? '\n' : ''), 'utf-8');
        debug(`✓ post_targets.txt generado: ${postTargets.length} targets`);

        return {
            getTargetsPath,
            postTargetsPath,
            getCount: getTargets.length,
            postCount: postTargets.length
        };
    }

    async processGetTargets(getTargetsPath, onEndpointDiscovered, onVulnerabilityFound, options = {}) {
        if (!fs.existsSync(getTargetsPath)) {
            debug(`get_targets.txt no encontrado: ${getTargetsPath}`);
            return;
        }

        const content = fs.readFileSync(getTargetsPath, 'utf-8');
        const urls = content.split('\n').map(l => l.trim()).filter(l => l);

        if (urls.length === 0) {
            this.logger.addLog('No hay targets GET para procesar', 'info');
            return;
        }

        this.logger.addLog(`Procesando ${urls.length} targets GET...`, 'info');

        for (const url of urls) {
            if (!url) continue;

            if (options.questionHandler) {
                await options.questionHandler.waitIfPaused();
            }

            try {
                if (onEndpointDiscovered) {
                    onEndpointDiscovered({
                        url,
                        method: 'GET',
                        parameters: this._extractUrlParams(url)
                    });
                }

                if (this.config.flags?.sqli !== false) {
                    await this._testUrlWithSqlmap(url, null, onVulnerabilityFound, options);
                }

                if (this.config.flags?.xss !== false && options.dalfoxExecutor) {
                    await options.dalfoxExecutor.scanUrl(url, onVulnerabilityFound);
                }
            } catch (error) {
                debug('ERROR en processGetTargets:', error);
                debug('Error message:', error.message);
                debug('URL:', url);
                this.logger.addLog(`Error procesando GET target ${url}: ${error.message}`, 'warning');
            }
        }
    }

    async processPostTargets(postTargetsPath, onEndpointDiscovered, onVulnerabilityFound, options = {}) {
        if (!fs.existsSync(postTargetsPath)) {
            debug(`post_targets.txt no encontrado: ${postTargetsPath}`);
            return;
        }

        const content = fs.readFileSync(postTargetsPath, 'utf-8');
        const lines = content.split('\n').map(l => l.trim()).filter(l => l);

        if (lines.length === 0) {
            this.logger.addLog('No hay targets POST para procesar', 'info');
            return;
        }

        this.logger.addLog(`Procesando ${lines.length} targets POST...`, 'info');

        for (const line of lines) {
            if (!line) continue;

            const parts = line.split('|||');
            if (parts.length < 2) {
                this.logger.addLog(`Formato inválido en línea POST: ${line}`, 'warning');
                continue;
            }

            const url = parts[0].trim();
            const postData = parts.slice(1).join('|||').trim();

            if (!url || !postData) {
                continue;
            }

            if (options.questionHandler) {
                await options.questionHandler.waitIfPaused();
            }

            try {
                if (onEndpointDiscovered) {
                    onEndpointDiscovered({
                        url,
                        method: 'POST',
                        parameters: this._extractPostParams(postData)
                    });
                }

                if (this.config.flags?.sqli !== false) {
                    await this._testUrlWithSqlmap(url, postData, onVulnerabilityFound, options);
                }

            } catch (error) {
                debug('ERROR en processPostTargets:', error);
                debug('Error message:', error.message);
                debug('URL:', url);
                debug('Post data:', postData);
                this.logger.addLog(`Error procesando POST target ${url}: ${error.message}`, 'warning');
            }
        }
    }

    async _testUrlWithSqlmap(url, postData, onVulnerabilityFound, options = {}) {
        const args = [
            '-u', url,
            ...this.toolConfig.commonArgs,
            '--level', this.toolConfig.level.toString(),
            '--risk', this.toolConfig.risk.toString(),
            '--threads', this.toolConfig.threads.toString()
        ];

        if (postData) {
            args.push('--data', postData);
        }

        this._addDbmsAndHeaders(args);

        this.logger.addLog(`Ejecutando sqlmap sobre: ${url}${postData ? ' (POST)' : ''}`, 'debug', null, true);

        const params = postData ? this._extractPostParams(postData) : this._extractUrlParams(url);

        if (params.length === 0) {
            try {
                const param = {
                    endpoint: url,
                    name: '*',
                    type: postData ? 'body' : 'query',
                    postData: postData || null,
                    testable: true
                };

                await this.testParameter(param, 'detection', onVulnerabilityFound);
            } catch (error) {
                debug('ERROR en _testUrlWithSqlmap (full test):', error);
                debug('Error message:', error.message);
                debug('URL:', url);
                this.logger.addLog(`Error testeando URL ${url}: ${error.message}`, 'warning');
            }
        } else {
            for (const paramName of params) {
                try {
                    if (options.questionHandler) {
                        await options.questionHandler.waitIfPaused();
                    }

                    const param = {
                        endpoint: url,
                        name: paramName,
                        type: postData ? 'body' : 'query',
                        postData: postData || null,
                        testable: true
                    };

                    await this.testParameter(param, 'detection', onVulnerabilityFound);
                } catch (error) {
                    debug('ERROR en _testUrlWithSqlmap (param test):', error);
                    debug('Error message:', error.message);
                    debug('Param name:', paramName);
                    debug('URL:', url);
                    this.logger.addLog(`Error testeando parámetro ${paramName}: ${error.message}`, 'warning');
                }
            }
        }
    }

    _extractUrlParams(url) {
        try {
            const urlObj = new URL(url);
            return Array.from(urlObj.searchParams.keys());
        } catch {
            const match = url.match(/[?&]([^=&]+)=/g);
            return match ? match.map(p => p.slice(1, -1)) : [];
        }
    }

    _extractPostParams(postData) {
        const params = new Set();
        const pairs = postData.split('&');

        for (const pair of pairs) {
            const equalIndex = pair.indexOf('=');
            if (equalIndex > 0) {
                const key = pair.substring(0, equalIndex).trim();
                if (key) {
                    params.add(key);
                }
            }
        }

        return Array.from(params);
    }

    async testEndpoint(endpoint, params, phase = 'detection', onVulnerabilityFound) {
        if (!params || params.length === 0) return;
        
        const paramNames = params.map(p => p.name).join(',');
        // Extraer postData del primer parámetro (todos los params del mismo endpoint tienen el mismo postData)
        const postData = params[0]?.postData || null;
        
        this.logger.addLog(`Ejecutando sqlmap para endpoint ${endpoint} con parámetros: ${paramNames}${postData ? ' (POST)' : ''}`, 'info');
        
        await this._testWithSqlmap({
            endpoint,
            paramNames,
            params,
            postData,
            phase,
            onVulnerabilityFound,
            processKey: `sqlmap-test-endpoint-${endpoint.replace(/[^a-zA-Z0-9]/g, '_')}-${phase}`,
            logContext: endpoint
        });
    }

    async testParameter(param, phase = 'detection', onVulnerabilityFound) {
        await this._testWithSqlmap({
            endpoint: param.endpoint,
            paramNames: param.name,
            params: [param],
            postData: param.postData,
            phase,
            onVulnerabilityFound,
            processKey: `sqlmap-test-${param.name}-${phase}`,
            logContext: param.name
        });
    }

    async _testWithSqlmap({ endpoint, paramNames, params, postData, phase, onVulnerabilityFound, processKey, logContext }) {
        const args = [
            '-u', endpoint,
            '-p', paramNames,
            '--level', this.toolConfig.level.toString(),
            '--risk', this.toolConfig.risk.toString(),
            ...this.toolConfig.commonArgs,
            '--threads', this.toolConfig.threads.toString()
        ];

        if (postData) args.push('--data', postData);
        this._addDbmsAndHeaders(args);

        if (phase === 'fingerprint') args.push('--fingerprint');
        if (phase === 'exploit') {
            args.push('--current-db', '--banner');
        }

        // Log detallado solo en consola del servidor (no en frontend)
        debug('\n[SQLmap] ===== COMANDO A EJECUTAR =====');
        debug('[SQLmap] Endpoint:', endpoint);
        debug('[SQLmap] Parámetros:', paramNames);
        if (postData) debug('[SQLmap] POST Data:', postData);
        debug('[SQLmap] Fase:', phase);
        debug('[SQLmap] Args completos:', args);
        console.log('[SQLmap] ====================================\n');

        return new Promise((resolve) => {
            const { executable, args: spawnArgs, spawnOpts } = this.getSpawnCommandForTool(this.toolConfig.path, args);
            
            // Log del comando final spawn solo en servidor
            console.log('[SQLmap Spawn] Ejecutable:', executable);
            console.log('[SQLmap Spawn] Argumentos:', spawnArgs);
            console.log('[SQLmap Spawn] Comando completo:', executable, spawnArgs.join(' '));
            console.log('[SQLmap Spawn] Shell:', spawnOpts.shell, '\n');
            
            const proc = spawn(executable, spawnArgs, spawnOpts);
            this.activeProcesses.set(processKey, proc);

            let buffer = '';
            let csvResultPath = null;
            let fullOutput = ''; // Capturar toda la salida para extraer POC
            let pocData = null; // Almacenar datos del POC

            proc.stdout.on('data', (data) => {
                const output = data.toString();
                // Solo en consola del servidor, no en frontend
                console.log(`[sqlmap stdout] ${output}`);
                
                // Capturar toda la salida para extraer POC
                fullOutput += output;
                
                buffer += output;
                const lines = buffer.split('\n');
                buffer = lines.pop() || '';

                for (const line of lines) {
                    params.forEach(p => this._parseTestOutput(line, p, phase));

                    const csvMatch = line.match(/you can find results.*inside the CSV file ['"](.+?\.csv)['"]/i);
                    if (csvMatch) {
                        csvResultPath = csvMatch[1];
                        console.log(`[SQLmap] CSV de resultados detectado: ${csvResultPath}`);
                    }
                }
            });

            proc.stderr.on('data', (data) => {
                const error = data.toString();
                // Solo en consola del servidor, no en frontend
                console.error(`[sqlmap stderr] ${error}`);
            });

            proc.on('close', async () => {
                this.activeProcesses.delete(processKey);
                
                // Extraer POC de la salida completa
                pocData = this._extractPOCFromOutput(fullOutput);
                
                if (csvResultPath && fs.existsSync(csvResultPath)) {
                    try {
                        await this._parseResultsCSV(csvResultPath, onVulnerabilityFound, pocData);
                        this.logger.addLog(`Completado escaneo SQLi para ${logContext}`, 'info');
                    } catch (error) {
                        debug('ERROR leyendo CSV de resultados:', error);
                        debug('Error message:', error.message);
                        debug('CSV path:', csvResultPath);
                        debug('Log context:', logContext);
                        this.logger.addLog(`Error leyendo CSV de resultados: ${error.message}`, 'warning');
                    }
                } else {
                    this.logger.addLog(`Completado escaneo SQLi para ${logContext} (sin CSV de resultados)`, 'info');
                }
                
                resolve();
            });

            proc.on('error', (error) => {
                this.activeProcesses.delete(processKey);
                this.logger.addLog(`Error ejecutando sqlmap: ${error.message}`, 'error');
                resolve();
            });

            setTimeout(() => {
                if (this.activeProcesses.has(processKey)) {
                    proc.kill('SIGTERM');
                    this.logger.addLog(`Timeout testeando ${logContext}`, 'warning');
                    resolve();
                }
            }, this.toolConfig.timeout * 1000);
        });
    }

    _parseTestOutput(line, param, phase) {
        // Log informativo relevante (los resultados reales vienen del CSV)
        if (line.match(/Parameter:.*vulnerable/i)) {
            this.logger.addLog(`✓ ${line.trim()}`, 'success');
        } else if (phase === 'fingerprint' && line.match(/back-end DBMS/i)) {
            // Solo mostrar DBMS en fase de fingerprinting - solo el más importante
            if (!line.includes('WARNING') && 
                !line.includes('zero knowledge') && 
                !line.includes('resuming back-end') &&
                !line.includes('[INFO] the back-end DBMS is') &&
                line.includes('active fingerprint')) {
                this.logger.addLog(`DBMS identificado: ${line.trim()}`, 'success');
            }
        } else if (line.match(/injection type:/i)) {
            this.logger.addLog(`Tipo de inyección: ${line.trim()}`, 'info');
        }
    }

    _extractPOCFromOutput(output) {
        // Buscar el patrón de POC en la salida de SQLmap
        const pocPattern = /Parameter:\s+([^\n]+)\s+Type:\s+([^\n]+)\s+Title:\s+([^\n]+)\s+Payload:\s+([^\n]+)/gi;
        const pocs = [];
        
        // Extraer información del DBMS
        let dbms = 'Desconocido';
        const dbmsMatch = output.match(/back-end DBMS:\s+([^\n]+)/i);
        if (dbmsMatch) {
            dbms = dbmsMatch[1].trim();
        }
        
        let match;
        while ((match = pocPattern.exec(output)) !== null) {
            pocs.push({
                parameter: match[1].trim(),
                type: match[2].trim(),
                title: match[3].trim(),
                payload: match[4].trim(),
                dbms: dbms
            });
        }
        
        return pocs;
    }

    async _parseResultsCSV(csvPath, onVulnerabilityFound, pocData = null) {
        try {
            const content = fs.readFileSync(csvPath, 'utf-8');
            const lines = content.split('\n').map(l => l.trim()).filter(l => l);
            
            if (lines.length < 2) {
                console.log('CSV de resultados vacío o sin datos', 'debug');
                return;
            }

            // Primera línea es el header: Target URL, Place, Parameter, Technique(s), Note(s)
            const header = lines[0];
            console.log(`CSV Header: ${header}`, 'debug');

            const callbackPromises = []; // Track async callbacks

            // Procesar cada línea de resultados
            for (let i = 1; i < lines.length; i++) {
                const line = lines[i];
                if (!line) continue;

                // Parsear CSV considerando que puede haber comas dentro de comillas
                const columns = this._parseCSVLine(line);
                
                if (columns.length < 4) {
                    this.logger.addLog(`Línea CSV inválida: ${line}`, 'debug');
                    continue;
                }

                const [targetUrl, place, parameter, techniques, notes] = columns;

                // Si tiene técnicas detectadas, es vulnerable
                if (techniques && techniques.trim() && techniques.trim() !== '' && techniques.trim() !== '-') {
                    // Crear ID único para esta vulnerabilidad
                    const vulnId = `${targetUrl}|${place}|${parameter}|${techniques}`;
                    
                    // Verificar si ya fue reportada
                    if (this.reportedVulnerabilities.has(vulnId)) {
                        console.log(`Vulnerabilidad duplicada omitida: ${targetUrl} - ${parameter}`);
                        continue;
                    }
                    
                    // Marcar como reportada
                    this.reportedVulnerabilities.add(vulnId);
                    
                    // Traducir técnicas de letras a nombres completos en español
                    const translatedTechniques = this._translateTechniques(techniques);
                    const severity = this._determineSeverityFromTechnique(techniques);
                    
                    // Buscar POC correspondiente a este parámetro
                    let pocInfo = '';
                    let dbmsInfo = 'Desconocido';
                    
                    if (pocData && pocData.length > 0) {
                        const matchingPoc = pocData.find(poc => 
                            poc.parameter.toLowerCase().includes(parameter.toLowerCase())
                        );
                        
                        if (matchingPoc) {
                            dbmsInfo = matchingPoc.dbms || 'Desconocido';
                            pocInfo = `\n\nPrueba de concepto (PoC):\n\n${matchingPoc.payload}`;
                        }
                    }
                    
                    // Determinar método HTTP (GET/POST)
                    const httpMethod = place === 'POST' || place.includes('POST') ? 'POST' : 'GET';
                    
                    // Construir descripción detallada
                    const description = `El parámetro ${parameter} ${httpMethod} del endpoint ${targetUrl} presenta una vulnerabilidad de SQL Injection debido a una sanitización insuficiente de los datos de entrada. La aplicación concatena directamente los valores proporcionados por el usuario dentro de la sentencia SQL, lo que permite a un atacante alterar la lógica de la consulta.\n\nLa causa raíz del problema es la ausencia de consultas parametrizadas y de validación robusta de entradas. Aprovechando esta vulnerabilidad, fue posible identificar el gestor de base de datos utilizado (${dbmsInfo}) y confirmar el punto de inyección mediante la siguiente prueba de concepto:${pocInfo}`;
                    
                    this.logger.addLog(`✓ Vulnerabilidad SQLi encontrada: ${targetUrl} - ${parameter} (${translatedTechniques})`, 'success');

                    if (onVulnerabilityFound) {
                        const callbackResult = onVulnerabilityFound({
                            type: 'SQLi',
                            severity: severity,
                            endpoint: targetUrl,
                            parameter: parameter || 'unknown',
                            description: description,
                            techniqueType: translatedTechniques, // Pasar el tipo de técnica
                            subtype: translatedTechniques // Usar la técnica traducida como subtipo
                        });
                        
                        // If callback returns a promise, track it
                        if (callbackResult && callbackResult.then) {
                            callbackPromises.push(callbackResult);
                        }
                    }
                }
            }
            
            // Wait for all async callbacks to complete
            debug(`Esperando ${callbackPromises.length} callbacks asíncronos de SQLi...`);
            await Promise.all(callbackPromises);
            debug('Todos los callbacks de SQLi completados');
        } catch (error) {
            debug('ERROR en _parseResultsCSV:', error);
            debug('Error message:', error.message);
            debug('Error stack:', error.stack);
            console.log(`Error parseando CSV: ${error.message}`);
            throw error;
        }
    }

    _parseCSVLine(line) {
        const columns = [];
        let current = '';
        let inQuotes = false;

        for (let i = 0; i < line.length; i++) {
            const char = line[i];
            
            if (char === '"') {
                inQuotes = !inQuotes;
            } else if (char === ',' && !inQuotes) {
                columns.push(current.trim());
                current = '';
            } else {
                current += char;
            }
        }
        
        // Agregar última columna
        columns.push(current.trim());
        
        return columns;
    }

    _translateTechniques(techniques) {
        if (!techniques) return techniques;
        
        const techMap = {
            'B': 'Inyección ciega basada en booleanos (Boolean-based blind)',
            'E': 'Basada en errores (Error-based)',
            'U': 'Basada en consultas UNION (Union query-based)',
            'S': 'Consultas apiladas (Stacked queries)',
            'T': 'Inyección ciega basada en tiempo (Time-based blind)',
            'Q': 'Consultas en línea (Inline queries)'
        };
        
        // Separar por comas y traducir cada técnica
        const parts = techniques.split(',').map(t => t.trim());
        const translated = parts.map(tech => {
            // Si es una sola letra, traducir
            if (tech.length === 1 && techMap[tech]) {
                return techMap[tech];
            }
            return tech;
        });
        
        return translated.join(', ');
    }

    _determineSeverityFromTechnique(techniques) {
        const techLower = techniques.toLowerCase();
        
        // Técnicas más peligrosas
        if (techLower.includes('time-based') || techLower.includes('stacked')) {
            return 'critical';
        }
        
        // Técnicas que permiten extracción directa
        if (techLower.includes('union') || techLower.includes('error-based')) {
            return 'critical';
        }
        
        // Boolean-based es también crítico pero ligeramente menos directo
        if (techLower.includes('boolean')) {
            return 'critical';
        }
        
        // Cualquier otra técnica detectada
        return 'critical';
    }

    _addDbmsAndHeaders(args) {
        if (this.config.dbms) {
            args.push('--dbms', this.config.dbms);
        }

        if (this.config.customHeaders) {
            const headers = this.config.customHeaders.split('\n').filter(h => h.trim());
            headers.forEach(header => {
                args.push('--header', header.trim());
            });
        }
    }

    getSpawnCommandForTool(toolPath, args = []) {
        const spawnOpts = { shell: false };
        const isBare = !/[\\/]/.test(String(toolPath));
      
        if (process.platform === 'win32' && isBare) {
          spawnOpts.shell = true;
          return { executable: toolPath, args, spawnOpts };
        }
      
        if (fs.existsSync(toolPath)) {
          const ext = path.extname(String(toolPath)).toLowerCase();
          if (ext === '.py') {
            const pythonCmd = process.platform === 'win32' ? 'py' : 'python';
            return { executable: pythonCmd, args: [toolPath, ...args], spawnOpts };
          } else {
            return { executable: toolPath, args, spawnOpts };
          }
        }
      
        if (process.platform === 'win32' && isBare) spawnOpts.shell = true;
        return { executable: toolPath, args, spawnOpts };
    }

    async runCommand(args, timeout = 30000, opts = {}) {
        const autoRespond = opts.autoRespond !== false;
        const autoRespondRegex = opts.autoRespondRegex || /press\s+(enter|any key|return)\b/i;
        const useShellFallback = opts.useShellFallback !== false;
    
        const { executable, args: finalArgs, spawnOpts } = this.getSpawnCommandForTool(this.toolConfig.path, Array.isArray(args) ? args.slice() : []);
        console.log(`Ejecutando comando: ${executable} ${finalArgs.join(' ')}`, 'debug', null, true);
    
        try {
            return await this._executeProcess(executable, finalArgs, spawnOpts, timeout, autoRespond, autoRespondRegex);
        } catch (error) {
            debug('ERROR en executeCommand:', error);
            debug('Error message:', error.message);
            debug('Executable:', executable);
            debug('Args:', finalArgs);
            if (useShellFallback && !spawnOpts.shell) {
                const safeArgs = finalArgs.map(a => typeof a === 'string' && a.includes(' ') ? `"${a}"` : a).join(' ');
                const shellCmd = `${executable} ${safeArgs}`;
                this.logger.addLog(`Fallback ejecutando en shell: ${shellCmd}`, 'debug');
                return await this._executeProcess(shellCmd, [], { shell: true }, timeout, autoRespond, autoRespondRegex);
            }
            throw error;
        }
    }

    _executeProcess(executable, args, spawnOpts, timeout, autoRespond, autoRespondRegex) {
        return new Promise((resolve, reject) => {
            let stdout = '';
            let stderr = '';
            let responded = false;
            let finished = false;
    
            const proc = spawn(executable, args, spawnOpts);
    
            const timer = setTimeout(() => {
                if (finished) return;
                finished = true;
                try { proc.kill(); } catch (e) {}
                reject({ message: 'Command timeout', stdout, stderr });
            }, timeout);
    
            const tryAutoRespond = (text) => {
                if (!autoRespond || responded) return;
                try {
                    if (autoRespondRegex.test(text) && proc.stdin && !proc.stdin.destroyed) {
                        proc.stdin.write('\n');
                        try { proc.stdin.end(); } catch (_) {}
                        responded = true;
                    }
                } catch (e) {
                    debug('ERROR en auto-respond:', e);
                    debug('Error message:', e.message);
                    this.logger.addLog(`Auto-respond failed: ${e.message}`, 'debug');
                }
            };
    
            proc.stdout.on('data', (d) => {
                const t = d.toString();
                stdout += t;
                tryAutoRespond(t);
            });
    
            proc.stderr.on('data', (d) => {
                const t = d.toString();
                stderr += t;
                tryAutoRespond(t);
            });
    
            proc.on('close', (code) => {
                if (finished) return;
                finished = true;
                clearTimeout(timer);
    
                if (code === 0) {
                    resolve({ stdout, stderr });
                } else {
                    reject({ message: `Command failed with code ${code}`, stdout, stderr });
                }
            });
    
            proc.on('error', (err) => {
                if (finished) return;
                finished = true;
                clearTimeout(timer);
                reject({ message: err.message, stdout, stderr });
            });
        });
    }  
}

module.exports = SqlmapExecutor;

