const express = require('express');
const auth = require('../middleware/auth.middleware');
const { Scan } = require('../../models/scan/scan.model');
const { Vulnerability } = require('../../models/scan/vulnerability.model');
const { VulnerabilityType } = require('../../models/catalog/vulnerability-type.model');
const { SeverityLevel } = require('../../models/catalog/severity-level.model');
const router = express.Router();

router.get('/', auth, async (req, res) => {
    try {
        const scanDocs = await Scan.Model.find({ usuario_id: req.user._id })
            .sort({ fecha_inicio: -1 });

        const scansWithDetails = await Promise.all(scanDocs.map(async (scanDoc) => {
            const scan = Scan.fromMongoose(scanDoc);
            const vulnerabilityDocs = await Vulnerability.Model.find({ escaneo_id: scan._id })
                .populate('tipo_id', 'nombre')
                .populate('nivel_severidad_id', 'nombre nivel');

            const vulnerabilities = vulnerabilityDocs.map(v => Vulnerability.fromMongoose(v));
            const vulnerabilityCount = vulnerabilities.length;
            const vulnerabilityTypes = [...new Set(vulnerabilities.map(v => v.tipo_id?.nombre).filter(Boolean))];

            return {
                _id: scan._id,
                alias: scan.alias,
                url: scan.url,
                fecha_inicio: scan.fecha_inicio,
                fecha_fin: scan.fecha_fin,
                estado: scan.estado,
                flags: scan.flags,
                vulnerabilidades: {
                    count: vulnerabilityCount,
                    types: vulnerabilityTypes
                }
            };
        }));

        res.json({
            success: true,
            scans: scansWithDetails
        });
    } catch (error) {
        console.error('Error en GET /api/scan:', error);
        res.status(500).json({
            success: false,
            error: 'Error interno del servidor',
            details: error.message
        });
    }
});

router.get('/:id', auth, async (req, res) => {
    try {
        const scanDoc = await Scan.Model.findOne({ 
            _id: req.params.id, 
            usuario_id: req.user._id 
        });

        if (!scanDoc) {
            return res.status(404).json({
                success: false,
                error: 'Escaneo no encontrado'
            });
        }

        const scan = Scan.fromMongoose(scanDoc);
        const vulnerabilityDocs = await Vulnerability.Model.find({ escaneo_id: scan._id })
            .populate('tipo_id', 'nombre descripcion')
            .populate('nivel_severidad_id', 'nombre nivel color');

        const vulnerabilities = vulnerabilityDocs.map(v => Vulnerability.fromMongoose(v).toDTO());

        res.json({
            success: true,
            scan: {
                ...scan.toDTO(),
                vulnerabilidades: vulnerabilities
            }
        });
    } catch (error) {
        console.error('Error en GET /api/scan/:id:', error);
        res.status(500).json({
            success: false,
            error: 'Error interno del servidor',
            details: error.message
        });
    }
});

router.get('/:id/report', auth, async (req, res) => {
    try {
        const { Question } = require('../../models/quiz/question.model');
        const { Answer } = require('../../models/quiz/answer.model');

        const scanDoc = await Scan.Model.findOne({ 
            _id: req.params.id, 
            usuario_id: req.user._id 
        });

        if (!scanDoc) {
            return res.status(404).json({
                success: false,
                error: 'Escaneo no encontrado'
            });
        }

        const scan = Scan.fromMongoose(scanDoc);
        const vulnerabilityDocs = await Vulnerability.Model.find({ escaneo_id: scan._id })
            .populate('tipo_id', 'nombre descripcion')
            .populate('nivel_severidad_id', 'nombre nivel color');

        const severityCounts = {
            critica: 0,
            alta: 0,
            media: 0,
            baja: 0
        };

        const vulnerabilitiesDTO = vulnerabilityDocs.map(v => {
            const vuln = Vulnerability.fromMongoose(v);
            const severityLevel = v.nivel_severidad_id;
            const vulnerabilityType = v.tipo_id;
            
            // Contar por severidad
            const severity = severityLevel?.nombre?.toLowerCase();
            if (severity === 'crítica' || severity === 'critica') {
                severityCounts.critica++;
            } else if (severity === 'alta') {
                severityCounts.alta++;
            } else if (severity === 'media') {
                severityCounts.media++;
            } else if (severity === 'baja') {
                severityCounts.baja++;
            }
            
            const dto = vuln.toDTO(severityLevel, vulnerabilityType);
            
            // Para SQLi, extraer el subtipo de técnica de la descripción si existe
            if (vulnerabilityType?.nombre === 'SQLi' && vuln.descripcion) {
                // Buscar patrones de técnicas en la descripción
                const techniquePatterns = [
                    'Inyección ciega basada en booleanos (Boolean-based blind)',
                    'Basada en errores (Error-based)',
                    'Basada en consultas UNION (Union query-based)',
                    'Consultas apiladas (Stacked queries)',
                    'Inyección ciega basada en tiempo (Time-based blind)',
                    'Consultas en línea (Inline queries)'
                ];
                
                for (const pattern of techniquePatterns) {
                    if (vuln.descripcion.includes(pattern)) {
                        // Crear un objeto tipo_id modificado solo para este DTO
                        dto.tipo_id = {
                            _id: vulnerabilityType._id,
                            nombre: vulnerabilityType.nombre,
                            descripcion: pattern
                        };
                        break;
                    }
                }
            }
            
            return dto;
        });

        const quizResults = [];
        if (scan.respuestas_usuario && scan.respuestas_usuario.length > 0) {
            for (const userAnswer of scan.respuestas_usuario) {
                try {
                    const questionDoc = await Question.Model.findById(userAnswer.pregunta_id);
                    if (!questionDoc) continue;
                    
                    const question = Question.fromMongoose(questionDoc);
                    
                    const answerDocs = await Answer.Model.find({ pregunta_id: userAnswer.pregunta_id });
                    const allAnswers = answerDocs.map(a => Answer.fromMongoose(a));
                    
                    const selectedAnswerDoc = await Answer.Model.findById(userAnswer.respuesta_seleccionada_id);
                    if (!selectedAnswerDoc) continue;
                    
                    const selectedAnswer = Answer.fromMongoose(selectedAnswerDoc);
                    const correctAnswer = allAnswers.find(a => a.es_correcta);

                    quizResults.push({
                        pregunta: question.toDTO(),
                        respuestas: allAnswers.map(a => a.toDTO()),
                        respuesta_seleccionada: selectedAnswer.toDTO(),
                        respuesta_correcta: correctAnswer?.toDTO(),
                        es_correcta: userAnswer.es_correcta,
                        puntos_obtenidos: userAnswer.puntos_obtenidos
                    });
                } catch (err) {
                    console.error('Error processing quiz answer:', err);
                    continue;
                }
            }
        }

        res.json({
            success: true,
            report: {
                scan: scan.toDTO(),
                vulnerabilidades: vulnerabilitiesDTO,
                resumen_vulnerabilidades: {
                    total: vulnerabilitiesDTO.length,
                    por_severidad: severityCounts
                },
                cuestionario: quizResults,
                puntuacion: scan.puntuacion.toObject()
            }
        });
    } catch (error) {
        console.error('Error fetching scan report:', error);
        res.status(500).json({
            success: false,
            error: 'Error interno del servidor',
            details: error.message
        });
    }
});

router.post('/', auth, async (req, res) => {
    try {
        const { alias, url, flags, tipo_autenticacion, credenciales } = req.body;

        const scanData = {
            usuario_id: req.user._id,
            alias,
            url,
            flags: flags || { xss: false, sqli: false },
            tipo_autenticacion,
            credenciales,
            estado: 'pendiente'
        };

        const scan = new Scan(scanData);
        await scan.save();

        res.status(201).json({
            success: true,
            scan: scan.toDTO()
        });
    } catch (error) {
        console.error('Error en POST /api/scan:', error);
        res.status(500).json({
            success: false,
            error: 'Error interno del servidor',
            details: error.message
        });
    }
});

router.put('/:id', auth, async (req, res) => {
    try {
        const { estado, fecha_fin } = req.body;

        const scanDoc = await Scan.Model.findOne(
            { _id: req.params.id, usuario_id: req.user._id }
        );

        if (!scanDoc) {
            return res.status(404).json({
                success: false,
                error: 'Escaneo no encontrado'
            });
        }

        const scan = Scan.fromMongoose(scanDoc);
        if (estado) scan.estado = estado;
        if (fecha_fin) scan.fecha_fin = new Date(fecha_fin);

        await scan.save();

        res.json({
            success: true,
            scan: scan.toDTO()
        });
    } catch (error) {
        console.error('Error en PUT /api/scan/:id:', error);
        res.status(500).json({
            success: false,
            error: 'Error interno del servidor',
            details: error.message
        });
    }
});

router.delete('/:id', auth, async (req, res) => {
    try {
        const scan = await Scan.Model.findOneAndDelete({ 
            _id: req.params.id, 
            usuario_id: req.user._id 
        });

        if (!scan) {
            return res.status(404).json({
                success: false,
                error: 'Escaneo no encontrado'
            });
        }

        await Vulnerability.Model.deleteMany({ escaneo_id: scan._id });

        res.json({
            success: true,
            message: 'Escaneo eliminado exitosamente'
        });
    } catch (error) {
        console.error('Error en DELETE /api/scan/:id:', error);
        res.status(500).json({
            success: false,
            error: 'Error interno del servidor',
            details: error.message
        });
    }
});

router.post('/:id/vulnerabilities', auth, async (req, res) => {
    try {
        const { tipo_id, nivel_severidad_id, parametro_afectado, url_afectada, descripcion, sugerencia, referencia } = req.body;

        const vulnerability = new Vulnerability({
            escaneo_id: req.params.id,
            tipo_id,
            nivel_severidad_id,
            parametro_afectado,
            url_afectada,
            descripcion,
            sugerencia,
            referencia
        });

        await vulnerability.save();

        await Scan.findByIdAndUpdate(req.params.id, {
            $push: { vulnerabilidades: vulnerability._id }
        });

        res.status(201).json({
            success: true,
            vulnerability: {
                _id: vulnerability._id,
                tipo_id: vulnerability.tipo_id,
                nivel_severidad_id: vulnerability.nivel_severidad_id,
                parametro_afectado: vulnerability.parametro_afectado,
                url_afectada: vulnerability.url_afectada,
                descripcion: vulnerability.descripcion,
                sugerencia: vulnerability.sugerencia,
                referencia: vulnerability.referencia
            }
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: 'Error interno del servidor'
        });
    }
});

router.post('/:id/start', auth, async (req, res) => {
    try {
        const scan = await Scan.findOne({
            _id: req.params.id,
            usuario_id: req.user._id
        });

        if (!scan) {
            return res.status(404).json({
                success: false,
                error: 'Escaneo no encontrado'
            });
        }

        const socketService = require('../services/socketService');
        if (socketService.isScanning(scan._id.toString())) {
            return res.status(400).json({
                success: false,
                error: 'El escaneo ya está en ejecución'
            });
        }

        const { dbms, customHeaders } = req.body;

        res.json({
            success: true,
            message: 'Use WebSocket connection to start the scan',
            scanId: scan._id,
            config: {
                dbms: dbms || 'auto',
                customHeaders: customHeaders || ''
            }
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: 'Error interno del servidor'
        });
    }
});

router.get('/:id/status', auth, async (req, res) => {
    try {
        const scan = await Scan.findOne({
            _id: req.params.id,
            usuario_id: req.user._id
        });

        if (!scan) {
            return res.status(404).json({
                success: false,
                error: 'Escaneo no encontrado'
            });
        }

        const socketService = require('../services/socketService');
        const status = socketService.getScanStatus(scan._id.toString());

        res.json({
            success: true,
            status: status || {
                scanId: scan._id,
                isRunning: false,
                dbStatus: scan.estado
            }
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: 'Error interno del servidor'
        });
    }
});

router.get('/search', auth, async (req, res) => {
  try {
    const { query, status, dateFrom, dateTo } = req.query;
    
    let filter = { usuario_id: req.user._id };
    
    if (query) {
      filter.alias = { $regex: query, $options: 'i' };
    }
    
    if (status) {
      filter.estado = status;
    }
    
    if (dateFrom || dateTo) {
      filter.fecha_inicio = {};
      if (dateFrom) filter.fecha_inicio.$gte = new Date(dateFrom);
      if (dateTo) filter.fecha_inicio.$lte = new Date(dateTo);
    }
    
    const scans = await Scan.find(filter)
      .sort({ fecha_inicio: -1 })
      .populate('tipo_autenticacion')
      .populate('gestor');
    
    res.json(scans);
  } catch (error) {
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

router.get('/scoreboard', auth, async (req, res) => {
  try {
    const scans = await Scan.find({ 
      usuario_id: req.user._id,
      estado: 'finalizado'
    })
    .sort({ puntuacion_final: -1 })
    .select('alias puntuacion_final vulnerabilidades_encontradas fecha_fin');
    
    if (scans.length === 0) {
      return res.json({ 
        message: 'Aún no has realizado ningún escaneo',
        scans: []
      });
    }
    
    res.json({ scans });
  } catch (error) {
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

module.exports = router;
