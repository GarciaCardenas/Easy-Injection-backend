const express = require("express");
const auth = require("../middleware/auth.middleware");
const { User } = require("../../models/user/user.model");
const { Scan } = require("../../models/scan/scan.model");

const router = express.Router();

router.get("/", auth, async (req, res) => {
  try {
    const { timeframe = "all", limit = 100 } = req.query;

    let dateFilter = {};

    if (timeframe === "week") {
      const weekAgo = new Date();
      weekAgo.setDate(weekAgo.getDate() - 7);
      dateFilter = { fecha_fin: { $gte: weekAgo } };
    } else if (timeframe === "month") {
      const monthAgo = new Date();
      monthAgo.setMonth(monthAgo.getMonth() - 1);
      dateFilter = { fecha_fin: { $gte: monthAgo } };
    }

    const userScans = await Scan.Model.find({
      usuario_id: req.user._id,
      estado: "finalizado",
      ...dateFilter,
    })
      .populate('respuestas_usuario.respuestas_seleccionadas')
      .sort({ "puntuacion.puntuacion_final": -1 })
      .limit(parseInt(limit))
      .select("alias url fecha_inicio fecha_fin puntuacion vulnerabilidades respuestas_usuario");

    const scoreboard = userScans.map((scan, index) => {
      const vulnerabilitiesFound = scan.puntuacion?.vulnerabilidades_encontradas || 0;
      const quizScore = scan.puntuacion?.puntos_cuestionario || 0;
      const totalQuizScore = scan.puntuacion?.total_puntos_cuestionario || 60;
      // Calcular puntaje ponderado en escala de 100
      const quizScorePercentage = totalQuizScore > 0 ? (quizScore / totalQuizScore) * 100 : 0;

      return {
        rank: index + 1,
        scanId: scan._id,
        scanAlias: scan.alias,
        scanUrl: scan.url,
        score: scan.puntuacion?.puntuacion_final || 0,
        quizScore: Math.round(quizScorePercentage * 100) / 100, // Redondear a 2 decimales
        vulnerabilitiesFound: vulnerabilitiesFound,
        grade: scan.puntuacion?.calificacion || 'Regular',
        completedAt: scan.fecha_fin,
      };
    });

    res.json({
      success: true,
      scoreboard,
      timeframe,
    });
  } catch (err) {
    console.error('Error en /api/scoreboard:', err);
    res.status(500).json({ message: "Server Error", error: err.message });
  }
});

router.get("/me", auth, async (req, res) => {
  try {
    const scans = await Scan.Model.find({
      usuario_id: req.user._id,
      estado: "finalizado",
    });

    const totalPoints = scans.reduce(
      (sum, scan) => sum + (scan.puntuacion?.puntuacion_final || 0),
      0
    );
    const totalVulnerabilities = scans.reduce(
      (sum, scan) => sum + (scan.puntuacion?.vulnerabilidades_encontradas || 0),
      0
    );
    const avgScore = scans.length > 0 ? totalPoints / scans.length : 0;
    const bestScan = scans.sort(
      (a, b) =>
        (b.puntuacion?.puntuacion_final || 0) -
        (a.puntuacion?.puntuacion_final || 0)
    )[0];

    const level = Math.floor(totalPoints / 1000) + 1;

    const userDoc = await User.Model.findById(req.user._id);
    if (userDoc) {
      const user = User.fromMongoose(userDoc);
      user.updateLevel(level);
      await user.save();
    }

    res.json({
      success: true,
      stats: {
        totalPoints: Math.round(totalPoints),
        totalScans: scans.length,
        totalVulnerabilities,
        avgScore: Math.round(avgScore),
        bestScore: bestScan
          ? Math.round(bestScan.puntuacion?.puntuacion_final || 0)
          : 0,
        bestScanAlias: bestScan?.alias || "N/A",
        level,
      },
    });
  } catch (error) {
    res.status(500).json({
      error: "Error interno del servidor",
    });
  }
});

module.exports = router;
