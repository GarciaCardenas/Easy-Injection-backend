const express = require("express");
const debug = require('debug')('easyinjection:api:notifications');
const auth = require("../middleware/auth.middleware");
const { Notification } = require("../../models/user/notification.model");

const router = express.Router();

router.get("/", auth, async (req, res) => {
  try {
    const notifications = await Notification.Model.find({ user_id: req.user._id })
      .sort({ createdAt: -1 })
      .limit(50);
    res.json(notifications);
  } catch (error) {
    debug('ERROR en GET /api/notifications:', error);
    debug('Error message:', error.message);
    debug('User ID:', req.user?._id);
    console.error('Error en /api/notifications:', error);
    res.status(500).json({ error: "Error interno del servidor", details: error.message });
  }
});

router.get('/unread-count', auth, async (req, res) => {
  try {
    const count = await Notification.Model.countDocuments({ 
      user_id: req.user._id, 
      leido: false 
    });
    res.json({ count });
  } catch (error) {
    debug('ERROR en GET /api/notifications/unread-count:', error);
    debug('Error message:', error.message);
    debug('User ID:', req.user?._id);
    console.error('Error en /api/notifications/unread-count:', error);
    res.status(500).json({ error: 'Error interno del servidor', details: error.message });
  }
});

router.put('/:id/read', auth, async (req, res) => {
  try {
    const notification = await Notification.Model.findOneAndUpdate(
      { _id: req.params.id, user_id: req.user._id },
      { leido: true },
      { new: true }
    );
    res.json(notification);
  } catch (error) {
    debug('ERROR en PUT /api/notifications/:id/read:', error);
    debug('Error message:', error.message);
    debug('Notification ID:', req.params.id);
    debug('User ID:', req.user?._id);
    console.error('Error en /api/notifications/:id/read:', error);
    res.status(500).json({ error: 'Error interno del servidor', details: error.message });
  }
});

router.post('/mark-all-read', auth, async (req, res) => {
  try {
    await Notification.Model.updateMany(
      { user_id: req.user._id, leido: false },
      { leido: true }
    );
    res.json({ message: 'Todas las notificaciones marcadas como leídas' });
  } catch (error) {
    debug('ERROR en POST /api/notifications/mark-all-read:', error);
    debug('Error message:', error.message);
    debug('User ID:', req.user?._id);
    console.error('Error en /api/notifications/mark-all-read:', error);
    res.status(500).json({ error: 'Error interno del servidor', details: error.message });
  }
});

router.delete('/:id', auth, async (req, res) => {
  try {
    await Notification.Model.findOneAndDelete({ 
      _id: req.params.id, 
      user_id: req.user._id 
    });
    res.json({ message: 'Notificación eliminada' });
  } catch (error) {
    debug('ERROR en DELETE /api/notifications/:id:', error);
    debug('Error message:', error.message);
    debug('Notification ID:', req.params.id);
    debug('User ID:', req.user?._id);
    console.error('Error en /api/notifications/:id DELETE:', error);
    res.status(500).json({ error: 'Error interno del servidor', details: error.message });
  }
});

module.exports = router;