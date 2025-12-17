const express = require('express');
const debug = require('debug')('easyinjection:api:sessions');
const auth = require('../middleware/auth.middleware');
const { User } = require('../../models/user/user.model');
const router = express.Router();

router.get('/', auth, async (req, res) => {
  try {
    const userDoc = await User.Model.findById(req.user._id).select('activeSessions');
    const user = User.fromMongoose(userDoc);
    
    const sortedSessions = [...user.activeSessions].sort((a, b) => 
      new Date(b.createdAt) - new Date(a.createdAt)
    );
    
    // Find current session by matching sessionId from JWT
    const currentJWTSessionId = req.user.sessionId;
    const currentSession = sortedSessions.find(s => s.sessionId === currentJWTSessionId);
    const currentSessionId = currentSession ? currentSession._id.toString() : null;
    
    debug('GET /api/sessions - User ID: %s, Total sessions: %d, Current sessionId: %s', req.user._id, sortedSessions.length, currentJWTSessionId);
    res.json({ 
      sessions: sortedSessions,
      currentSessionId
    });
  } catch (error) {
    debug('ERROR en GET /api/sessions:', error);
    debug('Error message:', error.message);
    debug('User ID:', req.user?._id);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

router.post('/close-all', auth, async (req, res) => {
  try {
    const userDoc = await User.Model.findById(req.user._id);
    const user = User.fromMongoose(userDoc);
    user.clearAllSessions();
    await user.save();
    
    res.clearCookie('auth_token', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax'
    });
    
    res.clearCookie('refresh_token', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax'
    });
    
    debug('POST /api/sessions/close-all - Todas las sesiones cerradas para usuario: %s', req.user._id);
    res.json({ message: 'Todas las sesiones han sido cerradas' });
  } catch (error) {
    debug('ERROR en POST /api/sessions/close-all:', error);
    debug('Error message:', error.message);
    debug('User ID:', req.user?._id);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

router.delete('/:sessionId', auth, async (req, res) => {
  try {
    debug('DELETE /api/sessions/:sessionId - Session ID: %s, User ID: %s', req.params.sessionId, req.user._id);
    
    const userDoc = await User.Model.findById(req.user._id);
    const user = User.fromMongoose(userDoc);
    
    const sessionToDelete = user.activeSessions.find(s => s._id.toString() === req.params.sessionId);
    
    if (!sessionToDelete) {
      return res.status(404).json({ error: 'Sesión no encontrada' });
    }
    
    // Check if this is the current session being deleted
    const isCurrentSession = req.user.sessionId === sessionToDelete.sessionId;
    
    // Remove session from array (this invalidates the JWT with that sessionId)
    await User.Model.findByIdAndUpdate(req.user._id, {
      $pull: { activeSessions: { _id: req.params.sessionId } }
    });
    
    // Only clear cookie if deleting current session
    if (isCurrentSession) {
      res.clearCookie('auth_token', {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax'
      });
      res.clearCookie('refresh_token', {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax'
      });
      debug('Sesión actual cerrada - Session ID: %s', req.params.sessionId);
    } else {
      debug('Sesión remota cerrada - Session ID: %s', req.params.sessionId);
    }
    
    res.json({ 
      message: 'Sesión cerrada exitosamente',
      isCurrentSession
    });
  } catch (error) {
    debug('ERROR en DELETE /api/sessions/:sessionId:', error);
    debug('Error message:', error.message);
    debug('Session ID:', req.params.sessionId);
    debug('User ID:', req.user?._id);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

module.exports = router;