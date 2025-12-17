const express = require('express');
const cors = require('cors');
const morgan = require('morgan');
const cookieParser = require('cookie-parser');
const register = require('../api/routes/register.routes');
const verifyEmail = require('../api/routes/verify-email.routes');
const login = require('../api/routes/login.routes');
const auth = require('../api/routes/auth.routes');
const refresh = require('../api/routes/refresh.routes');
const user = require('../api/routes/user.routes');
const scans = require('../api/routes/scan.routes');
const error = require('../api/middleware/error.middleware');
const activity = require('../api/routes/activity.routes');
const notifications = require('../api/routes/notifications.routes');
const sessions = require('../api/routes/sessions.routes');
const scoreboard = require('../api/routes/scoreboard.routes');
const passwordReset = require('../api/routes/password-reset.routes');
const lessonProgress = require('../api/routes/lessonProgress.routes');
const ipTest = require('../api/routes/ip-test.routes');

module.exports = function(app) {
    app.use(morgan('combined'));
    
    app.use(cors({
        origin: process.env.FRONTEND_URL || 'http://localhost:4200',
        credentials: true
    }));
    app.use(express.json());
    app.use(cookieParser());
    app.use('/api/register', register);
    app.use('/api/activity', activity);
    app.use('/api/notifications', notifications);
    app.use('/api/sessions', sessions);
    app.use('/api/verify-email', verifyEmail);
    app.use('/api/login', login);
    app.use('/api/auth/refresh', refresh);
    app.use('/api/auth', auth);
    app.use('/api/auth', passwordReset);
    app.use('/api/user', user);
    app.use('/api/scans', scans);
    app.use('/api/scoreboard', scoreboard);
    app.use('/api/lessons', lessonProgress);
    app.use('/api/ip-test', ipTest);
    app.use(error);
}

