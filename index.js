require("dotenv").config();
const express = require('express');
//const passport = require('passport');
const app = express();
const http = require('http');
const path = require('path');
const socketService = require('./src/services/socket.service');

//require('./src/config/passport');
require('./src/config/database')();

app.set('trust proxy', true);

//app.use(passport.initialize());

require('./src/config/routes')(app);

const angularDistPath = path.join(__dirname, './dist/frontend/browser');

// En producción, Nginx sirve los archivos estáticos
// Solo servir Angular si estamos en desarrollo
if (process.env.NODE_ENV !== 'production') {
  app.use(express.static(angularDistPath));
  app.get(/(.*)/, (req, res) => {
    res.sendFile(path.join(angularDistPath, 'index.html'));
  });
}

const port = process.env.PORT || 3000;
const host = process.env.HOST || '127.0.0.1';
const server = http.createServer(app);

socketService.initialize(server);

server.listen(port, host, () => {
  console.log(`[${process.env.NODE_ENV || 'development'}] Server listening on ${host}:${port}`);
});

module.exports = server;
