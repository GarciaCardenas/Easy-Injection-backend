# Resumen de Catch Blocks en el Proyecto Backend

## Archivos Procesados con Debug

### ✅ Ya tienen debug completo:
- `src/services/scan/scan-orchestrator.service.js` - Ya tiene debug detallado
- `src/services/scan/question-handler.service.js` - Debug agregado
- `src/services/scan/dalfox-executor.service.js` - Debug agregado
- `src/services/phases/xss.phase.js` - Debug agregado  
- `src/services/socket.service.js` - Debug agregado (parcial)

## Archivos que necesitan debug

### CRÍTICOS (Services y Phases):

#### `src/services/scan/sqlmap-executor.service.js` - 19 catch blocks
- Línea 37: catch en checkAvailability()
- Línea 56: catch en crawlAndExtractEndpoints()
- Línea 139: catch en procesamiento de stdout
- Línea 226-230: catch en procesamiento de entradas CSV
- Línea 245: catch en closeCrawlSession()
- Línea 340: catch en generateTargetsFiles()
- Línea 421, 476, 512, 531: catch en lectura de archivos
- Línea 682: catch en parseado de JSON
- Línea 834: catch en scanEndpoint()
- Línea 957: catch en runCommand()
- Líneas 980, 989, 992: catch de cleanup

#### `src/services/phases/sqli.phase.js` - 3 catch blocks
- Línea 117: catch en crawl
- Línea 154: catch en targets generation
- Línea 220: catch en scan execution

#### `src/services/phases/discovery.phase.js` - 2 catch blocks
- Línea 61: catch en runPhase()
- Línea 105: catch en procesamiento CSV

#### `src/services/scan/config-validator.service.js` - 1 catch block
- Línea 15: catch en validateAndNormalizeConfig()

#### `src/services/email.service.js` - 2 catch blocks
- Línea 55: catch en sendEmail()
- Línea 71: catch en sendEmailVerification()

#### `src/services/socket.service.js` - Adicionales
- Línea 41: catch en autenticación
- Línea 67: catch en join room
- Línea 173, 203, 224, 249: catch en eventos scan
- Línea 304, 414: catch en guardado de vulnerabilidades
- Línea 490, 504, 510, 525: catch en notificaciones/actividades

### RUTAS API (Menos crítico para debugging):

#### `src/api/routes/scan.routes.js` - 12 catch blocks
- Múltiples endpoints de gestión de scans

#### `src/api/routes/user.routes.js` - 10 catch blocks
- Endpoints de gestión de usuarios

#### `src/api/routes/auth.routes.js` - 3 catch blocks
- Autenticación OAuth

#### Otros routes/ - ~30 catch blocks adicionales
- notifications, sessions, password-reset, verify-email, etc.

#### `src/api/controllers/lessonProgress.controller.js` - 6 catch blocks
- Controladores de progreso de lecciones

#### `src/api/middleware/auth.middleware.js` - 1 catch block
- Middleware de autenticación

## Próximos Pasos

Se agregará debug en este orden de prioridad:
1. ✅ services/scan/*.js (CRÍTICO - ya completado parcialmente)
2. ✅ services/phases/*.js (CRÍTICO - ya completado)
3. services/socket.service.js (resto de catches)
4. api/routes/scan.routes.js (importante)
5. Resto de routes y controllers (menor prioridad)

## Template de Debug para Catch Blocks

```javascript
} catch (error) {
    debug('ERROR en [NOMBRE_FUNCION]:', error);
    debug('Error message:', error.message);
    debug('Error stack:', error.stack);
    // Contexto adicional relevante
    // ... resto del código original
}
```
