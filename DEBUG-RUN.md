# Cómo Ejecutar el Backend con Debug Logging

## Módulo Debug Implementado

Se ha agregado el módulo `debug` en todos los archivos críticos del sistema para diagnosticar problemas al iniciar escaneos.

### Archivos con Debug Logging:

1. **scan-orchestrator.service.js** - `easyinjection:scan:orchestrator`
2. **socket.service.js** - `easyinjection:socket`
3. **question-handler.service.js** - `easyinjection:scan:questions`
4. **sqlmap-executor.service.js** - `easyinjection:scan:sqlmap`
5. **discovery.phase.js** - `easyinjection:scan:discovery`
6. **xss.phase.js** - `easyinjection:scan:xss`

## Comandos para Ejecutar con Debug

### Windows (PowerShell):
```powershell
# Ver TODOS los logs de debug
$env:DEBUG="easyinjection:*"; npm start

# Ver solo logs de scan orchestrator
$env:DEBUG="easyinjection:scan:orchestrator"; npm start

# Ver solo logs de socket
$env:DEBUG="easyinjection:socket"; npm start

# Ver solo logs de scan (orchestrator + sqlmap + questions + phases)
$env:DEBUG="easyinjection:scan:*"; npm start

# Combinar múltiples namespaces
$env:DEBUG="easyinjection:scan:orchestrator,easyinjection:socket"; npm start
```

### Windows (CMD):
```cmd
# Ver TODOS los logs de debug
set DEBUG=easyinjection:* && npm start

# Ver solo logs de scan orchestrator
set DEBUG=easyinjection:scan:orchestrator && npm start

# Ver solo logs de socket
set DEBUG=easyinjection:socket && npm start
```

### Linux/Mac (Bash):
```bash
# Ver TODOS los logs de debug
DEBUG=easyinjection:* npm start

# Ver solo logs de scan orchestrator
DEBUG=easyinjection:scan:orchestrator npm start

# Ver solo logs de socket
DEBUG=easyinjection:socket npm start

# Ver solo logs de scan (orchestrator + sqlmap + questions + phases)
DEBUG=easyinjection:scan:* npm start
```

## Qué Logs Verás

### Al Iniciar un Escaneo:

Con `DEBUG=easyinjection:*` verás:

```
easyinjection:socket === SCAN:START EVENT ===
easyinjection:socket Data recibida: {"scanId":"...","config":{...}}
easyinjection:socket ScanId: 675f1a2b3c4d5e6f7a8b9c0d
easyinjection:socket Config: {...}
easyinjection:socket Buscando scan en BD...
easyinjection:socket Scan encontrado: SI
easyinjection:socket Scan estado: pendiente
easyinjection:socket Verificando si scan ya está activo...
easyinjection:socket Cargando estado previo...
easyinjection:socket Estado previo: NO
easyinjection:socket Creando ScanOrchestrator...
easyinjection:scan:orchestrator Constructor llamado
easyinjection:socket ScanOrchestrator creado exitosamente
easyinjection:socket Orchestrator agregado a activeScans
easyinjection:socket Configurando listeners del orchestrator...
easyinjection:socket Listeners configurados
easyinjection:socket Emitiendo scan:status...
easyinjection:socket Guardando estado del scan en BD...
easyinjection:socket Estado guardado en BD
easyinjection:socket Iniciando orchestrator.start()...
easyinjection:scan:orchestrator === INICIO DE ESCANEO ===
easyinjection:scan:orchestrator ScanId: 675f1a2b3c4d5e6f7a8b9c0d
easyinjection:scan:orchestrator Config: {...}
easyinjection:scan:orchestrator Phases completed: []
easyinjection:scan:orchestrator Actualizando estado a en_progreso...
easyinjection:scan:orchestrator Estado actualizado: OK
easyinjection:scan:orchestrator Iniciando auto-save periódico...
easyinjection:scan:orchestrator Auto-save iniciado
easyinjection:scan:orchestrator Es reanudación? false
```

### Si Hay un Error:

```
easyinjection:scan:orchestrator ERROR CRÍTICO EN START: Error: ...
easyinjection:scan:orchestrator Error message: Invalid configuration
easyinjection:scan:orchestrator Error stack: Error: Invalid configuration
    at ScanOrchestrator.start (...)
    at ...
```

## Para Diagnosticar el Error Actual

Ejecuta el backend con:

```powershell
# PowerShell
$env:DEBUG="easyinjection:*"; npm start
```

O:

```bash
# Bash
DEBUG=easyinjection:* npm start
```

Luego:
1. Inicia un escaneo desde el frontend
2. Observa EXACTAMENTE dónde se detiene el flujo
3. Copia y pega el output completo del debug
4. El error mostrará el stack trace completo y el punto exacto donde falla

## Logs en Producción

Para **desactivar** los logs de debug en producción, simplemente NO configures la variable DEBUG:

```bash
npm start  # Sin DEBUG, no se muestran logs de debug
```

## Guardar Logs en Archivo

```bash
# Guardar todos los logs en archivo
DEBUG=easyinjection:* npm start > debug.log 2>&1

# En PowerShell
$env:DEBUG="easyinjection:*"; npm start *> debug.log
```

## Filtrar Logs en Tiempo Real

```bash
# Solo errores críticos
DEBUG=easyinjection:* npm start 2>&1 | grep "ERROR"

# Solo logs de orchestrator
DEBUG=easyinjection:scan:orchestrator npm start
```

## Importante

- Los logs de debug **NO afectan el performance** si DEBUG no está configurado
- Los logs se muestran en la consola del servidor, NO del navegador
- Los console.log/error en catches fueron reemplazados con debug para mejor control
- El color de los logs varía por namespace para fácil identificación
