# Testing de Resiliencia ante Desconexión del Navegador

## Cambios Implementados

### 1. Auto-save Periódico
- **Ubicación**: `scan-orchestrator.service.js`
- **Funcionalidad**: Guarda automáticamente el progreso cada 15 segundos durante el escaneo activo
- **Métodos agregados**:
  - `startAutoSave()`: Inicia el interval timer al comenzar el scan
  - `stopAutoSave()`: Limpia el timer al pausar, detener o completar

### 2. Estado Inmediato
- **Ubicación**: `scan-orchestrator.service.js` → método `start()`
- **Funcionalidad**: Actualiza `scan.estado = 'en_progreso'` inmediatamente al iniciar
- **Beneficio**: Permite detectar scans activos incluso si hay desconexión inmediata

### 3. Disconnect Handler
- **Ubicación**: `socket.service.js` → evento `socket.on('disconnect')`
- **Funcionalidad**: Cuando un socket se desconecta:
  1. Identifica qué scan estaba ejecutando ese socket
  2. Guarda el progreso actual (`saveProgress()`)
  3. Detiene el auto-save timer
  4. Mata procesos activos de sqlmap/dalfox
  5. Actualiza el estado a 'pausado' en BD
  6. Limpia el orchestrator de memoria

### 4. Limpieza de Recursos
- **Ubicación**: Múltiples métodos en `scan-orchestrator.service.js`
- **Funcionalidad**: `stopAutoSave()` se llama en:
  - `pause()`: Al pausar manualmente
  - `stop()`: Al detener manualmente
  - `start()` (éxito): Al completar exitosamente
  - `start()` (error): Al ocurrir un error crítico

## Escenarios de Testing

### Escenario 1: Cierre de Navegador Durante Escaneo
**Pasos:**
1. Iniciar un scan desde scan-progress
2. Esperar a que comience una subfase (ej: sqli-detection)
3. Cerrar el navegador/tab sin pausar el scan
4. Esperar 30 segundos
5. Reabrir la aplicación
6. Ir a my-scans
7. Reanudar el scan

**Resultado Esperado:**
- ✅ El scan muestra estado 'pausado' en my-scans
- ✅ Al reanudar, muestra todas las vulnerabilidades encontradas antes
- ✅ Reanuda desde la subfase correcta (no desde el inicio)
- ✅ No repite preguntas ya contestadas
- ✅ Los endpoints ya testeados no se vuelven a testear

### Escenario 2: Cambio de Página Durante Escaneo
**Pasos:**
1. Iniciar un scan desde scan-progress
2. Esperar a que descubra algunos endpoints
3. Navegar a otra página (ej: dashboard, scoreboard)
4. Esperar 30 segundos
5. Volver a my-scans
6. Reanudar el scan

**Resultado Esperado:**
- ✅ El progreso hasta el momento del cambio de página se guardó
- ✅ Los endpoints descubiertos están presentes
- ✅ Las vulnerabilidades encontradas se muestran
- ✅ El scan continúa desde donde se quedó

### Escenario 3: Pérdida de Conexión de Red
**Pasos:**
1. Iniciar un scan
2. Durante el scan, desconectar la red/WiFi
3. Esperar 1 minuto
4. Reconectar la red
5. Recargar la página
6. Ir a my-scans
7. Reanudar el scan

**Resultado Esperado:**
- ✅ El scan se guardó como 'pausado'
- ✅ Todo el progreso hasta la desconexión está preservado
- ✅ Los procesos de sqlmap/dalfox fueron terminados correctamente

### Escenario 4: Refresh de Página Durante Escaneo
**Pasos:**
1. Iniciar un scan
2. Durante el scan, presionar F5 o hacer refresh
3. Ir a my-scans
4. Reanudar el scan

**Resultado Esperado:**
- ✅ El scan se guardó correctamente antes del refresh
- ✅ Al reanudar, continúa desde donde se quedó
- ✅ No hay pérdida de datos

### Escenario 5: Completar Escaneo Normalmente
**Pasos:**
1. Iniciar un scan
2. Dejar que complete todas las fases
3. Verificar que el scan termine con estado 'completado'

**Resultado Esperado:**
- ✅ El auto-save se detiene al completar
- ✅ Todos los recursos se limpian correctamente
- ✅ El scan tiene estado 'completado' en BD

## Verificación de Logs

### Backend Logs (Consola del servidor)
Durante desconexión, deberías ver:
```
Socket <socket_id> disconnected
Suspendiendo scan <scan_id> por desconexión...
Scan <scan_id> suspendido exitosamente
```

### Base de Datos
Verificar en MongoDB que el documento del scan tenga:
```javascript
{
  estado: 'pausado',
  current_phase: 'sqli',
  current_subphase: 'sqli-detection', // o el que estaba activo
  completed_subphases: [...], // subfases completadas
  discovered_endpoints: [...], // endpoints descubiertos
  tested_endpoints_sqli: [...], // endpoints testeados
  vulnerabilidades: [...], // referencias a vulnerabilidades
  respuestas_usuario: [...] // preguntas respondidas
}
```

## Auto-Save Verification

Para verificar que el auto-save funciona:

1. Iniciar un scan
2. Abrir MongoDB Compass o mongosh
3. Observar el documento del scan
4. Cada 15 segundos, el documento debería actualizarse con el progreso actual
5. Verificar timestamps o cambios en los arrays (discovered_endpoints, etc.)

## Notas Importantes

- **Auto-save Interval**: 15 segundos (configurable en línea 205 de scan-orchestrator.service.js)
- **Estado en Desconexión**: 'pausado' (no 'error' ni 'detenido')
- **Procesos Activos**: Se terminan con SIGTERM en desconexión
- **questionAttempts**: No se persiste - se reinicia al reanudar (comportamiento aceptable)

## Posibles Mejoras Futuras

1. **Persistencia de questionAttempts**: Guardar intentos en BD en tiempo real
2. **Heartbeat Detection**: Detectar scans huérfanos después de X tiempo sin actividad
3. **Auto-resume**: Opción para reanudar automáticamente al reconectar
4. **Real-time Logs**: Persistir logs en BD en lugar de solo en memoria
5. **Configuración de Auto-save**: Hacer configurable el intervalo de 15 segundos
