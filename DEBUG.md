# Debug Configuration

Este proyecto utiliza el módulo `debug` de npm para logging estructurado.

## Uso

Para habilitar los logs, establece la variable de entorno `DEBUG`:

```powershell
# Ver todos los logs del proyecto
$env:DEBUG = "easyinjection:*"

# Ver logs de un módulo específico
$env:DEBUG = "easyinjection:models:*"
$env:DEBUG = "easyinjection:models:user"

# Ver múltiples módulos
$env:DEBUG = "easyinjection:models:scan,easyinjection:models:user"
```

## Namespaces Disponibles

### **Models - Catalog (4 archivos)**

- `easyinjection:models:severity` - `src/models/catalog/severity-level.model.js`
  - Logs de SeverityLevel (creación, conversión, operaciones CRUD)
  
- `easyinjection:models:vulntype` - `src/models/catalog/vulnerability-type.model.js`
  - Logs de VulnerabilityType (creación, conversión, operaciones CRUD)
  
- `easyinjection:models:gestordb` - `src/models/catalog/db-manager.model.js`
  - Logs de DBManager (gestores de base de datos, conexiones)

### **Models - Quiz (2 archivos)**

- `easyinjection:models:question` - `src/models/quiz/question.model.js`
  - Logs de Question (creación, random selection por fase, conversión)
  - `random: getting random question for phase %s`
  
- `easyinjection:models:answer` - `src/models/quiz/answer.model.js`
  - Logs de Answer (creación, validación de respuestas correctas)

### **Models - Scan (3 archivos)**

- `easyinjection:models:scan` - `src/models/scan/scan.model.js`
  - Logs de Scan (inicio, finalización, cálculo de score 60/40)
  - `calculateScore: calculating final score with 60/40 formula`
  
- `easyinjection:models:vulnerability` - `src/models/scan/vulnerability.model.js`
  - Logs de Vulnerability (creación, getRiskScore, CVSS calculation)
  - `getRiskScore: calculating for severity=%s type=%s`
  
- `easyinjection:models:report` - `src/models/scan/report.model.js`
  - Logs de Report y ReportSummary (generación de reportes, agregación de datos)

### **Models - User (4 archivos)**

- `easyinjection:models:user` - `src/models/user/user.model.js`
  - Logs completos del ciclo de vida del usuario:
    - Creación: `Usuario creado: %s (%s)`
    - Activación/Desactivación: `Activando usuario: %s`
    - Autenticación: `Generando token JWT para usuario: %s`
    - Email: `Verificando email con código para: %s`
    - Login: `Login actualizado para usuario: %s`
    - Puntos: `Agregando %d puntos a usuario: %s`
    - Historial: `Historial de respuestas actualizado`
    - Sesiones: `Sesión agregada/removida para usuario: %s`
    - Términos: `Términos aceptados por usuario: %s`
    - Password Reset: `Token de reseteo de contraseña establecido`

- `easyinjection:models:lessonProgress` - `src/models/user/lessonProgress.model.js`
  - Logs de progreso de lecciones:
    - `LessonProgress creado para usuario: %s con %d lecciones`
    - `Obteniendo progreso para usuario: %s`
    - `Creando nuevo progreso para usuario: %s`
    - `Marcando lección %s como vista/completada para usuario: %s`
    - `Obteniendo estadísticas de progreso`
    - `Obteniendo detalles de lección %s`

- `easyinjection:models:notification` - `src/models/user/notification.model.js`
  - Logs de notificaciones:
    - `Notificación creada: [%s] %s` (tipo y título)
    - `Marcando notificación como leída/no leída: %s`
    - `Creando nueva notificación para usuario %s: [%s] %s`

- `easyinjection:models:activity` - `src/models/user/activity.model.js`
  - Logs de actividades del usuario:
    - `Activity creada: %s - %s` (tipo y título)
    - `Marcando actividad como leída/no leída: %s`

### **Base Model**

- Todos los modelos heredan de `BaseModel.js` que implementa:
  - `fromMongoose: converting to %s` (conversión de documentos Mongoose a POO)
  - Logging automático usando el namespace del modelo hijo

## Estructura del Proyecto (POO)

El proyecto utiliza programación orientada a objetos con las siguientes capas:

### **Value Objects** (`src/models/value-objects/`)
- `ScanFlags` - Flags de tipo de escaneo (XSS, SQLi)
- `Credentials` - Credenciales de autenticación
- `UserAnswer` - Respuestas del usuario en cuestionarios
- `Score` - Sistema de puntuación 60/40 (quiz + seguridad)

### **Base Classes** (`src/models/base/`)
- `BaseModel` - Clase base con métodos comunes (fromMongoose, toObject, toDTO)
- `ModelHelpers` - Utilidades para construcción de objetos

### **Models Organization**
```
src/models/
├── base/           - Clases base y helpers
├── catalog/        - Catálogos del sistema (severidad, tipos, gestores)
├── quiz/          - Sistema de cuestionarios (preguntas y respuestas)
├── scan/          - Escaneos de seguridad (scan, vulnerabilidades, reportes)
├── user/          - Usuarios y datos relacionados (perfil, notificaciones, actividades)
└── value-objects/ - Objetos de valor inmutables
```

## Patrones de Diseño

- **POO Encapsulación**: Campos privados con `#` notation
- **Factory Pattern**: `fromMongoose()` para conversión de documentos
- **Value Objects**: Objetos inmutables para datos de dominio
- **DTO Pattern**: `toDTO()` para serialización a frontend
- **Static Access**: `.Model` para acceso al modelo Mongoose desde clases POO

## Comandos Útiles

```powershell
# Ver logs de scoring
$env:DEBUG = "easyinjection:models:scan"; npm start

# Ver logs de usuario y autenticación
$env:DEBUG = "easyinjection:models:user"; npm start

# Ver logs de cuestionarios
$env:DEBUG = "easyinjection:models:question,easyinjection:models:answer"; npm start

# Ver logs de vulnerabilidades
$env:DEBUG = "easyinjection:models:vulnerability,easyinjection:models:severity"; npm start

# Ver todos los logs de modelos
$env:DEBUG = "easyinjection:models:*"; npm start
```

## Notas

- Las rutas, servicios y middleware **NO** tienen debug configurado actualmente
- Solo los modelos implementan logging con el módulo `debug`
- Los logs se pueden habilitar selectivamente sin afectar el rendimiento en producción