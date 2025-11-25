const mongoose = require('mongoose');
require('dotenv').config();
const { Question } = require('../src/models/quiz/question.model');
const { Answer } = require('../src/models/quiz/answer.model');

const db = process.env.EASYINJECTION_DB;

const questions = [
  {
    texto_pregunta: 'La seguridad en aplicaciones web se enfoca principalmente en:',
    dificultad: 'facil',
    puntos: 10,
    fase: 'init',
    respuestas: [
      { texto: 'Reducir comportamientos inesperados entre módulos de la aplicación para mantener la estabilidad operativa.', es_correcta: false },
      { texto: 'Proteger la integridad, confidencialidad y disponibilidad de los sistemas.', es_correcta: true },
      { texto: 'Garantizar la continuidad del soporte para componentes desactualizados utilizados por navegadores antiguos.', es_correcta: false },
      { texto: 'Ajustar el uso de recursos del servidor para mejorar la eficiencia del sistema sin modificar la lógica interna.', es_correcta: false }
    ]
  },
  {
    texto_pregunta: '¿Qué te sugiere un archivo robots.txt con múltiples rutas deshabilitadas?',
    dificultad: 'media',
    puntos: 15,
    fase: 'init',
    respuestas: [
      { texto: 'Que la aplicación utiliza HTTP/3 como protocolo principal.', es_correcta: false },
      { texto: 'Que el servidor se encuentra temporalmente fuera de servicio para actualizaciones.', es_correcta: false },
      { texto: 'Que existen endpoints relevantes que podrían no ser públicos', es_correcta: true },
      { texto: 'Que el sitio requiere autenticación mediante certificados de cliente.', es_correcta: false }
    ]
  },
  {
    texto_pregunta: 'Durante el reconocimiento y fingerprinting, ¿qué indicador puede revelar el framework utilizado?',
    dificultad: 'media',
    puntos: 15,
    fase: 'init',
    respuestas: [
      { texto: 'La zona horaria o configuración horaria del navegador del cliente.', es_correcta: false },
      { texto: 'La resolución o dimensiones del monitor utilizado por el usuario.', es_correcta: false },
      { texto: 'Encabezados HTTP característicos de ciertos servidores', es_correcta: true },
      { texto: 'El tamaño del correo electrónico ingresado durante el formulario de registro.', es_correcta: false }
    ]
  },
  {
    texto_pregunta: '¿Cuál es una técnica común para enumerar aplicaciones alojadas en un mismo servidor, además del crawling utilizado para descubrir rutas automáticamente?',
    dificultad: 'media',
    puntos: 15,
    fase: 'discovery',
    respuestas: [
      { texto: 'Ajustar el brillo o modo de color del navegador.', es_correcta: false },
      { texto: 'Cambiar la hora local del dispositivo para observar diferencias de sesión.', es_correcta: false },
      { texto: 'Probar rutas típicas como /admin, /test, /backup', es_correcta: true },
      { texto: 'Desactivar la carga automática de imágenes para acelerar la navegación.', es_correcta: false }
    ]
  },
  {
    texto_pregunta: '¿Cuál es una razón común por la que los parámetros GET se consideran vectores de ataque?',
    dificultad: 'media',
    puntos: 15,
    fase: 'parameters',
    respuestas: [
      { texto: 'Son los más fáciles de ordenar alfabéticamente', es_correcta: false },
      { texto: 'No requieren que el servidor almacene sesiones', es_correcta: false },
      { texto: 'Pueden ser modificados sin controles previos del cliente', es_correcta: true },
      { texto: 'Están protegidos por defecto por todos los frameworks', es_correcta: false }
    ]
  },
  {
    texto_pregunta: '¿Qué es SQL Injection?',
    dificultad: 'facil',
    puntos: 10,
    fase: 'sqli-detection',
    respuestas: [
      { texto: 'Una metodología para combinar parámetros y consultas SQL en una estructura optimizada para el servidor.', es_correcta: false },
      { texto: 'Una vulnerabilidad que permite manipular o alterar consultas que la aplicación envía a la base de datos.', es_correcta: true },
      { texto: 'Un mecanismo utilizado por motores SQL para reordenar índices y acelerar el proceso de búsqueda.', es_correcta: false },
      { texto: 'Un proceso de validación que cifra las operaciones antes de almacenar datos sensibles en una tabla.', es_correcta: false }
    ]
  },
  {
    texto_pregunta: '¿Cuál es un indicio común de SQL Injection en una respuesta HTTP?',
    dificultad: 'facil',
    puntos: 10,
    fase: 'sqli-detection',
    respuestas: [
      { texto: 'Un mensaje de error que revela detalles del motor o sintaxis de la base de datos.', es_correcta: true },
      { texto: 'La devolución de una página con los mismos elementos pero con encabezados de caché modificados.', es_correcta: false },
      { texto: 'Un incremento ligero en el tiempo de respuesta causado por validaciones adicionales del servidor.', es_correcta: false },
      { texto: 'Un redireccionamiento automático a una ruta previamente almacenada en caché.', es_correcta: false }
    ]
  },
  {
    texto_pregunta: '¿Cuál es un indicador de que se debe usar la técnica time-based blind SQL injection?',
    dificultad: 'media',
    puntos: 15,
    fase: 'sqli-detection',
    respuestas: [
      { texto: 'Que se puede deducir información de la base de datos analizando retrasos generados de forma intencional.', es_correcta: true },
      { texto: 'Que el servidor realiza verificaciones automáticas de latencia para compensar problemas de red.', es_correcta: false },
      { texto: 'Que la aplicación no detalla errores SQL visibles, aunque haya fallos en la consulta.', es_correcta: false },
      { texto: 'Que la vulnerabilidad depende del navegador utilizado por el usuario final y no del procesamiento del servidor.', es_correcta: false }
    ]
  },
  {
    texto_pregunta: '¿Cuál es una prueba manual básica para detectar SQL injection?',
    dificultad: 'facil',
    puntos: 10,
    fase: 'sqli-detection',
    respuestas: [
      { texto: 'Probar entradas con etiquetas HTML simples para verificar si son procesadas en el servidor.', es_correcta: false },
      { texto: "Enviar una comilla simple ( ' ) y observar si se generan errores o cambios inesperados.", es_correcta: true },
      { texto: 'Revisar las cabeceras HTTP en busca de tokens que no correspondan al flujo normal de autenticación.', es_correcta: false },
      { texto: 'Confirmar si el sitio expone rutas internas mediante respuestas del archivo robots del sistema.', es_correcta: false }
    ]
  },
  {
    texto_pregunta: '¿Qué hace la carga OR 1=1 cuando se inyecta en una cláusula WHERE?',
    dificultad: 'facil',
    puntos: 10,
    fase: 'sqli-detection',
    respuestas: [
      { texto: 'Hace que la condición se evalúe como verdadera para todas las filas y aumenta los resultados devueltos.', es_correcta: true },
      { texto: 'Provoca que el motor de bases de datos redirija la consulta hacia un índice secundario.', es_correcta: false },
      { texto: 'Hace que la conexión SQL entre en modo de aislamiento para evitar errores de concurrencia.', es_correcta: false },
      { texto: 'Activa un mecanismo de filtrado que limita columnas sensibles en la respuesta final.', es_correcta: false }
    ]
  },
  {
    texto_pregunta: '¿Qué caracteriza a un SQLi "blind" (ciego)?',
    dificultad: 'media',
    puntos: 15,
    fase: 'sqli-detection',
    respuestas: [
      { texto: 'La aplicación procesa las consultas y muestra resultados completos sin restricciones visibles.', es_correcta: false },
      { texto: 'No se devuelven resultados claros ni errores; el atacante extrae información mediante cambios en tiempos, comportamientos o canales indirectos.', es_correcta: true },
      { texto: 'Se presenta únicamente cuando la base de datos utiliza esquemas no relacionales sin soporte para errores detallados.', es_correcta: false },
      { texto: 'Se manifiesta directamente en el contenido renderizado como modificaciones visibles en el DOM.', es_correcta: false }
    ]
  },
  {
    texto_pregunta: '¿Qué diferencia hay entre SQL injection de primer orden y segundo orden?',
    dificultad: 'media',
    puntos: 15,
    fase: 'sqli-detection',
    respuestas: [
      { texto: 'La de segundo orden se almacena y se activa posteriormente cuando la aplicación reutiliza el valor, mientras que la de primer orden ocurre en la misma interacción con el servidor.', es_correcta: true },
      { texto: 'Ambas siguen exactamente el mismo proceso y se consideran equivalentes en términos prácticos.', es_correcta: false },
      { texto: 'La de segundo orden requiere una combinación con otro vector como un XSS reflejado antes de ejecutarse, mientras que la de primer orden ocurre en la misma interacción con el servidor', es_correcta: false },
      { texto: 'La de primer orden únicamente afecta a sistemas sin un ORM o sin mecanismos de parametrización, mientras que la de segundo orden afecta a sistemas con más protecciones.', es_correcta: false }
    ]
  },
  {
    texto_pregunta: '¿Por qué no sirven las prepared statements para prevenir inyecciones en partes de la query como nombres de tabla o ORDER BY?',
    dificultad: 'dificil',
    puntos: 20,
    fase: 'sqli-detection',
    respuestas: [
      { texto: 'Porque solo permiten parametrizar valores de datos, no identificadores ni fragmentos completos de la sintaxis SQL.', es_correcta: true },
      { texto: 'Porque generan una sobrecarga significativa en la ejecución de consultas complejas en el servidor.', es_correcta: false },
      { texto: 'Porque dependen del entorno del cliente y no del motor de la base de datos.', es_correcta: false },
      { texto: 'Porque su funcionamiento está limitado exclusivamente a operaciones de lectura simples.', es_correcta: false }
    ]
  },
  {
    texto_pregunta: '¿Qué técnica es útil para identificar el motor de base de datos tras encontrar un SQLi?',
    dificultad: 'media',
    puntos: 15,
    fase: 'sqli-fingerprint',
    respuestas: [
      { texto: 'Realizar consultas características como SELECT * FROM information_schema.tables o variantes como SELECT * FROM v$version, según el motor.', es_correcta: true },
      { texto: 'Examinar el contenido HTML devuelto buscando comentarios que incluyan referencias a la infraestructura.', es_correcta: false },
      { texto: 'Ejecutar una función en el navegador que intente inferir el tipo de base de datos desde el lado del cliente.', es_correcta: false },
      { texto: 'Revisar elementos estáticos del sitio, como iconos o recursos cargados de forma predeterminada.', es_correcta: false }
    ]
  },
  {
    texto_pregunta: '¿Qué acción evita eficazmente la mayoría de las SQL injection clásicas en la capa de acceso a datos?',
    dificultad: 'facil',
    puntos: 10,
    fase: 'sqli-exploit',
    respuestas: [
      { texto: 'Construir consultas uniendo valores dinámicos y parámetros directamente en cadenas de texto.', es_correcta: false },
      { texto: 'Utilizar consultas parametrizadas para separar la lógica SQL de los datos proporcionados por el usuario.', es_correcta: true },
      { texto: 'Almacenar credenciales cifradas para minimizar el impacto en brechas de seguridad en la base de datos.', es_correcta: false },
      { texto: 'Ejecutar todas las consultas con un usuario de permisos reducidos como mecanismo único de protección.', es_correcta: false }
    ]
  },
  {
    texto_pregunta: '¿Cuál es un posible impacto de un SQL injection exitoso?',
    dificultad: 'media',
    puntos: 15,
    fase: 'sqli-exploit',
    respuestas: [
      { texto: 'La activación de reglas temporales del firewall que limitan solicitudes según el tráfico observado.', es_correcta: false },
      { texto: 'Acceso no autorizado a datos sensibles, modificaciones persistentes e incluso la inserción de puertas traseras en el sistema.', es_correcta: true },
      { texto: 'Una disminución en el tamaño de ciertas tablas debido a procesos automáticos de reorganización.', es_correcta: false },
      { texto: 'Leves caídas de rendimiento asociadas a la generación de registros adicionales por parte del motor.', es_correcta: false }
    ]
  },
  {
    texto_pregunta: '¿Qué es OAST (Out-of-Band Application Security Testing) en el contexto de SQL injection?',
    dificultad: 'dificil',
    puntos: 20,
    fase: 'sqli-exploit',
    respuestas: [
      { texto: 'Un enfoque basado en ofuscar cargas útiles utilizando transformaciones estructuradas en XML.', es_correcta: false },
      { texto: 'Una técnica que usa canales fuera de banda (DNS/HTTP) para detectar o exfiltrar datos cuando la respuesta directa no revela información.', es_correcta: true },
      { texto: 'Un encabezado utilizado para negociar políticas de seguridad entre cliente y servidor y que mitiga el impacto de las vulnerabilidades de SQL injection.', es_correcta: false },
      { texto: 'Un tipo particular de consulta preparada utilizado al ejecutar operaciones remotas.', es_correcta: false }
    ]
  },
  {
    texto_pregunta: '¿Cuál es una técnica para intentar burlar filtros/WAFs al realizar Inyección SQL?',
    dificultad: 'media',
    puntos: 15,
    fase: 'sqli-exploit',
    respuestas: [
      { texto: 'Usar codificaciones alternativas y caracteres equivalentes que el servidor decodifica antes de ejecutar la consulta.', es_correcta: true },
      { texto: 'Cambiar la dirección IP del servidor objetivo para modificar la superficie de exposición, evadiendo protecciones basadas en IP.', es_correcta: false },
      { texto: 'Incluir un disparador de JavaScript simple dentro de la carga para ofuscar el payload y este no sea fácilmente reconocible.', es_correcta: false },
      { texto: 'Subir un ejecutable al sistema para verificar cómo responde el servidor.', es_correcta: false }
    ]
  },
  {
    texto_pregunta: '¿Cuál es el objetivo principal al probar un ataque basado en UNION?',
    dificultad: 'dificil',
    puntos: 20,
    fase: 'sqli-exploit',
    respuestas: [
      { texto: 'Disminuir el volumen de solicitudes enviadas por el cliente.', es_correcta: false },
      { texto: 'Insertar comentarios HTML o estructuras invisibles en la respuesta.', es_correcta: false },
      { texto: 'Combinar resultados con el fin de obtener información adicional desde otras tablas', es_correcta: true },
      { texto: 'Obligar al navegador a ignorar scripts que se ejecutan de forma predeterminada.', es_correcta: false }
    ]
  },
  {
    texto_pregunta: '¿Qué condición debe cumplirse para que una SQLi permita extraer datos mediante UNION?',
    dificultad: 'dificil',
    puntos: 20,
    fase: 'sqli-exploit',
    respuestas: [
      { texto: 'Que el servidor esté en hora UTC', es_correcta: false },
      { texto: 'Que la consulta vulnerable incluya operadores OR', es_correcta: false },
      { texto: 'Que el número de columnas coincida entre ambas consultas', es_correcta: true },
      { texto: 'Que la aplicación acepte únicamente parámetros numéricos', es_correcta: false }
    ]
  },
  {
    texto_pregunta: '¿Cuál es la definición de Cross-Site Scripting (XSS)?',
    dificultad: 'facil',
    puntos: 10,
    fase: 'xss-context',
    respuestas: [
      { texto: 'La inserción de contenido HTML malicioso procesado únicamente en la lógica del servidor a través de una página web.', es_correcta: false },
      { texto: 'La inyección de código malicioso JavaScript que se ejecuta en el navegador de otros usuarios a través de una página web.', es_correcta: true },
      { texto: 'La manipulación del tráfico TCP con el fin de alterar respuestas HTML en tránsito.', es_correcta: false },
      { texto: 'Una técnica para inducir a los navegadores a cargar recursos externos sin que se ejecuten scripts.', es_correcta: false }
    ]
  },
  {
    texto_pregunta: 'Contextos de XSS a considerar al diseñar payloads:',
    dificultad: 'facil',
    puntos: 10,
    fase: 'xss-context',
    respuestas: [
      { texto: 'Solo contenido textual dentro del cuerpo HTML.', es_correcta: false },
      { texto: 'HTML, atributos, JavaScript, URL, CSS…', es_correcta: true },
      { texto: 'Exclusivamente estructuras de datos JSON en respuestas API.', es_correcta: false },
      { texto: 'Únicamente encabezados generados por el servidor.', es_correcta: false }
    ]
  },
  {
    texto_pregunta: 'DOM-based XSS aparece cuando…',
    dificultad: 'facil',
    puntos: 10,
    fase: 'xss-context',
    respuestas: [
      { texto: 'El servidor construye instrucciones SQL sin validar parámetros dentro del DOM', es_correcta: false },
      { texto: 'El código del cliente procesa y escribe datos no confiables en el DOM de forma insegura.', es_correcta: true },
      { texto: 'El navegador aplica restricciones automáticas en la apertura de ventanas emergentes que influyen directamente en el DOM', es_correcta: false },
      { texto: 'Se emplean cookies con atributos seguros para evitar exposición accidental.', es_correcta: false }
    ]
  },
  {
    texto_pregunta: '¿Cómo se detecta manualmente XSS reflejado/almacenado?',
    dificultad: 'facil',
    puntos: 10,
    fase: 'xss-context',
    respuestas: [
      { texto: 'Inspeccionando reglas de estilo que puedan causar errores de interpretación en el código JavaScript de la aplicación.', es_correcta: false },
      { texto: 'Enviando entradas identificables y verificando si aparecen en la respuesta y ejecutan JavaScript según el contexto', es_correcta: true },
      { texto: 'Cambiando el valor del User-Agent para analizar variaciones.', es_correcta: false },
      { texto: 'Probando únicamente atributos de eventos como onload', es_correcta: false }
    ]
  },
  {
    texto_pregunta: '¿Cuál de estas es un sink riesgoso para DOM XSS?',
    dificultad: 'facil',
    puntos: 10,
    fase: 'xss-context',
    respuestas: [
      { texto: 'innerHTML', es_correcta: true },
      { texto: 'toUpperCase()', es_correcta: false },
      { texto: 'Array.map()', es_correcta: false },
      { texto: 'console.info()', es_correcta: false }
    ]
  },
  {
    texto_pregunta: 'Ejemplo de sink en el DOM que provoca JavaScript injection en cliente:',
    dificultad: 'facil',
    puntos: 10,
    fase: 'xss-context',
    respuestas: [
      { texto: 'eval()', es_correcta: true },
      { texto: 'JSON.stringify()', es_correcta: false },
      { texto: 'Object.freeze()', es_correcta: false },
      { texto: 'encodeURIComponent()', es_correcta: false }
    ]
  },
  {
    texto_pregunta: '¿Qué sink en el DOM se asocia a "Web message manipulation"?',
    dificultad: 'dificil',
    puntos: 20,
    fase: 'xss-context',
    respuestas: [
      { texto: 'postMessage()', es_correcta: true },
      { texto: 'localStorage.getItem()', es_correcta: false },
      { texto: 'document.evaluate()', es_correcta: false },
      { texto: 'RegExp()', es_correcta: false }
    ]
  },
  {
    texto_pregunta: '¿Qué fuente permite ataques al leer la URL completa sin sanitizar?',
    dificultad: 'media',
    puntos: 15,
    fase: 'xss-context',
    respuestas: [
      { texto: 'document.baseURI', es_correcta: false },
      { texto: 'document.URL/document.documentURI', es_correcta: true },
      { texto: 'navigator.userAgent con spoofing imposible', es_correcta: false },
      { texto: 'Date.toISOString()', es_correcta: false }
    ]
  },
  {
    texto_pregunta: 'Un ejemplo de sink en el DOM asociado a manipulación de enlaces (link manipulation) es:',
    dificultad: 'media',
    puntos: 15,
    fase: 'xss-context',
    respuestas: [
      { texto: 'element.src', es_correcta: true },
      { texto: 'document.cookie', es_correcta: false },
      { texto: 'setTimeout()', es_correcta: false },
      { texto: 'history.pushState()', es_correcta: false }
    ]
  },
  {
    texto_pregunta: 'Si un script hace document.body.innerHTML = userInput; con userInput tomado de document.URL, el riesgo es:',
    dificultad: 'facil',
    puntos: 10,
    fase: 'xss-context',
    respuestas: [
      { texto: 'SQLi', es_correcta: false },
      { texto: 'DOM XSS', es_correcta: true },
      { texto: 'CSRF', es_correcta: false },
      { texto: 'SSRF', es_correcta: false }
    ]
  },
  {
    texto_pregunta: 'Durante una prueba de XSS reflejado, ¿qué lugar es más común para detectar la inyección?',
    dificultad: 'media',
    puntos: 15,
    fase: 'xss-context',
    respuestas: [
      { texto: 'En encabezados relacionados con dispositivos de impresión.', es_correcta: false },
      { texto: 'En registros internos del sistema operativo del servidor.', es_correcta: false },
      { texto: 'En parámetros incluidos directamente en la URL de la petición.', es_correcta: true },
      { texto: 'En configuraciones vinculadas al manejo de certificados del sitio.', es_correcta: false }
    ]
  },
  {
    texto_pregunta: '¿Qué es el DOM?',
    dificultad: 'facil',
    puntos: 10,
    fase: 'xss-context',
    respuestas: [
      { texto: 'Un procedimiento que analiza tiempos de respuesta para estimar comportamientos anómalos.', es_correcta: false },
      { texto: 'El recorrido de datos controlables por el atacante desde una fuente insegura hasta un punto donde pueden causar efectos peligrosos.', es_correcta: true },
      { texto: 'Un método para reducir el tamaño de recursos mediante compresión.', es_correcta: false },
      { texto: 'Un componente que filtra tráfico malicioso a nivel de navegador.', es_correcta: false }
    ]
  },
  {
    texto_pregunta: '¿Qué es "taint flow" en el contexto de vulnerabilidades DOM-based?',
    dificultad: 'media',
    puntos: 15,
    fase: 'xss-context',
    respuestas: [
      { texto: 'Un procedimiento que analiza tiempos de respuesta para estimar comportamientos anómalos.', es_correcta: false },
      { texto: 'El recorrido de datos controlables por el atacante desde una fuente insegura hasta un punto donde pueden causar efectos peligrosos.', es_correcta: true },
      { texto: 'Un método para reducir el tamaño de recursos mediante compresión.', es_correcta: false },
      { texto: 'Un componente que filtra tráfico malicioso a nivel de navegador.', es_correcta: false }
    ]
  },
  {
    texto_pregunta: '¿Cuál NO es una fuente común para taint flow?',
    dificultad: 'dificil',
    puntos: 20,
    fase: 'xss-context',
    respuestas: [
      { texto: 'document.cookie', es_correcta: false },
      { texto: 'document.referrer', es_correcta: false },
      { texto: 'window.name', es_correcta: false },
      { texto: 'process.env', es_correcta: true }
    ]
  },
  {
    texto_pregunta: '¿Cuál es la diferencia clave entre XSS y CSRF?',
    dificultad: 'media',
    puntos: 15,
    fase: 'xss-context',
    respuestas: [
      { texto: 'XSS obliga el uso de métodos POST, mientras que CSRF solo se basa en solicitudes GET.', es_correcta: false },
      { texto: 'XSS ejecuta código controlado por el atacante en el navegador; CSRF fuerza acciones legítimas sin interacción del usuario.', es_correcta: true },
      { texto: 'XSS únicamente compromete cuentas administrativas, mientras que CSRF afecta a usuarios estándar.', es_correcta: false },
      { texto: 'No existe diferencia práctica, ambos ataques funcionan igual.', es_correcta: false }
    ]
  },
  {
    texto_pregunta: '¿Qué atributo ayuda a impedir que JavaScript acceda a una cookie?',
    dificultad: 'facil',
    puntos: 10,
    fase: 'xss-fuzzing',
    respuestas: [
      { texto: 'Secure', es_correcta: false },
      { texto: 'HttpOnly', es_correcta: true },
      { texto: 'SameSite', es_correcta: false },
      { texto: 'X-Frame-Options', es_correcta: false }
    ]
  },
  {
    texto_pregunta: '¿Qué tipo de XSS ocurre cuando la entrada del usuario se almacena en la base de datos y se muestra a otros usuarios?',
    dificultad: 'facil',
    puntos: 10,
    fase: 'xss-fuzzing',
    respuestas: [
      { texto: 'Reflected XSS', es_correcta: false },
      { texto: 'Stored XSS', es_correcta: true },
      { texto: 'DOM-based XSS', es_correcta: false },
      { texto: 'CSP XSS', es_correcta: false }
    ]
  },
  {
    texto_pregunta: '¿Qué significa que una vulnerabilidad sea persistente (Stored XSS)?',
    dificultad: 'facil',
    puntos: 10,
    fase: 'xss-fuzzing',
    respuestas: [
      { texto: 'Que es de alta complejidad y difícil de remediar.', es_correcta: false },
      { texto: 'Que la carga maliciosa se guarda en el servidor y afecta a múltiples usuarios posteriores.', es_correcta: true },
      { texto: 'Que la vulnerabilidad sólo se presenta en sesiones autenticadas con tokens persistentes.', es_correcta: false },
      { texto: 'Que el payload se guarda en la caché del navegador y se replica en peticiones subsiguientes.', es_correcta: false }
    ]
  },
  {
    texto_pregunta: '¿Cuál de las siguientes prácticas reduce la ventana de exposición si ocurre un XSS que roba cookies de sesión?',
    dificultad: 'media',
    puntos: 15,
    fase: 'xss-fuzzing',
    respuestas: [
      { texto: 'Marcar cookies como HttpOnly y Secure.', es_correcta: true },
      { texto: 'Usar nombres de cookies triviales.', es_correcta: false },
      { texto: 'Aumentar la duración de la sesión.', es_correcta: false },
      { texto: 'Almacenar la sesión solo en el cliente.', es_correcta: false }
    ]
  },
  {
    texto_pregunta: '¿Cuál NO es un tipo principal de XSS?',
    dificultad: 'facil',
    puntos: 10,
    fase: 'xss-fuzzing',
    respuestas: [
      { texto: 'Reflected.', es_correcta: false },
      { texto: 'Stored.', es_correcta: false },
      { texto: 'DOM-based.', es_correcta: false },
      { texto: 'Server-based.', es_correcta: true }
    ]
  },
  {
    texto_pregunta: 'Cabeceras que ayudan a reducir XSS en respuestas que no deben contener HTML/JS:',
    dificultad: 'media',
    puntos: 15,
    fase: 'xss-fuzzing',
    respuestas: [
      { texto: 'Content-Type y X-Content-Type-Options.', es_correcta: true },
      { texto: 'Accept-Language y ETag.', es_correcta: false },
      { texto: 'Server y Date.', es_correcta: false },
      { texto: 'Location y Upgrade-Insecure-Requests.', es_correcta: false }
    ]
  },
  {
    texto_pregunta: 'Para "Client-side XPath injection", el sink típico es:',
    dificultad: 'dificil',
    puntos: 20,
    fase: 'xss-fuzzing',
    respuestas: [
      { texto: 'document.evaluate()', es_correcta: true },
      { texto: 'WebSocket()', es_correcta: false },
      { texto: 'ExecuteSql()', es_correcta: false },
      { texto: 'sessionStorage.setItem()', es_correcta: false }
    ]
  },
  {
    texto_pregunta: 'Impacto potencial de XSS:',
    dificultad: 'facil',
    puntos: 10,
    fase: 'xss-fuzzing',
    respuestas: [
      { texto: 'Alteraciones menores en la interfaz sin modificar el comportamiento del usuario.', es_correcta: false },
      { texto: 'Suplantación de usuario y ejecución de acciones con los privilegios de la víctima.', es_correcta: true },
      { texto: 'Desactivación de funciones críticas del servidor mediante llamadas directas.', es_correcta: false },
      { texto: 'Interrupción de conexiones seguras como HTTPS sin interacción adicional.', es_correcta: false }
    ]
  },
  {
    texto_pregunta: '¿Qué es dangling markup injection?',
    dificultad: 'dificil',
    puntos: 20,
    fase: 'xss-fuzzing',
    respuestas: [
      { texto: 'Una variante de ataque que busca manipular solicitudes autenticadas sin intervención del usuario.', es_correcta: false },
      { texto: 'Una técnica que aprovecha el cierre incompleto de marcadores HTML para filtrar información cuando un XSS completo no es viable.', es_correcta: true },
      { texto: 'Un mecanismo interno del navegador utilizado para bloquear contenido mixto.', es_correcta: false },
      { texto: 'Un procedimiento para generar valores hash en formularios web.', es_correcta: false }
    ]
  },
  {
    texto_pregunta: '¿Qué vulnerabilidad se produce si el código hace location = goto con goto tomado de location.hash y sólo valida que empiece con https: ?',
    dificultad: 'media',
    puntos: 15,
    fase: 'xss-fuzzing',
    respuestas: [
      { texto: 'SQL Injection', es_correcta: false },
      { texto: 'DOM-based open redirection', es_correcta: true },
      { texto: 'Clickjacking', es_correcta: false },
      { texto: 'Directory traversal', es_correcta: false }
    ]
  },
  {
    texto_pregunta: '¿Qué combinación describe mejor cómo prevenir taint-flow en cliente?',
    dificultad: 'dificil',
    puntos: 20,
    fase: 'xss-fuzzing',
    respuestas: [
      { texto: 'Validación mediante listas blancas y sanitización/encoding específico del contexto.', es_correcta: true },
      { texto: 'Reducir el tamaño del código minificándolo para evitar manipulación directa.', es_correcta: false },
      { texto: 'Utilizar HTTP/3 para mejorar el manejo de recursos entre cliente y servidor.', es_correcta: false },
      { texto: 'Migrar la aplicación a un framework SPA moderno para evitar entradas directas.', es_correcta: false }
    ]
  },
  {
    texto_pregunta: 'Mitigación correcta cuando debes permitir redirecciones controladas por usuario (open redirect DOM):',
    dificultad: 'media',
    puntos: 15,
    fase: 'xss-fuzzing',
    respuestas: [
      { texto: 'Aceptar cualquier URL siempre que comience con http o https como medida mínima, evitando así prefijos peligrosos como javascript:', es_correcta: false },
      { texto: 'Utilizar una lista blanca de rutas o identificadores internos y construir la URL final en cliente o servidor.', es_correcta: true },
      { texto: 'Cambiar cualquier asignación de location por una escritura directa en innerHTML.', es_correcta: false },
      { texto: 'Ejecutar la redirección solamente mediante window.open() para aislar la navegación.', es_correcta: false }
    ]
  },
  {
    texto_pregunta: '¿Qué ventaja proporciona una política CSP bien configurada frente a ataques XSS?',
    dificultad: 'media',
    puntos: 15,
    fase: 'xss-fuzzing',
    respuestas: [
      { texto: 'Mejora el SEO del sitio', es_correcta: false },
      { texto: 'Asegura compatibilidad con navegadores antiguos', es_correcta: false },
      { texto: 'Limita la ejecución de scripts no autorizados', es_correcta: true },
      { texto: 'Aumenta la velocidad de renderizado del DOM', es_correcta: false }
    ]
  },
  {
    texto_pregunta: '¿Por qué algunos payloads XSS incluyen variantes como <svg/onload=...>?',
    dificultad: 'media',
    puntos: 15,
    fase: 'xss-fuzzing',
    respuestas: [
      { texto: 'Porque SVG acelera el renderizado', es_correcta: false },
      { texto: 'Para probar contextos menos filtrados y vectores alternativos', es_correcta: true },
      { texto: 'Para reducir el consumo de memoria del navegador', es_correcta: false },
      { texto: 'Porque evitan completamente los filtros de CSP', es_correcta: false }
    ]
  }
];

async function updateQuestions() {
  try {
    console.log('Conectando a la base de datos...');
    await mongoose.connect(db);
    console.log('Conectado exitosamente a MongoDB');

    console.log('\nEliminando preguntas antiguas...');
    const deletedQuestions = await Question.Model.deleteMany({});
    console.log(`${deletedQuestions.deletedCount} preguntas eliminadas`);

    console.log('Eliminando respuestas antiguas...');
    const deletedAnswers = await Answer.Model.deleteMany({});
    console.log(`${deletedAnswers.deletedCount} respuestas eliminadas`);

    console.log('\nInsertando nuevas preguntas...');
    let questionCount = 0;
    let answerCount = 0;

    for (const questionData of questions) {
      const question = await Question.Model.create({
        texto_pregunta: questionData.texto_pregunta,
        dificultad: questionData.dificultad,
        puntos: questionData.puntos,
        fase: questionData.fase
      });

      questionCount++;
      console.log(`Pregunta ${questionCount}: "${questionData.texto_pregunta.substring(0, 50)}..." [${questionData.fase}]`);

      for (const answerData of questionData.respuestas) {
        await Answer.Model.create({
          pregunta_id: question._id,
          texto_respuesta: answerData.texto,
          es_correcta: answerData.es_correcta
        });
        answerCount++;
      }
    }

    console.log('\nMigración completada exitosamente!');
    console.log(`Total de preguntas insertadas: ${questionCount}`);
    console.log(`Total de respuestas insertadas: ${answerCount}`);

    console.log('\nResumen por fase:');
    const phases = ['init', 'discovery', 'parameters', 'sqli-detection', 'sqli-fingerprint', 'sqli-exploit', 'xss-context', 'xss-fuzzing'];
    for (const phase of phases) {
      const count = await Question.Model.countDocuments({ fase: phase });
      console.log(`${phase.padEnd(20)}: ${count} preguntas`);
    }

    await mongoose.connection.close();
    console.log('\nConexión a la base de datos cerrada');
    process.exit(0);

  } catch (error) {
    console.error('Error durante la migración:', error);
    await mongoose.connection.close();
    process.exit(1);
  }
}

updateQuestions();
