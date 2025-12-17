# Script de población de subtipos de vulnerabilidades

Este script puebla la base de datos con los subtipos de vulnerabilidades para XSS y SQLi.

## Requisitos previos

Asegúrate de que la base de datos tenga los tipos de vulnerabilidades XSS y SQLi creados. Si no están, ejecuta primero:

```bash
node scripts/update-questions.js
```

## Ejecución

Desde el directorio raíz del backend:

```bash
node scripts/populate-vulnerability-subtypes.js
```

## Subtipos creados

### XSS (4 subtipos)
- **Inyección en contenido HTML**: Vulnerabilidad XSS donde el payload se inyecta directamente en el contenido HTML
- **Inyección en contenido JavaScript**: Vulnerabilidad XSS donde el payload se inyecta dentro de un contexto JavaScript
- **Inyección en atributo HTML**: Vulnerabilidad XSS donde el payload se inyecta en un atributo HTML
- **Cross-Site Scripting**: Vulnerabilidad XSS genérica sin contexto específico

### SQLi (6 subtipos)
- **Inyección ciega basada en booleanos (Boolean-based blind)**: SQL Injection ciega basada en respuestas booleanas
- **Basada en errores (Error-based)**: SQL Injection que extrae información de mensajes de error
- **Basada en consultas UNION (Union query-based)**: SQL Injection que usa UNION para combinar resultados
- **Consultas apiladas (Stacked queries)**: SQL Injection que ejecuta múltiples consultas
- **Inyección ciega basada en tiempo (Time-based blind)**: SQL Injection ciega basada en retrasos
- **Consultas en línea (Inline queries)**: SQL Injection que usa subconsultas inline

## Notas

- El script usa `findOneAndUpdate` con `upsert: true`, por lo que es seguro ejecutarlo múltiples veces
- No se crearán duplicados si ejecutas el script nuevamente
- Los subtipos se asocian automáticamente a sus respectivos tipos de vulnerabilidad usando el campo `tipo_id`
