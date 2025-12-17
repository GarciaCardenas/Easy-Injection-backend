#!/bin/bash
# Script para ejecutar el backend con debug completo en Linux/Mac
# Para ver todos los logs de easyinjection

echo "========================================"
echo "Easy Injection Backend - Debug Mode"
echo "========================================"
echo ""
echo "Este script ejecutará el backend con TODOS los logs de debug habilitados."
echo "Para ver solo ciertos logs, edita la variable DEBUG abajo."
echo ""
echo "Ejemplos:"
echo "  DEBUG=easyinjection:*                    (TODOS los logs)"
echo "  DEBUG=easyinjection:scan:*               (Solo logs de scan)"
echo "  DEBUG=easyinjection:socket               (Solo logs de socket)"
echo "  DEBUG=easyinjection:scan:orchestrator    (Solo orchestrator)"
echo ""
echo "Presiona Ctrl+C para detener el servidor"
echo "========================================"
echo ""

DEBUG=easyinjection:* npm start
