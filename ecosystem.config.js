module.exports = {
  apps: [
    {
      name: 'easyinjection-backend',
      script: './index.js',
      instances: 1, // Puedes usar 'max' para usar todos los cores disponibles
      exec_mode: 'fork', // Usa 'cluster' si instances > 1
      
      // Variables de entorno (se sobrescriben con .env)
      env_production: {
        NODE_ENV: 'production',
        PORT: 3000,
        HOST: '127.0.0.1'
      },
      
      // Configuración de logs
      error_file: './logs/pm2-error.log',
      out_file: './logs/pm2-out.log',
      log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
      
      // Reinicio automático
      max_memory_restart: '500M',
      restart_delay: 4000,
      
      // Comportamiento ante fallos
      autorestart: true,
      max_restarts: 10,
      min_uptime: '10s',
      
      // Ignorar archivos en watch (deshabilitado por defecto en producción)
      watch: false,
      ignore_watch: ['node_modules', 'logs', '.git'],
      
      // Configuración avanzada
      merge_logs: true,
      time: true
    }
  ]
};
