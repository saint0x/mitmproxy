import { join } from 'path';
import { logger } from '@/middleware/logger';
import { PureProxyServer } from '@/pure-proxy-server';

const config = {
  port: parseInt(process.env['PROXY_PORT'] || '8080'),
  certPath: process.env['CERT_PATH'] || join(process.cwd(), 'certificates', 'mitm-proxy.pem'),
  keyPath: process.env['KEY_PATH'] || join(process.cwd(), 'certificates', 'mitm-proxy-key.pem'),
  logLevel: process.env['LOG_LEVEL'] || 'info',
  dbPath: process.env['DB_PATH'] || join(process.cwd(), 'logs', 'telemetry.db'),
};

const proxyServer = new PureProxyServer(config);
const shutdown = (signal: string): void => {
  logger.info(`Received ${signal}, shutting down gracefully...`);
  
  try {
    proxyServer.cleanup();
    logger.info('Proxy server cleaned up');
    process.exit(0);
  } catch (error) {
    logger.error('Error during shutdown', {
      error: (error as Error).message,
    });
    process.exit(1);
  }
};

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('uncaughtException', (error) => {
  logger.error('Uncaught exception', {
    error: {
      message: error.message,
      stack: error.stack,
    },
  });
  shutdown('UNCAUGHT_EXCEPTION');
});

process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled promise rejection', {
    reason,
    promise,
  });
});

async function startServer(): Promise<void> {
  try {
    await proxyServer.start();
    
    logger.info('Arc Browser MITM Proxy is ready!', {
      config: {
        port: config.port,
        logLevel: config.logLevel,
        dbPath: config.dbPath,
      },
      stats: proxyServer.getStats(),
    });
    
  } catch (error) {
    logger.error('Failed to start server', {
      error: {
        message: (error as Error).message,
        stack: (error as Error).stack,
      },
    });
    process.exit(1);
  }
}

startServer().catch((error) => {
  logger.error('Server startup failed', { error });
  process.exit(1);
});

export default proxyServer;