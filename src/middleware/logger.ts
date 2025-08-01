import winston from 'winston';
import DailyRotateFile from 'winston-daily-rotate-file';
import { join } from 'path';
import type { Context, Next } from 'hono';
import '@/types/hono';
import { 
  generateRequestId, 
  generateTimestamp, 
  extractDomain, 
  isTelemetryDomain,
  sanitizeHeaders,
  extractTrackingIds,
  extractTrackingIdsFromBody,
  containsSensitiveData
} from '@/utils/crypto';

// Configure Winston logger
const createLogger = (logDir: string): winston.Logger => {
  const transports: winston.transport[] = [
    // Console transport for development
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.timestamp(),
        winston.format.printf(({ timestamp, level, message, ...meta }) => {
          return `${timestamp} [${level}]: ${message} ${Object.keys(meta).length ? JSON.stringify(meta, null, 2) : ''}`;
        })
      )
    }),

    // Daily rotating file for requests
    new DailyRotateFile({
      filename: join(logDir, 'arc-requests-%DATE%.json'),
      datePattern: 'YYYY-MM-DD',
      maxSize: '20m',
      maxFiles: '30d',
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
      ),
      level: 'info'
    }),

    // Daily rotating file for telemetry (separate file)
    new DailyRotateFile({
      filename: join(logDir, 'arc-telemetry-%DATE%.json'),
      datePattern: 'YYYY-MM-DD',
      maxSize: '20m',
      maxFiles: '90d',
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
      ),
      level: 'info'
    }),

    // Error log
    new DailyRotateFile({
      filename: join(logDir, 'arc-errors-%DATE%.log'),
      datePattern: 'YYYY-MM-DD',
      maxSize: '10m',
      maxFiles: '30d',
      level: 'error',
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.json()
      )
    })
  ];

  return winston.createLogger({
    level: process.env['LOG_LEVEL'] || 'info',
    transports,
    exceptionHandlers: [
      new winston.transports.File({ filename: join(logDir, 'exceptions.log') })
    ],
    rejectionHandlers: [
      new winston.transports.File({ filename: join(logDir, 'rejections.log') })
    ]
  });
};

// Initialize logger
const logger = createLogger(join(process.cwd(), 'logs'));

export interface RequestLogEntry {
  id: string;
  timestamp: string;
  sessionId?: string;
  method: string;
  url: string;
  domain: string;
  isTelemetry: boolean;
  headers: Record<string, string>;
  body?: string;
  userAgent?: string;
  origin?: string;
  trackingIds: Array<{ type: string; value: string }>;
  containsSensitive: boolean;
  responseTime?: number;
  response?: {
    status: number;
    statusText: string;
    headers: Record<string, string>;
    body?: string;
  };
}

/**
 * Middleware to log all requests and responses
 */
export function requestLogger() {
  return async (c: Context, next: Next): Promise<void> => {
    const startTime = performance.now();
    const requestId = generateRequestId();
    const timestamp = generateTimestamp();
    
    // Extract request information
    const method = c.req.method;
    const url = c.req.url;
    const domain = extractDomain(url);
    const isTelemetry = isTelemetryDomain(url);
    const headers: Record<string, string> = {};
    for (const [key, value] of c.req.raw.headers.entries()) {
      headers[key] = value;
    }
    const userAgent = c.req.header('user-agent');
    const origin = c.req.header('origin');
    const contentType = c.req.header('content-type');
    
    // Get request body if present
    let body: string | undefined;
    try {
      if (c.req.method !== 'GET' && c.req.method !== 'HEAD') {
        // Clone the request to read body without consuming it
        const clonedReq = c.req.raw.clone();
        body = await clonedReq.text();
      }
    } catch (error) {
      logger.warn('Failed to read request body', { requestId, error: (error as Error).message });
    }

    // Extract tracking IDs
    const urlTrackingIds = extractTrackingIds(url);
    const bodyTrackingIds = body ? extractTrackingIdsFromBody(body, contentType) : [];
    const trackingIds = [...urlTrackingIds, ...bodyTrackingIds];

    // Check for sensitive data
    const containsSensitive = containsSensitiveData(url, body);

    // Store request info in context for other middleware
    c.set('requestId', requestId);
    c.set('requestTimestamp', timestamp);
    c.set('isTelemetry', isTelemetry);

    const logEntry: RequestLogEntry = {
      id: requestId,
      timestamp,
      sessionId: c.get('sessionId'),
      method,
      url,
      domain,
      isTelemetry,
      headers: sanitizeHeaders(headers),
      body: containsSensitive ? '[SENSITIVE_DATA_REDACTED]' : body,
      userAgent,
      origin,
      trackingIds,
      containsSensitive,
    };

    try {
      // Continue to next middleware/handler
      await next();

      // Calculate response time
      const endTime = performance.now();
      const responseTime = endTime - startTime;

      // Get response information
      const response = c.res;
      const responseHeaders = Object.fromEntries(response.headers.entries());
      
      // Get response body if it's small enough and not binary
      let responseBody: string | undefined;
      try {
        const contentLength = parseInt(response.headers.get('content-length') || '0');
        const contentType = response.headers.get('content-type') || '';
        
        if (contentLength < 100000 && // Less than 100KB
            (contentType.includes('json') || 
             contentType.includes('text') || 
             contentType.includes('xml'))) {
          
          // Clone response to read body
          const clonedRes = response.clone();
          responseBody = await clonedRes.text();
        }
      } catch (error) {
        logger.warn('Failed to read response body', { requestId, error: (error as Error).message });
      }

      // Complete log entry
      logEntry.responseTime = responseTime;
      logEntry.response = {
        status: response.status,
        statusText: response.statusText,
        headers: sanitizeHeaders(responseHeaders),
        body: responseBody,
      };

      // Log to appropriate file based on whether it's telemetry
      if (isTelemetry) {
        logger.info('Telemetry request captured', {
          ...logEntry,
          type: 'telemetry',
          service: getTelemetryService(domain),
        });
      } else {
        logger.info('Request processed', {
          ...logEntry,
          type: 'request',
        });
      }

      // Log high-level metrics
      if (responseTime > 5000) {
        logger.warn('Slow request detected', {
          requestId,
          url,
          responseTime,
          status: response.status,
        });
      }

      if (response.status >= 400) {
        logger.warn('Error response', {
          requestId,
          url,
          status: response.status,
          statusText: response.statusText,
        });
      }

    } catch (error) {
      const endTime = performance.now();
      const responseTime = endTime - startTime;
      
      logEntry.responseTime = responseTime;
      logEntry.response = {
        status: 500,
        statusText: 'Internal Server Error',
        headers: {},
        body: (error as Error).message,
      };

      logger.error('Request failed', {
        ...logEntry,
        error: {
          message: (error as Error).message,
          stack: (error as Error).stack,
        },
      });

      throw error;
    }
  };
}

/**
 * Determine telemetry service based on domain
 */
function getTelemetryService(domain: string): string {
  const serviceMap: Record<string, string> = {
    'api.segment.io': 'segment',
    'firebaseio.com': 'firebase',
    'amplitude.com': 'amplitude',
    'sentry.io': 'sentry',
    'launchdarkly.com': 'launchdarkly',
    'telemetry.arc.net': 'arc_telemetry',
    'analytics.arc.net': 'arc_analytics',
    'api.mixpanel.com': 'mixpanel',
    'track.customer.io': 'customer_io',
    'api.intercom.io': 'intercom',
  };

  for (const [serviceDomain, serviceName] of Object.entries(serviceMap)) {
    if (domain === serviceDomain || domain.endsWith(`.${serviceDomain}`)) {
      return serviceName;
    }
  }

  return 'unknown';
}

/**
 * Middleware to log user actions
 */
export function userActionLogger() {
  return async (c: Context, next: Next): Promise<void> => {
    if (c.req.path === '/action-log' && c.req.method === 'POST') {
      const actionId = generateRequestId();
      const timestamp = generateTimestamp();
      
      try {
        const body = await c.req.json();
        
        logger.info('User action logged', {
          id: actionId,
          timestamp,
          sessionId: c.get('sessionId'),
          type: 'user_action',
          action: body.action,
          description: body.description,
          metadata: body.metadata,
        });
      } catch (error) {
        logger.error('Failed to log user action', {
          id: actionId,
          timestamp,
          error: (error as Error).message,
        });
      }
    }

    await next();
  };
}

/**
 * Export the logger instance for use in other parts of the application
 */
export { logger };