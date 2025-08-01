import { randomUUID } from 'crypto';
import { createHash } from 'crypto';

export function generateSessionId(): string {
  return randomUUID();
}

export function generateRequestId(): string {
  return randomUUID();
}

export function generateRequestHash(method: string, url: string, body?: string): string {
  const content = `${method}:${url}:${body || ''}`;
  return createHash('sha256').update(content).digest('hex');
}

export function hashSensitiveData(data: string): string {
  return createHash('sha256').update(data).digest('hex').substring(0, 16);
}

/**
 * Extract domain from URL
 */
export function extractDomain(url: string): string {
  try {
    const parsedUrl = new URL(url);
    return parsedUrl.hostname;
  } catch {
    return '';
  }
}

/**
 * Check if URL is from a known telemetry domain
 */
export function isTelemetryDomain(url: string): boolean {
  const domain = extractDomain(url);
  const telemetryDomains = [
    'api.segment.io',
    'firebaseio.com',
    'amplitude.com',
    'sentry.io',
    'launchdarkly.com',
    'telemetry.arc.net',
    'analytics.arc.net',
    'api.mixpanel.com',
    'track.customer.io',
    'api.intercom.io',
  ];
  
  return telemetryDomains.some(telemetryDomain => 
    domain === telemetryDomain || domain.endsWith(`.${telemetryDomain}`)
  );
}

/**
 * Sanitize headers for logging (remove sensitive information)
 */
export function sanitizeHeaders(headers: Record<string, string>): Record<string, string> {
  const sensitiveHeaders = [
    'authorization',
    'cookie',
    'set-cookie',
    'x-api-key',
    'x-auth-token',
    'x-session-token',
  ];
  
  const sanitized: Record<string, string> = {};
  
  for (const [key, value] of Object.entries(headers)) {
    const lowerKey = key.toLowerCase();
    if (sensitiveHeaders.includes(lowerKey)) {
      sanitized[key] = hashSensitiveData(value);
    } else {
      sanitized[key] = value;
    }
  }
  
  return sanitized;
}

/**
 * Extract potential tracking IDs from URL parameters
 */
export function extractTrackingIds(url: string): Array<{ type: string; value: string }> {
  const trackingIds: Array<{ type: string; value: string }> = [];
  
  try {
    const parsedUrl = new URL(url);
    const params = parsedUrl.searchParams;
    
    // Common tracking parameter names
    const trackingParams = {
      'utm_source': 'utm_source',
      'utm_medium': 'utm_medium',
      'utm_campaign': 'utm_campaign',
      'utm_term': 'utm_term',
      'utm_content': 'utm_content',
      'gclid': 'google_click_id',
      'fbclid': 'facebook_click_id',
      'msclkid': 'microsoft_click_id',
      '_ga': 'google_analytics',
      'session_id': 'session_id',
      'user_id': 'user_id',
      'device_id': 'device_id',
      'anonymous_id': 'anonymous_id',
    };
    
    for (const [param, type] of Object.entries(trackingParams)) {
      const value = params.get(param);
      if (value) {
        trackingIds.push({ type, value: hashSensitiveData(value) });
      }
    }
  } catch {
    // Invalid URL, skip extraction
  }
  
  return trackingIds;
}

/**
 * Extract potential tracking IDs from request body
 */
export function extractTrackingIdsFromBody(body: string, contentType?: string): Array<{ type: string; value: string }> {
  const trackingIds: Array<{ type: string; value: string }> = [];
  
  try {
    let data: any = {};
    
    // Parse body based on content type
    if (contentType?.includes('application/json')) {
      data = JSON.parse(body);
    } else if (contentType?.includes('application/x-www-form-urlencoded')) {
      const params = new URLSearchParams(body);
      data = Object.fromEntries(params.entries());
    } else {
      return trackingIds;
    }
    
    // Common tracking fields in telemetry payloads
    const trackingFields = {
      'userId': 'user_id',
      'user_id': 'user_id',
      'anonymousId': 'anonymous_id',
      'anonymous_id': 'anonymous_id',
      'deviceId': 'device_id',
      'device_id': 'device_id',
      'sessionId': 'session_id',
      'session_id': 'session_id',
      'messageId': 'message_id',
      'message_id': 'message_id',
      'cid': 'client_id',
      'client_id': 'client_id',
      'tid': 'tracking_id',
      'tracking_id': 'tracking_id',
    };
    
    // Extract IDs from flat structure
    for (const [field, type] of Object.entries(trackingFields)) {
      if (data[field] && typeof data[field] === 'string') {
        trackingIds.push({ type, value: hashSensitiveData(data[field]) });
      }
    }
    
    // Extract IDs from nested structures (e.g., Segment context)
    if (data.context) {
      const context = data.context;
      if (context.device?.id) {
        trackingIds.push({ type: 'device_id', value: hashSensitiveData(context.device.id) });
      }
      if (context.sessionId) {
        trackingIds.push({ type: 'session_id', value: hashSensitiveData(context.sessionId) });
      }
    }
    
    // Extract IDs from events array (e.g., Amplitude)
    if (Array.isArray(data.events)) {
      for (const event of data.events) {
        if (event.user_id) {
          trackingIds.push({ type: 'user_id', value: hashSensitiveData(event.user_id) });
        }
        if (event.device_id) {
          trackingIds.push({ type: 'device_id', value: hashSensitiveData(event.device_id) });
        }
        if (event.session_id) {
          trackingIds.push({ type: 'session_id', value: hashSensitiveData(String(event.session_id)) });
        }
      }
    }
  } catch {
    // Failed to parse body, skip extraction
  }
  
  return trackingIds;
}

/**
 * Generate timestamp in ISO format
 */
export function generateTimestamp(): string {
  return new Date().toISOString();
}

/**
 * Check if request contains potentially sensitive data
 */
export function containsSensitiveData(url: string, body?: string): boolean {
  const sensitivePatterns = [
    /password/i,
    /credit.?card/i,
    /ssn|social.?security/i,
    /api.?key/i,
    /secret/i,
    /token/i,
    /\b\d{3}-\d{2}-\d{4}\b/, // SSN pattern
    /\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b/, // Credit card pattern
  ];
  
  const content = `${url} ${body || ''}`;
  return sensitivePatterns.some(pattern => pattern.test(content));
}