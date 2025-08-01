import { z } from 'zod';

// Known Arc Browser telemetry endpoints
export const TELEMETRY_DOMAINS = [
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
] as const;

// Segment.io tracking payload schema
export const SegmentPayloadSchema = z.object({
  userId: z.string().optional(),
  anonymousId: z.string().optional(),
  event: z.string().optional(),
  properties: z.record(z.string(), z.unknown()).optional(),
  context: z.object({
    app: z.object({
      name: z.string().optional(),
      version: z.string().optional(),
    }).optional(),
    device: z.object({
      id: z.string().optional(),
      manufacturer: z.string().optional(),
      model: z.string().optional(),
      type: z.string().optional(),
    }).optional(),
    os: z.object({
      name: z.string().optional(),
      version: z.string().optional(),
    }).optional(),
    screen: z.object({
      width: z.number().optional(),
      height: z.number().optional(),
    }).optional(),
    userAgent: z.string().optional(),
    ip: z.string().optional(),
  }).optional(),
  timestamp: z.string().optional(),
  messageId: z.string().optional(),
});

// Amplitude tracking payload schema
export const AmplitudePayloadSchema = z.object({
  api_key: z.string().optional(),
  events: z.array(z.object({
    user_id: z.string().optional(),
    device_id: z.string().optional(),
    event_type: z.string().optional(),
    event_properties: z.record(z.string(), z.unknown()).optional(),
    user_properties: z.record(z.string(), z.unknown()).optional(),
    time: z.number().optional(),
    session_id: z.number().optional(),
    platform: z.string().optional(),
    os_name: z.string().optional(),
    os_version: z.string().optional(),
    device_brand: z.string().optional(),
    device_model: z.string().optional(),
  })).optional(),
});

// Firebase/Google Analytics payload schema
export const FirebasePayloadSchema = z.object({
  v: z.string().optional(), // Version
  tid: z.string().optional(), // Tracking ID
  cid: z.string().optional(), // Client ID
  t: z.string().optional(), // Hit Type
  ec: z.string().optional(), // Event Category
  ea: z.string().optional(), // Event Action
  el: z.string().optional(), // Event Label
  ev: z.number().optional(), // Event Value
  cd: z.record(z.string(), z.string()).optional(), // Custom Dimensions
  cm: z.record(z.string(), z.number()).optional(), // Custom Metrics
});

// Sentry error tracking payload schema
export const SentryPayloadSchema = z.object({
  event_id: z.string().optional(),
  timestamp: z.string().optional(),
  platform: z.string().optional(),
  sdk: z.object({
    name: z.string().optional(),
    version: z.string().optional(),
  }).optional(),
  user: z.object({
    id: z.string().optional(),
    username: z.string().optional(),
    email: z.string().optional(),
  }).optional(),
  request: z.object({
    url: z.string().optional(),
    method: z.string().optional(),
    headers: z.record(z.string(), z.string()).optional(),
  }).optional(),
  exception: z.object({
    values: z.array(z.object({
      type: z.string().optional(),
      value: z.string().optional(),
      stacktrace: z.object({
        frames: z.array(z.unknown()).optional(),
      }).optional(),
    })).optional(),
  }).optional(),
});

// LaunchDarkly feature flag payload schema
export const LaunchDarklyPayloadSchema = z.object({
  kind: z.string().optional(),
  key: z.string().optional(),
  user: z.object({
    key: z.string().optional(),
    anonymous: z.boolean().optional(),
    custom: z.record(z.string(), z.unknown()).optional(),
  }).optional(),
  value: z.unknown().optional(),
  default: z.unknown().optional(),
  version: z.number().optional(),
  variation: z.number().optional(),
});

// Generic telemetry payload schema
export const GenericTelemetryPayloadSchema = z.object({
  timestamp: z.string().optional(),
  sessionId: z.string().optional(),
  userId: z.string().optional(),
  deviceId: z.string().optional(),
  event: z.string().optional(),
  properties: z.record(z.string(), z.unknown()).optional(),
  userAgent: z.string().optional(),
  url: z.string().optional(),
  referrer: z.string().optional(),
});

// Telemetry analysis result
export const TelemetryAnalysisSchema = z.object({
  domain: z.string(),
  service: z.enum(['segment', 'amplitude', 'firebase', 'sentry', 'launchdarkly', 'unknown']),
  payload: z.union([
    SegmentPayloadSchema,
    AmplitudePayloadSchema,
    FirebasePayloadSchema,
    SentryPayloadSchema,
    LaunchDarklyPayloadSchema,
    GenericTelemetryPayloadSchema,
  ]),
  extractedIds: z.array(z.object({
    type: z.enum(['user_id', 'device_id', 'session_id', 'anonymous_id', 'tracking_id']),
    value: z.string(),
  })),
  privacyFlags: z.array(z.object({
    type: z.enum(['pii_collection', 'device_fingerprinting', 'location_tracking', 'excessive_data']),
    severity: z.enum(['low', 'medium', 'high', 'critical']),
    description: z.string(),
  })),
});

// Privacy violation detection patterns
export const PRIVACY_PATTERNS = {
  // PII patterns
  email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
  phone: /(\+\d{1,3}[- ]?)?\(?\d{3}\)?[- ]?\d{3}[- ]?\d{4}/g,
  ssn: /\b\d{3}-\d{2}-\d{4}\b/g,
  creditCard: /\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b/g,
  
  // Device fingerprinting patterns
  canvasFingerprint: /canvas.*fingerprint|fingerprint.*canvas/i,
  webglFingerprint: /webgl.*fingerprint|fingerprint.*webgl/i,
  audioFingerprint: /audio.*fingerprint|fingerprint.*audio/i,
  fontFingerprint: /font.*detect|detect.*font/i,
  
  // Location patterns
  geolocation: /navigator\.geolocation|getCurrentPosition|watchPosition/i,
  ipGeolocation: /ip.*location|location.*ip|geoip/i,
  
  // Tracking patterns
  trackingPixel: /pixel.*track|track.*pixel|1x1\.gif|tracking\.gif/i,
  thirdPartyTracking: /doubleclick|googletagmanager|facebook\.com\/tr|analytics\.google/i,
} as const;

// Export types
export type SegmentPayload = z.infer<typeof SegmentPayloadSchema>;
export type AmplitudePayload = z.infer<typeof AmplitudePayloadSchema>;
export type FirebasePayload = z.infer<typeof FirebasePayloadSchema>;
export type SentryPayload = z.infer<typeof SentryPayloadSchema>;
export type LaunchDarklyPayload = z.infer<typeof LaunchDarklyPayloadSchema>;
export type GenericTelemetryPayload = z.infer<typeof GenericTelemetryPayloadSchema>;
export type TelemetryAnalysis = z.infer<typeof TelemetryAnalysisSchema>;