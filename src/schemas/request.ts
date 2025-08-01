import { z } from 'zod';

export const TelemetryRequestSchema = z.object({
  id: z.string().uuid(),
  timestamp: z.date(),
  method: z.enum(['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD']),
  url: z.string().url(),
  headers: z.record(z.string(), z.string()),
  body: z.string().optional(),
  userAgent: z.string().optional(),
  origin: z.string().optional(),
});

export const TelemetryResponseSchema = z.object({
  id: z.string().uuid(),
  requestId: z.string().uuid(),
  timestamp: z.date(),
  status: z.number().int().min(100).max(599),
  statusText: z.string(),
  headers: z.record(z.string(), z.string()),
  body: z.string().optional(),
  responseTime: z.number().positive(),
});

export const TelemetrySessionSchema = z.object({
  id: z.string().uuid(),
  startTime: z.date(),
  endTime: z.date().optional(),
  requestCount: z.number().int().nonnegative(),
  uniqueDomains: z.array(z.string()),
  trackingIds: z.array(z.string()),
});

export const UserActionSchema = z.object({
  id: z.string().uuid(),
  timestamp: z.date(),
  action: z.string().min(1),
  description: z.string().optional(),
  metadata: z.record(z.string(), z.unknown()).optional(),
});

export const AnalysisResultSchema = z.object({
  id: z.string().uuid(),
  sessionId: z.string().uuid(),
  timestamp: z.date(),
  type: z.enum(['privacy_violation', 'tracking_id', 'fingerprint', 'suspicious_pattern']),
  severity: z.enum(['low', 'medium', 'high', 'critical']),
  description: z.string().min(1),
  evidence: z.record(z.string(), z.unknown()),
});

export const ProxyConfigSchema = z.object({
  port: z.number().int().min(1).max(65535),
  httpsPort: z.number().int().min(1).max(65535),
  certPath: z.string().min(1),
  keyPath: z.string().min(1),
  logLevel: z.enum(['error', 'warn', 'info', 'debug']),
  targetDomains: z.array(z.string()),
});

export const ConnectRequestSchema = z.object({
  id: z.string().uuid(),
  timestamp: z.date(),
  method: z.literal('CONNECT'),
  host: z.string().min(1),
  port: z.number().int().min(1).max(65535),
  headers: z.record(z.string(), z.string()),
  userAgent: z.string().optional(),
  sessionId: z.string().uuid(),
});

export const TLSConnectionInfoSchema = z.object({
  serverName: z.string(),
  protocol: z.string(),
  cipher: z.string(),
  clientCert: z.string().optional(),
  serverCert: z.string(),
  injectedCert: z.boolean(),
});

export const TunnelConnectionSchema = z.object({
  id: z.string().uuid(),
  connectRequestId: z.string().uuid(),
  sessionId: z.string().uuid(),
  startTime: z.date(),
  endTime: z.date().optional(),
  host: z.string(),
  port: z.number().int().min(1).max(65535),
  bytesReceived: z.number().nonnegative(),
  bytesSent: z.number().nonnegative(),
  tlsIntercepted: z.boolean(),
  certificateInjected: z.boolean(),
  requests: z.array(TelemetryRequestSchema),
  responses: z.array(TelemetryResponseSchema),
});

export const HttpsRequestSchema = TelemetryRequestSchema.extend({
  tunnelId: z.string().uuid(),
  tlsInfo: TLSConnectionInfoSchema,
  isDecrypted: z.boolean(),
});

export const HttpsResponseSchema = TelemetryResponseSchema.extend({
  tunnelId: z.string().uuid(),
  tlsInfo: TLSConnectionInfoSchema,
  isDecrypted: z.boolean(),
});

export const EvidencePackageSchema = z.object({
  id: z.string().uuid(),
  sessionId: z.string().uuid(),
  timestamp: z.date(),
  requests: z.array(TelemetryRequestSchema),
  responses: z.array(TelemetryResponseSchema),
  httpsRequests: z.array(HttpsRequestSchema),
  httpsResponses: z.array(HttpsResponseSchema),
  tunnelConnections: z.array(TunnelConnectionSchema),
  connectRequests: z.array(ConnectRequestSchema),
  userActions: z.array(UserActionSchema),
  analysisResults: z.array(AnalysisResultSchema),
  metadata: z.object({
    arcVersion: z.string().optional(),
    osVersion: z.string(),
    userAgent: z.string(),
    duration: z.number().positive(),
    totalTunnels: z.number().nonnegative(),
    httpsIntercepted: z.number().nonnegative(),
  }),
});

// Input schemas for API endpoints
export const ActionLogInputSchema = z.object({
  action: z.string().min(1),
  description: z.string().optional(),
  metadata: z.record(z.string(), z.unknown()).optional(),
});

export const ProxyRequestLogSchema = z.object({
  method: z.string(),
  url: z.string(),
  headers: z.record(z.string(), z.string()),
  body: z.string().optional(),
  timestamp: z.string().datetime(),
});

export const ProxyResponseLogSchema = z.object({
  status: z.number().int(),
  statusText: z.string(),
  headers: z.record(z.string(), z.string()),
  body: z.string().optional(),
  responseTime: z.number().positive(),
  timestamp: z.string().datetime(),
});

// Export types inferred from schemas
export type TelemetryRequest = z.infer<typeof TelemetryRequestSchema>;
export type TelemetryResponse = z.infer<typeof TelemetryResponseSchema>;
export type TelemetrySession = z.infer<typeof TelemetrySessionSchema>;
export type UserAction = z.infer<typeof UserActionSchema>;
export type AnalysisResult = z.infer<typeof AnalysisResultSchema>;
export type ProxyConfig = z.infer<typeof ProxyConfigSchema>;
export type ConnectRequest = z.infer<typeof ConnectRequestSchema>;
export type TLSConnectionInfo = z.infer<typeof TLSConnectionInfoSchema>;
export type TunnelConnection = z.infer<typeof TunnelConnectionSchema>;
export type HttpsRequest = z.infer<typeof HttpsRequestSchema>;
export type HttpsResponse = z.infer<typeof HttpsResponseSchema>;
export type EvidencePackage = z.infer<typeof EvidencePackageSchema>;
export type ActionLogInput = z.infer<typeof ActionLogInputSchema>;
export type ProxyRequestLog = z.infer<typeof ProxyRequestLogSchema>;
export type ProxyResponseLog = z.infer<typeof ProxyResponseLogSchema>;