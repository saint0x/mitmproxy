export interface TelemetryRequest {
  id: string;
  timestamp: Date;
  method: string;
  url: string;
  headers: Record<string, string>;
  body?: string;
  userAgent?: string;
  origin?: string;
}

export interface TelemetryResponse {
  id: string;
  requestId: string;
  timestamp: Date;
  status: number;
  statusText: string;
  headers: Record<string, string>;
  body?: string;
  responseTime: number;
}

export interface TelemetrySession {
  id: string;
  startTime: Date;
  endTime?: Date;
  requestCount: number;
  uniqueDomains: string[];
  trackingIds: string[];
}

export interface UserAction {
  id: string;
  timestamp: Date;
  action: string;
  description?: string;
  metadata?: Record<string, unknown>;
}

export interface AnalysisResult {
  id: string;
  sessionId: string;
  timestamp: Date;
  type: 'privacy_violation' | 'tracking_id' | 'fingerprint' | 'suspicious_pattern';
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  evidence: Record<string, unknown>;
}

export interface ProxyConfig {
  port: number;
  httpsPort: number;
  certPath: string;
  keyPath: string;
  logLevel: 'error' | 'warn' | 'info' | 'debug';
  targetDomains: string[];
}

export interface ConnectRequest {
  id: string;
  timestamp: Date;
  method: 'CONNECT';
  host: string;
  port: number;
  headers: Record<string, string>;
  userAgent?: string;
  sessionId: string;
}

export interface TunnelConnection {
  id: string;
  connectRequestId: string;
  sessionId: string;
  startTime: Date;
  endTime?: Date;
  host: string;
  port: number;
  bytesReceived: number;
  bytesSent: number;
  tlsIntercepted: boolean;
  certificateInjected: boolean;
  requests: TelemetryRequest[];
  responses: TelemetryResponse[];
}

export interface TLSConnectionInfo {
  serverName: string;
  protocol: string;
  cipher: string;
  clientCert?: string;
  serverCert: string;
  injectedCert: boolean;
}

export interface HttpsRequest extends TelemetryRequest {
  tunnelId: string;
  tlsInfo: TLSConnectionInfo;
  isDecrypted: boolean;
}

export interface HttpsResponse extends TelemetryResponse {
  tunnelId: string;
  tlsInfo: TLSConnectionInfo;
  isDecrypted: boolean;
}

export interface EvidencePackage {
  id: string;
  sessionId: string;
  timestamp: Date;
  requests: TelemetryRequest[];
  responses: TelemetryResponse[];
  httpsRequests: HttpsRequest[];
  httpsResponses: HttpsResponse[];
  tunnelConnections: TunnelConnection[];
  connectRequests: ConnectRequest[];
  userActions: UserAction[];
  analysisResults: AnalysisResult[];
  metadata: {
    arcVersion?: string;
    osVersion: string;
    userAgent: string;
    duration: number;
    totalTunnels: number;
    httpsIntercepted: number;
  };
}