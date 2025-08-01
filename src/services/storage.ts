import Database from 'better-sqlite3';
import { existsSync, mkdirSync } from 'fs';
import { dirname } from 'path';
import type {
  TelemetryRequest,
  TelemetryResponse,
  TelemetrySession,
  UserAction,
  AnalysisResult,
  ConnectRequest,
  TunnelConnection,
  HttpsRequest,
  HttpsResponse,
} from '@/schemas/request';

export class StorageService {
  private db: Database.Database;
  private initialized = false;

  constructor(dbPath: string) {
    const dir = dirname(dbPath);
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }

    this.db = new Database(dbPath);
    this.initialize();
  }

  private initialize(): void {
    if (this.initialized) return;

    this.db.pragma('journal_mode = WAL');
    this.db.pragma('synchronous = NORMAL');
    this.db.pragma('cache_size = 1000');
    this.db.pragma('temp_store = memory');

    this.createTables();
    this.initialized = true;
  }

  private createTables(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY,
        start_time INTEGER NOT NULL,
        end_time INTEGER,
        request_count INTEGER DEFAULT 0,
        unique_domains TEXT DEFAULT '[]',
        tracking_ids TEXT DEFAULT '[]',
        created_at INTEGER DEFAULT (strftime('%s', 'now'))
      )
    `);

    // Requests table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS requests (
        id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        timestamp INTEGER NOT NULL,
        method TEXT NOT NULL,
        url TEXT NOT NULL,
        headers TEXT NOT NULL,
        body TEXT,
        user_agent TEXT,
        origin TEXT,
        domain TEXT,
        is_telemetry BOOLEAN DEFAULT FALSE,
        request_hash TEXT,
        created_at INTEGER DEFAULT (strftime('%s', 'now')),
        FOREIGN KEY (session_id) REFERENCES sessions (id)
      )
    `);

    // Responses table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS responses (
        id TEXT PRIMARY KEY,
        request_id TEXT NOT NULL,
        session_id TEXT NOT NULL,
        timestamp INTEGER NOT NULL,
        status INTEGER NOT NULL,
        status_text TEXT NOT NULL,
        headers TEXT NOT NULL,
        body TEXT,
        response_time REAL NOT NULL,
        created_at INTEGER DEFAULT (strftime('%s', 'now')),
        FOREIGN KEY (request_id) REFERENCES requests (id),
        FOREIGN KEY (session_id) REFERENCES sessions (id)
      )
    `);

    // User actions table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS user_actions (
        id TEXT PRIMARY KEY,
        session_id TEXT,
        timestamp INTEGER NOT NULL,
        action TEXT NOT NULL,
        description TEXT,
        metadata TEXT DEFAULT '{}',
        created_at INTEGER DEFAULT (strftime('%s', 'now')),
        FOREIGN KEY (session_id) REFERENCES sessions (id)
      )
    `);

    // Analysis results table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS analysis_results (
        id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        timestamp INTEGER NOT NULL,
        type TEXT NOT NULL,
        severity TEXT NOT NULL,
        description TEXT NOT NULL,
        evidence TEXT NOT NULL,
        created_at INTEGER DEFAULT (strftime('%s', 'now')),
        FOREIGN KEY (session_id) REFERENCES sessions (id)
      )
    `);

    // CONNECT requests table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS connect_requests (
        id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        timestamp INTEGER NOT NULL,
        host TEXT NOT NULL,
        port INTEGER NOT NULL,
        headers TEXT NOT NULL,
        user_agent TEXT,
        created_at INTEGER DEFAULT (strftime('%s', 'now')),
        FOREIGN KEY (session_id) REFERENCES sessions (id)
      )
    `);

    // Tunnel connections table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS tunnel_connections (
        id TEXT PRIMARY KEY,
        connect_request_id TEXT NOT NULL,
        session_id TEXT NOT NULL,
        start_time INTEGER NOT NULL,
        end_time INTEGER,
        host TEXT NOT NULL,
        port INTEGER NOT NULL,
        bytes_received INTEGER DEFAULT 0,
        bytes_sent INTEGER DEFAULT 0,
        tls_intercepted BOOLEAN DEFAULT FALSE,
        certificate_injected BOOLEAN DEFAULT FALSE,
        created_at INTEGER DEFAULT (strftime('%s', 'now')),
        FOREIGN KEY (connect_request_id) REFERENCES connect_requests (id),
        FOREIGN KEY (session_id) REFERENCES sessions (id)
      )
    `);

    // Create indexes for better query performance
    this.db.exec(`
      CREATE INDEX IF NOT EXISTS idx_requests_session_id ON requests (session_id);
      CREATE INDEX IF NOT EXISTS idx_requests_timestamp ON requests (timestamp);
      CREATE INDEX IF NOT EXISTS idx_requests_domain ON requests (domain);
      CREATE INDEX IF NOT EXISTS idx_requests_is_telemetry ON requests (is_telemetry);
      CREATE INDEX IF NOT EXISTS idx_responses_request_id ON responses (request_id);
      CREATE INDEX IF NOT EXISTS idx_responses_session_id ON responses (session_id);
      CREATE INDEX IF NOT EXISTS idx_user_actions_session_id ON user_actions (session_id);
      CREATE INDEX IF NOT EXISTS idx_user_actions_timestamp ON user_actions (timestamp);
      CREATE INDEX IF NOT EXISTS idx_analysis_results_session_id ON analysis_results (session_id);
      CREATE INDEX IF NOT EXISTS idx_analysis_results_type ON analysis_results (type);
      CREATE INDEX IF NOT EXISTS idx_analysis_results_severity ON analysis_results (severity);
      CREATE INDEX IF NOT EXISTS idx_connect_requests_session_id ON connect_requests (session_id);
      CREATE INDEX IF NOT EXISTS idx_connect_requests_host ON connect_requests (host);
      CREATE INDEX IF NOT EXISTS idx_tunnel_connections_session_id ON tunnel_connections (session_id);
      CREATE INDEX IF NOT EXISTS idx_tunnel_connections_connect_request_id ON tunnel_connections (connect_request_id);
    `);
  }

  // Session operations
  public createSession(session: TelemetrySession): void {
    const stmt = this.db.prepare(`
      INSERT INTO sessions (id, start_time, end_time, request_count, unique_domains, tracking_ids)
      VALUES (?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      session.id,
      session.startTime.getTime(),
      session.endTime?.getTime() || null,
      session.requestCount,
      JSON.stringify(session.uniqueDomains),
      JSON.stringify(session.trackingIds)
    );
  }

  public updateSession(sessionId: string, updates: Partial<TelemetrySession>): void {
    const fields: string[] = [];
    const values: any[] = [];

    if (updates.endTime !== undefined) {
      fields.push('end_time = ?');
      values.push(updates.endTime?.getTime() || null);
    }
    if (updates.requestCount !== undefined) {
      fields.push('request_count = ?');
      values.push(updates.requestCount);
    }
    if (updates.uniqueDomains !== undefined) {
      fields.push('unique_domains = ?');
      values.push(JSON.stringify(updates.uniqueDomains));
    }
    if (updates.trackingIds !== undefined) {
      fields.push('tracking_ids = ?');
      values.push(JSON.stringify(updates.trackingIds));
    }

    if (fields.length > 0) {
      values.push(sessionId);
      const stmt = this.db.prepare(`
        UPDATE sessions SET ${fields.join(', ')} WHERE id = ?
      `);
      stmt.run(...values);
    }
  }

  public getSession(sessionId: string): TelemetrySession | null {
    const stmt = this.db.prepare(`
      SELECT * FROM sessions WHERE id = ?
    `);
    const row = stmt.get(sessionId) as any;

    if (!row) return null;

    return {
      id: row.id,
      startTime: new Date(row.start_time),
      endTime: row.end_time ? new Date(row.end_time) : undefined,
      requestCount: row.request_count,
      uniqueDomains: JSON.parse(row.unique_domains),
      trackingIds: JSON.parse(row.tracking_ids),
    };
  }

  // Request operations
  public saveRequest(request: TelemetryRequest & { sessionId: string; domain: string; isTelemetry: boolean; requestHash: string }): void {
    const stmt = this.db.prepare(`
      INSERT INTO requests (
        id, session_id, timestamp, method, url, headers, body, user_agent, origin, 
        domain, is_telemetry, request_hash
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      request.id,
      request.sessionId,
      request.timestamp.getTime(),
      request.method,
      request.url,
      JSON.stringify(request.headers),
      request.body || null,
      request.userAgent || null,
      request.origin || null,
      request.domain,
      request.isTelemetry ? 1 : 0,
      request.requestHash
    );
  }

  public saveResponse(response: TelemetryResponse & { sessionId: string }): void {
    try {
      const stmt = this.db.prepare(`
        INSERT OR IGNORE INTO responses (
          id, request_id, session_id, timestamp, status, status_text, headers, body, response_time
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);

      const result = stmt.run(
        response.id,
        response.requestId,
        response.sessionId,
        response.timestamp.getTime(),
        response.status,
        response.statusText,
        JSON.stringify(response.headers),
        response.body || null,
        response.responseTime
      );

      // Log if the response was ignored due to foreign key constraint
      if (result.changes === 0) {
        console.warn(`Response ignored due to missing request: ${response.requestId}`);
      }
    } catch (error) {
      console.error('Failed to save response:', {
        responseId: response.id,
        requestId: response.requestId,
        error: (error as Error).message,
      });
      // Don't throw - continue processing other requests
    }
  }

  // User action operations
  public saveUserAction(action: UserAction & { sessionId?: string }): void {
    const stmt = this.db.prepare(`
      INSERT INTO user_actions (id, session_id, timestamp, action, description, metadata)
      VALUES (?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      action.id,
      action.sessionId || null,
      action.timestamp.getTime(),
      action.action,
      action.description || null,
      JSON.stringify(action.metadata || {})
    );
  }

  // Analysis operations
  public saveAnalysisResult(result: AnalysisResult): void {
    const stmt = this.db.prepare(`
      INSERT INTO analysis_results (id, session_id, timestamp, type, severity, description, evidence)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      result.id,
      result.sessionId,
      result.timestamp.getTime(),
      result.type,
      result.severity,
      result.description,
      JSON.stringify(result.evidence)
    );
  }

  // CONNECT request operations
  public saveConnectRequest(request: ConnectRequest): void {
    const stmt = this.db.prepare(`
      INSERT INTO connect_requests (id, session_id, timestamp, host, port, headers, user_agent)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      request.id,
      request.sessionId,
      request.timestamp.getTime(),
      request.host,
      request.port,
      JSON.stringify(request.headers),
      request.userAgent || null
    );
  }

  // Tunnel connection operations
  public saveTunnelConnection(tunnel: TunnelConnection): void {
    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO tunnel_connections 
      (id, connect_request_id, session_id, start_time, end_time, host, port, 
       bytes_received, bytes_sent, tls_intercepted, certificate_injected)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      tunnel.id,
      tunnel.connectRequestId,
      tunnel.sessionId,
      tunnel.startTime.getTime(),
      tunnel.endTime?.getTime() || null,
      tunnel.host,
      tunnel.port,
      tunnel.bytesReceived,
      tunnel.bytesSent,
      tunnel.tlsIntercepted ? 1 : 0,
      tunnel.certificateInjected ? 1 : 0
    );
  }

  // Query operations
  public getRequestsBySession(sessionId: string): TelemetryRequest[] {
    const stmt = this.db.prepare(`
      SELECT * FROM requests WHERE session_id = ? ORDER BY timestamp ASC
    `);
    const rows = stmt.all(sessionId) as any[];

    return rows.map(row => ({
      id: row.id,
      timestamp: new Date(row.timestamp),
      method: row.method,
      url: row.url,
      headers: JSON.parse(row.headers),
      body: row.body || undefined,
      userAgent: row.user_agent || undefined,
      origin: row.origin || undefined,
    }));
  }

  public getResponsesBySession(sessionId: string): TelemetryResponse[] {
    const stmt = this.db.prepare(`
      SELECT * FROM responses WHERE session_id = ? ORDER BY timestamp ASC
    `);
    const rows = stmt.all(sessionId) as any[];

    return rows.map(row => ({
      id: row.id,
      requestId: row.request_id,
      timestamp: new Date(row.timestamp),
      status: row.status,
      statusText: row.status_text,
      headers: JSON.parse(row.headers),
      body: row.body || undefined,
      responseTime: row.response_time,
    }));
  }

  public getTelemetryRequests(sessionId?: string): Array<TelemetryRequest & { domain: string }> {
    const stmt = sessionId
      ? this.db.prepare(`SELECT * FROM requests WHERE session_id = ? AND is_telemetry = TRUE ORDER BY timestamp ASC`)
      : this.db.prepare(`SELECT * FROM requests WHERE is_telemetry = TRUE ORDER BY timestamp ASC`);
    
    const rows = sessionId ? stmt.all(sessionId) as any[] : stmt.all() as any[];

    return rows.map(row => ({
      id: row.id,
      timestamp: new Date(row.timestamp),
      method: row.method,
      url: row.url,
      headers: JSON.parse(row.headers),
      body: row.body || undefined,
      userAgent: row.user_agent || undefined,
      origin: row.origin || undefined,
      domain: row.domain,
    }));
  }

  public getUserActionsBySession(sessionId: string): UserAction[] {
    const stmt = this.db.prepare(`
      SELECT * FROM user_actions WHERE session_id = ? ORDER BY timestamp ASC
    `);
    const rows = stmt.all(sessionId) as any[];

    return rows.map(row => ({
      id: row.id,
      timestamp: new Date(row.timestamp),
      action: row.action,
      description: row.description || undefined,
      metadata: JSON.parse(row.metadata),
    }));
  }

  public getAnalysisResults(sessionId?: string): AnalysisResult[] {
    const stmt = sessionId
      ? this.db.prepare(`SELECT * FROM analysis_results WHERE session_id = ? ORDER BY timestamp ASC`)
      : this.db.prepare(`SELECT * FROM analysis_results ORDER BY timestamp ASC`);
    
    const rows = sessionId ? stmt.all(sessionId) as any[] : stmt.all() as any[];

    return rows.map(row => ({
      id: row.id,
      sessionId: row.session_id,
      timestamp: new Date(row.timestamp),
      type: row.type as any,
      severity: row.severity as any,
      description: row.description,
      evidence: JSON.parse(row.evidence),
    }));
  }

  public getConnectRequestsBySession(sessionId: string): ConnectRequest[] {
    const stmt = this.db.prepare(`
      SELECT * FROM connect_requests WHERE session_id = ? ORDER BY timestamp ASC
    `);
    const rows = stmt.all(sessionId) as any[];

    return rows.map(row => ({
      id: row.id,
      timestamp: new Date(row.timestamp),
      method: 'CONNECT' as const,
      host: row.host,
      port: row.port,
      headers: JSON.parse(row.headers),
      userAgent: row.user_agent || undefined,
      sessionId: row.session_id,
    }));
  }

  public getTunnelConnectionsBySession(sessionId: string): TunnelConnection[] {
    const stmt = this.db.prepare(`
      SELECT * FROM tunnel_connections WHERE session_id = ? ORDER BY start_time ASC
    `);
    const rows = stmt.all(sessionId) as any[];

    return rows.map(row => ({
      id: row.id,
      connectRequestId: row.connect_request_id,
      sessionId: row.session_id,
      startTime: new Date(row.start_time),
      endTime: row.end_time ? new Date(row.end_time) : undefined,
      host: row.host,
      port: row.port,
      bytesReceived: row.bytes_received,
      bytesSent: row.bytes_sent,
      tlsIntercepted: Boolean(row.tls_intercepted),
      certificateInjected: Boolean(row.certificate_injected),
      requests: [], // Would need to implement request linking
      responses: [], // Would need to implement response linking
    }));
  }

  // Statistics
  public getSessionStats(sessionId: string): {
    requestCount: number;
    telemetryCount: number;
    uniqueDomains: number;
    duration: number;
    tunnelCount: number;
    httpsIntercepted: number;
  } {
    const session = this.getSession(sessionId);
    if (!session) {
      return { 
        requestCount: 0, 
        telemetryCount: 0, 
        uniqueDomains: 0, 
        duration: 0,
        tunnelCount: 0,
        httpsIntercepted: 0
      };
    }

    const telemetryStmt = this.db.prepare(`
      SELECT COUNT(*) as count FROM requests WHERE session_id = ? AND is_telemetry = TRUE
    `);
    const telemetryCount = (telemetryStmt.get(sessionId) as any).count;

    const tunnelStmt = this.db.prepare(`
      SELECT COUNT(*) as count FROM tunnel_connections WHERE session_id = ?
    `);
    const tunnelCount = (tunnelStmt.get(sessionId) as any).count;

    const httpsInterceptedStmt = this.db.prepare(`
      SELECT COUNT(*) as count FROM tunnel_connections WHERE session_id = ? AND tls_intercepted = 1
    `);
    const httpsIntercepted = (httpsInterceptedStmt.get(sessionId) as any).count;

    const duration = session.endTime 
      ? session.endTime.getTime() - session.startTime.getTime()
      : Date.now() - session.startTime.getTime();

    return {
      requestCount: session.requestCount,
      telemetryCount,
      uniqueDomains: session.uniqueDomains.length,
      duration,
      tunnelCount,
      httpsIntercepted,
    };
  }

  // Cleanup operations
  public cleanupOldData(daysToKeep: number = 30): number {
    const cutoffTime = Date.now() - (daysToKeep * 24 * 60 * 60 * 1000);
    
    const stmt = this.db.prepare(`
      DELETE FROM sessions WHERE start_time < ?
    `);
    
    const result = stmt.run(cutoffTime);
    return result.changes;
  }

  public close(): void {
    if (this.db) {
      this.db.close();
    }
  }
}