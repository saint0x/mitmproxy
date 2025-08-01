import { createServer, Server, Socket } from 'net';
import { logger } from '@/middleware/logger';
import { MITMTunnel } from '@/services/mitm-tunnel';
import { StorageService } from '@/services/storage';
import { TLSManager } from '@/utils/tls';
import { 
  generateRequestId, 
  generateSessionId, 
  extractDomain, 
  isTelemetryDomain,
  generateRequestHash,
  extractTrackingIds,
  extractTrackingIdsFromBody,
  classifyTelemetryDomain,
  TelemetryCategory
} from '@/utils/crypto';
import type { TelemetryRequest, TelemetryResponse, ConnectRequest } from '@/schemas/request';

export class PureProxyServer {
  private server: Server;
  private storage: StorageService;
  private mitmTunnel?: MITMTunnel;
  private currentSessionId: string;
  private config: {
    port: number;
    certPath?: string;
    keyPath?: string;
    dbPath: string;
    logLevel: string;
  };

  constructor(config: {
    port: number;
    certPath?: string;
    keyPath?: string;
    dbPath: string;
    logLevel: string;
  }) {
    this.config = config;
    this.storage = new StorageService(config.dbPath);
    this.currentSessionId = generateSessionId();
    
    this.initializeSession();
    
    if (config.certPath && config.keyPath) {
      try {
        this.mitmTunnel = new MITMTunnel(config.certPath, config.keyPath);
        this.setupMITMEventHandlers();
        logger.info('🔐 MITM tunnel initialized for HTTPS interception');
      } catch (error) {
        logger.warn('Failed to initialize MITM tunnel', {
          error: (error as Error).message,
        });
      }
    }

    this.server = createServer((socket: Socket) => {
      this.handleConnection(socket);
    });

    this.server.on('error', (error) => {
      logger.error('Proxy server error', { error: error.message });
    });
  }

  private initializeSession(): void {
    this.storage.createSession({
      id: this.currentSessionId,
      startTime: new Date(),
      requestCount: 0,
      uniqueDomains: [],
      trackingIds: [],
    });
    
    logger.info('New session started', { sessionId: this.currentSessionId });
  }

  /**
   * Setup event handlers for MITM tunnel
   */
  private setupMITMEventHandlers(): void {
    if (!this.mitmTunnel) return;
    
    // Handle HTTPS requests from tunnels
    this.mitmTunnel.on('httpsRequest', (request) => {
      const domain = extractDomain(request.url);
      const telemetryCategory = classifyTelemetryDomain(domain);
      
      if (telemetryCategory !== 'ignore') {
        logger.info('🎯 Arc telemetry intercepted', {
          requestId: request.id,
          tunnelId: request.tunnelId,
          method: request.method,
          url: request.url,
          domain,
          category: telemetryCategory,
          sessionId: this.currentSessionId,
        });
        
        this.storage.saveRequest({
          ...request,
          sessionId: this.currentSessionId,
          domain,
          isTelemetry: isTelemetryDomain(request.url),
          telemetryCategory,
          requestHash: generateRequestHash(request.method, request.url, request.body),
        });
        
        const trackingIds = extractTrackingIds(request.url);
        const bodyTrackingIds = request.body ? extractTrackingIdsFromBody(request.body, request.headers['content-type']) : [];
        this.updateSessionStats(domain, [...trackingIds, ...bodyTrackingIds].map(t => t.value));
      }
    });
    
    // Handle HTTPS responses from tunnels
    this.mitmTunnel.on('httpsResponse', (response) => {
      const domain = response.tlsInfo?.serverName || '';
      const telemetryCategory = classifyTelemetryDomain(domain);
      
      if (telemetryCategory !== 'ignore') {
        logger.info('📨 Arc telemetry response', {
          responseId: response.id,
          tunnelId: response.tunnelId,
          status: response.status,
          domain,
          category: telemetryCategory,
          sessionId: this.currentSessionId,
        });
        
        this.storage.saveResponse({
          ...response,
          sessionId: this.currentSessionId,
        });
      }
    });
  }

  private updateSessionStats(domain: string, trackingIds: string[]): void {
    const session = this.storage.getSession(this.currentSessionId);
    if (!session) return;

    const uniqueDomains = Array.from(new Set([...session.uniqueDomains, domain]));
    const allTrackingIds = Array.from(new Set([...session.trackingIds, ...trackingIds]));

    this.storage.updateSession(this.currentSessionId, {
      requestCount: session.requestCount + 1,
      uniqueDomains,
      trackingIds: allTrackingIds,
    });
  }

  /**
   * Handle incoming TCP connection
   */
  private handleConnection(socket: Socket): void {
    logger.debug('New connection established');

    let buffer = Buffer.alloc(0);
    let requestProcessed = false;

    socket.on('data', async (data: Buffer) => {
      if (requestProcessed) return;

      buffer = Buffer.concat([buffer, data]);

      // Try to parse HTTP request
      const requestStr = buffer.toString('utf8');
      const headerEndIndex = requestStr.indexOf('\r\n\r\n');
      
      if (headerEndIndex === -1) return; // Haven't received complete headers yet

      requestProcessed = true;
      const headerSection = requestStr.substring(0, headerEndIndex);
      const bodySection = requestStr.substring(headerEndIndex + 4);
      const lines = headerSection.split('\r\n');
      const requestLine = lines[0];

      if (!requestLine) {
        socket.destroy();
        return;
      }

      logger.debug('Request received', { requestLine });

      // Parse request method and URL
      const match = requestLine.match(/^(\w+)\s+(.+)\s+HTTP\/[\d.]+$/);
      if (!match || !match[1] || !match[2]) {
        logger.warn('Invalid HTTP request format', { requestLine });
        socket.destroy();
        return;
      }

      const method = match[1];
      const url = match[2];

      if (method === 'CONNECT') {
        await this.handleConnectRequest(socket, url, lines.slice(1));
      } else {
        await this.handleHttpRequest(socket, method, url, lines.slice(1), bodySection);
      }
    });

    socket.on('error', (error) => {
      logger.error('Socket error', { error: error.message });
    });

    socket.on('close', () => {
      logger.debug('Connection closed');
    });
  }

  /**
   * Handle regular HTTP request
   */
  private async handleHttpRequest(
    clientSocket: Socket,
    method: string,
    url: string,
    headerLines: string[],
    body: string
  ): Promise<void> {
    const startTime = performance.now();
    const requestId = generateRequestId();
    
    // Parse headers
    const headers: Record<string, string> = {};
    for (const line of headerLines) {
      if (line.trim() === '') break;
      const headerMatch = line.match(/^([^:]+):\s*(.+)$/);
      if (headerMatch && headerMatch[1] && headerMatch[2]) {
        headers[headerMatch[1].toLowerCase()] = headerMatch[2];
      }
    }

    // Build full URL if relative
    let fullUrl = url;
    if (url.startsWith('/')) {
      const host = headers['host'] || 'localhost';
      fullUrl = `http://${host}${url}`;
    }

    const domain = extractDomain(fullUrl);
    const isTelemetry = isTelemetryDomain(fullUrl);
    const telemetryCategory = classifyTelemetryDomain(domain);

    if (telemetryCategory !== 'ignore') {
      logger.info('🎯 Arc HTTP telemetry', {
        requestId,
        method,
        url: fullUrl,
        domain,
        category: telemetryCategory,
        sessionId: this.currentSessionId,
      });
    }

    const urlTrackingIds = extractTrackingIds(fullUrl);
    const bodyTrackingIds = body ? extractTrackingIdsFromBody(body, headers['content-type']) : [];
    const allTrackingIds = [...urlTrackingIds, ...bodyTrackingIds];

    const telemetryRequest: TelemetryRequest & {
      sessionId: string;
      domain: string;
      isTelemetry: boolean;
      telemetryCategory: string;
      requestHash: string;
    } = {
      id: requestId,
      timestamp: new Date(),
      method: method as any,
      url: fullUrl,
      headers,
      body: body || undefined,
      userAgent: headers['user-agent'],
      origin: headers['origin'],
      sessionId: this.currentSessionId,
      domain,
      isTelemetry,
      telemetryCategory,
      requestHash: generateRequestHash(method, fullUrl, body),
    };

    // Always save Arc telemetry, but only log it
    if (telemetryCategory !== 'ignore') {
      this.storage.saveRequest(telemetryRequest);
    }

    try {
      // Always forward ALL requests (proxy must handle all traffic)
      const response = await this.forwardHttpRequest(method, fullUrl, headers, body);
      const endTime = performance.now();
      const responseTime = endTime - startTime;

      // Save response
      const telemetryResponse: TelemetryResponse & { sessionId: string } = {
        id: generateRequestId(),
        requestId,
        timestamp: new Date(),
        status: response.status,
        statusText: response.statusText,
        headers: response.headers,
        body: response.body,
        responseTime,
        sessionId: this.currentSessionId,
      };

      this.storage.saveResponse(telemetryResponse);

      // Update session statistics
      this.updateSessionStats(domain, allTrackingIds.map(t => t.value));

      // Send response back to client
      this.sendHttpResponse(clientSocket, response);

      logger.info('HTTP request completed', {
        requestId,
        status: response.status,
        responseTime,
        sessionId: this.currentSessionId,
      });

    } catch (error) {
      logger.error('HTTP request failed', {
        requestId,
        error: (error as Error).message,
        sessionId: this.currentSessionId,
      });

      // Send error response
      const errorResponse = 'HTTP/1.1 502 Bad Gateway\r\n\r\nProxy Error: ' + (error as Error).message;
      clientSocket.write(errorResponse);
      clientSocket.destroy();
    }
  }

  /**
   * Forward HTTP request to target server
   */
  private async forwardHttpRequest(
    method: string,
    url: string,
    headers: Record<string, string>,
    body?: string
  ): Promise<{
    status: number;
    statusText: string;
    headers: Record<string, string>;
    body?: string;
  }> {
    const requestHeaders = { ...headers };
    delete requestHeaders['host']; // Let fetch handle this
    
    const response = await fetch(url, {
      method,
      headers: requestHeaders,
      body: (method !== 'GET' && method !== 'HEAD') ? body : undefined,
    });

    const responseHeaders: Record<string, string> = {};
    response.headers.forEach((value, key) => {
      responseHeaders[key] = value;
    });

    let responseBody: string | undefined;
    const contentType = response.headers.get('content-type') || '';
    
    if (contentType.includes('json') || contentType.includes('text') || contentType.includes('xml')) {
      try {
        responseBody = await response.text();
      } catch (error) {
        logger.warn('Failed to read response body', { error: (error as Error).message });
      }
    }

    return {
      status: response.status,
      statusText: response.statusText,
      headers: responseHeaders,
      body: responseBody,
    };
  }

  /**
   * Send HTTP response to client
   */
  private sendHttpResponse(
    socket: Socket,
    response: {
      status: number;
      statusText: string;
      headers: Record<string, string>;
      body?: string;
    }
  ): void {
    let responseText = `HTTP/1.1 ${response.status} ${response.statusText}\r\n`;
    
    // Add headers
    for (const [key, value] of Object.entries(response.headers)) {
      responseText += `${key}: ${value}\r\n`;
    }
    
    responseText += '\r\n';
    
    // Add body if present
    if (response.body) {
      responseText += response.body;
    }

    socket.write(responseText);
    socket.destroy();
  }

  /**
   * Handle CONNECT request for HTTPS tunneling
   */
  private async handleConnectRequest(
    clientSocket: Socket,
    target: string,
    headerLines: string[]
  ): Promise<void> {
    const connectTarget = TLSManager.parseConnectRequest(target);
    if (!connectTarget) {
      logger.warn('Invalid CONNECT target format', { target });
      clientSocket.write('HTTP/1.1 400 Bad Request\r\n\r\n');
      clientSocket.destroy();
      return;
    }

    const { host, port } = connectTarget;

    // Parse headers
    const headers: Record<string, string> = {};
    for (const line of headerLines) {
      if (line.trim() === '') break;
      const headerMatch = line.match(/^([^:]+):\s*(.+)$/);
      if (headerMatch && headerMatch[1] && headerMatch[2]) {
        headers[headerMatch[1].toLowerCase()] = headerMatch[2];
      }
    }

    // Create CONNECT request record
    const connectRequest: ConnectRequest = {
      id: generateRequestId(),
      timestamp: new Date(),
      method: 'CONNECT',
      host,
      port,
      headers,
      userAgent: headers['user-agent'],
      sessionId: this.currentSessionId,
    };

    const isTelemetryHost = isTelemetryDomain(`https://${host}`);
    const telemetryCategory = classifyTelemetryDomain(host);
    
    // Only log and store Arc telemetry domains
    if (telemetryCategory !== 'ignore') {
      logger.warn('🎯 ARC TELEMETRY DOMAIN DETECTED', {
        requestId: connectRequest.id,
        telemetryService: this.getTelemetryServiceName(host),
        host,
        port,
        category: telemetryCategory,
        userAgent: connectRequest.userAgent,
        sessionId: this.currentSessionId,
        timestamp: connectRequest.timestamp.toISOString(),
      });
      
      this.storage.saveConnectRequest({
        ...connectRequest,
        telemetryCategory
      });
    }

    try {
      // Always handle ALL CONNECT requests (proxy functionality)
      if (this.mitmTunnel) {
        // Only intercept Arc telemetry for TLS decryption
        const shouldIntercept = telemetryCategory === 'arc' || telemetryCategory === 'possible';
        await this.mitmTunnel.handleConnect(clientSocket, connectRequest, shouldIntercept);
      } else {
        // Always create direct tunnel for all traffic
        await this.createDirectTunnel(clientSocket, host, port);
      }
    } catch (error) {
      logger.error('CONNECT request failed', {
        requestId: connectRequest.id,
        host,
        port,
        error: (error as Error).message,
      });
      
      clientSocket.write('HTTP/1.1 502 Bad Gateway\r\n\r\n');
      clientSocket.destroy();
    }
  }

  /**
   * Create direct tunnel without interception (fallback)
   */
  private async createDirectTunnel(
    clientSocket: Socket,
    host: string,
    port: number
  ): Promise<void> {
    return new Promise((resolve, reject) => {
      const targetSocket = new Socket();

      targetSocket.connect(port, host, () => {
        logger.info('Direct tunnel established (fallback)', { host, port });

        // Send 200 Connection Established
        clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');

        // Setup bidirectional data flow
        clientSocket.pipe(targetSocket);
        targetSocket.pipe(clientSocket);

        resolve();
      });

      targetSocket.on('error', (error) => {
        logger.error('Direct tunnel connection failed', {
          host,
          port,
          error: error.message,
        });
        reject(error);
      });

      clientSocket.on('error', () => {
        targetSocket.destroy();
      });

      targetSocket.on('close', () => {
        clientSocket.destroy();
      });

      clientSocket.on('close', () => {
        targetSocket.destroy();
      });
    });
  }

  /**
   * Get telemetry service name from hostname
   */
  private getTelemetryServiceName(hostname: string): string {
    const serviceMap: Record<string, string> = {
      'api.segment.io': 'Segment Analytics',
      'firebaseio.com': 'Firebase',
      'amplitude.com': 'Amplitude',
      'sentry.io': 'Sentry Error Tracking',
      'launchdarkly.com': 'LaunchDarkly Feature Flags',
      'clientstream.launchdarkly.com': 'LaunchDarkly Streaming',
      'telemetry.arc.net': 'Arc Browser Telemetry',
      'analytics.arc.net': 'Arc Browser Analytics',
      'api.mixpanel.com': 'Mixpanel',
      'track.customer.io': 'Customer.io',
      'api.intercom.io': 'Intercom',
    };

    const lowerHost = hostname.toLowerCase();
    for (const [domain, service] of Object.entries(serviceMap)) {
      if (lowerHost === domain || lowerHost.endsWith(`.${domain}`)) {
        return service;
      }
    }

    return 'Unknown Telemetry Service';
  }

  /**
   * Start the proxy server
   */
  public async start(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.server.listen(this.config.port, () => {
        logger.info(`🚀 Pure Proxy Server started on port ${this.config.port}`);
        logger.info(`📊 Session: ${this.currentSessionId}`);
        logger.info('Setup Instructions:');
        logger.info(`1. Configure Arc Browser to use localhost:${this.config.port} as HTTP proxy`);
        logger.info(`2. Configure Arc Browser to use localhost:${this.config.port} as HTTPS proxy`);
        logger.info('3. Install the CA certificate for HTTPS interception');
        logger.info('4. Start browsing - telemetry traffic will be intercepted and analyzed');
        
        if (this.mitmTunnel) {
          logger.info('5. 🔐 HTTPS TLS interception is fully enabled for telemetry domains');
        }
        
        resolve();
      });

      this.server.on('error', reject);
    });
  }

  /**
   * Get current statistics
   */
  public getStats() {
    const sessionStats = this.storage.getSessionStats(this.currentSessionId);

    return {
      session: {
        sessionId: this.currentSessionId,
        ...sessionStats,
      },
      mitm: {
        enabled: !!this.mitmTunnel,
        certificatesLoaded: !!this.config.certPath && !!this.config.keyPath,
      },
    };
  }

  /**
   * Get storage service
   */
  public getStorage(): StorageService {
    return this.storage;
  }

  /**
   * Start new session
   */
  public startNewSession(): string {
    // End current session
    const currentSession = this.storage.getSession(this.currentSessionId);
    if (currentSession) {
      this.storage.updateSession(this.currentSessionId, {
        endTime: new Date(),
      });
      
      logger.info('Session ended', { 
        sessionId: this.currentSessionId,
        duration: Date.now() - currentSession.startTime.getTime(),
        requestCount: currentSession.requestCount,
      });
    }

    // Start new session
    this.currentSessionId = generateSessionId();
    this.initializeSession();
    
    return this.currentSessionId;
  }

  /**
   * Cleanup and close server
   */
  public cleanup(): void {
    // End current session
    const currentSession = this.storage.getSession(this.currentSessionId);
    if (currentSession && !currentSession.endTime) {
      this.storage.updateSession(this.currentSessionId, {
        endTime: new Date(),
      });
    }

    this.storage.close();
    
    this.server.close(() => {
      logger.info('Pure proxy server closed');
    });
  }
}