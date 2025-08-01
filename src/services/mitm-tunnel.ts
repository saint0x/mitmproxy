import { Socket } from 'net';
import { connect as tlsConnect, TLSSocket } from 'tls';
import { EventEmitter } from 'events';
import { logger } from '@/middleware/logger';
import { TLSManager } from '@/utils/tls';
import { generateRequestId } from '@/utils/crypto';
import type { ConnectRequest, HttpsRequest, HttpsResponse } from '@/schemas/request';

export class MITMTunnel extends EventEmitter {
  private tlsManager: TLSManager;

  constructor(certPath: string, keyPath: string) {
    super();
    this.tlsManager = new TLSManager(certPath, keyPath);
  }

  public async handleConnect(
    clientSocket: Socket,
    connectRequest: ConnectRequest,
    shouldIntercept: boolean = false
  ): Promise<void> {
    const { host, port } = connectRequest;

    if (shouldIntercept && TLSManager.isHttpsPort(port)) {
      logger.info('🔐 Attempting TLS interception', {
        requestId: connectRequest.id,
        host,
        port,
      });
      
      try {
        await this.createInterceptedTunnel(clientSocket, connectRequest);
      } catch (error) {
        logger.warn('TLS interception failed, falling back to direct tunnel', {
          requestId: connectRequest.id,
          host,
          port,
          error: (error as Error).message,
        });
        await this.createDirectTunnel(clientSocket, connectRequest);
      }
    } else {
      await this.createDirectTunnel(clientSocket, connectRequest);
    }
  }

  private async createDirectTunnel(
    clientSocket: Socket,
    connectRequest: ConnectRequest
  ): Promise<void> {
    const { host, port } = connectRequest;

    return new Promise((resolve, reject) => {
      const targetSocket = new Socket();

      targetSocket.connect(port, host, () => {
        logger.info('✅ Direct tunnel established', {
          requestId: connectRequest.id,
          host,
          port,
        });

        clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        clientSocket.pipe(targetSocket);
        targetSocket.pipe(clientSocket);

        resolve();
      });

      targetSocket.on('error', (error) => {
        logger.error('Direct tunnel failed', {
          requestId: connectRequest.id,
          host,
          port,
          error: error.message,
        });
        reject(error);
      });

      const cleanup = () => {
        targetSocket.destroy();
        clientSocket.destroy();
      };

      clientSocket.on('error', cleanup);
      clientSocket.on('close', cleanup);
      targetSocket.on('close', cleanup);
    });
  }

  private async createInterceptedTunnel(
    clientSocket: Socket,
    connectRequest: ConnectRequest
  ): Promise<void> {
    const { host, port } = connectRequest;

    return new Promise((resolve, reject) => {
      try {
        // Send 200 Connection Established first
        clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');

        const secureContext = this.tlsManager.createSecureContext();
        setImmediate(() => {
          try {
            const clientTLSSocket = new TLSSocket(clientSocket, {
              secureContext,
              isServer: true,
              rejectUnauthorized: false,
            });

            const targetSocket = tlsConnect({
              host,
              port,
              rejectUnauthorized: false,
            });
            let clientReady = false;
            let targetReady = false;

            const setupInterception = () => {
              if (clientReady && targetReady) {
                logger.info('🔓 TLS interception established', {
                  requestId: connectRequest.id,
                  host,
                  port,
                  clientCipher: clientTLSSocket.getCipher(),
                  targetCipher: targetSocket.getCipher(),
                });

                this.setupTrafficInterception(clientTLSSocket, targetSocket, connectRequest);
                resolve();
              }
            };

            clientTLSSocket.on('secure', () => {
              clientReady = true;
              setupInterception();
            });

            targetSocket.on('secureConnect', () => {
              targetReady = true;
              setupInterception();
            });

            // Error handlers
            clientTLSSocket.on('error', (error) => {
              logger.error('Client TLS error during interception', {
                requestId: connectRequest.id,
                host,
                error: error.message,
              });
              reject(error);
            });

            targetSocket.on('error', (error) => {
              logger.error('Target TLS error during interception', {
                requestId: connectRequest.id,
                host,
                error: error.message,
              });
              reject(error);
            });

          } catch (error) {
            reject(error);
          }
        });

      } catch (error) {
        reject(error);
      }
    });
  }

  /**
   * Setup traffic interception between client and target
   */
  private setupTrafficInterception(
    clientTLSSocket: TLSSocket,
    targetSocket: TLSSocket,
    connectRequest: ConnectRequest
  ): void {
    const { host, port } = connectRequest;

    // Buffer for parsing HTTP requests/responses
    let clientBuffer = Buffer.alloc(0);
    let targetBuffer = Buffer.alloc(0);
    let currentRequestId: string | null = null;

    // Client -> Target (requests)
    clientTLSSocket.on('data', (data: Buffer) => {
      clientBuffer = Buffer.concat([clientBuffer, data]);

      // Try to parse HTTP request
      const request = this.tryParseHttpRequest(clientBuffer, connectRequest);
      if (request) {
        currentRequestId = request.id; // Store for linking with response
        
        logger.info('📤 HTTPS request intercepted', {
          requestId: request.id,
          method: request.method,
          url: request.url,
          host,
        });

        this.emit('httpsRequest', request);
        clientBuffer = Buffer.alloc(0); // Reset buffer
      }

      // Forward to target
      targetSocket.write(data);
    });

    // Target -> Client (responses)
    targetSocket.on('data', (data: Buffer) => {
      targetBuffer = Buffer.concat([targetBuffer, data]);

      // Try to parse HTTP response
      const response = this.tryParseHttpResponse(targetBuffer, connectRequest, currentRequestId);
      if (response) {
        logger.info('📥 HTTPS response intercepted', {
          responseId: response.id,
          requestId: response.requestId,
          status: response.status,
          host,
        });

        this.emit('httpsResponse', response);
        targetBuffer = Buffer.alloc(0); // Reset buffer
        currentRequestId = null; // Reset after linking
      }

      // Forward to client
      clientTLSSocket.write(data);
    });

    // Cleanup handlers
    const cleanup = () => {
      clientTLSSocket.destroy();
      targetSocket.destroy();
    };

    clientTLSSocket.on('error', cleanup);
    clientTLSSocket.on('close', cleanup);
    targetSocket.on('error', cleanup);
    targetSocket.on('close', cleanup);
  }

  /**
   * Try to parse HTTP request from buffer
   */
  private tryParseHttpRequest(
    buffer: Buffer,
    connectRequest: ConnectRequest
  ): HttpsRequest | null {
    try {
      const data = buffer.toString('utf8');
      const headerEndIndex = data.indexOf('\r\n\r\n');
      
      if (headerEndIndex === -1) return null; // Incomplete request
      
      const headerSection = data.substring(0, headerEndIndex);
      const bodySection = data.substring(headerEndIndex + 4);
      const lines = headerSection.split('\r\n');
      const requestLine = lines[0];
      
      if (!requestLine) return null;
      
      const match = requestLine.match(/^(\w+)\s+(.+)\s+HTTP\/[\d.]+$/);
      if (!match || !match[1] || !match[2]) return null;
      
      const method = match[1] as any;
      const path = match[2];
      
      // Parse headers
      const headers: Record<string, string> = {};
      for (let i = 1; i < lines.length; i++) {
        const line = lines[i];
        if (line) {
          const headerMatch = line.match(/^([^:]+):\s*(.+)$/);
          if (headerMatch && headerMatch[1] && headerMatch[2]) {
            headers[headerMatch[1].toLowerCase()] = headerMatch[2];
          }
        }
      }
      
      // Construct full URL
      const url = path.startsWith('/') 
        ? `https://${connectRequest.host}${path}` 
        : path;
      
      return {
        id: generateRequestId(),
        timestamp: new Date(),
        method,
        url,
        headers,
        body: bodySection || undefined,
        userAgent: headers['user-agent'],
        origin: headers['origin'],
        tunnelId: connectRequest.id,
        tlsInfo: {
          serverName: connectRequest.host,
          protocol: 'TLS',
          cipher: 'unknown',
          serverCert: 'injected',
          injectedCert: true,
        },
        isDecrypted: true,
      };
      
    } catch (error) {
      // Failed to parse - not a complete HTTP request yet
      return null;
    }
  }

  /**
   * Try to parse HTTP response from buffer
   */
  private tryParseHttpResponse(
    buffer: Buffer,
    connectRequest: ConnectRequest,
    requestId?: string | null
  ): HttpsResponse | null {
    try {
      const data = buffer.toString('utf8');
      const headerEndIndex = data.indexOf('\r\n\r\n');
      
      if (headerEndIndex === -1) return null; // Incomplete response
      
      const headerSection = data.substring(0, headerEndIndex);
      const bodySection = data.substring(headerEndIndex + 4);
      const lines = headerSection.split('\r\n');
      const statusLine = lines[0];
      
      if (!statusLine) return null;
      
      const match = statusLine.match(/^HTTP\/[\d.]+\s+(\d+)\s+(.+)$/);
      if (!match || !match[1] || !match[2]) return null;
      
      const status = parseInt(match[1], 10);
      const statusText = match[2];
      
      // Parse headers
      const headers: Record<string, string> = {};
      for (let i = 1; i < lines.length; i++) {
        const line = lines[i];
        if (line) {
          const headerMatch = line.match(/^([^:]+):\s*(.+)$/);
          if (headerMatch && headerMatch[1] && headerMatch[2]) {
            headers[headerMatch[1].toLowerCase()] = headerMatch[2];
          }
        }
      }
      
      return {
        id: generateRequestId(),
        requestId: requestId || connectRequest.id, // Link to request or use connect ID as fallback
        timestamp: new Date(),
        status,
        statusText,
        headers,
        body: bodySection || undefined,
        responseTime: 0, // Will be calculated later
        tunnelId: connectRequest.id,
        tlsInfo: {
          serverName: connectRequest.host,
          protocol: 'TLS',
          cipher: 'unknown',
          serverCert: 'real',
          injectedCert: false,
        },
        isDecrypted: true,
      };
      
    } catch (error) {
      // Failed to parse - not a complete HTTP response yet
      return null;
    }
  }
}