import { readFileSync } from 'fs';
import { createSecureContext, SecureContext } from 'tls';

export class TLSManager {
  private caCert: string;
  private caKey: string;

  constructor(certPath: string, keyPath: string) {
    try {
      this.caCert = readFileSync(certPath, 'utf8');
      this.caKey = readFileSync(keyPath, 'utf8');
    } catch (error) {
      throw new Error(`Failed to load TLS certificates: ${(error as Error).message}`);
    }
  }

  public createSecureContext(): SecureContext {
    return createSecureContext({
      key: this.caKey,
      cert: this.caCert,
    });
  }

  public static parseConnectRequest(url: string): { host: string; port: number } | null {
    try {
      const match = url.match(/^([^:]+):(\d+)$/);
      if (!match || !match[1] || !match[2]) return null;

      const host = match[1];
      const port = parseInt(match[2], 10);

      if (isNaN(port) || port < 1 || port > 65535) return null;

      return { host, port };
    } catch {
      return null;
    }
  }

  public static isHttpsPort(port: number): boolean {
    return port === 443 || port === 8443 || port === 9443;
  }
}