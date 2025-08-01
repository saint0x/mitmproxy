# Arc Browser MITM Proxy

TypeScript MITM proxy for intercepting and analyzing Arc Browser telemetry traffic.

## Technical Features

- **TLS Interception**: Decrypts HTTPS traffic using certificate injection
- **TCP Proxy Server**: Pure Node.js implementation handling CONNECT method
- **Telemetry Detection**: Identifies tracking domains (LaunchDarkly, Sentry, Segment, etc.)
- **SQLite Storage**: Structured logging of requests/responses with foreign key relationships
- **Type Safety**: Full TypeScript with Zod validation

## Architecture

- `pure-proxy-server.ts` - Main TCP server handling HTTP/HTTPS tunneling
- `mitm-tunnel.ts` - TLS certificate injection and traffic interception
- `storage.ts` - SQLite database operations
- `utils/crypto.ts` - Request hashing and ID generation
- `utils/tls.ts` - Certificate management

## Quick Start

```bash
bun install
bun run cert && bun run install-cert
bun run build && bun start
```

Configure Arc Browser proxy settings to `localhost:8080` for both HTTP and HTTPS.

## Requirements

- Node.js 18+
- macOS (for mkcert certificate generation)
- Arc Browser

## Legal

Defensive security research only. Use on your own devices and traffic only.
