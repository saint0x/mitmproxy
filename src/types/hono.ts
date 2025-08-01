import { Context } from 'hono';

// Extend Hono's Context with custom variables
declare module 'hono' {
  interface ContextVariableMap {
    sessionId: string;
    requestId: string;
    requestTimestamp: string;
    isTelemetry: boolean;
  }
}

export type ExtendedContext = Context<{
  Variables: {
    sessionId: string;
    requestId: string;
    requestTimestamp: string;
    isTelemetry: boolean;
  };
}>;