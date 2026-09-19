import type { Context } from '@deepseek-ai/cordis';
import type WebServerBase from '@deepseek-ai/dsh-host-webserver';
import z from '@deepseek-ai/schemastery';
export declare const name = 'auth-gate-webserver';
export interface AuthConfig {
    dataDir: string;
    cookieName: string;
    sessionTtlHours: number;
    publicPaths: string[];
    trustProxy: boolean;
    issuer: string;
}
export declare const Config: z<any>;
export declare class GatedWebServer extends WebServerBase {
    gate: import('./gate.js').AuthGate;
    gateReady: boolean;
    constructor(ctx: Context, config: any);
    register(route: any): () => void;
    registerUpgrade(route: any): () => void;
    registerFallback(handler: any): () => void;
    init(): Promise<void>;
}
