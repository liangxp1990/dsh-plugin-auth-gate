import type { Context } from '@deepseek-ai/cordis';
import z from '@deepseek-ai/schemastery';
export declare const name = 'auth-gate';
export declare const inject: string[];
export interface Config {
    dataDir: string;
    cookieName: string;
    sessionTtlHours: number;
    publicPaths: string[];
    trustProxy: boolean;
    issuer: string;
}
export declare const Config: z<Config>;
export declare function apply(ctx: Context, config: Config): Promise<void>;
export { AuthGate } from './gate.js';
export { GatedWebServer } from './webserver.js';
