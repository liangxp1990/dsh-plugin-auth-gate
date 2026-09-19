/**
 * The gated Web server: a drop-in replacement for the stock
 * `@deepseek-ai/dsh-host-webserver` service. It extends the stock class and
 * wraps every HTTP route registration, WebSocket upgrade registration, and the
 * fallback seat with the login gate, then mounts its own `/login` and
 * `/auth/*` control plane. Because the wrapping happens inside the service the
 * rest of the composition injects, route ordering carries no security weight:
 * rows registered before or after the gate all pass through it.
 *
 * The bundled `cordis.patch.yml` overrides the shipped `webserver` row with
 * this service, so a profile only needs this bundle in
 * `dsh.profile.bundles`.
 * @module dsh-plugin-auth-gate/webserver
 */
import { Service } from '@deepseek-ai/cordis';
import WebServerBase from '@deepseek-ai/dsh-host-webserver';
import z from '@deepseek-ai/schemastery';
import { AuthGate } from './gate.js';

/** Stable Cordis plugin (service) name. */
export const name = 'auth-gate-webserver';

export const Config = z.object({
  host: z.string().default('127.0.0.1'),
  port: z.number().default(3080),
  compression: z.string().default('gzip'),
  compressionLevel: z.number().default(1),
  compressionThresholdBytes: z.number().default(1024),
  auth: z.object({
    /** Absolute, or relative to the server's workspace root; default '.dsh-auth'. */
    dataDir: z.string().default(''),
    cookieName: z.string().default('dsh_auth'),
    sessionTtlHours: z.number().default(24 * 7),
    /** Extra ungated exact paths, e.g. a load-balancer health endpoint. */
    publicPaths: z.array(z.string()).default([]),
    /** Honor X-Forwarded-For / X-Forwarded-Proto from a trusted reverse proxy. */
    trustProxy: z.boolean().default(false),
    /** Issuer name shown in authenticator apps. */
    issuer: z.string().default('DSH')
  }).default({})
});

export class GatedWebServer extends WebServerBase {
  constructor(ctx, config) {
    super(ctx, config);
    this.gate = new AuthGate(config.auth ?? {}, process.cwd());
    this.gateReady = false;
  }

  async [Service.init]() {
    await this.gate.init();
    this.gateReady = true;
    for (const route of this.gate.routes()) super.register(route);
    this.ctx.logger.info('auth-gate: login gate active for workspace %s (accounts: %s)', this.gate.workspaceId, this.gate.store.directory);
    return super[Service.init]();
  }

  /** Every named route answers only with a valid session (gate paths exempt). */
  register(route) {
    return super.register({ ...route, handler: this.gate.guardHttp(route.handler) });
  }

  /** Every WebSocket upgrade requires a valid session before its handshake. */
  registerUpgrade(route) {
    return super.registerUpgrade({ ...route, handler: this.gate.guardUpgrade(route.handler) });
  }

  /** The SPA fallback seat is gated like any other route. */
  registerFallback(handler) {
    return super.registerFallback(this.gate.guardHttp(handler));
  }
}

//#region stock-class shims so the extension keeps the base's static surface
GatedWebServer.Config = Config;
//#endregion
