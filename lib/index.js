/**
 * @deepseek-ai/dsh-plugin-auth-gate — login gate, TOTP MFA, signed sessions,
 * and workspace-scoped account isolation for the DeepSeek Harness Web GUI.
 *
 * Two mounting forms:
 * 1. Bundled (recommended): the `cordis.patch.yml` in this package overrides
 *    the profile's `webserver` row with
 *    `dsh-plugin-auth-gate/webserver` (`GatedWebServer`), which gates every
 *    route regardless of registration order.
 * 2. Ordinary plugin (`dsh-plugin-auth-gate`, this module): wraps the already
 *    mounted `webServer` service's registration methods. Use this only in
 *    compositions where this plugin activates before any route registers.
 * @module dsh-plugin-auth-gate
 */
import z from '@deepseek-ai/schemastery';
import { AuthGate } from './gate.js';
import { name as webserverName, Config as webserverConfig, GatedWebServer } from './webserver.js';

/** Stable Cordis plugin name. */
export const name = 'auth-gate';

/** Services required before the gate can wrap the transport. */
export const inject = ['webServer'];

export const Config = z.object({
  dataDir: z.string().default(''),
  cookieName: z.string().default('dsh_auth'),
  sessionTtlHours: z.number().default(24 * 7),
  publicPaths: z.array(z.string()).default([]),
  trustProxy: z.boolean().default(false),
  issuer: z.string().default('DSH')
});

/**
 * Wrap the mounted webServer: install the gate, then rewrite the three
 * registration surfaces so routes registered afterwards are covered too.
 * @param ctx - plugin context carrying the webServer service.
 * @param config - validated {@link Config}.
 */
export function apply(ctx, config) {
  const webServer = ctx.webServer;
  const gate = new AuthGate(config, process.cwd());
  const prototype = Object.getPrototypeOf(webServer);
  const baseRegister = prototype.register;
  const baseRegisterUpgrade = prototype.registerUpgrade;
  const baseRegisterFallback = prototype.registerFallback;

  // Gate-owned routes must not wrap themselves; guardHttp exempts them by path.
  const ownRegister = baseRegister.bind(webServer);
  const ready = gate.init().then(() => {
    for (const route of gate.routes()) ownRegister(route);
    ctx.logger.info('auth-gate: wrapping webServer registrations for workspace %s', gate.workspaceId);
    prototype.register = function register(route) {
      return baseRegister.call(this, { ...route, handler: gate.guardHttp(route.handler) });
    };
    prototype.registerUpgrade = function registerUpgrade(route) {
      return baseRegisterUpgrade.call(this, { ...route, handler: gate.guardUpgrade(route.handler) });
    };
    prototype.registerFallback = function registerFallback(handler) {
      return baseRegisterFallback.call(this, gate.guardHttp(handler));
    };
  });
  ctx.on('dispose', () => {
    prototype.register = baseRegister;
    prototype.registerUpgrade = baseRegisterUpgrade;
    prototype.registerFallback = baseRegisterFallback;
  });
  return ready;
}

export { AuthGate, GatedWebServer, webserverName, webserverConfig };
