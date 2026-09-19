export declare class AuthGate {
    constructor(config?: Partial<import('./webserver.js').AuthConfig>, workspaceRoot?: string);
    init(): Promise<void>;
    routes(): { kind: 'exact' | 'prefix'; path: string; handler: (req: import('node:http').IncomingMessage, res: import('node:http').ServerResponse) => Promise<void> | void }[];
    guardHttp(handler: (req: import('node:http').IncomingMessage, res: import('node:http').ServerResponse) => unknown): (req: import('node:http').IncomingMessage, res: import('node:http').ServerResponse) => Promise<void>;
    guardUpgrade(handler: any): any;
    readonly workspaceId: string;
    handleAdminPage(req: import('node:http').IncomingMessage, res: import('node:http').ServerResponse): void;
}
