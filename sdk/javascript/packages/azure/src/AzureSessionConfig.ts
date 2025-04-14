
export class AzureSessionConfig {
    tenantId: string;
    clientId: string;
    clientSecret: string;

    constructor(tenantId: string, clientId: string, clientSecret: string) {
        this.tenantId = tenantId;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
    }
}