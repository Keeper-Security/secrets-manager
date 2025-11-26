namespace AzureKeyVault
{
    public class AzureSessionConfig
    {
        public string TenantId { get; }
        public string ClientId { get; }
        public string ClientSecret { get; }

        public AzureSessionConfig(string tenantId, string clientId, string clientSecret)
        {
            TenantId = tenantId;
            ClientId = clientId;
            ClientSecret = clientSecret;
        }
    }
}