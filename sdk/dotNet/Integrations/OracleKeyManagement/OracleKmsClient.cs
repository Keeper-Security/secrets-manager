using System;
using Microsoft.Extensions.Logging;
using Oci.Common;
using Oci.Common.Auth;
using Oci.KeymanagementService;
using Oci.KeymanagementService.Requests;
using Oci.KeymanagementService.Responses;
using OracleKeyManagement;

public class OciKmsClient
{
    private readonly KmsCryptoClient _kmsCryptoClient;
    private readonly KmsManagementClient _kmsManagementClient;
    private readonly ILogger _logger;

    public OciKmsClient(OciSessionConfig sessionConfig, ILogger logger)
    {
        try
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));

            var provider = sessionConfig.GetProvider();
            var cryptoEndpoint = sessionConfig.GetKmsCryptoEndpoint();
            var managementEndpoint = sessionConfig.GetKmsManagementEndpoint();

            _kmsCryptoClient = new KmsCryptoClient(provider);
            _kmsCryptoClient.SetEndpoint(cryptoEndpoint);
            _kmsManagementClient = new KmsManagementClient(provider);
            _kmsManagementClient.SetEndpoint(managementEndpoint);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to initialize OCI KMS Clients.");
            throw new Exception($"Failed to initialize OCI KMS Clients: {ex.Message}", ex);
        }
    }

    public KmsCryptoClient GetCryptoClient()
    {
        return _kmsCryptoClient ?? throw new InvalidOperationException("KMS Crypto Client is not initialized.");
    }

    public KmsManagementClient GetManagementClient()
    {
        return _kmsManagementClient ?? throw new InvalidOperationException("KMS Management Client is not initialized.");
    }
}

