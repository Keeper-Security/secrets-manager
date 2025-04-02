#nullable enable

using Google.Cloud.Kms.V1;
using Grpc.Auth;
using Google.Apis.Auth.OAuth2;
using System;
using System.IO;

public class GCPKMSClient
{
    private KeyManagementServiceClient? _kmsClient;

    /// <summary>
    /// Initializes a GCP KMS client using the default configuration.
    /// Uses Application Default Credentials (ADC) for authentication.
    /// </summary>
    public GCPKMSClient()
    {
        _kmsClient = null;
    }

    /// <summary>
    /// Creates a new GCP KMS client using the specified credentials file.
    /// </summary>
    /// <param name="credentialsKeyFilePath">The file path to the JSON key file containing service account credentials.</param>
    /// <returns>The GCPKMSClient instance.</returns>
    public GCPKMSClient CreateClientFromCredentialsFile(string credentialsKeyFilePath)
    {
        if (!File.Exists(credentialsKeyFilePath))
        {
            throw new ArgumentException("Invalid credentials file path.");
        }

        GoogleCredential credential = GoogleCredential.FromFile(credentialsKeyFilePath)
            .CreateScoped(KeyManagementServiceClient.DefaultScopes);

        _kmsClient = new KeyManagementServiceClientBuilder
        {
            ChannelCredentials = credential.ToChannelCredentials()
        }.Build();

        return this;
    }

    /// <summary>
    /// Creates a new GCP KMS client using the specified client email and private key.
    /// </summary>
    /// <param name="clientEmail">The email address associated with the service account.</param>
    /// <param name="privateKey">The private key corresponding to the service account.</param>
    /// <returns>The GCPKMSClient instance.</returns>
    public GCPKMSClient CreateClientUsingCredentials(string clientEmail, string privateKey)
    {
        var credential = GoogleCredential.FromJson($@"
        {{
            ""type"": ""service_account"",
            ""client_email"": ""{clientEmail}"",
            ""private_key"": ""{privateKey.Replace("\n", "\\n")}""
        }}").CreateScoped(KeyManagementServiceClient.DefaultScopes);

        _kmsClient = new KeyManagementServiceClientBuilder
        {
            ChannelCredentials = credential.ToChannelCredentials()
        }.Build();

        return this;
    }

    /// <summary>
    /// Returns the KMS client.
    /// </summary>
    /// <returns>The KMS client.</returns>
    public KeyManagementServiceClient GetCryptoClient()
    {
        if (_kmsClient == null)
        {
            throw new InvalidOperationException("KMS client not initialized. Please call CreateClientFromCredentialsFile or CreateClientUsingCredentials first.");
        }
        return _kmsClient;
    }
}
