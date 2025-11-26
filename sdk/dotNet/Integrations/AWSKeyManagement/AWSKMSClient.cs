#nullable enable

using System;
using Amazon;
using Amazon.KeyManagementService;
using Amazon.Runtime;
using AWSKeyManagement;
using Microsoft.Extensions.Logging;

public class AwsKmsClient
{
    private readonly AmazonKeyManagementServiceClient kmsClient;

    public AwsKmsClient(AWSSessionConfig? awsSessionConfig = null, ILogger? logger = null)
    {
        logger = GetLogger(logger);
        if (awsSessionConfig == null)
        {
            kmsClient = new AmazonKeyManagementServiceClient();
        }
        else
        {
            if (awsSessionConfig.AwsAccessKeyId != null && awsSessionConfig.AwsSecretAccessKey != null){
                logger.LogInformation("AWS Access Key ID and Secret Access Key are given, choosing credentials from given credentials");
            }
            else if (awsSessionConfig.AwsAccessKeyId == null || awsSessionConfig.AwsSecretAccessKey == null)
            {
                awsSessionConfig.AwsAccessKeyId = Environment.GetEnvironmentVariable("AWS_ACCESS_KEY_ID");
                awsSessionConfig.AwsSecretAccessKey = Environment.GetEnvironmentVariable("AWS_SECRET_ACCESS_KEY");
                logger.LogInformation("AWS Access Key ID and Secret Access Key are not given, trying to choose credentials from Environment");
            }
            if (awsSessionConfig.AwsAccessKeyId != null && awsSessionConfig.AwsSecretAccessKey != null)
            {
                var credentials = new BasicAWSCredentials(
                    awsSessionConfig.AwsAccessKeyId,
                    awsSessionConfig.AwsSecretAccessKey
                );
                if (awsSessionConfig.RegionName == null || awsSessionConfig.RegionName == "")
                {
                    throw new Exception("AWS Region is not given");
                }
                kmsClient = new AmazonKeyManagementServiceClient(credentials, RegionEndpoint.GetBySystemName(awsSessionConfig.RegionName));
            }
            else
            {
                logger.LogInformation("AWS Access Key ID and Secret Access Key are not given, choosing default credentials from file");
                kmsClient = new AmazonKeyManagementServiceClient();

            }
        }
    }

    private ILogger GetLogger(ILogger? logger)
    {
        return logger ?? LoggerFactory.Create(builder =>
        {
            builder.SetMinimumLevel(LogLevel.Information);
            builder.AddConsole();
        }).CreateLogger<AWSKeyValueStorage>();
    }

    public AmazonKeyManagementServiceClient GetCryptoClient()
    {
        return kmsClient;
    }
}
