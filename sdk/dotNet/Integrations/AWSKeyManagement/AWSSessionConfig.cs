#nullable enable

namespace AWSKeyManagement
{
    public class AWSSessionConfig
    {
        public string? RegionName { get; set; }
        public string? AwsAccessKeyId { get; set; }
        public string? AwsSecretAccessKey { get; set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="AWSSessionConfig"/> class with specified AWS credentials and region.
        /// </summary>
        /// <param name="awsAccessKeyId">The AWS access key ID.</param>
        /// <param name="awsSecretAccessKey">The AWS secret access key.</param>
        /// <param name="regionName">The AWS region name.</param>

        public AWSSessionConfig(string? awsAccessKeyId, string? awsSecretAccessKey, string? regionName)
        {
            AwsAccessKeyId = awsAccessKeyId;
            AwsSecretAccessKey = awsSecretAccessKey;
            RegionName = regionName;
        }

        public AWSSessionConfig()
        {
            AwsAccessKeyId = System.Environment.GetEnvironmentVariable("AWS_ACCESS_KEY_ID");
            AwsSecretAccessKey = System.Environment.GetEnvironmentVariable("AWS_SECRET_ACCESS_KEY");
            RegionName = System.Environment.GetEnvironmentVariable("AWS_REGION");
        }
    }
}