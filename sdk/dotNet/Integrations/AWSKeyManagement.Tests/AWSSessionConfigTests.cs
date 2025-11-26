using NUnit.Framework;
using AWSKeyManagement;
using System;

namespace AWSKeyManagement.Tests
{
    [TestFixture]
    public class AWSSessionConfigTests
    {
        [TestFixture]
        public class Constructor
        {
            [Test]
            public void Should_Create_Config_With_Valid_Parameters()
            {
                // Given
                var awsAccessKeyId = "AKIAIOSFODNN7EXAMPLE";
                var awsSecretAccessKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
                var regionName = "us-east-1";

                // When
                var config = new AWSSessionConfig(awsAccessKeyId, awsSecretAccessKey, regionName);

                // Then
                Assert.That(config.AwsAccessKeyId, Is.EqualTo(awsAccessKeyId));
                Assert.That(config.AwsSecretAccessKey, Is.EqualTo(awsSecretAccessKey));
                Assert.That(config.RegionName, Is.EqualTo(regionName));
            }

            [Test]
            public void Should_Handle_Empty_String_Values()
            {
                // When
                var config = new AWSSessionConfig("", "", "");

                // Then
                Assert.That(config.AwsAccessKeyId, Is.EqualTo(""));
                Assert.That(config.AwsSecretAccessKey, Is.EqualTo(""));
                Assert.That(config.RegionName, Is.EqualTo(""));
            }

            [Test]
            public void Should_Handle_Null_Values()
            {
                // When
                var config = new AWSSessionConfig(null, null, null);

                // Then
                Assert.That(config.AwsAccessKeyId, Is.Null);
                Assert.That(config.AwsSecretAccessKey, Is.Null);
                Assert.That(config.RegionName, Is.Null);
            }

            [Test]
            public void Should_Store_All_Provided_Values_Correctly()
            {
                // Given
                var configs = new[]
                {
                    ("AKIAIOSFODNN7EXAMPLE", "secret1", "us-east-1"),
                    ("AKIATESTKEYID123456", "very-long-secret-key-here", "eu-west-1"),
                    ("AKIA", "s", "us-west-2")
                };

                foreach (var (accessKey, secretKey, region) in configs)
                {
                    // When
                    var config = new AWSSessionConfig(accessKey, secretKey, region);

                    // Then
                    Assert.That(config.AwsAccessKeyId, Is.EqualTo(accessKey));
                    Assert.That(config.AwsSecretAccessKey, Is.EqualTo(secretKey));
                    Assert.That(config.RegionName, Is.EqualTo(region));
                }
            }
        }

        [TestFixture]
        public class DefaultConstructor
        {
            [Test]
            public void Should_Read_From_Environment_Variables()
            {
                // Given
                var originalAccessKey = Environment.GetEnvironmentVariable("AWS_ACCESS_KEY_ID");
                var originalSecretKey = Environment.GetEnvironmentVariable("AWS_SECRET_ACCESS_KEY");
                var originalRegion = Environment.GetEnvironmentVariable("AWS_REGION");

                try
                {
                    Environment.SetEnvironmentVariable("AWS_ACCESS_KEY_ID", "AKIAENVTESTKEY");
                    Environment.SetEnvironmentVariable("AWS_SECRET_ACCESS_KEY", "env-secret-key");
                    Environment.SetEnvironmentVariable("AWS_REGION", "eu-central-1");

                    // When
                    var config = new AWSSessionConfig();

                    // Then
                    Assert.That(config.AwsAccessKeyId, Is.EqualTo("AKIAENVTESTKEY"));
                    Assert.That(config.AwsSecretAccessKey, Is.EqualTo("env-secret-key"));
                    Assert.That(config.RegionName, Is.EqualTo("eu-central-1"));
                }
                finally
                {
                    // Restore original environment variables
                    Environment.SetEnvironmentVariable("AWS_ACCESS_KEY_ID", originalAccessKey);
                    Environment.SetEnvironmentVariable("AWS_SECRET_ACCESS_KEY", originalSecretKey);
                    Environment.SetEnvironmentVariable("AWS_REGION", originalRegion);
                }
            }

            [Test]
            public void Should_Return_Null_When_Environment_Variables_Not_Set()
            {
                // Given
                var originalAccessKey = Environment.GetEnvironmentVariable("AWS_ACCESS_KEY_ID");
                var originalSecretKey = Environment.GetEnvironmentVariable("AWS_SECRET_ACCESS_KEY");
                var originalRegion = Environment.GetEnvironmentVariable("AWS_REGION");

                try
                {
                    Environment.SetEnvironmentVariable("AWS_ACCESS_KEY_ID", null);
                    Environment.SetEnvironmentVariable("AWS_SECRET_ACCESS_KEY", null);
                    Environment.SetEnvironmentVariable("AWS_REGION", null);

                    // When
                    var config = new AWSSessionConfig();

                    // Then
                    Assert.That(config.AwsAccessKeyId, Is.Null);
                    Assert.That(config.AwsSecretAccessKey, Is.Null);
                    Assert.That(config.RegionName, Is.Null);
                }
                finally
                {
                    // Restore original environment variables
                    Environment.SetEnvironmentVariable("AWS_ACCESS_KEY_ID", originalAccessKey);
                    Environment.SetEnvironmentVariable("AWS_SECRET_ACCESS_KEY", originalSecretKey);
                    Environment.SetEnvironmentVariable("AWS_REGION", originalRegion);
                }
            }
        }

        [TestFixture]
        public class PropertyAssignment
        {
            [Test]
            public void Should_Allow_Modifying_AwsAccessKeyId_After_Creation()
            {
                // Given
                var config = new AWSSessionConfig("AKIAORIGINAL", "secret", "us-east-1");
                var newAccessKeyId = "AKIANEWKEYID";

                // When
                config.AwsAccessKeyId = newAccessKeyId;

                // Then
                Assert.That(config.AwsAccessKeyId, Is.EqualTo(newAccessKeyId));
                Assert.That(config.AwsSecretAccessKey, Is.EqualTo("secret"));
                Assert.That(config.RegionName, Is.EqualTo("us-east-1"));
            }

            [Test]
            public void Should_Allow_Modifying_AwsSecretAccessKey_After_Creation()
            {
                // Given
                var config = new AWSSessionConfig("AKIATEST", "original-secret", "us-east-1");
                var newSecretAccessKey = "new-secret-key";

                // When
                config.AwsSecretAccessKey = newSecretAccessKey;

                // Then
                Assert.That(config.AwsAccessKeyId, Is.EqualTo("AKIATEST"));
                Assert.That(config.AwsSecretAccessKey, Is.EqualTo(newSecretAccessKey));
                Assert.That(config.RegionName, Is.EqualTo("us-east-1"));
            }

            [Test]
            public void Should_Allow_Modifying_RegionName_After_Creation()
            {
                // Given
                var config = new AWSSessionConfig("AKIATEST", "secret", "us-east-1");
                var newRegionName = "eu-central-1";

                // When
                config.RegionName = newRegionName;

                // Then
                Assert.That(config.AwsAccessKeyId, Is.EqualTo("AKIATEST"));
                Assert.That(config.AwsSecretAccessKey, Is.EqualTo("secret"));
                Assert.That(config.RegionName, Is.EqualTo(newRegionName));
            }

            [Test]
            public void Should_Allow_Setting_Properties_To_Empty_Strings()
            {
                // Given
                var config = new AWSSessionConfig("AKIATEST", "secret", "us-east-1");

                // When
                config.AwsAccessKeyId = "";
                config.AwsSecretAccessKey = "";
                config.RegionName = "";

                // Then
                Assert.That(config.AwsAccessKeyId, Is.EqualTo(""));
                Assert.That(config.AwsSecretAccessKey, Is.EqualTo(""));
                Assert.That(config.RegionName, Is.EqualTo(""));
            }

            [Test]
            public void Should_Allow_Setting_Properties_To_Null()
            {
                // Given
                var config = new AWSSessionConfig("AKIATEST", "secret", "us-east-1");

                // When
                config.AwsAccessKeyId = null;
                config.AwsSecretAccessKey = null;
                config.RegionName = null;

                // Then
                Assert.That(config.AwsAccessKeyId, Is.Null);
                Assert.That(config.AwsSecretAccessKey, Is.Null);
                Assert.That(config.RegionName, Is.Null);
            }
        }

        [TestFixture]
        public class AwsSpecificFormats
        {
            [Test]
            public void Should_Accept_Valid_AWS_Access_Key_ID_Formats()
            {
                // Given - AWS access keys start with AKIA, ASIA, etc.
                var accessKeyIds = new[]
                {
                    "AKIAIOSFODNN7EXAMPLE",      // Long-term credential
                    "ASIATESTACCESSKEY123",       // Temporary credential (STS)
                    "AKIA1234567890ABCDEF",       // Standard format
                    "AKIAT1234567890ABCDE"        // Varied length
                };

                foreach (var accessKeyId in accessKeyIds)
                {
                    // When
                    var config = new AWSSessionConfig(accessKeyId, "test-secret", "us-east-1");

                    // Then
                    Assert.That(config.AwsAccessKeyId, Is.EqualTo(accessKeyId));
                }
            }

            [Test]
            public void Should_Accept_Valid_AWS_Region_Name_Formats()
            {
                // Given - AWS region formats
                var regionNames = new[]
                {
                    "us-east-1",          // US East (N. Virginia)
                    "us-west-2",          // US West (Oregon)
                    "eu-central-1",       // Europe (Frankfurt)
                    "ap-southeast-1",     // Asia Pacific (Singapore)
                    "ca-central-1",       // Canada (Central)
                    "sa-east-1",          // South America (Sao Paulo)
                    "us-gov-west-1",      // AWS GovCloud (US-West)
                    "cn-north-1",         // China (Beijing)
                    "me-south-1",         // Middle East (Bahrain)
                    "af-south-1"          // Africa (Cape Town)
                };

                foreach (var regionName in regionNames)
                {
                    // When
                    var config = new AWSSessionConfig("AKIATEST", "test-secret", regionName);

                    // Then
                    Assert.That(config.RegionName, Is.EqualTo(regionName));
                }
            }

            [Test]
            public void Should_Accept_Various_Secret_Access_Key_Formats()
            {
                // Given - AWS secret access keys are 40 characters
                var secretAccessKeys = new[]
                {
                    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                    "abcdefghijklmnopqrstuvwxyz0123456789+/AB",
                    "A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T",
                    "1234567890abcdefghijklmnopqrstuvwxyz+/=="
                };

                foreach (var secretAccessKey in secretAccessKeys)
                {
                    // When
                    var config = new AWSSessionConfig("AKIATEST", secretAccessKey, "us-east-1");

                    // Then
                    Assert.That(config.AwsSecretAccessKey, Is.EqualTo(secretAccessKey));
                }
            }
        }
    }
}
