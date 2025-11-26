using NUnit.Framework;
using System;

namespace OracleKeyManagement.Tests
{
    [TestFixture]
    public class OciSessionConfigTests
    {
        [TestFixture]
        public class Constructor
        {
            [Test]
            public void Should_Create_Config_With_Required_Parameters()
            {
                // Given
                var configFile = "/path/to/oci/config";

                // When
                var config = new OciSessionConfig(configFile);

                // Then - verify config was created (GetProvider will throw if invalid, but we can't test without real file)
                Assert.That(config.GetKmsCryptoEndpoint(), Is.EqualTo(""));
                Assert.That(config.GetKmsManagementEndpoint(), Is.EqualTo(""));
            }

            [Test]
            public void Should_Create_Config_With_All_Parameters()
            {
                // Given
                var configFile = "/path/to/oci/config";
                var profile = "CUSTOM_PROFILE";
                var cryptoEndpoint = "https://crypto.kms.us-ashburn-1.oraclecloud.com";
                var managementEndpoint = "https://management.kms.us-ashburn-1.oraclecloud.com";

                // When
                var config = new OciSessionConfig(configFile, profile, cryptoEndpoint, managementEndpoint);

                // Then
                Assert.That(config.GetKmsCryptoEndpoint(), Is.EqualTo(cryptoEndpoint));
                Assert.That(config.GetKmsManagementEndpoint(), Is.EqualTo(managementEndpoint));
            }

            [Test]
            public void Should_Use_DEFAULT_Profile_When_Profile_Is_Null()
            {
                // Given
                var configFile = "/path/to/oci/config";

                // When - profile defaults to "DEFAULT" internally
                var config = new OciSessionConfig(configFile, null);

                // Then - can't directly verify profile, but construction should succeed
                Assert.That(config.GetKmsCryptoEndpoint(), Is.EqualTo(""));
            }

            [Test]
            public void Should_Throw_When_ConfigFile_Is_Null()
            {
                // When/Then
                Assert.Throws<ArgumentNullException>(() => new OciSessionConfig(null!));
            }
        }

        [TestFixture]
        public class GetKmsCryptoEndpoint
        {
            [Test]
            public void Should_Return_Empty_String_When_Not_Set()
            {
                // Given
                var config = new OciSessionConfig("/path/to/config");

                // When
                var endpoint = config.GetKmsCryptoEndpoint();

                // Then
                Assert.That(endpoint, Is.EqualTo(""));
            }

            [Test]
            public void Should_Return_Provided_Endpoint()
            {
                // Given
                var cryptoEndpoint = "https://crypto.kms.us-ashburn-1.oraclecloud.com";
                var config = new OciSessionConfig("/path/to/config", null, cryptoEndpoint);

                // When
                var endpoint = config.GetKmsCryptoEndpoint();

                // Then
                Assert.That(endpoint, Is.EqualTo(cryptoEndpoint));
            }
        }

        [TestFixture]
        public class GetKmsManagementEndpoint
        {
            [Test]
            public void Should_Return_Empty_String_When_Not_Set()
            {
                // Given
                var config = new OciSessionConfig("/path/to/config");

                // When
                var endpoint = config.GetKmsManagementEndpoint();

                // Then
                Assert.That(endpoint, Is.EqualTo(""));
            }

            [Test]
            public void Should_Return_Provided_Endpoint()
            {
                // Given
                var managementEndpoint = "https://management.kms.us-ashburn-1.oraclecloud.com";
                var config = new OciSessionConfig("/path/to/config", null, "", managementEndpoint);

                // When
                var endpoint = config.GetKmsManagementEndpoint();

                // Then
                Assert.That(endpoint, Is.EqualTo(managementEndpoint));
            }
        }

        [TestFixture]
        public class OciSpecificFormats
        {
            [Test]
            public void Should_Accept_Valid_OCI_Region_Endpoints()
            {
                // Given - OCI KMS endpoints for different regions
                var endpoints = new[]
                {
                    "https://crypto.kms.us-ashburn-1.oraclecloud.com",
                    "https://crypto.kms.us-phoenix-1.oraclecloud.com",
                    "https://crypto.kms.eu-frankfurt-1.oraclecloud.com",
                    "https://crypto.kms.ap-tokyo-1.oraclecloud.com",
                    "https://crypto.kms.uk-london-1.oraclecloud.com"
                };

                foreach (var endpoint in endpoints)
                {
                    // When
                    var config = new OciSessionConfig("/path/to/config", null, endpoint);

                    // Then
                    Assert.That(config.GetKmsCryptoEndpoint(), Is.EqualTo(endpoint));
                }
            }

            [Test]
            public void Should_Accept_Various_Profile_Names()
            {
                // Given - OCI profile names
                var profiles = new[]
                {
                    "DEFAULT",
                    "development",
                    "production",
                    "my-custom-profile"
                };

                foreach (var profile in profiles)
                {
                    // When - construction should not throw
                    var config = new OciSessionConfig("/path/to/config", profile);

                    // Then - profile is stored (can't directly verify, but construction succeeded)
                    Assert.That(config.GetKmsCryptoEndpoint(), Is.EqualTo(""));
                }
            }

            [Test]
            public void Should_Accept_Various_Config_File_Paths()
            {
                // Given - OCI config file paths
                var configPaths = new[]
                {
                    "/home/user/.oci/config",
                    "/etc/oci/config",
                    "~/.oci/config",
                    "/path/with spaces/config"
                };

                foreach (var path in configPaths)
                {
                    // When - construction should not throw for path format
                    var config = new OciSessionConfig(path);

                    // Then
                    Assert.That(config.GetKmsCryptoEndpoint(), Is.EqualTo(""));
                }
            }
        }
    }
}
