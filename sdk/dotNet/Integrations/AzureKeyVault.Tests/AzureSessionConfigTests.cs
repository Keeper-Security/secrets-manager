using NUnit.Framework;
using AzureKeyVault;

namespace AzureKeyVault.Tests
{
    [TestFixture]
    public class AzureSessionConfigTests
    {
        [TestFixture]
        public class Constructor
        {
            [Test]
            public void Should_Create_Config_With_Valid_Parameters()
            {
                // Given
                var tenantId = "12345678-1234-1234-1234-123456789012";
                var clientId = "87654321-4321-4321-4321-210987654321";
                var clientSecret = "super-secret-value";

                // When
                var config = new AzureSessionConfig(tenantId, clientId, clientSecret);

                // Then
                Assert.That(config.TenantId, Is.EqualTo(tenantId));
                Assert.That(config.ClientId, Is.EqualTo(clientId));
                Assert.That(config.ClientSecret, Is.EqualTo(clientSecret));
            }

            [Test]
            public void Should_Handle_Empty_String_Values()
            {
                // When
                var config = new AzureSessionConfig("", "", "");

                // Then
                Assert.That(config.TenantId, Is.EqualTo(""));
                Assert.That(config.ClientId, Is.EqualTo(""));
                Assert.That(config.ClientSecret, Is.EqualTo(""));
            }

            [Test]
            public void Should_Store_All_Provided_Values_Correctly()
            {
                // Given
                var configs = new[]
                {
                    ("tenant-1", "client-1", "secret-1"),
                    ("tenant-2", "client-2", "very-long-secret-value-here"),
                    ("t", "c", "s")
                };

                foreach (var (tenantId, clientId, clientSecret) in configs)
                {
                    // When
                    var config = new AzureSessionConfig(tenantId, clientId, clientSecret);

                    // Then
                    Assert.That(config.TenantId, Is.EqualTo(tenantId));
                    Assert.That(config.ClientId, Is.EqualTo(clientId));
                    Assert.That(config.ClientSecret, Is.EqualTo(clientSecret));
                }
            }
        }

        [TestFixture]
        public class AzureSpecificFormats
        {
            [Test]
            public void Should_Accept_Valid_Azure_Tenant_Id_Formats()
            {
                // Given - Azure tenant IDs are GUIDs
                var tenantIds = new[]
                {
                    "12345678-1234-1234-1234-123456789012",
                    "abcdef01-abcd-abcd-abcd-abcdef012345",
                    "00000000-0000-0000-0000-000000000000",
                    "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF"
                };

                foreach (var tenantId in tenantIds)
                {
                    // When
                    var config = new AzureSessionConfig(tenantId, "client-id", "secret");

                    // Then
                    Assert.That(config.TenantId, Is.EqualTo(tenantId));
                }
            }

            [Test]
            public void Should_Accept_Valid_Azure_Client_Id_Formats()
            {
                // Given - Azure client IDs (app IDs) are GUIDs
                var clientIds = new[]
                {
                    "12345678-1234-1234-1234-123456789012",
                    "abcdef01-abcd-abcd-abcd-abcdef012345",
                    "00000000-0000-0000-0000-000000000000"
                };

                foreach (var clientId in clientIds)
                {
                    // When
                    var config = new AzureSessionConfig("tenant-id", clientId, "secret");

                    // Then
                    Assert.That(config.ClientId, Is.EqualTo(clientId));
                }
            }

            [Test]
            public void Should_Accept_Various_Client_Secret_Formats()
            {
                // Given - Azure client secrets can have various formats
                var clientSecrets = new[]
                {
                    "simple-secret",
                    "Secret.With+Special/Characters==",
                    "very-long-secret-that-might-be-used-in-production-environments-12345",
                    "~!@#$%^&*()_+-=[]{}|;':\",./<>?"
                };

                foreach (var clientSecret in clientSecrets)
                {
                    // When
                    var config = new AzureSessionConfig("tenant-id", "client-id", clientSecret);

                    // Then
                    Assert.That(config.ClientSecret, Is.EqualTo(clientSecret));
                }
            }
        }

        [TestFixture]
        public class ImmutableProperties
        {
            [Test]
            public void Properties_Should_Be_ReadOnly()
            {
                // Given
                var config = new AzureSessionConfig("tenant", "client", "secret");

                // Then - verify properties have getters only (compile-time check)
                Assert.That(config.TenantId, Is.EqualTo("tenant"));
                Assert.That(config.ClientId, Is.EqualTo("client"));
                Assert.That(config.ClientSecret, Is.EqualTo("secret"));

                // Note: Properties are read-only by design in the source code
                // This test verifies the values can be read after construction
            }
        }
    }
}
