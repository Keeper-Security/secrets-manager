using NUnit.Framework;
using System;

namespace AzureKeyVault.Tests
{
    [TestFixture]
    public class ConstantsTests
    {
        [TestFixture]
        public class IntegrationConstantsTests
        {
            [Test]
            public void BLOB_HEADER_Should_Be_Two_Bytes_0xFF_0xFF()
            {
                // Then
                Assert.That(IntegrationConstants.BLOB_HEADER.Length, Is.EqualTo(2));
                Assert.That(IntegrationConstants.BLOB_HEADER[0], Is.EqualTo(0xFF));
                Assert.That(IntegrationConstants.BLOB_HEADER[1], Is.EqualTo(0xFF));
            }

            [Test]
            public void HEADER_SIZE_Should_Be_2()
            {
                Assert.That(IntegrationConstants.HEADER_SIZE, Is.EqualTo(2));
            }

            [Test]
            public void AES_KEY_SIZE_Should_Be_32_Bytes()
            {
                // 256-bit key = 32 bytes
                Assert.That(IntegrationConstants.AES_KEY_SIZE, Is.EqualTo(32));
            }

            [Test]
            public void NONCE_SIZE_Should_Be_12_Bytes()
            {
                // AES-GCM standard nonce size
                Assert.That(IntegrationConstants.NONCE_SIZE, Is.EqualTo(12));
            }

            [Test]
            public void AES_GCM_TAG_BYTE_SIZE_Should_Be_16_Bytes()
            {
                // AES-GCM tag size
                Assert.That(IntegrationConstants.AES_GCM_TAG_BYTE_SIZE, Is.EqualTo(16));
            }

            [Test]
            public void RSA_OAEP_KEY_SIZE_Should_Be_2048()
            {
                Assert.That(IntegrationConstants.RSA_OAEP_KEY_SIZE, Is.EqualTo(2048));
            }

            [Test]
            public void LATIN1_ENCODING_Should_Be_Correct()
            {
                Assert.That(IntegrationConstants.LATIN1_ENCODING, Is.EqualTo("ISO-8859-1"));
            }

            [Test]
            public void UTF_8_ENCODING_Should_Be_Correct()
            {
                Assert.That(IntegrationConstants.UTF_8_ENCODING, Is.EqualTo("utf-8"));
            }

            [Test]
            public void AES_256_GCM_Should_Be_Correct()
            {
                Assert.That(IntegrationConstants.AES_256_GCM, Is.EqualTo("AES-GCM"));
            }

            [Test]
            public void RSA_OAEP_Should_Be_Correct()
            {
                Assert.That(IntegrationConstants.RSA_OAEP, Is.EqualTo("RSA-OAEP"));
            }

            [Test]
            public void DEFAULT_AZURE_CREDENTIAL_ENVIRONMENTAL_VARIABLE_Should_Be_Correct()
            {
                Assert.That(IntegrationConstants.DEFAULT_AZURE_CREDENTIAL_ENVIRONMENTAL_VARIABLE,
                    Is.EqualTo("KSM_AZ_KEY_ID"));
            }

            [Test]
            public void MD5_HASH_Should_Be_Correct()
            {
                Assert.That(IntegrationConstants.MD5_HASH, Is.EqualTo("MD5"));
            }

            [Test]
            public void HEX_DIGEST_Should_Be_Correct()
            {
                Assert.That(IntegrationConstants.HEX_DIGEST, Is.EqualTo("hex"));
            }

            [Test]
            public void DEFAULT_JSON_INDENT_Should_Be_4()
            {
                Assert.That(IntegrationConstants.DEFAULT_JSON_INDENT, Is.EqualTo(4));
            }
        }
    }
}
