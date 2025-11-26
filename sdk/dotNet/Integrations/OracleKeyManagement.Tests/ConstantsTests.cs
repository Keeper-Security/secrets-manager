using NUnit.Framework;
using System;

namespace OracleKeyManagement.Tests
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
            public void LENGTH_PREFIX_SIZE_Should_Be_2_Bytes()
            {
                // ushort = 2 bytes
                Assert.That(IntegrationConstants.LENGTH_PREFIX_SIZE, Is.EqualTo(2));
            }
        }

        [TestFixture]
        public class OptionsTests
        {
            [Test]
            public void Should_Allow_Setting_All_Properties()
            {
                // Given
                var options = new Options
                {
                    IsAsymmetric = true,
                    KeyId = "ocid1.key.oc1.iad.abc123",
                    keyVersionId = "ocid1.keyversion.oc1.iad.abc123"
                };

                // Then
                Assert.That(options.IsAsymmetric, Is.True);
                Assert.That(options.KeyId, Is.EqualTo("ocid1.key.oc1.iad.abc123"));
                Assert.That(options.keyVersionId, Is.EqualTo("ocid1.keyversion.oc1.iad.abc123"));
            }

            [Test]
            public void Should_Default_IsAsymmetric_To_False()
            {
                // Given
                var options = new Options();

                // Then
                Assert.That(options.IsAsymmetric, Is.False);
            }
        }

        [TestFixture]
        public class BufferOptionsTests
        {
            [Test]
            public void Should_Inherit_From_Options()
            {
                // Then
                Assert.That(typeof(BufferOptions).BaseType, Is.EqualTo(typeof(Options)));
            }

            [Test]
            public void Should_Have_KeyPurpose_Property()
            {
                // Given
                var options = new BufferOptions
                {
                    KeyPurpose = "ENCRYPT"
                };

                // Then
                Assert.That(options.KeyPurpose, Is.EqualTo("ENCRYPT"));
            }
        }

        [TestFixture]
        public class EncryptOptionsTests
        {
            [Test]
            public void Should_Inherit_From_Options()
            {
                // Then
                Assert.That(typeof(EncryptOptions).BaseType, Is.EqualTo(typeof(Options)));
            }

            [Test]
            public void Should_Have_Message_Property()
            {
                // Given
                var options = new EncryptOptions
                {
                    Message = "test message to encrypt"
                };

                // Then
                Assert.That(options.Message, Is.EqualTo("test message to encrypt"));
            }

            [Test]
            public void Should_Allow_Empty_Message()
            {
                // Given
                var options = new EncryptOptions
                {
                    Message = ""
                };

                // Then
                Assert.That(options.Message, Is.EqualTo(""));
            }

            [Test]
            public void Should_Handle_Special_Characters_In_Message()
            {
                // Given
                var specialMessage = "test\u2122 \u4f60\u597d \ud83c\udf89 \n\t\r";
                var options = new EncryptOptions
                {
                    Message = specialMessage
                };

                // Then
                Assert.That(options.Message, Is.EqualTo(specialMessage));
            }
        }

        [TestFixture]
        public class DecryptOptionsTests
        {
            [Test]
            public void Should_Inherit_From_Options()
            {
                // Then
                Assert.That(typeof(DecryptOptions).BaseType, Is.EqualTo(typeof(Options)));
            }

            [Test]
            public void Should_Have_CipherText_Property()
            {
                // Given
                var ciphertext = new byte[] { 0x01, 0x02, 0x03, 0x04 };
                var options = new DecryptOptions
                {
                    CipherText = ciphertext
                };

                // Then
                Assert.That(options.CipherText, Is.EqualTo(ciphertext));
            }

            [Test]
            public void Should_Allow_Empty_CipherText()
            {
                // Given
                var options = new DecryptOptions
                {
                    CipherText = Array.Empty<byte>()
                };

                // Then
                Assert.That(options.CipherText, Is.Empty);
            }
        }
    }
}
