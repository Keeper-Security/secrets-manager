using NUnit.Framework;
using System;

namespace AWSKeyManagement.Tests
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

            [Test]
            public void SupportedKeySpecs_Should_Contain_Expected_Values()
            {
                // Then
                Assert.That(IntegrationConstants.SupportedKeySpecs, Contains.Item(KeySpecEnum.RSA_2048));
                Assert.That(IntegrationConstants.SupportedKeySpecs, Contains.Item(KeySpecEnum.RSA_4096));
                Assert.That(IntegrationConstants.SupportedKeySpecs, Contains.Item(KeySpecEnum.RSA_3072));
                Assert.That(IntegrationConstants.SupportedKeySpecs, Contains.Item(KeySpecEnum.SYMMETRIC_DEFAULT));
                Assert.That(IntegrationConstants.SupportedKeySpecs.Length, Is.EqualTo(4));
            }
        }

        [TestFixture]
        public class KeySpecEnumTests
        {
            [Test]
            public void RSA_2048_Should_Be_Correct_String()
            {
                Assert.That(KeySpecEnum.RSA_2048, Is.EqualTo("RSA_2048"));
            }

            [Test]
            public void RSA_4096_Should_Be_Correct_String()
            {
                Assert.That(KeySpecEnum.RSA_4096, Is.EqualTo("RSA_4096"));
            }

            [Test]
            public void RSA_3072_Should_Be_Correct_String()
            {
                Assert.That(KeySpecEnum.RSA_3072, Is.EqualTo("RSA_3072"));
            }

            [Test]
            public void SYMMETRIC_DEFAULT_Should_Be_Correct_String()
            {
                Assert.That(KeySpecEnum.SYMMETRIC_DEFAULT, Is.EqualTo("SYMMETRIC_DEFAULT"));
            }
        }

        [TestFixture]
        public class BufferOptionsTests
        {
            [Test]
            public void Should_Allow_Setting_All_Properties()
            {
                // Given
                var options = new BufferOptions();

                // When
                options.KeyId = "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012";
                options.EncryptionAlgorithm = "RSAES_OAEP_SHA_256";
                options.KeyType = KeySpecEnum.RSA_2048;

                // Then
                Assert.That(options.KeyId, Is.EqualTo("arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"));
                Assert.That(options.EncryptionAlgorithm, Is.EqualTo("RSAES_OAEP_SHA_256"));
                Assert.That(options.KeyType, Is.EqualTo(KeySpecEnum.RSA_2048));
            }
        }

        [TestFixture]
        public class EncryptBufferOptionsTests
        {
            [Test]
            public void Should_Inherit_From_BufferOptions()
            {
                // Then
                Assert.That(typeof(EncryptBufferOptions).BaseType, Is.EqualTo(typeof(BufferOptions)));
            }

            [Test]
            public void Should_Have_Message_Property()
            {
                // Given
                var options = new EncryptBufferOptions
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
                var options = new EncryptBufferOptions
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
                var options = new EncryptBufferOptions
                {
                    Message = specialMessage
                };

                // Then
                Assert.That(options.Message, Is.EqualTo(specialMessage));
            }

            [Test]
            public void Should_Handle_Long_Messages()
            {
                // Given
                var longMessage = new string('a', 10000);
                var options = new EncryptBufferOptions
                {
                    Message = longMessage
                };

                // Then
                Assert.That(options.Message.Length, Is.EqualTo(10000));
            }
        }

        [TestFixture]
        public class DecryptBufferOptionsTests
        {
            [Test]
            public void Should_Inherit_From_BufferOptions()
            {
                // Then
                Assert.That(typeof(DecryptBufferOptions).BaseType, Is.EqualTo(typeof(BufferOptions)));
            }

            [Test]
            public void Should_Have_Ciphertext_Property()
            {
                // Given
                var ciphertext = new byte[] { 0x01, 0x02, 0x03, 0x04 };
                var options = new DecryptBufferOptions
                {
                    Ciphertext = ciphertext
                };

                // Then
                Assert.That(options.Ciphertext, Is.EqualTo(ciphertext));
            }

            [Test]
            public void Should_Allow_Empty_Ciphertext()
            {
                // Given
                var options = new DecryptBufferOptions
                {
                    Ciphertext = Array.Empty<byte>()
                };

                // Then
                Assert.That(options.Ciphertext, Is.Empty);
            }

            [Test]
            public void Should_Allow_Null_Ciphertext()
            {
                // Given
                var options = new DecryptBufferOptions
                {
                    Ciphertext = null!
                };

                // Then
                Assert.That(options.Ciphertext, Is.Null);
            }
        }
    }
}
