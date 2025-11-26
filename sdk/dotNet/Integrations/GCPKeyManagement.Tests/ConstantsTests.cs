using NUnit.Framework;
using System;

namespace GCPKeyManagement.Tests
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
            public void ADDITIONAL_AUTHENTICATION_DATA_Should_Be_Correct()
            {
                Assert.That(IntegrationConstants.ADDITIONAL_AUTHENTICATION_DATA, Is.EqualTo("keeper_auth"));
            }

            [Test]
            public void TOKEN_SCOPE_Should_Be_Correct()
            {
                Assert.That(IntegrationConstants.TOKEN_SCOPE, Is.EqualTo("https://www.googleapis.com/auth/cloud-platform"));
            }

            [Test]
            public void RAW_ENCRYPT_GCP_API_URL_Should_Be_Correct()
            {
                Assert.That(IntegrationConstants.RAW_ENCRYPT_GCP_API_URL, Is.EqualTo("https://cloudkms.googleapis.com/v1/{0}:rawEncrypt"));
            }

            [Test]
            public void RAW_DECRYPT_GCP_API_URL_Should_Be_Correct()
            {
                Assert.That(IntegrationConstants.RAW_DECRYPT_GCP_API_URL, Is.EqualTo("https://cloudkms.googleapis.com/v1/{0}:rawDecrypt"));
            }

            [Test]
            public void SupportedKeySpecs_Should_Contain_Expected_Values()
            {
                // Then
                Assert.That(IntegrationConstants.SupportedKeySpecs, Has.Length.EqualTo(3));
            }

            [Test]
            public void SupportedKeyPurpose_Should_Contain_Expected_Values()
            {
                // Then
                Assert.That(IntegrationConstants.SupportedKeyPurpose, Contains.Item("RAW_ENCRYPT_DECRYPT"));
                Assert.That(IntegrationConstants.SupportedKeyPurpose, Contains.Item("ENCRYPT_DECRYPT"));
                Assert.That(IntegrationConstants.SupportedKeyPurpose, Contains.Item("ASYMMETRIC_DECRYPT"));
                Assert.That(IntegrationConstants.SupportedKeyPurpose, Has.Length.EqualTo(3));
            }
        }

        [TestFixture]
        public class KeyPurposeEnumTests
        {
            [Test]
            public void Should_Have_EncryptDecrypt_Value()
            {
                Assert.That(KeyPurpose.ENCRYPT_DECRYPT.ToString(), Is.EqualTo("ENCRYPT_DECRYPT"));
            }

            [Test]
            public void Should_Have_AsymmetricDecrypt_Value()
            {
                Assert.That(KeyPurpose.ASYMMETRIC_DECRYPT.ToString(), Is.EqualTo("ASYMMETRIC_DECRYPT"));
            }

            [Test]
            public void Should_Have_RawEncryptDecrypt_Value()
            {
                Assert.That(KeyPurpose.RAW_ENCRYPT_DECRYPT.ToString(), Is.EqualTo("RAW_ENCRYPT_DECRYPT"));
            }

            [Test]
            public void Should_Have_CryptoKeyPurposeUnspecified_Value()
            {
                Assert.That(KeyPurpose.CRYPTO_KEY_PURPOSE_UNSPECIFIED.ToString(), Is.EqualTo("CRYPTO_KEY_PURPOSE_UNSPECIFIED"));
            }

            [Test]
            public void Should_Have_AsymmetricSign_Value()
            {
                Assert.That(KeyPurpose.ASYMMETRIC_SIGN.ToString(), Is.EqualTo("ASYMMETRIC_SIGN"));
            }

            [Test]
            public void Should_Have_Mac_Value()
            {
                Assert.That(KeyPurpose.MAC.ToString(), Is.EqualTo("MAC"));
            }
        }

        [TestFixture]
        public class KeyPurposeHelperTests
        {
            [Test]
            public void GetEnumMemberValue_Should_Return_EncryptDecrypt_For_ENCRYPT_DECRYPT()
            {
                // When
                var value = KeyPurposeHelper.GetEnumMemberValue(KeyPurpose.ENCRYPT_DECRYPT);

                // Then
                Assert.That(value, Is.EqualTo("EncryptDecrypt"));
            }

            [Test]
            public void GetEnumMemberValue_Should_Return_AsymmetricDecrypt_For_ASYMMETRIC_DECRYPT()
            {
                // When
                var value = KeyPurposeHelper.GetEnumMemberValue(KeyPurpose.ASYMMETRIC_DECRYPT);

                // Then
                Assert.That(value, Is.EqualTo("AsymmetricDecrypt"));
            }

            [Test]
            public void GetEnumMemberValue_Should_Return_RawEncryptDecrypt_For_RAW_ENCRYPT_DECRYPT()
            {
                // When
                var value = KeyPurposeHelper.GetEnumMemberValue(KeyPurpose.RAW_ENCRYPT_DECRYPT);

                // Then
                Assert.That(value, Is.EqualTo("RawEncryptDecrypt"));
            }
        }

        [TestFixture]
        public class BufferOptionsTests
        {
            [Test]
            public void Should_Allow_Setting_All_Properties()
            {
                // Given
                var options = new BufferOptions
                {
                    IsAsymmetric = true,
                    KeyPurpose = "ENCRYPT_DECRYPT",
                    EncryptionAlgorithm = "RSA_OAEP_2048_SHA256"
                };

                // Then
                Assert.That(options.IsAsymmetric, Is.True);
                Assert.That(options.KeyPurpose, Is.EqualTo("ENCRYPT_DECRYPT"));
                Assert.That(options.EncryptionAlgorithm, Is.EqualTo("RSA_OAEP_2048_SHA256"));
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
        }
    }
}
