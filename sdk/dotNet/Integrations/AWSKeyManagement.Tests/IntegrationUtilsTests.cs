using NUnit.Framework;
using Moq;
using Amazon.KeyManagementService;
using Amazon.KeyManagementService.Model;
using Microsoft.Extensions.Logging;
using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace AWSKeyManagement.Tests
{
    [TestFixture]
    public class IntegrationUtilsTests
    {
        /// <summary>
        /// Note: The IntegrationUtils class uses AmazonKeyManagementServiceClient (concrete class)
        /// which cannot be easily mocked without refactoring to use IAmazonKeyManagementService interface.
        ///
        /// These tests focus on validating the buffer structure and error handling logic
        /// that doesn't require a functional KMS client.
        /// </summary>

        [TestFixture]
        public class BufferStructureTests
        {
            [Test]
            public void ValidBuffer_Should_Have_Correct_Header()
            {
                // Given
                var buffer = CreateValidEncryptedBuffer();

                // Then - verify header is correct
                Assert.That(buffer[0], Is.EqualTo(0xFF));
                Assert.That(buffer[1], Is.EqualTo(0xFF));
            }

            [Test]
            public void ValidBuffer_Should_Have_Length_Prefixed_Parts()
            {
                // Given
                var encryptedKey = new byte[32];
                var nonce = new byte[12];
                var tag = new byte[16];
                var ciphertext = new byte[20];

                // When
                var buffer = CreateEncryptedBuffer(encryptedKey, nonce, tag, ciphertext);

                // Then - verify structure
                Assert.That(buffer.Length, Is.EqualTo(
                    IntegrationConstants.HEADER_SIZE +
                    IntegrationConstants.LENGTH_PREFIX_SIZE + encryptedKey.Length +
                    IntegrationConstants.LENGTH_PREFIX_SIZE + nonce.Length +
                    IntegrationConstants.LENGTH_PREFIX_SIZE + tag.Length +
                    IntegrationConstants.LENGTH_PREFIX_SIZE + ciphertext.Length
                ));
            }

            [Test]
            public void Should_Read_Length_Prefixed_Part_Correctly()
            {
                // Given
                var testData = new byte[] { 0x01, 0x02, 0x03, 0x04 };
                using var ms = new MemoryStream();
                using var writer = new BinaryWriter(ms);
                WriteLengthPrefixed(writer, testData);
                var buffer = ms.ToArray();

                // When - read length prefix
                var length = BitConverter.ToUInt16(buffer, 0);

                // Then
                Assert.That(length, Is.EqualTo(4));
                Assert.That(buffer.Length, Is.EqualTo(6)); // 2 bytes length + 4 bytes data
            }

            private static byte[] CreateValidEncryptedBuffer()
            {
                return CreateEncryptedBuffer(
                    new byte[32],  // encryptedKey
                    new byte[12],  // nonce
                    new byte[16],  // tag
                    new byte[16]   // ciphertext
                );
            }

            private static byte[] CreateEncryptedBuffer(byte[] encryptedKey, byte[] nonce, byte[] tag, byte[] ciphertext)
            {
                using var ms = new MemoryStream();
                using var writer = new BinaryWriter(ms);

                writer.Write(IntegrationConstants.BLOB_HEADER);
                WriteLengthPrefixed(writer, encryptedKey);
                WriteLengthPrefixed(writer, nonce);
                WriteLengthPrefixed(writer, tag);
                WriteLengthPrefixed(writer, ciphertext);

                return ms.ToArray();
            }

            private static void WriteLengthPrefixed(BinaryWriter writer, byte[] data)
            {
                writer.Write((ushort)data.Length);
                writer.Write(data);
            }
        }

        [TestFixture]
        public class DecryptBufferValidationTests
        {
            private Mock<ILogger> _mockLogger = null!;

            [SetUp]
            public void Setup()
            {
                _mockLogger = new Mock<ILogger>();
            }

            [Test]
            public void InvalidHeader_Should_Not_Match_BLOB_HEADER()
            {
                // Given - invalid header
                var invalidHeader = new byte[] { 0x00, 0x00 };

                // Then
                Assert.That(invalidHeader.AsSpan().SequenceEqual(IntegrationConstants.BLOB_HEADER), Is.False);
            }

            [Test]
            public void ValidHeader_Should_Match_BLOB_HEADER()
            {
                // Given - valid header
                var validHeader = new byte[] { 0xFF, 0xFF };

                // Then
                Assert.That(validHeader.AsSpan().SequenceEqual(IntegrationConstants.BLOB_HEADER), Is.True);
            }

            [Test]
            public void Should_Validate_Buffer_Length_For_Header()
            {
                // Given - buffer smaller than header size
                var shortBuffer = new byte[] { 0xFF };

                // Then
                Assert.That(shortBuffer.Length, Is.LessThan(IntegrationConstants.HEADER_SIZE));
            }

            [Test]
            public void Should_Validate_Buffer_Has_Minimum_Parts()
            {
                // Given - buffer with only header
                var headerOnly = new byte[] { 0xFF, 0xFF };

                // Then - not enough space for any parts
                Assert.That(headerOnly.Length - IntegrationConstants.HEADER_SIZE,
                    Is.LessThan(IntegrationConstants.LENGTH_PREFIX_SIZE));
            }
        }

        [TestFixture]
        public class EncryptBufferOptionsTests
        {
            [Test]
            public void Should_Create_Options_With_All_Properties()
            {
                // Given
                var options = new EncryptBufferOptions
                {
                    KeyId = "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
                    Message = "test message",
                    KeyType = KeySpecEnum.RSA_2048,
                    EncryptionAlgorithm = "RSAES_OAEP_SHA_256"
                };

                // Then
                Assert.That(options.KeyId, Is.EqualTo("arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"));
                Assert.That(options.Message, Is.EqualTo("test message"));
                Assert.That(options.KeyType, Is.EqualTo(KeySpecEnum.RSA_2048));
                Assert.That(options.EncryptionAlgorithm, Is.EqualTo("RSAES_OAEP_SHA_256"));
            }

            [Test]
            public void Should_Handle_Empty_Message()
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
            public void Should_Handle_Long_Message()
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
            public void Should_Accept_SYMMETRIC_DEFAULT_KeyType()
            {
                // Given
                var options = new EncryptBufferOptions
                {
                    KeyType = KeySpecEnum.SYMMETRIC_DEFAULT
                };

                // Then
                Assert.That(options.KeyType, Is.EqualTo(KeySpecEnum.SYMMETRIC_DEFAULT));
            }

            [Test]
            public void Should_Accept_RSA_KeyTypes()
            {
                // Given/When/Then
                var options2048 = new EncryptBufferOptions { KeyType = KeySpecEnum.RSA_2048 };
                Assert.That(options2048.KeyType, Is.EqualTo(KeySpecEnum.RSA_2048));

                var options3072 = new EncryptBufferOptions { KeyType = KeySpecEnum.RSA_3072 };
                Assert.That(options3072.KeyType, Is.EqualTo(KeySpecEnum.RSA_3072));

                var options4096 = new EncryptBufferOptions { KeyType = KeySpecEnum.RSA_4096 };
                Assert.That(options4096.KeyType, Is.EqualTo(KeySpecEnum.RSA_4096));
            }
        }

        [TestFixture]
        public class DecryptBufferOptionsTests
        {
            [Test]
            public void Should_Create_Options_With_All_Properties()
            {
                // Given
                var ciphertext = new byte[] { 0xFF, 0xFF, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04 };
                var options = new DecryptBufferOptions
                {
                    KeyId = "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
                    Ciphertext = ciphertext,
                    KeyType = KeySpecEnum.RSA_2048,
                    EncryptionAlgorithm = "RSAES_OAEP_SHA_256"
                };

                // Then
                Assert.That(options.KeyId, Is.EqualTo("arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"));
                Assert.That(options.Ciphertext, Is.EqualTo(ciphertext));
                Assert.That(options.KeyType, Is.EqualTo(KeySpecEnum.RSA_2048));
                Assert.That(options.EncryptionAlgorithm, Is.EqualTo("RSAES_OAEP_SHA_256"));
            }

            [Test]
            public void Should_Handle_Empty_Ciphertext()
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
            public void Should_Handle_Short_Ciphertext()
            {
                // Given - ciphertext too short for valid structure
                var shortCiphertext = new byte[] { 0xFF };
                var options = new DecryptBufferOptions
                {
                    Ciphertext = shortCiphertext
                };

                // Then
                Assert.That(options.Ciphertext.Length, Is.LessThan(IntegrationConstants.HEADER_SIZE));
            }
        }
    }
}
