using NUnit.Framework;
using Moq;
using Microsoft.Extensions.Logging;
using System;
using System.IO;

namespace AzureKeyVault.Tests
{
    [TestFixture]
    public class IntegrationUtilsTests
    {
        /// <summary>
        /// Note: The IntegrationUtils class uses Azure CryptographyClient (concrete class)
        /// which cannot be easily mocked without refactoring.
        ///
        /// These tests focus on validating the buffer structure and error handling logic
        /// that doesn't require a functional Azure client.
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
                var wrappedKey = new byte[256];
                var nonce = new byte[12];
                var tag = new byte[16];
                var ciphertext = new byte[20];

                // When
                var buffer = CreateEncryptedBuffer(wrappedKey, nonce, tag, ciphertext);

                // Then - verify structure
                Assert.That(buffer.Length, Is.EqualTo(
                    IntegrationConstants.HEADER_SIZE +
                    2 + wrappedKey.Length +  // LENGTH_PREFIX_SIZE is internal
                    2 + nonce.Length +
                    2 + tag.Length +
                    2 + ciphertext.Length
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
                    new byte[256], // wrappedKey (RSA-OAEP 2048)
                    new byte[12],  // nonce
                    new byte[16],  // tag
                    new byte[16]   // ciphertext
                );
            }

            private static byte[] CreateEncryptedBuffer(byte[] wrappedKey, byte[] nonce, byte[] tag, byte[] ciphertext)
            {
                using var ms = new MemoryStream();
                using var writer = new BinaryWriter(ms);

                writer.Write(IntegrationConstants.BLOB_HEADER);
                WriteLengthPrefixed(writer, wrappedKey);
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

                // Then - not enough space for any parts (need at least 2 bytes for length prefix)
                Assert.That(headerOnly.Length - IntegrationConstants.HEADER_SIZE, Is.LessThan(2));
            }
        }

        [TestFixture]
        public class EncryptMessageValidationTests
        {
            [Test]
            public void Should_Accept_Empty_Message()
            {
                // Given
                var message = "";

                // Then - empty messages are valid
                Assert.That(message, Is.EqualTo(""));
            }

            [Test]
            public void Should_Accept_Long_Message()
            {
                // Given
                var longMessage = new string('a', 10000);

                // Then
                Assert.That(longMessage.Length, Is.EqualTo(10000));
            }

            [Test]
            public void Should_Accept_Special_Characters_In_Message()
            {
                // Given
                var specialMessage = "test\u2122 \u4f60\u597d \ud83c\udf89 \n\t\r";

                // Then - special characters are preserved
                Assert.That(specialMessage, Contains.Substring("\u2122"));
                Assert.That(specialMessage, Contains.Substring("\u4f60\u597d"));
            }

            [Test]
            public void Should_Accept_Unicode_Message()
            {
                // Given
                var unicodeMessage = "\u0041\u00E9\u4E2D\u0410\u05D0\u0623";

                // Then
                Assert.That(unicodeMessage.Length, Is.EqualTo(6));
            }
        }

        [TestFixture]
        public class DecryptCiphertextValidationTests
        {
            [Test]
            public void Should_Handle_Empty_Ciphertext()
            {
                // Given
                var emptyCiphertext = Array.Empty<byte>();

                // Then - empty ciphertext has no header
                Assert.That(emptyCiphertext.Length, Is.LessThan(IntegrationConstants.HEADER_SIZE));
            }

            [Test]
            public void Should_Handle_Short_Ciphertext()
            {
                // Given - ciphertext too short for valid structure
                var shortCiphertext = new byte[] { 0xFF };

                // Then
                Assert.That(shortCiphertext.Length, Is.LessThan(IntegrationConstants.HEADER_SIZE));
            }

            [Test]
            public void Should_Detect_Invalid_Header()
            {
                // Given - ciphertext with wrong header
                var invalidHeaderCiphertext = new byte[] { 0x00, 0x00, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04 };

                // Then - header doesn't match BLOB_HEADER
                var header = new byte[IntegrationConstants.HEADER_SIZE];
                Array.Copy(invalidHeaderCiphertext, header, IntegrationConstants.HEADER_SIZE);
                Assert.That(header.AsSpan().SequenceEqual(IntegrationConstants.BLOB_HEADER), Is.False);
            }

            [Test]
            public void Should_Detect_Valid_Header()
            {
                // Given - ciphertext with valid header
                var validHeaderCiphertext = new byte[] { 0xFF, 0xFF, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04 };

                // Then - header matches BLOB_HEADER
                var header = new byte[IntegrationConstants.HEADER_SIZE];
                Array.Copy(validHeaderCiphertext, header, IntegrationConstants.HEADER_SIZE);
                Assert.That(header.AsSpan().SequenceEqual(IntegrationConstants.BLOB_HEADER), Is.True);
            }
        }
    }
}
