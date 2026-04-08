using NUnit.Framework;
using System;
using System.IO;

namespace SecretsManager.Test
{
    /// <summary>
    /// Regression test for GitHub issue #966:
    /// LocalConfigStorage.SaveToFile() throws ObjectDisposedException in v17.1.0
    /// because stream.Close() is called before writer.Dispose().
    /// </summary>
    [TestFixture]
    public class LocalConfigStorageBugReproTests
    {
        private string _tempFile;

        [SetUp]
        public void SetUp()
        {
            _tempFile = Path.Combine(Path.GetTempPath(), $"ksm-test-{Guid.NewGuid()}.json");
        }

        [TearDown]
        public void TearDown()
        {
            if (File.Exists(_tempFile))
                File.Delete(_tempFile);
        }

        [Test]
        public void SaveString_WithFilePath_DoesNotThrowObjectDisposedException()
        {
            // Arrange: LocalConfigStorage backed by a real file (triggers SaveToFile)
            var storage = new LocalConfigStorage(_tempFile);

            // Act & Assert: SaveString -> SaveToFile -> should NOT throw
            Assert.DoesNotThrow(() => storage.SaveString("hostname", "fake.keepersecurity.com"));
        }

        [Test]
        public void InitializeStorage_WithLocalConfigStorage_DoesNotThrowObjectDisposedException()
        {
            // This reproduces the exact call stack from the issue report:
            // SecretsManagerClient.InitializeStorage -> storage.SaveString -> SaveToFile
            var storage = new LocalConfigStorage(_tempFile);

            Assert.DoesNotThrow(() =>
                SecretsManagerClient.InitializeStorage(storage, "US:FAKE_ONE_TIME_TOKEN", "fake.keepersecurity.com")
            );
        }

        [Test]
        public void SaveString_WithFilePath_WritesValidJson()
        {
            var storage = new LocalConfigStorage(_tempFile);
            storage.SaveString("hostname", "fake.keepersecurity.com");

            var written = File.ReadAllText(_tempFile);
            Assert.That(written, Does.Contain("hostname"));
            Assert.That(written, Does.Contain("fake.keepersecurity.com"));
        }
    }
}
