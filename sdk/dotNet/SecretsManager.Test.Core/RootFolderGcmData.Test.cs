using NUnit.Framework;
using System;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecretsManager.Test
{
    [TestFixture]
    public class RootFolderGcmDataTests
    {
        private const int PaddedLength = 255;
        private static readonly byte[] AppKey = Enumerable.Range(1, 32).Select(i => (byte)i).ToArray();
        private static readonly byte[] TransmissionKey = Enumerable.Range(101, 32).Select(i => (byte)i).ToArray();

        private static byte[] NameJson(string name) => Encoding.UTF8.GetBytes($"{{\"name\":\"{name}\"}}");

        private static byte[] PadTo(byte[] data, int length) =>
            data.Concat(new byte[length - data.Length]).ToArray();

        // Encrypts until the last `zeroTail` bytes of the GCM value (the end of the tag) are 0x00.
        private static byte[] GcmEndingInZeros(byte[] folderKey, int zeroTail)
        {
            for (var i = 0; i < 2_000_000; i++)
            {
                var value = CryptoUtils.Encrypt(NameJson("tag-" + i), folderKey);
                if (value.Skip(value.Length - zeroTail).All(b => b == 0))
                {
                    return value;
                }
            }
            throw new InvalidOperationException("no GCM value with the requested tag tail");
        }

        private static byte[] CbcEndingInZero(byte[] folderKey)
        {
            for (var i = 0; i < 100_000; i++)
            {
                var value = CryptoUtils.Encrypt(NameJson("cbc-" + i), folderKey, true);
                if (value[value.Length - 1] == 0)
                {
                    return value;
                }
            }
            throw new InvalidOperationException("no CBC value ending in 0x00");
        }

        private static async Task<KeeperFolder[]> GetFoldersWith(string folderData, byte[] folderKey)
        {
            var storage = new InMemoryStorage();
            SecretsManagerClient.InitializeStorage(storage, "US:YyIhK5wXFHj36wGBAOmBsxI3v5rIruINrC8KXjyM58c");
            storage.SaveBytes("appKey", AppKey);
            storage.Delete("clientKey");

            var body = "{\"folders\":[{\"folderUid\":\"ROOTFOLDERUID000000001\",\"folderKey\":\""
                + CryptoUtils.BytesToBase64(CryptoUtils.Encrypt(folderKey, AppKey))
                + "\",\"data\":\"" + folderData + "\"}]}";

            SecretsManagerClient.TransmissionKeyStub = _ => TransmissionKey;
            Task<KeeperHttpResponse> Reply(string url, TransmissionKey tk, EncryptedPayload p, string proxy = null) =>
                Task.FromResult(new KeeperHttpResponse(CryptoUtils.Encrypt(Encoding.UTF8.GetBytes(body), TransmissionKey), false, 200));

            try
            {
                return await SecretsManagerClient.GetFolders(new SecretsManagerOptions(storage, Reply));
            }
            finally
            {
                SecretsManagerClient.TransmissionKeyStub = null;
            }
        }

        private static byte[] NewFolderKey() => CryptoUtils.GetRandomBytes(32);

        [Test]
        public async Task GcmName_ReadsWithUseGcmTrue()
        {
            var key = NewFolderKey();
            var data = CryptoUtils.BytesToBase64(CryptoUtils.Encrypt(NameJson("Drive Root"), key));
            var folders = await GetFoldersWith(data, key);
            Assert.That(folders.Select(f => f.Name), Is.EqualTo(new[] { "Drive Root" }));
            Assert.That(folders[0].UseGcm, Is.True);
        }

        [Test]
        public async Task GcmName_PaddedTo255Bytes_Reads()
        {
            var key = NewFolderKey();
            var padded = PadTo(CryptoUtils.Encrypt(NameJson("Padded Root"), key), PaddedLength);
            var folders = await GetFoldersWith(CryptoUtils.BytesToBase64(padded), key);
            Assert.That(folders.Select(f => f.Name), Is.EqualTo(new[] { "Padded Root" }));
            Assert.That(folders[0].UseGcm, Is.True);
        }

        [TestCase(1)]
        [TestCase(2)]
        public async Task GcmTagEndingInZeros_PaddedTo255Bytes_Reads(int zeroTail)
        {
            var key = NewFolderKey();
            var padded = PadTo(GcmEndingInZeros(key, zeroTail), PaddedLength);
            var folders = await GetFoldersWith(CryptoUtils.BytesToBase64(padded), key);
            Assert.That(folders, Has.Length.EqualTo(1));
            Assert.That(folders[0].Name, Does.StartWith("tag-"));
            Assert.That(folders[0].UseGcm, Is.True);
        }

        [Test]
        public async Task CbcName_ReadsWithUseGcmFalse()
        {
            var key = NewFolderKey();
            var data = CryptoUtils.BytesToBase64(CryptoUtils.Encrypt(NameJson("Classic Root"), key, true));
            var folders = await GetFoldersWith(data, key);
            Assert.That(folders.Select(f => f.Name), Is.EqualTo(new[] { "Classic Root" }));
            Assert.That(folders[0].UseGcm, Is.False);
        }

        [Test]
        public async Task CbcCiphertextEndingInZeroByte_ReadsUntrimmed()
        {
            var key = NewFolderKey();
            var folders = await GetFoldersWith(CryptoUtils.BytesToBase64(CbcEndingInZero(key)), key);
            Assert.That(folders, Has.Length.EqualTo(1));
            Assert.That(folders[0].Name, Does.StartWith("cbc-"));
            Assert.That(folders[0].UseGcm, Is.False);
        }

        [Test]
        public async Task GcmDataThatIsNotJson_ReturnsEmptyNameWithUseGcmTrue()
        {
            var key = NewFolderKey();
            var value = CryptoUtils.Encrypt(Encoding.UTF8.GetBytes("not json at all"), key);
            var folders = await GetFoldersWith(CryptoUtils.BytesToBase64(PadTo(value, PaddedLength)), key);
            Assert.That(folders, Has.Length.EqualTo(1));
            Assert.That(folders[0].Name, Is.EqualTo(""));
            Assert.That(folders[0].UseGcm, Is.True);
        }
    }
}
