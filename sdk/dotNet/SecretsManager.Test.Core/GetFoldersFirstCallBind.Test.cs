using NUnit.Framework;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace SecretsManager.Test
{
    [TestFixture]
    public class GetFoldersFirstCallBindTests
    {
        private static readonly byte[] AppKey = Enumerable.Range(1, 32).Select(i => (byte)i).ToArray();
        private static readonly byte[] FolderKey = Enumerable.Range(51, 32).Select(i => (byte)i).ToArray();
        private static readonly byte[] TransmissionKey = Enumerable.Range(101, 32).Select(i => (byte)i).ToArray();

        private static string FoldersJson() =>
            "\"folders\":[{\"folderUid\":\"BINDFOLDERUID0000001\",\"folderKey\":\""
            + CryptoUtils.BytesToBase64(CryptoUtils.Encrypt(FolderKey, AppKey))
            + "\",\"data\":\""
            + CryptoUtils.BytesToBase64(CryptoUtils.Encrypt(Encoding.UTF8.GetBytes("{\"name\":\"Bound Folder\"}"), FolderKey, true))
            + "\"}]";

        [Test]
        public async Task FirstGetFolders_BindsTheApp_AndFinishesWithOneFollowUpRequest()
        {
            var storage = new InMemoryStorage();
            SecretsManagerClient.InitializeStorage(storage, "US:YyIhK5wXFHj36wGBAOmBsxI3v5rIruINrC8KXjyM58c");
            var clientKey = storage.GetBytes("clientKey");

            var bindReply = "{\"encryptedAppKey\":\"" + CryptoUtils.BytesToBase64(CryptoUtils.Encrypt(AppKey, clientKey))
                + "\",\"appOwnerPublicKey\":\"owner-public-key\"," + FoldersJson() + "}";
            var plainReply = "{" + FoldersJson() + "}";

            var sentPayloads = new List<JsonElement>();
            var replies = new Queue<string>(new[] { bindReply, plainReply, plainReply });
            SecretsManagerClient.TransmissionKeyStub = _ => TransmissionKey;
            Task<KeeperHttpResponse> Reply(string url, TransmissionKey tk, EncryptedPayload p, string proxy = null)
            {
                sentPayloads.Add(JsonDocument.Parse(CryptoUtils.Decrypt(p.Payload, TransmissionKey)).RootElement.Clone());
                return Task.FromResult(new KeeperHttpResponse(
                    CryptoUtils.Encrypt(Encoding.UTF8.GetBytes(replies.Dequeue()), TransmissionKey), false, 200));
            }

            try
            {
                var options = new SecretsManagerOptions(storage, Reply);

                var folders = await SecretsManagerClient.GetFolders(options);

                Assert.That(folders.Select(f => f.Name), Is.EqualTo(new[] { "Bound Folder" }));
                Assert.That(storage.GetBytes("appKey"), Is.EqualTo(AppKey));
                Assert.That(storage.GetBytes("clientKey"), Is.Null);
                Assert.That(storage.GetString("appOwnerPublicKey"), Is.EqualTo("owner-public-key"));

                Assert.That(sentPayloads, Has.Count.EqualTo(2), "the bind call plus one follow-up");
                Assert.That(sentPayloads[0].TryGetProperty("publicKey", out var first) && first.ValueKind == JsonValueKind.String, Is.True);
                Assert.That(sentPayloads[1].TryGetProperty("publicKey", out var second) && second.ValueKind != JsonValueKind.Null, Is.False);

                var again = await SecretsManagerClient.GetFolders(options);
                Assert.That(again.Select(f => f.Name), Is.EqualTo(new[] { "Bound Folder" }));
                Assert.That(sentPayloads, Has.Count.EqualTo(3), "a later call sends one request");
            }
            finally
            {
                SecretsManagerClient.TransmissionKeyStub = null;
            }
        }
    }
}
