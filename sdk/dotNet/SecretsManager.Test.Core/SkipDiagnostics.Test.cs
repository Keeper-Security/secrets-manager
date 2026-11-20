using NUnit.Framework;
using System;
using System.IO;
using System.Threading.Tasks;

namespace SecretsManager.Test
{
    // An item the SDK cannot decrypt is skipped with one line on standard error. That line must not
    // carry any byte of the decrypted payload. System.Text.Json echoes the first character of input that
    // does not start like JSON, so a payload that starts with '~' shows whether the payload reached stderr.
    public class SkipDiagnosticsTests
    {
        private const string FakeToken = "YyIhK5wXFHj36wGBAOmBsxI3v5rIruINrC8KXjyM58c";
        private const string Payload = "~SkipLeakCanary9";
        private const string ValidRecordJson = "{\"title\":\"t\",\"type\":\"login\",\"fields\":[],\"custom\":[]}";

        private static byte[] B(string s) => CryptoUtils.StringToBytes(s);

        private static string Enc(byte[] data, byte[] key, bool cbc = false) =>
            CryptoUtils.BytesToBase64(CryptoUtils.Encrypt(data, key, cbc));

        private static async Task<string> RunCapturingStderr(SecretsManagerResponse response, byte[] appKey, Func<SecretsManagerOptions, Task> act)
        {
            SecretsManagerClient.TransmissionKeyStub = null;
            var storage = new InMemoryStorage();
            SecretsManagerClient.InitializeStorage(storage, FakeToken, "fake.keepersecurity.com");
            storage.SaveBytes("appKey", appKey);
            var options = new SecretsManagerOptions(storage, (url, tk, payload, proxy) =>
            {
                var data = CryptoUtils.Encrypt(JsonUtils.SerializeJson(response), tk.Key);
                return Task.FromResult(new KeeperHttpResponse(data, false, 200));
            });

            var original = Console.Error;
            var captured = new StringWriter();
            Console.SetError(captured);
            try
            {
                await act(options);
            }
            finally
            {
                Console.SetError(original);
            }

            return captured.ToString();
        }

        [Test]
        public async Task RecordWithNonJsonData_SkipLineHoldsNoPayload()
        {
            var appKey = CryptoUtils.GetRandomBytes(32);
            var recordKey = CryptoUtils.GetRandomBytes(32);
            var response = new SecretsManagerResponse
            {
                records = new[]
                {
                    new SecretsManagerResponseRecord { recordUid = "REC_UID", recordKey = Enc(recordKey, appKey), data = Enc(B(Payload), recordKey) }
                }
            };

            var stderr = await RunCapturingStderr(response, appKey, async o =>
            {
                var secrets = await SecretsManagerClient.GetSecrets(o);
                Assert.That(secrets.Records, Is.Empty);
            });

            Assert.That(stderr, Does.Contain("REC_UID"));
            Assert.That(stderr, Does.Not.Contain("~"));
        }

        [Test]
        public async Task RecordInFolderWithNonJsonData_SkipLineHoldsNoPayload()
        {
            var appKey = CryptoUtils.GetRandomBytes(32);
            var folderKey = CryptoUtils.GetRandomBytes(32);
            var recordKey = CryptoUtils.GetRandomBytes(32);
            var response = new SecretsManagerResponse
            {
                folders = new[]
                {
                    new SecretsManagerResponseFolder
                    {
                        folderUid = "FOLDER_UID",
                        folderKey = Enc(folderKey, appKey),
                        records = new[]
                        {
                            new SecretsManagerResponseRecord { recordUid = "REC_UID", recordKey = Enc(recordKey, folderKey), data = Enc(B(Payload), recordKey) }
                        }
                    }
                }
            };

            var stderr = await RunCapturingStderr(response, appKey, async o =>
            {
                var secrets = await SecretsManagerClient.GetSecrets(o);
                Assert.That(secrets.Records, Is.Empty);
            });

            Assert.That(stderr, Does.Contain("REC_UID"));
            Assert.That(stderr, Does.Not.Contain("~"));
        }

        [Test]
        public async Task FileWithNonJsonMetadata_SkipLineHoldsNoPayload()
        {
            var appKey = CryptoUtils.GetRandomBytes(32);
            var recordKey = CryptoUtils.GetRandomBytes(32);
            var fileKey = CryptoUtils.GetRandomBytes(32);
            var response = new SecretsManagerResponse
            {
                records = new[]
                {
                    new SecretsManagerResponseRecord
                    {
                        recordUid = "REC_UID",
                        recordKey = Enc(recordKey, appKey),
                        data = Enc(B(ValidRecordJson), recordKey),
                        files = new[]
                        {
                            new SecretsManagerResponseFile { fileUid = "FILE_UID", fileKey = Enc(fileKey, recordKey), data = Enc(B(Payload), fileKey) }
                        }
                    }
                }
            };

            var stderr = await RunCapturingStderr(response, appKey, async o =>
            {
                var secrets = await SecretsManagerClient.GetSecrets(o);
                Assert.That(secrets.Records.Length, Is.EqualTo(1));
                Assert.That(secrets.Records[0].Files, Is.Empty);
            });

            Assert.That(stderr, Does.Contain("FILE_UID"));
            Assert.That(stderr, Does.Not.Contain("~"));
        }

        [Test]
        public async Task AppDataWithNonJsonData_ExceptionHoldsNoPayload()
        {
            var appKey = CryptoUtils.GetRandomBytes(32);
            var response = new SecretsManagerResponse
            {
                appData = CryptoUtils.WebSafe64FromBytes(CryptoUtils.Encrypt(B(Payload), appKey))
            };

            Exception thrown = null;
            await RunCapturingStderr(response, appKey, async o =>
            {
                thrown = Assert.CatchAsync(async () => await SecretsManagerClient.GetSecrets(o));
                await Task.CompletedTask;
            });

            Assert.That(thrown, Is.Not.Null);
            Assert.That(thrown.ToString(), Does.Not.Contain("~"));
        }

        [Test]
        public async Task FailedRefetchAfterBind_StderrHoldsNoPayloadOrStackTrace()
        {
            SecretsManagerClient.TransmissionKeyStub = null;
            var storage = new InMemoryStorage();
            SecretsManagerClient.InitializeStorage(storage, FakeToken, "fake.keepersecurity.com");
            var clientKey = CryptoUtils.WebSafe64ToBytes(FakeToken);
            var appKey = CryptoUtils.GetRandomBytes(32);
            var call = 0;
            var options = new SecretsManagerOptions(storage, (url, tk, payload, proxy) =>
            {
                var body = call++ == 0
                    ? JsonUtils.SerializeJson(new SecretsManagerResponse { encryptedAppKey = Enc(appKey, clientKey) })
                    : B(Payload);
                return Task.FromResult(new KeeperHttpResponse(CryptoUtils.Encrypt(body, tk.Key), false, 200));
            });

            var original = Console.Error;
            var captured = new StringWriter();
            Console.SetError(captured);
            try
            {
                await SecretsManagerClient.GetSecrets(options);
            }
            finally
            {
                Console.SetError(original);
            }

            var stderr = captured.ToString();
            Assert.That(stderr, Is.Not.Empty);
            Assert.That(stderr, Does.Not.Contain("~"));
            Assert.That(stderr, Does.Not.Contain("   at "));
        }

        [Test]
        public async Task FolderWithNonJsonData_SkipLineHoldsNoPayload()
        {
            var appKey = CryptoUtils.GetRandomBytes(32);
            var folderKey = CryptoUtils.GetRandomBytes(32);
            var response = new SecretsManagerResponse
            {
                folders = new[]
                {
                    new SecretsManagerResponseFolder { folderUid = "FOLDER_UID", folderKey = Enc(folderKey, appKey), data = Enc(B(Payload), folderKey, true) }
                }
            };

            var stderr = await RunCapturingStderr(response, appKey, async o =>
            {
                var folders = await SecretsManagerClient.GetFolders(o);
                Assert.That(folders, Is.Empty);
            });

            Assert.That(stderr, Does.Contain("FOLDER_UID"));
            Assert.That(stderr, Does.Not.Contain("~"));
        }
    }
}
