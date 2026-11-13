using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace SecretsManager.Test
{
    using QueryFunction = Func<string, TransmissionKey, EncryptedPayload, string, Task<KeeperHttpResponse>>;

    // Throttle retry with exponential backoff (KSM-876 / KSM-879). Unit tests target the internal
    // helpers (visible via InternalsVisibleTo); e2e tests drive GetSecrets with a mocked
    // QueryFunction and a recording ThrottleSleep so retries never actually wait.
    public class ThrottleTests
    {
        private const string FakeToken = "YyIhK5wXFHj36wGBAOmBsxI3v5rIruINrC8KXjyM58c";

        private static KeeperHttpResponse Throttle403(double? retryAfter = null)
        {
            var json = retryAfter.HasValue
                ? $"{{\"error\":\"throttled\",\"message\":\"throttled\",\"retry_after\":{retryAfter.Value}}}"
                : "{\"error\":\"throttled\",\"message\":\"throttled\"}";
            return new KeeperHttpResponse(CryptoUtils.StringToBytes(json), true, 403);
        }

        // --- unit: ThrottleDelayMs ---

        [Test]
        public void ThrottleDelay_ExponentialSequence_NoJitter()
        {
            var expected = new[] { 11000, 22000, 44000, 88000, 176000 };
            for (var attempt = 0; attempt < expected.Length; attempt++)
                Assert.That(SecretsManagerClient.ThrottleDelayMs(attempt, 0, 0), Is.EqualTo(expected[attempt]));
        }

        [Test]
        public void ThrottleDelay_RetryAfterPrecedence_And_NonPositiveIgnored()
        {
            Assert.That(SecretsManagerClient.ThrottleDelayMs(3, 7, 0), Is.EqualTo(7000));
            Assert.That(SecretsManagerClient.ThrottleDelayMs(0, 0, 0), Is.EqualTo(11000));
            Assert.That(SecretsManagerClient.ThrottleDelayMs(1, -5, 0), Is.EqualTo(22000));
        }

        [Test]
        public void ThrottleDelay_JitterBounds()
        {
            Assert.That(SecretsManagerClient.ThrottleDelayMs(0, 0, -0.25), Is.EqualTo(8250));
            Assert.That(SecretsManagerClient.ThrottleDelayMs(0, 0, 0.25), Is.EqualTo(13750));
        }

        // --- unit: ParseThrottle ---

        [Test]
        public void ParseThrottle_Table()
        {
            Assert.That(SecretsManagerClient.ParseThrottle(CryptoUtils.StringToBytes("{\"error\":\"throttled\"}")), Is.EqualTo(0));
            Assert.That(SecretsManagerClient.ParseThrottle(CryptoUtils.StringToBytes("{\"result_code\":\"throttled\",\"retry_after\":5}")), Is.EqualTo(5));
            Assert.That(SecretsManagerClient.ParseThrottle(CryptoUtils.StringToBytes("{\"error\":\"throttled\",\"retry_after\":\"3\"}")), Is.EqualTo(3));
            Assert.That(SecretsManagerClient.ParseThrottle(CryptoUtils.StringToBytes("{\"error\":\"throttled\",\"retry_after\":-2}")), Is.EqualTo(0));
            Assert.That(SecretsManagerClient.ParseThrottle(CryptoUtils.StringToBytes("{\"error\":\"key\"}")), Is.Null);
            Assert.That(SecretsManagerClient.ParseThrottle(CryptoUtils.StringToBytes("not json")), Is.Null);
            Assert.That(SecretsManagerClient.ParseThrottle(Array.Empty<byte>()), Is.Null);
        }

        // --- e2e via GetSecrets ---

        private static (SecretsManagerOptions options, List<int> sleeps) MakeOptions(QueryFunction queryFunction)
        {
            SecretsManagerClient.TransmissionKeyStub = null; // avoid static leakage from other tests
            var storage = new InMemoryStorage();
            SecretsManagerClient.InitializeStorage(storage, FakeToken, "fake.keepersecurity.com");
            // Seed an app key so the (non-bound) empty success response decrypts without error; the
            // key itself is unused because the mocked responses carry no records.
            storage.SaveBytes("appKey", new byte[32]);
            var sleeps = new List<int>();
            var options = new SecretsManagerOptions(storage, queryFunction,
                throttleSleep: ms => { sleeps.Add(ms); return Task.CompletedTask; });
            return (options, sleeps);
        }

        [Test]
        public async Task RetriesThenSucceeds()
        {
            var call = 0;
            var (options, sleeps) = MakeOptions((url, tk, payload, proxy) =>
            {
                if (call++ == 0) return Task.FromResult(Throttle403());
                var data = CryptoUtils.Encrypt(CryptoUtils.StringToBytes("{}"), tk.Key);
                return Task.FromResult(new KeeperHttpResponse(data, false, 200));
            });

            var secrets = await SecretsManagerClient.GetSecrets(options);
            Assert.That(secrets.Records, Is.Empty);
            Assert.That(sleeps.Count, Is.EqualTo(1));
        }

        [Test]
        public void Exhaustion_ThrowsKeeperThrottleException()
        {
            var call = 0;
            var (options, sleeps) = MakeOptions((url, tk, payload, proxy) =>
            {
                call++;
                return Task.FromResult(Throttle403());
            });

            Assert.ThrowsAsync<KeeperThrottleException>(async () => await SecretsManagerClient.GetSecrets(options));
            Assert.That(sleeps.Count, Is.EqualTo(5));
            Assert.That(call, Is.EqualTo(6)); // 5 retries + the final throttled response
        }

        [Test]
        public void RetryAfter_IsHonored()
        {
            var call = 0;
            var (options, sleeps) = MakeOptions((url, tk, payload, proxy) =>
                Task.FromResult(call++ == 0 ? Throttle403(3) : Throttle403()));

            Assert.ThrowsAsync<KeeperThrottleException>(async () => await SecretsManagerClient.GetSecrets(options));
            // retry_after = 3s with +/-25% jitter -> [2.25s, 3.75s] => [2250ms, 3750ms]
            Assert.That(sleeps[0], Is.InRange(2250, 3750));
        }

        [Test]
        public void NonThrottle403_NotRetried()
        {
            var (options, sleeps) = MakeOptions((url, tk, payload, proxy) =>
                Task.FromResult(new KeeperHttpResponse(
                    CryptoUtils.StringToBytes("{\"error\":\"access_denied\",\"message\":\"nope\"}"), true, 403)));

            // Exactly System.Exception (not the derived KeeperThrottleException) and no retries.
            Assert.ThrowsAsync<Exception>(async () => await SecretsManagerClient.GetSecrets(options));
            Assert.That(sleeps.Count, Is.EqualTo(0));
        }

        [Test]
        public void Non403ThrottleBody_NotRetried()
        {
            // A 502 carrying a {"error":"throttled"} body must NOT be retried (403 gate).
            var (options, sleeps) = MakeOptions((url, tk, payload, proxy) =>
                Task.FromResult(new KeeperHttpResponse(
                    CryptoUtils.StringToBytes("{\"error\":\"throttled\"}"), true, 502)));

            Assert.ThrowsAsync<Exception>(async () => await SecretsManagerClient.GetSecrets(options));
            Assert.That(sleeps.Count, Is.EqualTo(0));
        }
    }
}
