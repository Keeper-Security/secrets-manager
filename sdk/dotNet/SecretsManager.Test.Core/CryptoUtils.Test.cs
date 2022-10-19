using NUnit.Framework;
using System;
using System.Text.RegularExpressions;

namespace SecretsManager.Test
{
    public class CryptoUtilsTests
    {
        [Test]
        public void PrivateKeyIsCompatible()
        {
            const string fakeExternalPrivateKey64String = "MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQg34GXYbMpXKaHcHZW4dIMO3WYU8zTjB6t+41SRsY1rwqgCgYIKoZIzj0DAQehRANCAAQGH/4ZwpGR9B7AlMjVY7ekpjOcaD3rhuO25CmOZxI3wqRDdhXQIdDnuWvQPCZ3ymtjL3C8JrVIcloklwYI9T7+";
            var fakeExternalPrivateKey64Bytes = CryptoUtils.Base64ToBytes(fakeExternalPrivateKey64String);
            var fakeExportedPublicKey = CryptoUtils.ExportPublicKey(fakeExternalPrivateKey64Bytes);
            Assert.AreEqual("BAYf/hnCkZH0HsCUyNVjt6SmM5xoPeuG47bkKY5nEjfCpEN2FdAh0Oe5a9A8JnfKa2MvcLwmtUhyWiSXBgj1Pv4=", CryptoUtils.BytesToBase64(fakeExportedPublicKey));
        }

        [Test]
        public void PrivateKeySizeIs150()
        {
            var privateKey = CryptoUtils.GenerateKeyPair();
            Assert.AreEqual(150, privateKey.Length);
        }

        [Test]
        public void TestPasswordGeneration()
        {
            var password = CryptoUtils.GeneratePassword();
            Assert.AreEqual(32, password?.Length);

            password = CryptoUtils.GeneratePassword(32, 32);
            Assert.IsTrue(Regex.IsMatch(password, @"^[a-z]{32}$"));

            password = CryptoUtils.GeneratePassword(32, 0, 32);
            Assert.IsTrue(Regex.IsMatch(password, @"^[A-Z]{32}$"));

            password = CryptoUtils.GeneratePassword(32, 0, 0, 32);
            Assert.IsTrue(Regex.IsMatch(password, @"^[0-9]{32}$"));

            password = CryptoUtils.GeneratePassword(32, 0, 0, 0, 32);
            Assert.IsTrue(Regex.IsMatch(password, @"^[""!@#$%()+;<>=?[\\\]{}^.,]{32}$"));

            password = CryptoUtils.GeneratePassword(64, 16, 16, 16, 16);
            var chars = password.ToCharArray();
            Array.Sort(chars, (x, y) =>
            {
                int xgroup = (x >= 'a' && x <= 'z') ? 1 : (x >= 'A' && x <= 'Z') ? 2 : (x >= '0' && x <= '9') ? 3 : 4;
                int ygroup = (y >= 'a' && y <= 'z') ? 1 : (y >= 'A' && y <= 'Z') ? 2 : (y >= '0' && y <= '9') ? 3 : 4;
                int groupCompare = xgroup.CompareTo(ygroup);
                return groupCompare == 0 ? x.CompareTo(y) : groupCompare;
            });
            password = new string(chars);
            Assert.IsTrue(Regex.IsMatch(password, @"^[a-z]{16}[A-Z]{16}[0-9]{16}[""!@#$%()+;<>=?[\\\]{}^.,]{16}$"));
        }

        [Test]
        public void TestTotpDefaultAlgorithm()
        {
            // {Algorithm: "", Period: 30, UnixTime: 20000000000, Secret: "12345678901234567890", Digits: 8}, Output: "65353130"}
            const string url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME&algorithm=&digits=8&period=30";
            var totp = CryptoUtils.GetTotpCode(url, 20000000000);
            Assert.AreEqual("65353130", totp?.Code); // using default algorithm SHA1
        }

        [Test]
        public void TestTotpDefaultDigits()
        {
            // { Algorithm: "SHA1", Period: 30, UnixTime: 20000000000, Secret: "12345678901234567890", Digits: 0}, Output: "353130"}
            const string url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME&algorithm=SHA1&digits=0&period=30";
            var totp = CryptoUtils.GetTotpCode(url, 20000000000);
            Assert.AreEqual("353130", totp?.Code); // using default digits = 6
        }

        [Test]
        public void TestTotpDefaultPeriod()
        {
            // {Algorithm: "SHA1", Period: 0, UnixTime: 20000000000, Secret: "12345678901234567890", Digits: 8}, Output: "65353130"}
            const string url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME&algorithm=SHA1&digits=8&period=0";
            var totp = CryptoUtils.GetTotpCode(url, 20000000000);
            Assert.AreEqual("65353130", totp?.Code); // using default period = 30
        }

        [Test]
        public void TestTotpEmptySecret()
        {
            // {Algorithm: "SHA1", Period: 30, UnixTime: 0, Secret: "", Digits: 8}, Output: "no secret key provided"}
            const string url = "otpauth://totp/ACME:john.doe@email.com?secret=&issuer=ACME&algorithm=SHA1&digits=8&period=30";
            var totp = CryptoUtils.GetTotpCode(url);
            Assert.Null(totp, "Empty secret shouldn't produce valid TOTP");
        }

        [Test]
        public void TestTotpInvalidAlgorithm()
        {
            // { Algorithm: "SHA1024", Period: 30, UnixTime: 0, Secret: "12345678901234567890", Digits: 8}, Output: "invalid algorithm - use one of SHA1/SHA256/SHA512"}
            const string url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME&algorithm=SHA1024&digits=8&period=30";
            var totp = CryptoUtils.GetTotpCode(url);
            Assert.Null(totp, "SHA1024 is unsupported algorithm for TOTP");
        }

        [Test]
        public void TestTotpInvalidSecret()
        {
            // { Algorithm: "SHA1", Period: 30, UnixTime: 0, Secret: "1NVAL1D", Digits: 8}, Output: "bad secret key"}
            const string url = "otpauth://totp/ACME:john.doe@email.com?secret=1NVAL1D&issuer=ACME&algorithm=SHA1&digits=8&period=30";
            var totp = CryptoUtils.GetTotpCode(url);
            Assert.Null(totp, "Invalid secret shouldn't produce valid TOTP");
        }

        [Test]
        public void TestTotp()
        {
            // Check seconds passed
            // {Algorithm: "SHA1", Period: 30, UnixTime: 59, Secret: "12345678901234567890", Digits: 8}, Output: "94287082"}
            string url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME&algorithm=SHA1&digits=8&period=30";
            var totp = CryptoUtils.GetTotpCode(url, 59);
            Assert.AreEqual("94287082", totp?.Code);
            Assert.AreEqual(1, totp?.TimeLeft);
            // {Algorithm: "SHA256", Period: 30, UnixTime: 59, Secret: "12345678901234567890123456789012", Digits: 8}, Output: "46119246"}
            url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&issuer=ACME&algorithm=SHA256&digits=8&period=30";
            totp = CryptoUtils.GetTotpCode(url, 59);
            Assert.AreEqual("46119246", totp?.Code);
            Assert.AreEqual(1, totp?.TimeLeft);
            // {Algorithm: "SHA512", Period: 30, UnixTime: 59, Secret: "1234567890123456789012345678901234567890123456789012345678901234", Digits: 8}, Output: "90693936"}
            url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA=&issuer=ACME&algorithm=SHA512&digits=8&period=30";
            totp = CryptoUtils.GetTotpCode(url, 59);
            Assert.AreEqual("90693936", totp?.Code);
            Assert.AreEqual(1, totp?.TimeLeft);

            // Check different periods - 1 sec. before split
            // {Algorithm: "SHA1", Period: 30, UnixTime: 1111111109, Secret: "12345678901234567890", Digits: 8}, Output: "07081804"}
            url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME&algorithm=SHA1&digits=8&period=30";
            totp = CryptoUtils.GetTotpCode(url, 1111111109);
            Assert.AreEqual("07081804", totp?.Code);
            // {Algorithm: "SHA256", Period: 30, UnixTime: 1111111109, Secret: "12345678901234567890123456789012", Digits: 8}, Output: "68084774"}
            url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&issuer=ACME&algorithm=SHA256&digits=8&period=30";
            totp = CryptoUtils.GetTotpCode(url, 1111111109);
            Assert.AreEqual("68084774", totp?.Code);
            // {Algorithm: "SHA512", Period: 30, UnixTime: 1111111109, Secret: "1234567890123456789012345678901234567890123456789012345678901234", Digits: 8}, Output: "25091201"}
            url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA=&issuer=ACME&algorithm=SHA512&digits=8&period=30";
            totp = CryptoUtils.GetTotpCode(url, 1111111109);
            Assert.AreEqual("25091201", totp?.Code);

            // Check different periods - 1 sec. after split
            // {Algorithm: "SHA1", Period: 30, UnixTime: 1111111111, Secret: "12345678901234567890", Digits: 8}, Output: "14050471"}
            url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME&algorithm=SHA1&digits=8&period=30";
            totp = CryptoUtils.GetTotpCode(url, 1111111111);
            Assert.AreEqual("14050471", totp?.Code);
            // {Algorithm: "SHA256", Period: 30, UnixTime: 1111111111, Secret: "12345678901234567890123456789012", Digits: 8}, Output: "67062674"}
            url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&issuer=ACME&algorithm=SHA256&digits=8&period=30";
            totp = CryptoUtils.GetTotpCode(url, 1111111111);
            Assert.AreEqual("67062674", totp?.Code);
            // {Algorithm: "SHA512", Period: 30, UnixTime: 1111111111, Secret: "1234567890123456789012345678901234567890123456789012345678901234", Digits: 8}, Output: "99943326"}
            url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA=&issuer=ACME&algorithm=SHA512&digits=8&period=30";
            totp = CryptoUtils.GetTotpCode(url, 1111111111);
            Assert.AreEqual("99943326", totp?.Code);

            // Check different time periods
            // {Algorithm: "SHA1", Period: 30, UnixTime: 1234567890, Secret: "12345678901234567890", Digits: 8}, Output: "89005924"}
            url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME&algorithm=SHA1&digits=8&period=30";
            totp = CryptoUtils.GetTotpCode(url, 1234567890);
            Assert.AreEqual("89005924", totp?.Code);
            // {Algorithm: "SHA256", Period: 30, UnixTime: 1234567890, Secret: "12345678901234567890123456789012", Digits: 8}, Output: "91819424"}
            url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&issuer=ACME&algorithm=SHA256&digits=8&period=30";
            totp = CryptoUtils.GetTotpCode(url, 1234567890);
            Assert.AreEqual("91819424", totp?.Code);
            // {Algorithm: "SHA512", Period: 30, UnixTime: 1234567890, Secret: "1234567890123456789012345678901234567890123456789012345678901234", Digits: 8}, Output: "93441116"}
            url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA=&issuer=ACME&algorithm=SHA512&digits=8&period=30";
            totp = CryptoUtils.GetTotpCode(url, 1234567890);
            Assert.AreEqual("93441116", totp?.Code);

            // {Algorithm: "SHA1", Period: 30, UnixTime: 2000000000, Secret: "12345678901234567890", Digits: 8}, Output: "69279037"}
            url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME&algorithm=SHA1&digits=8&period=30";
            totp = CryptoUtils.GetTotpCode(url, 2000000000);
            Assert.AreEqual("69279037", totp?.Code);
            // {Algorithm: "SHA256", Period: 30, UnixTime: 2000000000, Secret: "12345678901234567890123456789012", Digits: 8}, Output: "90698825"}
            url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&issuer=ACME&algorithm=SHA256&digits=8&period=30";
            totp = CryptoUtils.GetTotpCode(url, 2000000000);
            Assert.AreEqual("90698825", totp?.Code);
            // {Algorithm: "SHA512", Period: 30, UnixTime: 2000000000, Secret: "1234567890123456789012345678901234567890123456789012345678901234", Digits: 8}, Output: "38618901"}
            url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA=&issuer=ACME&algorithm=SHA512&digits=8&period=30";
            totp = CryptoUtils.GetTotpCode(url, 2000000000);
            Assert.AreEqual("38618901", totp?.Code);

            // {Algorithm: "SHA1", Period: 30, UnixTime: 20000000000, Secret: "12345678901234567890", Digits: 8}, Output: "65353130"}
            url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME&algorithm=SHA1&digits=8&period=30";
            totp = CryptoUtils.GetTotpCode(url, 20000000000);
            Assert.AreEqual("65353130", totp?.Code);
            // {Algorithm: "SHA256", Period: 30, UnixTime: 20000000000, Secret: "12345678901234567890123456789012", Digits: 8}, Output: "77737706"}
            url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&issuer=ACME&algorithm=SHA256&digits=8&period=30";
            totp = CryptoUtils.GetTotpCode(url, 20000000000);
            Assert.AreEqual("77737706", totp?.Code);
            // {Algorithm: "SHA512", Period: 30, UnixTime: 20000000000, Secret: "1234567890123456789012345678901234567890123456789012345678901234", Digits: 8}, Output: "47863826"}
            url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA=&issuer=ACME&algorithm=SHA512&digits=8&period=30";
            totp = CryptoUtils.GetTotpCode(url, 20000000000);
            Assert.AreEqual("47863826", totp?.Code);
        }
    }
}