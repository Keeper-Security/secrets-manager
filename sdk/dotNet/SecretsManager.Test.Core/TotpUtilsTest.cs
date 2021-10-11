using NUnit.Framework;

namespace SecretsManager.Test
{
    public class TotpUtilsTest
    {
        [Test]
        public void TestDefaultAlgorithm()
        {
            // {Algorithm: "", Period: 30, UnixTime: 20000000000, Secret: "12345678901234567890", Digits: 8}, Output: "65353130"}
            const string url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME&algorithm=&digits=8&period=30";
            var totp = TotpUtils.GetTotpCode(url, 20000000000);
            Assert.AreEqual("65353130", totp?.Item1); // using default algorithm SHA1
        }

        [Test]
        public void TestDefaultDigits()
        {
            // { Algorithm: "SHA1", Period: 30, UnixTime: 20000000000, Secret: "12345678901234567890", Digits: 0}, Output: "353130"}
            const string url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME&algorithm=SHA1&digits=0&period=30";
            var totp = TotpUtils.GetTotpCode(url, 20000000000);
            Assert.AreEqual("353130", totp?.Item1); // using default digits = 6
        }

        [Test]
        public void TestDefaultPeriod()
        {
            // {Algorithm: "SHA1", Period: 0, UnixTime: 20000000000, Secret: "12345678901234567890", Digits: 8}, Output: "65353130"}
            const string url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME&algorithm=SHA1&digits=8&period=0";
            var totp = TotpUtils.GetTotpCode(url, 20000000000);
            Assert.AreEqual("65353130", totp?.Item1); // using default period = 30
        }

        [Test]
        public void TestEmptySecret()
        {
            // {Algorithm: "SHA1", Period: 30, UnixTime: 0, Secret: "", Digits: 8}, Output: "no secret key provided"}
            const string url = "otpauth://totp/ACME:john.doe@email.com?secret=&issuer=ACME&algorithm=SHA1&digits=8&period=30";
            var totp = TotpUtils.GetTotpCode(url);
            Assert.Null(totp, "Empty secret shouldn't produce valid TOTP");
        }

        [Test]
        public void TestInvalidAlgorithm()
        {
            // { Algorithm: "SHA1024", Period: 30, UnixTime: 0, Secret: "12345678901234567890", Digits: 8}, Output: "invalid algorithm - use one of SHA1/SHA256/SHA512"}
            const string url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME&algorithm=SHA1024&digits=8&period=30";
            var totp = TotpUtils.GetTotpCode(url);
            Assert.Null(totp, "SHA1024 is unsupported algorithm for TOTP");
        }

        [Test]
        public void TestInvalidSecret()
        {
            // { Algorithm: "SHA1", Period: 30, UnixTime: 0, Secret: "1NVAL1D", Digits: 8}, Output: "bad secret key"}
            const string url = "otpauth://totp/ACME:john.doe@email.com?secret=1NVAL1D&issuer=ACME&algorithm=SHA1&digits=8&period=30";
            var totp = TotpUtils.GetTotpCode(url);
            Assert.Null(totp, "Invalid secret shouldn't produce valid TOTP");
        }

        [Test]
        public void TestTotp()
        {
            // Check seconds passed
            // {Algorithm: "SHA1", Period: 30, UnixTime: 59, Secret: "12345678901234567890", Digits: 8}, Output: "94287082"}
            string url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME&algorithm=SHA1&digits=8&period=30";
            var totp = TotpUtils.GetTotpCode(url, 59);
            Assert.AreEqual("94287082", totp?.Item1);
            Assert.AreEqual(29, totp?.Item2);
            // {Algorithm: "SHA256", Period: 30, UnixTime: 59, Secret: "12345678901234567890123456789012", Digits: 8}, Output: "46119246"}
            url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&issuer=ACME&algorithm=SHA256&digits=8&period=30";
            totp = TotpUtils.GetTotpCode(url, 59);
            Assert.AreEqual("46119246", totp?.Item1);
            Assert.AreEqual(29, totp?.Item2);
            // {Algorithm: "SHA512", Period: 30, UnixTime: 59, Secret: "1234567890123456789012345678901234567890123456789012345678901234", Digits: 8}, Output: "90693936"}
            url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA=&issuer=ACME&algorithm=SHA512&digits=8&period=30";
            totp = TotpUtils.GetTotpCode(url, 59);
            Assert.AreEqual("90693936", totp?.Item1);
            Assert.AreEqual(29, totp?.Item2);

            // Check different periods - 1 sec. before split
            // {Algorithm: "SHA1", Period: 30, UnixTime: 1111111109, Secret: "12345678901234567890", Digits: 8}, Output: "07081804"}
            url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME&algorithm=SHA1&digits=8&period=30";
            totp = TotpUtils.GetTotpCode(url, 1111111109);
            Assert.AreEqual("07081804", totp?.Item1);
            // {Algorithm: "SHA256", Period: 30, UnixTime: 1111111109, Secret: "12345678901234567890123456789012", Digits: 8}, Output: "68084774"}
            url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&issuer=ACME&algorithm=SHA256&digits=8&period=30";
            totp = TotpUtils.GetTotpCode(url, 1111111109);
            Assert.AreEqual("68084774", totp?.Item1);
            // {Algorithm: "SHA512", Period: 30, UnixTime: 1111111109, Secret: "1234567890123456789012345678901234567890123456789012345678901234", Digits: 8}, Output: "25091201"}
            url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA=&issuer=ACME&algorithm=SHA512&digits=8&period=30";
            totp = TotpUtils.GetTotpCode(url, 1111111109);
            Assert.AreEqual("25091201", totp?.Item1);

            // Check different periods - 1 sec. after split
            // {Algorithm: "SHA1", Period: 30, UnixTime: 1111111111, Secret: "12345678901234567890", Digits: 8}, Output: "14050471"}
            url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME&algorithm=SHA1&digits=8&period=30";
            totp = TotpUtils.GetTotpCode(url, 1111111111);
            Assert.AreEqual("14050471", totp?.Item1);
            // {Algorithm: "SHA256", Period: 30, UnixTime: 1111111111, Secret: "12345678901234567890123456789012", Digits: 8}, Output: "67062674"}
            url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&issuer=ACME&algorithm=SHA256&digits=8&period=30";
            totp = TotpUtils.GetTotpCode(url, 1111111111);
            Assert.AreEqual("67062674", totp?.Item1);
            // {Algorithm: "SHA512", Period: 30, UnixTime: 1111111111, Secret: "1234567890123456789012345678901234567890123456789012345678901234", Digits: 8}, Output: "99943326"}
            url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA=&issuer=ACME&algorithm=SHA512&digits=8&period=30";
            totp = TotpUtils.GetTotpCode(url, 1111111111);
            Assert.AreEqual("99943326", totp?.Item1);

            // Check different time periods
            // {Algorithm: "SHA1", Period: 30, UnixTime: 1234567890, Secret: "12345678901234567890", Digits: 8}, Output: "89005924"}
            url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME&algorithm=SHA1&digits=8&period=30";
            totp = TotpUtils.GetTotpCode(url, 1234567890);
            Assert.AreEqual("89005924", totp?.Item1);
            // {Algorithm: "SHA256", Period: 30, UnixTime: 1234567890, Secret: "12345678901234567890123456789012", Digits: 8}, Output: "91819424"}
            url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&issuer=ACME&algorithm=SHA256&digits=8&period=30";
            totp = TotpUtils.GetTotpCode(url, 1234567890);
            Assert.AreEqual("91819424", totp?.Item1);
            // {Algorithm: "SHA512", Period: 30, UnixTime: 1234567890, Secret: "1234567890123456789012345678901234567890123456789012345678901234", Digits: 8}, Output: "93441116"}
            url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA=&issuer=ACME&algorithm=SHA512&digits=8&period=30";
            totp = TotpUtils.GetTotpCode(url, 1234567890);
            Assert.AreEqual("93441116", totp?.Item1);

            // {Algorithm: "SHA1", Period: 30, UnixTime: 2000000000, Secret: "12345678901234567890", Digits: 8}, Output: "69279037"}
            url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME&algorithm=SHA1&digits=8&period=30";
            totp = TotpUtils.GetTotpCode(url, 2000000000);
            Assert.AreEqual("69279037", totp?.Item1);
            // {Algorithm: "SHA256", Period: 30, UnixTime: 2000000000, Secret: "12345678901234567890123456789012", Digits: 8}, Output: "90698825"}
            url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&issuer=ACME&algorithm=SHA256&digits=8&period=30";
            totp = TotpUtils.GetTotpCode(url, 2000000000);
            Assert.AreEqual("90698825", totp?.Item1);
            // {Algorithm: "SHA512", Period: 30, UnixTime: 2000000000, Secret: "1234567890123456789012345678901234567890123456789012345678901234", Digits: 8}, Output: "38618901"}
            url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA=&issuer=ACME&algorithm=SHA512&digits=8&period=30";
            totp = TotpUtils.GetTotpCode(url, 2000000000);
            Assert.AreEqual("38618901", totp?.Item1);

            // {Algorithm: "SHA1", Period: 30, UnixTime: 20000000000, Secret: "12345678901234567890", Digits: 8}, Output: "65353130"}
            url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME&algorithm=SHA1&digits=8&period=30";
            totp = TotpUtils.GetTotpCode(url, 20000000000);
            Assert.AreEqual("65353130", totp?.Item1);
            // {Algorithm: "SHA256", Period: 30, UnixTime: 20000000000, Secret: "12345678901234567890123456789012", Digits: 8}, Output: "77737706"}
            url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&issuer=ACME&algorithm=SHA256&digits=8&period=30";
            totp = TotpUtils.GetTotpCode(url, 20000000000);
            Assert.AreEqual("77737706", totp?.Item1);
            // {Algorithm: "SHA512", Period: 30, UnixTime: 20000000000, Secret: "1234567890123456789012345678901234567890123456789012345678901234", Digits: 8}, Output: "47863826"}
            url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA=&issuer=ACME&algorithm=SHA512&digits=8&period=30";
            totp = TotpUtils.GetTotpCode(url, 20000000000);
            Assert.AreEqual("47863826", totp?.Item1);
        }
    }
}
