using NUnit.Framework;

namespace SecretsManager.Test
{
    public class CryptoUtilsTests
    {
        [Test]
        public void PrivateKeyIsCompatible()
        {
            const string privateKey64 = "MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQg34GXYbMpXKaHcHZW4dIMO3WYU8zTjB6t+41SRsY1rwqgCgYIKoZIzj0DAQehRANCAAQGH/4ZwpGR9B7AlMjVY7ekpjOcaD3rhuO25CmOZxI3wqRDdhXQIdDnuWvQPCZ3ymtjL3C8JrVIcloklwYI9T7+";
            var privateKey = CryptoUtils.Base64ToBytes(privateKey64);
            var exportedPublicKey = CryptoUtils.ExportPublicKey(privateKey);
            Assert.AreEqual("BAYf/hnCkZH0HsCUyNVjt6SmM5xoPeuG47bkKY5nEjfCpEN2FdAh0Oe5a9A8JnfKa2MvcLwmtUhyWiSXBgj1Pv4=", CryptoUtils.BytesToBase64(exportedPublicKey));
        }
        
        [Test]
        public void PrivateKeySizeIs150()
        {
            var privateKey = CryptoUtils.GenerateKeyPair();
            Assert.AreEqual(150, privateKey.Length);
        }
    }
}