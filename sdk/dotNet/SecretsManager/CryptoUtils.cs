using System;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace SecretsManager
{
    public static class CryptoUtils
    {
        private static readonly ECDomainParameters ECParameters;
        private static readonly SecureRandom RngCsp = new SecureRandom();

        static CryptoUtils()
        {
            var curve = ECNamedCurveTable.GetByName("secp256r1");
            ECParameters = new ECDomainParameters(curve.Curve, curve.G, curve.N);
        }

        public static byte[] WebSafe64ToBytes(string data)
        {
            if (data == null) return null;
            var base64 = data
                .Replace("-", "+")
                .Replace("_", "/")
                .Replace("=", "")
                .Replace("\r", "")
                .Replace("\n", "");
            base64 = base64.PadRight(base64.Length + (4 - base64.Length % 4) % 4, '=');
            return Convert.FromBase64String(base64);
        }

        public static byte[] StringToBytes(string data)
        {
            return Encoding.ASCII.GetBytes(data);
        }

        public static string BytesToBase64(byte[] data)
        {
            return Convert.ToBase64String(data);
        }

        public static byte[] GetRandomBytes(int length)
        {
            var bytes = new byte[length];
            RngCsp.NextBytes(bytes);
            return bytes;
        }

        public static Tuple<byte[], byte[]> GenerateKeyPair()
        {
            var keyGeneratorParams = new ECKeyGenerationParameters(ECParameters, RngCsp);
            var keyGenerator = new ECKeyPairGenerator("EC");
            keyGenerator.Init(keyGeneratorParams);
            var keyPair = keyGenerator.GenerateKeyPair();
            var publicRaw = ((ECPublicKeyParameters) keyPair.Public).Q.GetEncoded();
            var privateRaw = ExportECPrivateKey((ECPrivateKeyParameters) keyPair.Private);
            return new Tuple<byte[], byte[]>(publicRaw, privateRaw);
        }

        private static byte[] ExportECPrivateKey(ECPrivateKeyParameters key)
        {
            var privateKey = key.D.ToByteArrayUnsigned();
            var len = privateKey.Length;
            if (len >= 32) return privateKey;
            var pk = new byte[32];
            Array.Clear(pk, 0, pk.Length);
            Array.Copy(privateKey, 0, pk, 32 - len, len);
            return pk;
        }

        public static byte[] Hash(byte[] data, string tag)
        {
            var hmac = new HMACSHA512(data);
            return hmac.ComputeHash(StringToBytes(tag));
        }

        public static ECPublicKeyParameters ImportPublicKey(byte[] key)
        {
            var point = new X9ECPoint(ECParameters.Curve, new DerOctetString(key)).Point;
            return new ECPublicKeyParameters(point, ECParameters);
        }

        private static byte[] GetECIESSymmetricKey(ICipherParameters privateKey, ICipherParameters recipientPublicKey)
        {
            var ka = AgreementUtilities.GetBasicAgreement("ECDHC");
            ka.Init(privateKey);
            var commonSecret = ka.CalculateAgreement(recipientPublicKey).ToByteArrayUnsigned();
            return SHA256.Create().ComputeHash(commonSecret);
        }

        public static GcmBlockCipher GetCipher(bool forEncryption, byte[] iv, byte[] key)
        {
            var cipher = new GcmBlockCipher(new AesEngine());
            var gcmParameterSpec = new AeadParameters(new KeyParameter(key), 16 * 8, iv);
            cipher.Init(true, gcmParameterSpec);
            return cipher;
        }

        public static byte[] Encrypt(byte[] data, byte[] key)
        {
            var iv = GetRandomBytes(12);
            var cipher = GetCipher(true, iv, key);
            var cipherText = new byte[cipher.GetOutputSize(data.Length)];
            var len = cipher.ProcessBytes(data, 0, data.Length, cipherText, 0);
            len += cipher.DoFinal(cipherText, len);
            return iv.Concat(cipherText.Take(len)).ToArray();
        }

        public static byte[] PublicEncrypt(byte[] data, byte[] keeperPublicKey)
        {
            var keyGenerator = new ECKeyPairGenerator("ECDH");
            keyGenerator.Init(new ECKeyGenerationParameters(ECParameters, RngCsp));
            var ephemeralKeyPair = keyGenerator.GenerateKeyPair();
            var recipientPublicKey = ImportPublicKey(keeperPublicKey);
            var symmetricKey = GetECIESSymmetricKey(ephemeralKeyPair.Private, recipientPublicKey);
            var encryptedData = Encrypt(data, symmetricKey);
            return ((ECPublicKeyParameters) ephemeralKeyPair.Public).Q.GetEncoded().Concat(encryptedData).ToArray();
        }

        public static byte[] Sign(byte[] signatureBase, byte[] privateKey)
        {
            return new byte[] {1};
        }
    }
}