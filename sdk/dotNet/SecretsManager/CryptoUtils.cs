using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;

namespace SecretsManager
{
    public static class CryptoUtils
    {
        private static readonly SecureRandom Rng = new();
        private static readonly X9ECParameters Curve;
        private static readonly ECDomainParameters ECParameters;
        private static readonly ECKeyGenerationParameters KeyGenParams;

        static CryptoUtils()
        {
            var curveOid = X9ObjectIdentifiers.Prime256v1;
            Curve = X962NamedCurves.GetByOid(curveOid);
            ECParameters = new ECDomainParameters(Curve.Curve, Curve.G, Curve.N);
            KeyGenParams = new ECKeyGenerationParameters(curveOid, Rng);
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

        public static string WebSafe64FromBytes(byte[] data)
        {
            var base64 = Convert.ToBase64String(data);
            return base64.TrimEnd('=').Replace("+", "-").Replace("/", "_");
        }

        public static byte[] StringToBytes(string data)
        {
            return Encoding.ASCII.GetBytes(data);
        }
        
        public static string BytesToString(byte[] data)
        {
            return Encoding.ASCII.GetString(data);
        }

        public static string BytesToBase64(byte[] data)
        {
            return Convert.ToBase64String(data);
        }
        
        public static byte[] Base64ToBytes(string data)
        {
            return Convert.FromBase64String(data);
        }

        public static byte[] GetRandomBytes(int length)
        {
            var bytes = new byte[length];
            Rng.NextBytes(bytes);
            return bytes;
        }

        public static byte[] GenerateKeyPair()
        {
            var keyGenerator = new ECKeyPairGenerator();
            keyGenerator.Init(KeyGenParams);
            var keyPair = keyGenerator.GenerateKeyPair();
            return PrivateKeyInfoFactory.CreatePrivateKeyInfo(keyPair.Private).GetDerEncoded();
        }
       
        public static byte[] ExportPublicKey(byte[] privateKeyDer)
        {
            return Curve.G.Multiply(ImportPrivateKey(privateKeyDer).D).GetEncoded(false);
        }

        public static byte[] Hash(byte[] data, string tag)
        {
            var hmac = new HMACSHA512(data);
            return hmac.ComputeHash(StringToBytes(tag));
        }

        private static ECPublicKeyParameters ImportPublicKey(byte[] key)
        {
            var point = new X9ECPoint(ECParameters.Curve, new DerOctetString(key)).Point;
            return new ECPublicKeyParameters(point, ECParameters);
        }
        
        private static ECPrivateKeyParameters ImportPrivateKey(byte[] privateKeyDer)
        {
            return new ECPrivateKeyParameters(new BigInteger(1, privateKeyDer.Skip(36).Take(32).ToArray()), ECParameters);
        }

        private static byte[] GetECIESSymmetricKey(ICipherParameters privateKey, ICipherParameters recipientPublicKey)
        {
            var ka = AgreementUtilities.GetBasicAgreement("ECDHC");
            ka.Init(privateKey);
            var commonSecret = ka.CalculateAgreement(recipientPublicKey).ToByteArrayUnsigned();
            return SHA256.Create().ComputeHash(commonSecret);
        }

        private static GcmBlockCipher GetCipher(bool forEncryption, byte[] iv, byte[] key)
        {
            var cipher = new GcmBlockCipher(new AesEngine());
            var gcmParameterSpec = new AeadParameters(new KeyParameter(key), 16 * 8, iv);
            cipher.Init(forEncryption, gcmParameterSpec);
            return cipher;
        }
        
        private const int IvSize = 12;

        public static byte[] Encrypt(byte[] data, byte[] key)
        {
            var iv = GetRandomBytes(IvSize);
            var cipher = GetCipher(true, iv, key);
            var cipherText = new byte[cipher.GetOutputSize(data.Length)];
            var len = cipher.ProcessBytes(data, 0, data.Length, cipherText, 0);
            len += cipher.DoFinal(cipherText, len);
            return iv.Concat(cipherText.Take(len)).ToArray();
        }

        public static byte[] Decrypt(byte[] data, byte[] key)
        {
            var iv = data.Take(IvSize).ToArray();
            var cipher = GetCipher(false, iv, key);
            var decryptedData = new byte[cipher.GetOutputSize(data.Length - IvSize)];
            var len = cipher.ProcessBytes(data, IvSize, data.Length - IvSize, decryptedData, 0);
            cipher.DoFinal(decryptedData, len);
            return decryptedData;
        }

        public static byte[] Decrypt(string data, byte[] key)
        {
            return Decrypt(Base64ToBytes(data), key);
        }

        public static byte[] PublicEncrypt(byte[] data, byte[] key)
        {
            var keyGenerator = new ECKeyPairGenerator();
            keyGenerator.Init(KeyGenParams);
            var ephemeralKeyPair = keyGenerator.GenerateKeyPair();
            var recipientPublicKey = ImportPublicKey(key);
            var symmetricKey = GetECIESSymmetricKey(ephemeralKeyPair.Private, recipientPublicKey);
            var encryptedData = Encrypt(data, symmetricKey);
            return ((ECPublicKeyParameters) ephemeralKeyPair.Public).Q.GetEncoded().Concat(encryptedData).ToArray();
        }

        public static byte[] Sign(byte[] data, byte[] key)
        {
            var privateKey = ImportPrivateKey(key);
            var sig = SignerUtilities.GetSigner("SHA256withECDSA");
            sig.Init(true, privateKey);
            sig.BlockUpdate(data, 0, data.Length);
            var signature = sig.GenerateSignature();
            return signature;
        }
    }
}