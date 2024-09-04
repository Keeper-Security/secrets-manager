using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Paddings;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Sec;

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

        public static byte[] GetUidBytes()
        {
            byte dash = 0b1111_1000;
            var bytes = new byte[] { };
            for (int i = 0; i < 8; i++) {
                bytes = GetRandomBytes(16);
                if ((dash & bytes[0]) != dash) break;
            }
            if ((dash & bytes[0]) == dash)
                bytes[0] = (byte)(bytes[0] & (byte)0b0111_1111);
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
            var privateKeyInfo = PrivateKeyInfo.GetInstance(privateKeyDer);
            var privateKeyStructure = ECPrivateKeyStructure.GetInstance(privateKeyInfo.ParsePrivateKey());
            var privateKeyValue = privateKeyStructure.GetKey();
            return new ECPrivateKeyParameters(privateKeyValue, ECParameters);
        }

        private static byte[] GetECIESSymmetricKey(ICipherParameters privateKey, ICipherParameters recipientPublicKey)
        {
            var ka = AgreementUtilities.GetBasicAgreement("ECDHC");
            ka.Init(privateKey);
            var commonSecret = ka.CalculateAgreement(recipientPublicKey).ToByteArrayUnsigned();
            // CalculateAgreement may return less than 32 bytes - pad with leading 0
            if (commonSecret.Length < 32)
                commonSecret = Enumerable.Repeat<Byte>(0, 32 - commonSecret.Length).Concat(commonSecret).ToArray();
            return SHA256.Create().ComputeHash(commonSecret);
        }

        private static GcmBlockCipher GetCipher(bool forEncryption, byte[] iv, byte[] key)
        {
            var cipher = new GcmBlockCipher(new AesEngine());
            cipher.Init(forEncryption, new AeadParameters(new KeyParameter(key), 16 * 8, iv));
            return cipher;
        }

        private static PaddedBufferedBlockCipher GetCBCCipher(bool forEncryption, byte[] iv, byte[] key)
        {
            var cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(new AesEngine()), new Pkcs7Padding());
            cipher.Init(forEncryption, new ParametersWithIV(new KeyParameter(key), iv));
            return cipher;
        }

        private const int IvSize = 12;
        private const int IvSizeCBC = 16;

        public static byte[] Encrypt(byte[] data, byte[] key, bool useCBC = false)
        {
            if (useCBC)
            {
                return EncryptCBC(data, key);
            }
            var iv = GetRandomBytes(IvSize);
            var cipher = GetCipher(true, iv, key);
            var cipherText = new byte[cipher.GetOutputSize(data.Length)];
            var len = cipher.ProcessBytes(data, 0, data.Length, cipherText, 0);
            len += cipher.DoFinal(cipherText, len);
            return iv.Concat(cipherText.Take(len)).ToArray();
        }
        
        private static byte[] EncryptCBC(byte[] data, byte[] key)
        {
            var iv = GetRandomBytes(IvSizeCBC);
            var cipher = GetCBCCipher(true, iv, key);
            var cipherText = new byte[cipher.GetOutputSize(data.Length)];
            var len = cipher.ProcessBytes(data, 0, data.Length, cipherText, 0);
            len += cipher.DoFinal(cipherText, len);
            return iv.Concat(cipherText.Take(len)).ToArray();
        }

        public static byte[] Decrypt(byte[] data, byte[] key, bool useCBC = false)
        {
            if (useCBC)
            {
                return DecryptCBC(data, key);
            }
            var iv = data.Take(IvSize).ToArray();
            var cipher = GetCipher(false, iv, key);
            var decryptedData = new byte[cipher.GetOutputSize(data.Length - IvSize)];
            var len = cipher.ProcessBytes(data, IvSize, data.Length - IvSize, decryptedData, 0);
            cipher.DoFinal(decryptedData, len);
            return decryptedData;
        }
        
        public static byte[] DecryptCBC(byte[] data, byte[] key, bool useCBC = false)
        {
            var iv = data.Take(IvSizeCBC).ToArray();
            var cipher = GetCBCCipher(false, iv, key);
            var decryptedData = new byte[cipher.GetOutputSize(data.Length - IvSizeCBC)];
            var len = cipher.ProcessBytes(data, IvSizeCBC, data.Length - IvSizeCBC, decryptedData, 0);
            len += cipher.DoFinal(decryptedData, len);
            return decryptedData.Take(len).ToArray();
        }

        public static byte[] Decrypt(string data, byte[] key, bool useCBC = false)
        {
            return Decrypt(Base64ToBytes(data), key, useCBC);
        }

        public static byte[] PublicEncrypt(byte[] data, byte[] key)
        {
            var keyGenerator = new ECKeyPairGenerator();
            keyGenerator.Init(KeyGenParams);
            var ephemeralKeyPair = keyGenerator.GenerateKeyPair();
            var recipientPublicKey = ImportPublicKey(key);
            var symmetricKey = GetECIESSymmetricKey(ephemeralKeyPair.Private, recipientPublicKey);
            var encryptedData = Encrypt(data, symmetricKey);
            return ((ECPublicKeyParameters)ephemeralKeyPair.Public).Q.GetEncoded().Concat(encryptedData).ToArray();
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

        // TOTP functions
        const string DefaultAlgorithm = "SHA1";
        const int DefaultDigits = 6;
        const int DefaultPeriod = 30;
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        private static readonly Regex rxBase32Alphabet = new Regex($"^[A-Z2-7]+$", RegexOptions.Compiled);

        /// <summary>
        /// TotpCode provides detailed info about the generated TOTP code
        /// </summary>
        public class TotpCode
        {
            /// <summary>
            /// TOTP Code
            /// </summary>
            public string Code;
            /// <summary>
            /// Time left in seconds (time before expiration)
            /// </summary>
            public int TimeLeft;
            /// <summary>
            /// Period in seconds
            /// </summary>
            public int Period;
        }

        internal static byte[] Base32ToBytes(string base32)
        {
            // The padding specified in RFC 3548 section 2.2 is not required and should be omitted.
            base32 = base32?.Trim().TrimEnd('=');
            if (string.IsNullOrEmpty(base32) || !rxBase32Alphabet.IsMatch(base32))
                return null;

            var bytes = base32.ToCharArray();
            var output = new List<byte>();
            for (var bitIndex = 0; bitIndex < base32.Length * 5; bitIndex += 8)
            {
                var dualByte = alphabet.IndexOf(bytes[bitIndex / 5]) << 10;
                if (bitIndex / 5 + 1 < bytes.Length)
                    dualByte |= alphabet.IndexOf(bytes[bitIndex / 5 + 1]) << 5;
                if (bitIndex / 5 + 2 < bytes.Length)
                    dualByte |= alphabet.IndexOf(bytes[bitIndex / 5 + 2]);

                dualByte = 0xff & (dualByte >> (15 - bitIndex % 5 - 8));
                output.Add((byte)dualByte);
            }

            return output.ToArray();
        }

        private static Dictionary<string, string> ParseQueryString(string requestQueryString)
        {
            var rc = new Dictionary<string, string>();
            if (string.IsNullOrEmpty(requestQueryString)) return rc;

            var kvp = requestQueryString.Split(new char[] { '&', '?' }, StringSplitOptions.RemoveEmptyEntries);
            foreach (var row in kvp)
            {
                if (string.IsNullOrWhiteSpace(row)) continue;
                var index = row.IndexOf('=');
                if (index < 0) continue;
                rc[Uri.UnescapeDataString(row.Substring(0, index))] = Uri.UnescapeDataString(row.Substring(index + 1));
            }
            return rc;
        }

        /// <summary>
        /// Gets TOTP code for URL
        /// </summary>
        /// <param name="url">TOTP URL</param>
        /// <param name="unixTimeSeconds">unix time seconds to use as starting timestamp</param>
        /// <returns>
        /// A tuple containing three values:
        /// <list type="number">
        /// <item><description>TOTP code</description></item>
        /// <item><description>Seconds passed</description></item>
        /// <item><description>TOTP Period in seconds</description></item>
        /// </list>
        /// </returns>
        public static TotpCode GetTotpCode(string url, long unixTimeSeconds = 0)
        {
            if (!Uri.TryCreate(url, UriKind.Absolute, out Uri uri))
                return null;

            if (uri.Scheme != "otpauth")
                return null;

            string secret = null;
            var algorithm = "SHA1";
            var digits = 6;
            var period = 30;

            var coll = ParseQueryString(uri.Query);
            foreach (var key in coll.Keys)
                switch (key)
                {
                    case "secret":
                        secret = coll[key];
                        break;
                    case "algorithm":
                        algorithm = string.IsNullOrWhiteSpace(coll[key]) ? DefaultAlgorithm : coll[key];
                        break;
                    case "digits":
                        if (!int.TryParse(coll[key], out digits) || digits == 0) digits = DefaultDigits;
                        break;
                    case "period":
                        if (!int.TryParse(coll[key], out period) || period == 0) period = DefaultPeriod;
                        break;
                }

            if (string.IsNullOrEmpty(secret))
                return null;

            var tmBase = unixTimeSeconds != 0 ? unixTimeSeconds : DateTimeOffset.Now.ToUnixTimeSeconds();
            var tm = tmBase / period;
            var msg = BitConverter.GetBytes(tm);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(msg);

            var secretBytes = Base32ToBytes(secret.ToUpper());
            if (secretBytes == null)
                return null;

            HMAC hmac = null;
            switch (algorithm)
            {
                // although once part of Google Key Uri Format - https://github.com/google/google-authenticator/wiki/Key-Uri-Format/_history
                // removed MD5 as unreliable - only digests of length >= 20 can be used (MD5 has a digest length of 16)
                //case "MD5": hmac = new HMACMD5(secretBytes); break;
                case "SHA1": hmac = new HMACSHA1(secretBytes); break;
                case "SHA256": hmac = new HMACSHA256(secretBytes); break;
                case "SHA512": hmac = new HMACSHA512(secretBytes); break;
            }

            if (hmac == null)
                return null;

            var digest = hmac.ComputeHash(msg);
            var offset = digest[digest.Length - 1] & 0x0f;
            var codeBytes = new byte[4];
            Array.Copy(digest, offset, codeBytes, 0, codeBytes.Length);
            codeBytes[0] &= 0x7f;
            if (BitConverter.IsLittleEndian)
                Array.Reverse(codeBytes);

            var codeInt = BitConverter.ToInt32(codeBytes, 0);
            codeInt %= (int)Math.Pow(10, digits);
            var codeStr = codeInt.ToString();
            while (codeStr.Length < digits)
                codeStr = "0" + codeStr;

            int elapsed = (int)(tmBase % period); // time elapsed in current period in seconds
            int ttl = period - elapsed; // time to live in seconds
            return new TotpCode() { Code = codeStr, TimeLeft = ttl, Period = period };
        }

        // password generation
        const int DefaultPasswordLength = 32;
        const string AsciiLowercase = @"abcdefghijklmnopqrstuvwxyz";
        const string AsciiUppercase = @"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        const string AsciiDigits = @"0123456789";
        const string AsciiSpecialCharacters = @"""!@#$%()+;<>=?[]{}^.,";

        internal static string RandomSample(int sampleLength = 0, string sampleString = "")
        {
            sampleLength = sampleLength < 0 ? 0 : sampleLength;
            var result = new StringBuilder(sampleLength);
            if (sampleLength > 0 && !string.IsNullOrEmpty(sampleString))
            {
                var data = GetRandomBytes(4 * sampleLength);
                for (int i = 0; i < sampleLength; i++)
                {
                    var rnd = BitConverter.ToUInt32(data, i * 4);
                    var idx = (int)(rnd % sampleString.Length);

                    result.Append(sampleString[idx]);
                }
            }
            return result.ToString();
        }

        // Returns random number in the range [0, maxValue) i.e. 0 <= number < maxValue
        internal static int GetRandomInt(int maxValue)
        {
            uint limit = Convert.ToUInt32(UInt32.MaxValue - UInt32.MaxValue % maxValue);
            uint value;
            do
            {
                var randomBytes = GetRandomBytes(4);
                value = BitConverter.ToUInt32(randomBytes, 0);
            } while (value > limit);
            return Convert.ToInt32(value % maxValue);
        }

        internal static string Shuffle(string text)
        {
            var result = "";

            if (!string.IsNullOrWhiteSpace(text))
            {
                var array = text.ToCharArray();
                for (var i = array.Length - 1; i >= 1; --i)
                {
                    int j = GetRandomInt(i + 1); // 0 <= j <= i
                    if (i != j)
                    {
                        var temp = array[i];
                        array[i] = array[j];
                        array[j] = temp;
                    }
                }
                result = new string(array);
            }

            return result;
        }

        /// <summary>
        /// Generates a new password of specified minimum length
        /// using provided number of uppercase, lowercase, digits and special characters.<para/>
        /// Note: If all character groups are unspecified or all have exact zero length
        /// then password characters are chosen from all groups uniformly at random.<para/>
        /// Note: If all charset lengths are negative or 0 but can't reach min_length
        /// then all exact/negative charset lengths will be treated as minimum number of characters instead.<para/>
        /// </summary>
        /// <param name="minLength">Minimum password length - default: 32</param>
        /// <param name="lowercase">Minimum number of lowercase characters if positive, exact if 0 or negative</param>
        /// <param name="uppercase">Minimum number of uppercase characters if positive, exact if 0 or negative</param>
        /// <param name="digits">Minimum number of digits if positive, exact if 0 or negative</param>
        /// <param name="specialCharacters">Minimum number of special characters if positive, exact if 0 or negative</param>
        /// <param name="specialCharacterSet">String containing custom set of special characters to pick from</param>
        /// <returns>Generated password string</returns>
        public static string GeneratePassword(
            int minLength = DefaultPasswordLength,
            int? lowercase = null,
            int? uppercase = null,
            int? digits = null,
            int? specialCharacters = null,
            string specialCharacterSet = AsciiSpecialCharacters)
        {
            List<int?> counts = new List<int?> { lowercase, uppercase, digits, specialCharacters };
            int sumCategories = counts.Sum(x => x.HasValue ? Math.Abs(x.Value) : 0);

            // If all lengths are exact/negative but don't reach min_length - convert to minimum/positive lengths
            int numExactCounts = counts.Sum(x => x.HasValue && x.Value <= 0 ? 1 : 0);
            if (counts.Count == numExactCounts && sumCategories < minLength)
            {
                if (lowercase.HasValue && lowercase.Value < 0) lowercase = Math.Abs(lowercase.Value);
                if (uppercase.HasValue && uppercase.Value < 0) uppercase = Math.Abs(uppercase.Value);
                if (digits.HasValue && digits.Value < 0) digits = Math.Abs(digits.Value);
                if (specialCharacters.HasValue && specialCharacters.Value < 0) specialCharacters = Math.Abs(specialCharacters.Value);
            }

            string extraChars = "";
            int extraCount = 0;
            if (minLength > sumCategories)
                extraCount = minLength - sumCategories;
            if (!lowercase.HasValue || lowercase.Value > 0)
                extraChars += AsciiLowercase;
            if (!uppercase.HasValue || uppercase.Value > 0)
                extraChars += AsciiUppercase;
            if (!digits.HasValue || digits.Value > 0)
                extraChars += AsciiDigits;
            if (!specialCharacters.HasValue || specialCharacters.Value > 0)
                extraChars += specialCharacterSet;
            if (extraCount > 0 && string.IsNullOrEmpty(extraChars))
                extraChars = AsciiLowercase + AsciiUppercase + AsciiDigits + specialCharacterSet;

            var categoryMap = new List<KeyValuePair<int, string>>
            {
                new KeyValuePair<int, string>(lowercase.HasValue ? Math.Abs(lowercase.Value) : 0, AsciiLowercase),
                new KeyValuePair<int, string>(uppercase.HasValue ? Math.Abs(uppercase.Value) : 0, AsciiUppercase),
                new KeyValuePair<int, string>(digits.HasValue ? Math.Abs(digits.Value) : 0, AsciiDigits),
                new KeyValuePair<int, string>(specialCharacters.HasValue ? Math.Abs(specialCharacters.Value) : 0, specialCharacterSet),
                new KeyValuePair<int, string>(extraCount, extraChars)
            };

            string passwordCharacters = "";
            foreach (KeyValuePair<int, string> kvp in categoryMap)
            {
                if (kvp.Key > 0)
                    passwordCharacters += RandomSample(kvp.Key, kvp.Value);
            }
            string password = Shuffle(passwordCharacters);
            return password;
        }
    }
}
