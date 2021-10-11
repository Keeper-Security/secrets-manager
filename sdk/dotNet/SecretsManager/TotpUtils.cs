using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Web;

namespace SecretsManager
{
    public static class TotpUtils
    {
        static TotpUtils() { }

        const string DefaultAlgorithm = "SHA1";
        const int DefaultDigits = 6;
        const int DefaultPeriod = 30;
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        private static readonly Regex rxBase32Alphabet = new Regex($"^[A-Z2-7]+$", RegexOptions.Compiled);

        internal static byte[] Base32ToBytes(string base32)
        {
            // The padding specified in RFC 3548 section 2.2 is not required and should be omitted.
            base32 = base32?.Trim().TrimEnd('=');
            if (string.IsNullOrEmpty(base32) || !rxBase32Alphabet.IsMatch(base32))
                return null;

            char[] bytes = base32.ToCharArray();
            List<byte> output = new List<byte>();
            for (int bitIndex = 0; bitIndex < base32.Length * 5; bitIndex += 8)
            {
                int dualByte = alphabet.IndexOf(bytes[bitIndex / 5]) << 10;
                if (bitIndex / 5 + 1 < bytes.Length)
                    dualByte |= alphabet.IndexOf(bytes[bitIndex / 5 + 1]) << 5;
                if (bitIndex / 5 + 2 < bytes.Length)
                    dualByte |= alphabet.IndexOf(bytes[bitIndex / 5 + 2]);

                dualByte = 0xff & (dualByte >> (15 - bitIndex % 5 - 8));
                output.Add((byte)dualByte);
            }

            return output.ToArray();
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
        public static Tuple<string, int, int> GetTotpCode(string url, long unixTimeSeconds = 0)
        {
            if (!Uri.TryCreate(url, UriKind.Absolute, out Uri uri))
                return null;

            if (uri.Scheme != "otpauth")
                return null;

            string secret = null;
            string algorithm = "SHA1";
            int digits = 6;
            int period = 30;

            NameValueCollection coll = HttpUtility.ParseQueryString(uri.Query);
            foreach (string key in coll.AllKeys)
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

            long tmBase = unixTimeSeconds != 0 ? unixTimeSeconds : DateTimeOffset.Now.ToUnixTimeSeconds();
            long tm = tmBase / period;
            byte[] msg = BitConverter.GetBytes(tm);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(msg);

            byte[] secretBytes = Base32ToBytes(secret.ToUpper());
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

            byte[] digest = hmac.ComputeHash(msg);
            int offset = digest[digest.Length - 1] & 0x0f;
            byte[] codeBytes = new byte[4];
            Array.Copy(digest, offset, codeBytes, 0, codeBytes.Length);
            codeBytes[0] &= 0x7f;
            if (BitConverter.IsLittleEndian)
                Array.Reverse(codeBytes);

            int codeInt = BitConverter.ToInt32(codeBytes, 0);
            codeInt %= (int)Math.Pow(10, digits);
            string codeStr = codeInt.ToString();
            while (codeStr.Length < digits)
                codeStr = "0" + codeStr;

            return Tuple.Create(codeStr, (int)(tmBase % period), period);
        }
    }
}