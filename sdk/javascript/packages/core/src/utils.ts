import {platform} from './platform'

export const webSafe64 = (source: string): string => source.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

export const webSafe64ToRegular = (source: string): string => source.replace(/-/g, '+').replace(/_/g, '/') + '=='.substring(0, (3 * source.length) % 4);

export const webSafe64ToBytes = (source: string): Uint8Array => platform.base64ToBytes(webSafe64ToRegular(source));

export const webSafe64FromBytes = (source: Uint8Array): string => webSafe64(platform.bytesToBase64(source));

// extracts public raw from private key for prime256v1 curve in der/pkcs8
// privateKey: key.slice(36, 68)
export const privateDerToPublicRaw = (key: Uint8Array): Uint8Array => key.slice(-65)

const b32encode = (base32Text: string): Uint8Array => {
    /* encodes a string to base32 and returns the encoded string */
    const alphabet: string = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    // The padding specified in RFC 3548 section 2.2 is not required and should be omitted.
    const base32: string = (base32Text || '').replace(/=+$/g, '').toUpperCase();
    if (!base32 || !/^[A-Z2-7]+$/.test(base32))
        return new Uint8Array();

    const bytes = Array.from(base32)
    let output = new Array()

    for (let bitIndex = 0; bitIndex < base32.length * 5; bitIndex += 8) {
        const idx = Math.floor(bitIndex / 5);
        let dualByte = alphabet.indexOf(bytes[idx]) << 10;
        if (idx + 1 < bytes.length)
            dualByte |= alphabet.indexOf(bytes[idx + 1]) << 5;
        if (idx + 2 < bytes.length)
            dualByte |= alphabet.indexOf(bytes[idx + 2]);
        dualByte = 0xff & (dualByte >> (15 - bitIndex % 5 - 8));
        output.push(dualByte);
    }

    return new Uint8Array(output);
}

export const getTotpCode = async (url: string, unixTimeSeconds: number = 0) : Promise<{ code: string; timeLeft: number; period: number; } | null>  => {
    let totpUrl: URL;
    try {
        totpUrl = new URL(url);
    } catch (e) {
        return null;
    }

    if (totpUrl.protocol != 'otpauth:')
        return null;

    const secret: string = (totpUrl.searchParams.get('secret') || '').trim();
    if (!secret)
        return null;

    let algorithm: string = (totpUrl.searchParams.get('algorithm') || '').trim();
    if (!algorithm)
        algorithm = 'SHA1'; // default algorithm

    const strDigits: string = (totpUrl.searchParams.get('digits') || '').trim();
    let digits: number = ((isNaN(+strDigits) || !Boolean(strDigits)) ? 6 : parseInt(strDigits));
    digits = digits == 0 ? 6 : digits;

    const strPeriod: string = (totpUrl.searchParams.get('period') || '').trim();
    let period: number = ((isNaN(+strPeriod) || !Boolean(strPeriod)) ? 30 : parseInt(strPeriod));
    period = period == 0 ? 30 : period;

    const tmBase: number = unixTimeSeconds != 0 ? unixTimeSeconds : Math.floor(Date.now() / 1000);
    const tm: bigint = BigInt(Math.floor(tmBase / period));

    const buffer = new ArrayBuffer(8)
    new DataView(buffer).setBigInt64(0, tm);
    const msg = new Uint8Array(buffer)

    const secretBytes = b32encode(secret.toUpperCase());
    if (secretBytes == null || secretBytes.length < 1)
        return null;

    const digest = await platform.getHmacDigest(algorithm, secretBytes, msg);
    if (digest.length < 1)
        return null;

    const offset = digest[digest.length - 1] & 0x0f;
    const codeBytes = new Uint8Array(digest.slice(offset, offset+4));
    codeBytes[0] &= 0x7f;
    let codeInt = new DataView(codeBytes.buffer).getInt32(0);
    codeInt %= Math.floor(Math.pow(10, digits));
    codeInt = Math.floor(codeInt);
    let codeStr = codeInt.toString(10);
    while (codeStr.length < digits)
        codeStr = '0' + codeStr;

    const elapsed = Math.floor(tmBase % period); // time elapsed in current period in seconds
    const ttl = period - elapsed; // time to live in seconds
    return { code: codeStr, timeLeft: ttl, period: period };
}

// password generation
const defaultPasswordLength: number = 32
const asciiSpecialCharacters: string = '"!@#$%()+;<>=?[]{}^.,'
const asciiLowercase: string = 'abcdefghijklmnopqrstuvwxyz'
const asciiUppercase: string = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
const asciiDigits: string = '0123456789'

const shuffle = async (text: string): Promise<string> => {
    // Fisher-Yates shuffle
    let result = text
    if (result.length > 1) {
        let a = result.split('')
        for (let i = a.length - 1; i > 0; i--) {
            const j = await platform.getRandomNumber(i+1) // 0 <= j <= i
            if (i != j) {
                const tmp = a[i]
                a[i] = a[j]
                a[j] = tmp
            }
        }
        result = a.join('')
    }
   return result
}

const randomSample = async (length: number, charset: string): Promise<string> => {
    let result = ''
    length = Math.abs(length)
    for (let i = 0; i < length; i++)
        result += await platform.getRandomCharacterInCharset(charset)
    return result
}

/**
 * Generates a new password of specified minimum length
 * using provided number of uppercase, lowercase, digits and special characters.
 *
 * Note: If all character groups are unspecified or all have exact zero length
 * then password characters are chosen from all groups uniformly at random.
 *
 * Note: If all charset lengths are negative or 0 but can't reach min_length
 * then all exact/negative charset lengths will be treated as minimum number of characters instead.
 *
 * @param {number} minLength - Minimum password length - default: 32
 * @param {number|null} lowercase - Minimum number of lowercase characters if positive, exact if 0 or negative
 * @param {number|null} uppercase - Minimum number of uppercase characters if positive, exact if 0 or negative
 * @param {number|null} digits - Minimum number of digits if positive, exact if 0 or negative
 * @param {number|null} specialCharacters - Minimum number of special characters if positive, exact if 0 or negative
 * @param {number} specialCharacterSet - String containing custom set of special characters to pick from
 * @returns {string} Generated password string
 */
export const generatePassword = async (
        minLength: number = defaultPasswordLength,
        lowercase: number | null = null,
        uppercase: number | null = null,
        digits: number | null = null,
        specialCharacters: number | null = null,
        specialCharacterSet: string = asciiSpecialCharacters) : Promise<string> => {

    const counts: (number | null)[] = [lowercase, uppercase, digits, specialCharacters]
    const sumCategories: number = counts.reduce((sum, x) => sum!! + Math.abs(x ?? 0), 0) ?? 0

    // If all lengths are exact/negative but don't reach minLength - convert to minimum/positive lengths
    const numExactCounts: number = counts.reduce((sum, x) => sum!! + (((x ?? 1) <= 0) ? 1 : 0), 0) ?? 0
    if (counts.length == numExactCounts && sumCategories < minLength) {
        if ((lowercase ?? 0) < 0) lowercase = Math.abs(lowercase ?? 0)
        if ((uppercase ?? 0) < 0) uppercase = Math.abs(uppercase ?? 0)
        if ((digits ?? 0) < 0) digits = Math.abs(digits ?? 0)
        if ((specialCharacters ?? 0) < 0) specialCharacters = Math.abs(specialCharacters ?? 0)
    }
    let extraChars: string  = ''
    let extraCount: number = 0
    if (minLength > sumCategories)
        extraCount = minLength - sumCategories;
    if ((lowercase ?? 1) > 0)
        extraChars += asciiLowercase;
    if ((uppercase ?? 1) > 0)
        extraChars += asciiUppercase;
    if ((digits ?? 1) > 0)
        extraChars += asciiDigits;
    if ((specialCharacters ?? 1) > 0)
        extraChars += specialCharacterSet;
    if (extraCount > 0 && !extraChars)
        extraChars = asciiLowercase + asciiUppercase + asciiDigits + specialCharacterSet;

    const categoryMap: { count: number; chars: string }[] = [
        { count: Math.abs(lowercase ?? 0), chars: asciiLowercase },
        { count: Math.abs(uppercase ?? 0), chars: asciiUppercase },
        { count: Math.abs(digits ?? 0), chars: asciiDigits },
        { count: Math.abs(specialCharacters ?? 0), chars: specialCharacterSet },
        { count: extraCount, chars: extraChars }
    ]

    let passwordCharacters: string = ''
    for (let i = 0; i < categoryMap.length; i++)
        if (categoryMap[i].count > 0)
            passwordCharacters += await randomSample(categoryMap[i].count, categoryMap[i].chars)

    const password: string = await shuffle(passwordCharacters)
    return password
}

/**
 * Try to parse an integer value from a string. Returns the number if successful, otherwise return a default value.
 * @param value The string with an integer to parse.
 * @param defaultValue Default value to return if parsing fails.
 */
export function tryParseInt(value: string, defaultValue: number = 0): number {
    let parsedValue = parseInt(value, 10)
    if (isNaN(parsedValue))
		return defaultValue // Failed to parse. Return the default value.
	else
		return parsedValue // Return the parsed value.
}
