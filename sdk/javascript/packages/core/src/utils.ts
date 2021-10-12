import {platform} from './platform'

export const webSafe64 = (source: string): string => source.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

export const webSafe64ToRegular = (source: string): string => source.replace(/-/g, '+').replace(/_/g, '/') + '=='.substring(0, (3 * source.length) % 4);

export const webSafe64ToBytes = (source: string): Uint8Array => platform.base64ToBytes(webSafe64ToRegular(source));

export const webSafe64FromBytes = (source: Uint8Array): string => webSafe64(platform.bytesToBase64(source));

// extracts public raw from private key for prime256v1 curve in der/pkcs8
// privateKey: key.slice(36, 68)
export const privateDerToPublicRaw = (key: Uint8Array): Uint8Array => key.slice(-65)

const b32encode = (base32Text: string): Uint8Array => {
    /* encodes a string s to base32 and returns the encoded string */
    const alphabet: string = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    // private static readonly Regex rxBase32Alphabet = new Regex($"", RegexOptions.Compiled);

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

export const getTotpCode = async (url: string, unixTimeSeconds: number = 0) : Promise<[string, number, number] | null>  => {
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
    let digits: number = (isNaN(+strDigits) ? 6 : parseInt(strDigits));
    digits = digits == 0 ? 6 : digits;

    const strPeriod: string = (totpUrl.searchParams.get('period') || '').trim();
    let period: number = (isNaN(+strPeriod) ? 30 : parseInt(strPeriod));
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
        codeStr = "0" + codeStr;

    return [codeStr, Math.floor(tmBase % period), period];
}
