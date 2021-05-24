import {platform} from './platform'

export const webSafe64 = (source: string): string => source.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

export const webSafe64ToRegular = (source: string): string => source.replace(/-/g, '+').replace(/_/g, '/') + '=='.substring(0, (3 * source.length) % 4);

export const webSafe64ToBytes = (source: string): Uint8Array => platform.base64ToBytes(webSafe64ToRegular(source));

export const webSafe64FromBytes = (source: Uint8Array): string => webSafe64(platform.bytesToBase64(source));
