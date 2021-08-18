
import * as fs from 'fs';
import {nodePlatform} from '../src/node/nodePlatform'
import {privateDerToPublicRaw} from '../src/utils'

test('private key compatibility', async () => {

    // val privateKey64 = "MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQg34GXYbMpXKaHcHZW4dIMO3WYU8zTjB6t+41SRsY1rwqgCgYIKoZIzj0DAQehRANCAAQGH/4ZwpGR9B7AlMjVY7ekpjOcaD3rhuO25CmOZxI3wqRDdhXQIdDnuWvQPCZ3ymtjL3C8JrVIcloklwYI9T7+"
    // val privateKey = base64ToBytes(privateKey64)
    // val importedPrivateKey = importPrivateKey(privateKey)
    // assertEquals(privateKey64, bytesToBase64(importedPrivateKey.s.toByteArray()))
    // val exportedPublicKey = exportPublicKey(privateKey)
    // assertEquals(65, exportedPublicKey.size)
    // assertEquals("BJyaZ/P2+IoV4nNSsjW9nCj3zLYF/ZM3LJuQ8c5LVckD5L9gUVGEewsyPvkjdBQO5hMA4tz1hBbnw9Ge970xyB0=", bytesToBase64(exportedPublicKey))



    const privateKey64 = "MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQg34GXYbMpXKaHcHZW4dIMO3WYU8zTjB6t+41SRsY1rwqgCgYIKoZIzj0DAQehRANCAAQGH/4ZwpGR9B7AlMjVY7ekpjOcaD3rhuO25CmOZxI3wqRDdhXQIdDnuWvQPCZ3ymtjL3C8JrVIcloklwYI9T7+"
    const privateDer = nodePlatform.base64ToBytes(privateKey64)
    const privateKeyRaw = privateDer.slice(36, 68)
    expect(privateKeyRaw.length).toBe(32)
    expect(nodePlatform.bytesToBase64(privateKeyRaw)).toBe('34GXYbMpXKaHcHZW4dIMO3WYU8zTjB6t+41SRsY1rwo=')
    const publicKeyRaw = privateDerToPublicRaw(privateDer)
    expect(publicKeyRaw.length).toBe(65)
    expect(nodePlatform.bytesToBase64(publicKeyRaw)).toBe('BJyaZ/P2+IoV4nNSsjW9nCj3zLYF/ZM3LJuQ8c5LVckD5L9gUVGEewsyPvkjdBQO5hMA4tz1hBbnw9Ge970xyB0=')
})
