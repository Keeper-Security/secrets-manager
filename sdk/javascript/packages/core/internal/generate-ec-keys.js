const { generateKeyPairSync } = require("crypto");

const webSafe64 = (source) => source.toString("base64").replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

for (let i = 0; i < 10; i++) {
    const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
    const privateKeyDer = pair.privateKey.export({ format: 'der', type: 'pkcs8' })
    const privateRaw = privateKeyDer.slice(36, 68)
    const publicRaw = privateKeyDer.slice(73)
    console.log(`priv${i}: ${webSafe64(privateRaw)} pub${i}: ${webSafe64(publicRaw)}`)
}
