import {createECDH, createSign, createVerify, generateKeyPairSync} from 'crypto';

function testSig() {
    // const privateKey1 = ecdh.getPrivateKey()

    const { privateKey, publicKey } = generateKeyPairSync('ec', {
        namedCurve: 'prime256v1'
    });
    const pke = privateKey.export({
        format: 'der',
        type: 'pkcs8'
    })
    console.log(pke.toString('hex'))
    const pke1 = privateKey.export({
        format: 'der',
        type: 'sec1'
    })
    console.log(pke1.toString('hex'))
    const privateRaw = pke.slice(36, 68)
    const publicRaw = pke.slice(73)
    console.log(privateRaw.toString('hex'))
    console.log(publicRaw.toString('hex'))
    console.log(publicRaw.length)

    const ecdh = createECDH('prime256v1')
    ecdh.generateKeys()
    const ephemeralPublicKey = ecdh.getPublicKey()
    const sharedSecret = ecdh.computeSecret(publicRaw)
    console.log(sharedSecret.toString('hex'))

    const data = new Buffer('hello')

    const sign = createSign('SHA256')
    sign.update(data)
    const sig = sign.sign(privateKey)

    console.log(sig)
}

testSig()
