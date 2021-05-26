import {generateTransmissionKey} from '../'

test('Transmission keys generated properly', async () => {
    for (let keyNumber of [1,2,3,4,5,6]) {
        const key = await generateTransmissionKey(keyNumber)
        expect(key.publicKeyId).toBe(keyNumber);
        expect(key.encryptedKey.length).toBe(125)
    }
})
