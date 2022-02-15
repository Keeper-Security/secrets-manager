package com.keepersecurity.secretsManager.core

import org.bouncycastle.asn1.x9.ECNamedCurveTable
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider
//import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.math.BigInteger
import java.security.Provider

class TestCryptoProvider : CryptoProvider {

    private val p = BouncyCastleFipsProvider()
//    val p = BouncyCastleProvider()

    override val provider: Provider
        get() = p

    override fun multiplyG(s: BigInteger): ByteArray {
        return ECNamedCurveTable.getByName("secp256r1").g.multiply(s).getEncoded(false)
    }
}