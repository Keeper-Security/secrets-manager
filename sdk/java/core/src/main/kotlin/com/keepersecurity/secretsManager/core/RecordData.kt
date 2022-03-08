@file:Suppress("unused")

package com.keepersecurity.secretsManager.core

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class KeeperRecordData @JvmOverloads constructor(
    var title: String,
    val type: String,
    val fields: MutableList<KeeperRecordField>,
    val custom: MutableList<KeeperRecordField>? = null,
    var notes: String? = null
) {
    inline fun <reified T> getField(): T? {
        return (fields + custom).find { x -> x is T } as T
    }

    fun getField(clazz: Class<out KeeperRecordField>): KeeperRecordField? {
        return (fields + (custom ?: listOf())).find { x -> x.javaClass == clazz }
    }
}

@Serializable
sealed class KeeperRecordField {
    abstract val label: String?
}

@Serializable
@SerialName("login")
data class Login @JvmOverloads constructor(
    override var label: String? = null,
    var required: Boolean? = null,
    var privacyScreen: Boolean? = null,
    val value: MutableList<String>
) : KeeperRecordField(){

    /**
     * Constructor with the single value to eliminate the complexity of the passing List as a value
     */
    constructor(value: String): this(null, null, null, mutableListOf(value))
}

@Serializable
data class PasswordComplexity(
    var length: Int? = null,
    var caps: Int? = null,
    var lowercase: Int? = null,
    var digits: Int? = null,
    var special: Int? = null
)

@Serializable
@SerialName("password")
data class Password @JvmOverloads constructor(
    override var label: String? = null,
    var required: Boolean? = null,
    var privacyScreen: Boolean? = null,
    var enforceGeneration: Boolean? = null,
    var complexity: PasswordComplexity? = null,
    val value: MutableList<String>
) : KeeperRecordField(){

    /**
     * Constructor with the single value to eliminate the complexity of the passing List as a value
     */
    constructor(value: String): this(null, null, null, null, null, mutableListOf(value))
}

@Serializable
@SerialName("url")
data class Url @JvmOverloads constructor(
    override var label: String? = null,
    var required: Boolean? = null,
    var privacyScreen: Boolean? = null,
    val value: MutableList<String>) : KeeperRecordField(){
    /**
     * Constructor with the single value to eliminate the complexity of the passing List as a value
     */
    constructor(value: String): this(null, null, null, mutableListOf(value))
}

@Serializable
@SerialName("fileRef")
data class FileRef @JvmOverloads constructor(
    override var label: String? = null,
    var required: Boolean? = null,
    val value: MutableList<String>) : KeeperRecordField(){

    /**
     * Constructor with the single value to eliminate the complexity of the passing List as a value
     */
    constructor(value: String): this(null, null, mutableListOf(value))
}

@Serializable
@SerialName("oneTimeCode")
data class OneTimeCode @JvmOverloads constructor(
    override var label: String? = null,
    var required: Boolean? = null,
    var privacyScreen: Boolean? = null,
    val value: MutableList<String>) : KeeperRecordField(){

    /**
     * Constructor with the single value to eliminate the complexity of the passing List as a value
     * @param value TOTP URL. Ex. otpauth://totp/asdfsadf:asdf@asdf.com?secret=2355666655444334&issuer=asdfsadf&algorithm=SHA256&digits=6&period=30
     */
    constructor(value: String): this(null, null, null, mutableListOf(value))
}

@Serializable
@SerialName("otp")
data class OneTimePassword @JvmOverloads constructor(
    override var label: String? = null,
    var required: Boolean? = null,
    var privacyScreen: Boolean? = null,
    val value: MutableList<String>) : KeeperRecordField(){

    /**
     * Constructor with the single value to eliminate the complexity of the passing List as a value
     */
    constructor(value: String): this(null, null, null, mutableListOf(value))
}

@Serializable
data class Name @JvmOverloads constructor( var first: String? = null, var middle: String? = null, var last: String? = null)

@Serializable
@SerialName("name")
data class Names @JvmOverloads constructor(
    override val label: String? = null,
    var required: Boolean? = null,
    var privacyScreen: Boolean? = null,
    val value: MutableList<Name>) : KeeperRecordField(){

    /**
     * Constructor with the single value to eliminate the complexity of the passing List as a value
     */
    constructor(value: Name): this(null, null, null, mutableListOf(value))
}

@Serializable
@SerialName("birthDate")
data class BirthDate @JvmOverloads constructor(
    override var label: String? = null,
    var required: Boolean? = null,
    var privacyScreen: Boolean? = null,
    val value: MutableList<Long>) : KeeperRecordField(){

    /**
     * Constructor with the single value to eliminate the complexity of the passing List as a value
     */
    constructor(value: Long): this(null, null, null, mutableListOf(value))
}

@Serializable
@SerialName("date")
data class Date @JvmOverloads constructor(
    override var label: String? = null,
    var required: Boolean? = null,
    var privacyScreen: Boolean? = null,
    val value: MutableList<Long>) : KeeperRecordField(){

    /**
     * Constructor with the single value to eliminate the complexity of the passing List as a value
     */
    constructor(value: Long): this(null, null, null, mutableListOf(value))
}

@Serializable
@SerialName("expirationDate")
data class ExpirationDate @JvmOverloads constructor(
    override var label: String? = null,
    var required: Boolean? = null,
    var privacyScreen: Boolean? = null,
    val value: MutableList<Long>) : KeeperRecordField(){

    /**
     * Constructor with the single value to eliminate the complexity of the passing List as a value
     */
    constructor(value: Long): this(null, null, null, mutableListOf(value))
}

@Serializable
@SerialName("text")
data class Text @JvmOverloads constructor(
    override var label: String? = null,
    var required: Boolean? = null,
    var privacyScreen: Boolean? = null,
    var value: MutableList<String>) : KeeperRecordField(){

    /**
     * Constructor with the single value to eliminate the complexity of the passing List as a value
     */
    constructor(value: String): this(null, null, null, mutableListOf(value))
}

@Serializable
data class SecurityQuestion @JvmOverloads constructor( var question: String? = null, var answer: String? = null)

@Serializable
@SerialName("securityQuestion")
data class SecurityQuestions @JvmOverloads constructor(
    override var label: String? = null,
    var required: Boolean? = null,
    var privacyScreen: Boolean? = null,
    val value: MutableList<SecurityQuestion>
) : KeeperRecordField(){

    /**
     * Constructor with the single value to eliminate the complexity of the passing List as a value
     */
    constructor(value: SecurityQuestion): this(null, null, null, mutableListOf(value))
}

@Serializable
@SerialName("multiline")
data class Multiline @JvmOverloads constructor(
    override var label: String? = null,
    var required: Boolean? = null,
    var privacyScreen: Boolean? = null,
    val value: MutableList<String>) : KeeperRecordField(){

    /**
     * Constructor with the single value to eliminate the complexity of the passing List as a value
     */
    constructor(value: String): this(null, null, null, mutableListOf(value))
}

@Serializable
@SerialName("email")
data class Email @JvmOverloads constructor(
    override var label: String? = null,
    var required: Boolean? = null,
    var privacyScreen: Boolean? = null,
    val value: MutableList<String>) : KeeperRecordField(){

    /**
     * Constructor with the single value to eliminate the complexity of the passing List as a value
     */
    constructor(value: String): this(null, null, null, mutableListOf(value))
}

@Serializable
@SerialName("cardRef")
data class CardRef @JvmOverloads constructor(
    override var label: String? = null,
    var required: Boolean? = null,
    var privacyScreen: Boolean? = null,
    val value: MutableList<String>) : KeeperRecordField(){

    /**
     * Constructor with the single value to eliminate the complexity of the passing List as a value
     */
    constructor(value: String): this(null, null, null, mutableListOf(value))
}

@Serializable
@SerialName("addressRef")
data class AddressRef @JvmOverloads constructor(
    override var label: String? = null,
    var required: Boolean? = null,
    var privacyScreen: Boolean? = null,
    val value: MutableList<String>) : KeeperRecordField(){

    /**
     * Constructor with the single value to eliminate the complexity of the passing List as a value
     */
    constructor(value: String): this(null, null, null, mutableListOf(value))
}

@Serializable
@SerialName("pinCode")
data class PinCode @JvmOverloads constructor(
    override var label: String? = null,
    var required: Boolean? = null,
    var privacyScreen: Boolean? = null,
    val value: MutableList<String>) : KeeperRecordField(){

    /**
     * Constructor with the single value to eliminate the complexity of the passing List as a value
     */
    constructor(value: String): this(null, null, null, mutableListOf(value))
}

@Serializable
data class Phone @JvmOverloads constructor(

    /**
     * Region code. Ex. US
     */
    val region: String? = null,

    /**
     * Phone number. Ex. 510-222-5555
     */
    val number: String? = null,

    /**
     * Extension number. Ex. 9987
     */
    val ext: String? = null,

    /**
     * Phone number type. Ex. Mobile
     */
    val type: String? = null
)

@Serializable
@SerialName("phone")
data class Phones @JvmOverloads constructor(
    override val label: String? = null,
    var required: Boolean? = null,
    var privacyScreen: Boolean? = null,
    val value: List<Phone>) : KeeperRecordField(){

    /**
     * Constructor with the single value to eliminate the complexity of the passing List as a value
     */
    constructor(value: Phone): this(null, null, null, mutableListOf(value))
}

@Serializable
@SerialName("secret")
data class HiddenField @JvmOverloads constructor(
    override val label: String? = null,
    var required: Boolean? = null,
    var privacyScreen: Boolean? = null,
    val value: List<String>) : KeeperRecordField(){

    /**
     * Constructor with the single value to eliminate the complexity of the passing List as a value
     */
    constructor(value: String): this(null, null, null, mutableListOf(value))
}

@Serializable
@SerialName("note")
data class SecureNote @JvmOverloads constructor(
    override val label: String? = null,
    var required: Boolean? = null,
    var privacyScreen: Boolean? = null,
    val value: List<String>) : KeeperRecordField(){

    /**
     * Constructor with the single value to eliminate the complexity of the passing List as a value
     */
    constructor(value: String): this(null, null, null, mutableListOf(value))
}

@Serializable
@SerialName("accountNumber")
data class AccountNumber @JvmOverloads constructor(
    override val label: String? = null,
    var required: Boolean? = null,
    var privacyScreen: Boolean? = null,
    val value: List<String>) : KeeperRecordField(){

    /**
     * Constructor with the single value to eliminate the complexity of the passing List as a value
     */
    constructor(value: String): this(null, null, null, mutableListOf(value))
}

@Serializable
data class PaymentCard @JvmOverloads constructor(
    var cardNumber: String? = null,
    var cardExpirationDate: String? = null,
    var cardSecurityCode: String? = null
)

@Serializable
@SerialName("paymentCard")
data class PaymentCards @JvmOverloads constructor(
    override val label: String? = null,
    var required: Boolean? = null,
    var privacyScreen: Boolean? = null,
    val value: MutableList<PaymentCard>) : KeeperRecordField(){

    /**
     * Constructor with the single value to eliminate the complexity of the passing List as a value
     */
    constructor(value: PaymentCard): this(null, null, null, mutableListOf(value))
}

@Serializable
data class BankAccount @JvmOverloads constructor(
    var accountType: String? = null,
    var routingNumber: String? = null,
    var accountNumber: String? = null,
    var otherType: String? = null
)

@Serializable
@SerialName("bankAccount")
data class BankAccounts @JvmOverloads constructor(
    override val label: String? = null,
    var required: Boolean? = null,
    var privacyScreen: Boolean? = null,
    val value: MutableList<BankAccount>) : KeeperRecordField() {

    /**
     * Constructor with the single value to eliminate the complexity of the passing List as a value
     */
    constructor(value: BankAccount): this(null, null, null, mutableListOf(value))
}

@Serializable
data class KeyPair @JvmOverloads constructor(
    val publicKey: String? = null,
    val privateKey: String? = null,
)

@Serializable
@SerialName("keyPair")
data class KeyPairs @JvmOverloads constructor(
    override val label: String? = null,
    var required: Boolean? = null,
    var privacyScreen: Boolean? = null,
    val value: MutableList<KeyPair>) : KeeperRecordField() {

    /**
     * Constructor with the single value to eliminate the complexity of the passing List as a value
     */
    constructor(value: KeyPair): this(null, null, null, mutableListOf(value))
}

@Serializable
data class Host @JvmOverloads constructor(
    val hostName: String? = null,
    val port: String? = null,
)

@Serializable
@SerialName("host")
data class Hosts @JvmOverloads constructor(
    override val label: String? = null,
    var required: Boolean? = null,
    var privacyScreen: Boolean? = null,
    val value: MutableList<Host>) : KeeperRecordField() {

    /**
     * Constructor with the single value to eliminate the complexity of the passing List as a value
     */
    constructor(value: Host): this(null, null, null, mutableListOf(value))
}

@Serializable
data class Address @JvmOverloads constructor(
    val street1: String? = null,
    val street2: String? = null,
    val city: String? = null,
    val state: String? = null,
    val country: String? = null,
    val zip: String? = null
)

@Serializable
@SerialName("address")
data class Addresses @JvmOverloads constructor(
    override val label: String? = null,
    var required: Boolean? = null,
    var privacyScreen: Boolean? = null,
    val value: MutableList<Address>) : KeeperRecordField() {

    /**
     * Constructor with the single value to eliminate the complexity of the passing List as a value
     */
    constructor(value: Address): this(null, null, null, mutableListOf(value))
}

@Serializable
@SerialName("licenseNumber")
data class LicenseNumber @JvmOverloads constructor(
    override val label: String? = null,
    var required: Boolean? = null,
    var privacyScreen: Boolean? = null,
    val value: MutableList<String>) : KeeperRecordField() {

    /**
     * Constructor with the single value to eliminate the complexity of the passing List as a value
     */
    constructor(value: String): this(null, null, null, mutableListOf(value))
}

@Serializable
data class KeeperFileData(
    val title: String,
    val name: String,
    val type: String?,
    val size: Long,
    val lastModified: Long
)