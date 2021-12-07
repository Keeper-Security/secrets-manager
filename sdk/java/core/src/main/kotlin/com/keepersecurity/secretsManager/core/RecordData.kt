@file:Suppress("unused")

package com.keepersecurity.secretsManager.core

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class KeeperRecordData(
    var title: String,
    val type: String,
    val fields: List<KeeperRecordField>,
    val custom: List<KeeperRecordField>? = null,
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
data class Login(override var label: String? = null, var required: Boolean? = null, var privacyScreen: Boolean? = null, val value: MutableList<String>) : KeeperRecordField()

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
data class Password(
    override var label: String? = null,
    var required: Boolean? = null,
    var privacyScreen: Boolean? = null,
    var enforceGeneration: Boolean? = null,
    var complexity: PasswordComplexity? = null,
    val value: MutableList<String>
) : KeeperRecordField()

@Serializable
@SerialName("url")
data class Url(override var label: String? = null, var required: Boolean? = null, var privacyScreen: Boolean? = null, val value: MutableList<String>) : KeeperRecordField()

@Serializable
@SerialName("fileRef")
data class FileRef(override var label: String? = null, var required: Boolean? = null, val value: MutableList<String>) : KeeperRecordField()

@Serializable
@SerialName("oneTimeCode")
data class OneTimeCode(override var label: String? = null, var required: Boolean? = null, val value: MutableList<String>) : KeeperRecordField()

@Serializable
@SerialName("otp")
data class OneTimePassword(override var label: String? = null, var required: Boolean? = null, val value: MutableList<String>) : KeeperRecordField()

@Serializable
data class Name(var first: String? = null, var middle: String? = null, var last: String? = null)

@Serializable
@SerialName("name")
data class Names(override val label: String? = null, var required: Boolean? = null, var privacyScreen: Boolean? = null, val value: MutableList<Name>) : KeeperRecordField()

@Serializable
@SerialName("birthDate")
data class BirthDate(override var label: String? = null, var required: Boolean? = null, var privacyScreen: Boolean? = null, val value: MutableList<Long>) : KeeperRecordField()

@Serializable
@SerialName("date")
data class Date(override var label: String? = null, var required: Boolean? = null, var privacyScreen: Boolean? = null, val value: MutableList<Long>) : KeeperRecordField()

@Serializable
@SerialName("expirationDate")
data class ExpirationDate(override var label: String? = null, var required: Boolean? = null, var privacyScreen: Boolean? = null, val value: MutableList<Long>) : KeeperRecordField()

@Serializable
@SerialName("text")
data class Text(override var label: String? = null, var required: Boolean? = null, var privacyScreen: Boolean? = null, var value: MutableList<String>) : KeeperRecordField()

@Serializable
data class SecurityQuestion(var question: String? = null, var answer: String? = null)

@Serializable
@SerialName("securityQuestion")
data class SecurityQuestions(
    override var label: String? = null,
    var required: Boolean? = null,
    var privacyScreen: Boolean? = null,
    val value: MutableList<SecurityQuestion>
) : KeeperRecordField()

@Serializable
@SerialName("multiline")
data class Multiline(override var label: String? = null, var required: Boolean? = null, var privacyScreen: Boolean? = null, val value: MutableList<String>) : KeeperRecordField()

@Serializable
@SerialName("email")
data class Email(override var label: String? = null, var required: Boolean? = null, var privacyScreen: Boolean? = null, val value: MutableList<String>) : KeeperRecordField()

@Serializable
@SerialName("cardRef")
data class CardRef(override var label: String? = null, var required: Boolean? = null, var privacyScreen: Boolean? = null, val value: MutableList<String>) : KeeperRecordField()

@Serializable
@SerialName("addressRef")
data class AddressRef(override var label: String? = null, var required: Boolean? = null, var privacyScreen: Boolean? = null, val value: MutableList<String>) : KeeperRecordField()

@Serializable
@SerialName("pinCode")
data class PinCode(override var label: String? = null, var required: Boolean? = null, val value: MutableList<String>) : KeeperRecordField()

@Serializable
data class Phone(
    val region: String? = null,
    val number: String? = null,
    val ext: String? = null,
    val type: String? = null
)

@Serializable
@SerialName("phone")
data class Phones(override val label: String? = null, var required: Boolean? = null, var privacyScreen: Boolean? = null, val value: List<Phone>) : KeeperRecordField()

@Serializable
@SerialName("secret")
data class HiddenField(override val label: String? = null, var required: Boolean? = null, val value: List<String>) : KeeperRecordField()

@Serializable
@SerialName("note")
data class SecureNote(override val label: String? = null, var required: Boolean? = null, var privacyScreen: Boolean? = null, val value: List<String>) : KeeperRecordField()

@Serializable
@SerialName("accountNumber")
data class AccountNumber(override val label: String? = null, var required: Boolean? = null, var privacyScreen: Boolean? = null, val value: List<String>) : KeeperRecordField()

@Serializable
data class PaymentCard(
    var cardNumber: String? = null,
    var cardExpirationDate: String? = null,
    var cardSecurityCode: String? = null
)

@Serializable
@SerialName("paymentCard")
data class PaymentCards(override val label: String? = null, var required: Boolean? = null, var privacyScreen: Boolean? = null, val value: MutableList<PaymentCard>) :
    KeeperRecordField()

@Serializable
data class BankAccount(
    var accountType: String? = null,
    var routingNumber: String? = null,
    var accountNumber: String? = null,
    var otherType: String? = null
)

@Serializable
@SerialName("bankAccount")
data class BankAccounts(override val label: String? = null, var required: Boolean? = null, var privacyScreen: Boolean? = null, val value: MutableList<BankAccount>) :
    KeeperRecordField()

@Serializable
data class KeyPair(
    val publicKey: String? = null,
    val privateKey: String? = null,
)

@Serializable
@SerialName("keyPair")
data class KeyPairs(override val label: String? = null, var required: Boolean? = null, var privacyScreen: Boolean? = null, val value: MutableList<KeyPair>) : KeeperRecordField()

@Serializable
data class Host(
    val hostName: String? = null,
    val port: String? = null,
)

@Serializable
@SerialName("host")
data class Hosts(override val label: String? = null, var required: Boolean? = null, var privacyScreen: Boolean? = null, val value: MutableList<Host>) : KeeperRecordField()

@Serializable
data class Address(
    val street1: String? = null,
    val street2: String? = null,
    val city: String? = null,
    val state: String? = null,
    val country: String? = null,
    val zip: String? = null
)

@Serializable
@SerialName("address")
data class Addresses(override val label: String? = null, var required: Boolean? = null, var privacyScreen: Boolean? = null, val value: MutableList<Address>) : KeeperRecordField()

@Serializable
@SerialName("licenseNumber")
data class LicenseNumber(override val label: String? = null, var required: Boolean? = null, var privacyScreen: Boolean? = null, val value: MutableList<String>) : KeeperRecordField()

@Serializable
data class KeeperFileData(
    val title: String,
    val name: String,
    val type: String,
    val size: Long,
    val lastModified: Long
)