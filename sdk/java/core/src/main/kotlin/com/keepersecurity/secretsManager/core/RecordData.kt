@file:Suppress("unused")

package com.keepersecurity.secretsManager.core

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class KeeperRecordData(
    val title: String,
    val type: String,
    val fields: List<KeeperRecordField>,
    val custom: List<KeeperRecordField>? = null,
    val notes: String? = null
) {
    inline fun <reified T> getField(): T? {
        return (fields + custom).find { x -> x is T } as T
    }

    fun getField(clazz: Class<out KeeperRecordField>): KeeperRecordField? {
        return (fields + (custom ?: listOf())).find { x -> x.javaClass == clazz }
    }
}

@Serializable
sealed class KeeperRecordField(val lbl: String? = null)

@Serializable
@SerialName("login")
data class Login(var label: String? = null, var required: Boolean? = null, var privacyScreen: Boolean? = null, val value: MutableList<String>) : KeeperRecordField(label)

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
    var label: String? = null,
    var required: Boolean? = null,
    var privacyScreen: Boolean? = null,
    var enforceGeneration: Boolean? = null,
    var complexity: PasswordComplexity? = null,
    val value: MutableList<String>
) : KeeperRecordField(label)

@Serializable
@SerialName("url")
data class Url(var label: String? = null, var required: Boolean? = null, var privacyScreen: Boolean? = null, val value: MutableList<String>) : KeeperRecordField(label)

@Serializable
@SerialName("fileRef")
data class FileRef(var label: String? = null, var required: Boolean? = null, val value: MutableList<String>) : KeeperRecordField(label)

@Serializable
@SerialName("oneTimeCode")
data class OneTimeCode(var label: String? = null, var required: Boolean? = null, val value: MutableList<String>) : KeeperRecordField(label)

@Serializable
@SerialName("otp")
data class OneTimePassword(var label: String? = null, var required: Boolean? = null, val value: MutableList<String>) : KeeperRecordField(label)

@Serializable
data class Name(var first: String? = null, var middle: String? = null, var last: String? = null)

@Serializable
@SerialName("name")
data class Names(val label: String? = null, var required: Boolean? = null, var privacyScreen: Boolean? = null, val value: MutableList<Name>) : KeeperRecordField(label)

@Serializable
@SerialName("birthDate")
data class BirthDate(var label: String? = null, var required: Boolean? = null, var privacyScreen: Boolean? = null, val value: MutableList<Long>) : KeeperRecordField(label)

@Serializable
@SerialName("date")
data class Date(var label: String? = null, var required: Boolean? = null, var privacyScreen: Boolean? = null, val value: MutableList<Long>) : KeeperRecordField(label)

@Serializable
@SerialName("expirationDate")
data class ExpirationDate(var label: String? = null, var required: Boolean? = null, var privacyScreen: Boolean? = null, val value: MutableList<Long>) : KeeperRecordField(label)

@Serializable
@SerialName("text")
data class Text(var label: String? = null, var required: Boolean? = null, var privacyScreen: Boolean? = null, var value: MutableList<String>) : KeeperRecordField(label)

@Serializable
data class SecurityQuestion(var question: String? = null, var answer: String? = null)

@Serializable
@SerialName("securityQuestion")
data class SecurityQuestions(
    var label: String? = null,
    var required: Boolean? = null,
    var privacyScreen: Boolean? = null,
    val value: MutableList<SecurityQuestion>
) : KeeperRecordField(label)

@Serializable
@SerialName("multiline")
data class Multiline(var label: String? = null, var required: Boolean? = null, var privacyScreen: Boolean? = null, val value: MutableList<String>) : KeeperRecordField(label)

@Serializable
@SerialName("email")
data class Email(var label: String? = null, var required: Boolean? = null, var privacyScreen: Boolean? = null, val value: MutableList<String>) : KeeperRecordField(label)

@Serializable
@SerialName("cardRef")
data class CardRef(var label: String? = null, var required: Boolean? = null, var privacyScreen: Boolean? = null, val value: MutableList<String>) : KeeperRecordField(label)

@Serializable
@SerialName("addressRef")
data class AddressRef(var label: String? = null, var required: Boolean? = null, var privacyScreen: Boolean? = null, val value: MutableList<String>) : KeeperRecordField(label)

@Serializable
@SerialName("pinCode")
data class PinCode(var label: String? = null, var required: Boolean? = null, val value: MutableList<String>) : KeeperRecordField(label)

@Serializable
data class Phone(
    val region: String? = null,
    val number: String? = null,
    val ext: String? = null,
    val type: String? = null
)

@Serializable
@SerialName("phone")
data class Phones(val label: String? = null, var required: Boolean? = null, var privacyScreen: Boolean? = null, val value: List<Phone>) : KeeperRecordField(label)

@Serializable
@SerialName("secret")
data class HiddenField(val label: String? = null, var required: Boolean? = null, val value: List<String>) : KeeperRecordField(label)

@Serializable
@SerialName("note")
data class SecureNote(val label: String? = null, var required: Boolean? = null, var privacyScreen: Boolean? = null, val value: List<String>) : KeeperRecordField(label)

@Serializable
@SerialName("accountNumber")
data class AccountNumber(val label: String? = null, var required: Boolean? = null, var privacyScreen: Boolean? = null, val value: List<String>) : KeeperRecordField(label)

@Serializable
data class PaymentCard(
    var cardNumber: String? = null,
    var cardExpirationDate: String? = null,
    var cardSecurityCode: String? = null
)

@Serializable
@SerialName("paymentCard")
data class PaymentCards(val label: String? = null, var required: Boolean? = null, var privacyScreen: Boolean? = null, val value: MutableList<PaymentCard>) :
    KeeperRecordField(label)

@Serializable
data class BankAccount(
    var accountType: String? = null,
    var routingNumber: String? = null,
    var accountNumber: String? = null,
    var otherType: String? = null
)

@Serializable
@SerialName("bankAccount")
data class BankAccounts(val label: String? = null, var required: Boolean? = null, var privacyScreen: Boolean? = null, val value: MutableList<BankAccount>) :
    KeeperRecordField(label)

@Serializable
data class KeyPair(
    val publicKey: String? = null,
    val privateKey: String? = null,
)

@Serializable
@SerialName("keyPair")
data class KeyPairs(val label: String? = null, var required: Boolean? = null, var privacyScreen: Boolean? = null, val value: MutableList<KeyPair>) : KeeperRecordField(label)

@Serializable
data class Host(
    val hostName: String? = null,
    val port: String? = null,
)

@Serializable
@SerialName("host")
data class Hosts(val label: String? = null, var required: Boolean? = null, var privacyScreen: Boolean? = null, val value: MutableList<Host>) : KeeperRecordField(label)

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
data class Addresses(val label: String? = null, var required: Boolean? = null, var privacyScreen: Boolean? = null, val value: MutableList<Address>) : KeeperRecordField(label)

@Serializable
@SerialName("licenseNumber")
data class LicenseNumber(val label: String? = null, var required: Boolean? = null, var privacyScreen: Boolean? = null, val value: MutableList<String>) : KeeperRecordField(label)

@Serializable
data class KeeperFileData(
    val title: String,
    val name: String,
    val type: String,
    val size: Long,
    val lastModified: Long
)