@file:Suppress("unused")

package com.keepersecurity.secretsManager.core

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class KeeperRecordData(
    val title: String,
    val type: String,
    val fields: List<KeeperRecordField>,
    val custom: List<KeeperRecordField>,
    val notes: String? = null
) {
    inline fun <reified T> getField(): T? {
        return try {
            fields.first { x -> x is T } as T
        } catch (e: Exception) {
            null
        }
    }

    inline fun <reified T> getCustomField(): T? {
        return try {
            custom.first { x -> x is T } as T
        } catch (e: Exception) {
            null
        }
    }

    fun getField(clazz: Class<out KeeperRecordField>): Any? {
        return try {
            fields.first { x -> x.javaClass == clazz }
        } catch (e: Exception) {
            null
        }
    }

    fun getCustomField(clazz: Class<out KeeperRecordField>): Any? {
        return try {
            custom.first { x -> x.javaClass == clazz }
        } catch (e: Exception) {
            null
        }
    }
}

@Serializable
sealed class KeeperRecordField

@Serializable
@SerialName("login")
data class Login(var label: String? = null, var required: Boolean? = null, var privacyScreen: Boolean? = null, val value: MutableList<String>) : KeeperRecordField()

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
) : KeeperRecordField()

@Serializable
@SerialName("url")
data class Url(var label: String? = null, var required: Boolean? = null, var privacyScreen: Boolean? = null, val value: MutableList<String>) : KeeperRecordField()

@Serializable
@SerialName("fileRef")
data class FileRef(var label: String? = null, var required: Boolean? = null, val value: MutableList<String>) : KeeperRecordField()

@Serializable
@SerialName("oneTimeCode")
data class OneTimeCode(var label: String? = null, var required: Boolean? = null, val value: MutableList<String>) : KeeperRecordField()

@Serializable
@SerialName("otp")
data class OneTimePassword(var label: String? = null, var required: Boolean? = null, val value: MutableList<String>) : KeeperRecordField()

@Serializable
data class Name(var first: String? = null, var middle: String? = null, var last: String? = null)

@Serializable
@SerialName("name")
data class Names(val label: String? = null, var required: Boolean? = null, var privacyScreen: Boolean? = null, val value: MutableList<Name>) : KeeperRecordField()

@Serializable
@SerialName("birthDate")
data class BirthDate(var label: String? = null, var required: Boolean? = null, var privacyScreen: Boolean? = null, val value: MutableList<Long>) : KeeperRecordField()

@Serializable
@SerialName("date")
data class Date(var label: String? = null, var required: Boolean? = null, var privacyScreen: Boolean? = null, val value: MutableList<Long>) : KeeperRecordField()

@Serializable
@SerialName("expirationDate")
data class ExpirationDate(var label: String? = null, var required: Boolean? = null, var privacyScreen: Boolean? = null, val value: MutableList<Long>) : KeeperRecordField()

@Serializable
@SerialName("text")
data class Text(var label: String? = null, var required: Boolean? = null, var privacyScreen: Boolean? = null, var value: MutableList<String>) : KeeperRecordField()

@Serializable
data class SecurityQuestion(var question: String? = null, var answer: String? = null)

@Serializable
@SerialName("securityQuestion")
data class SecurityQuestions(var label: String? = null, var required: Boolean? = null, var privacyScreen: Boolean? = null, val value: MutableList<SecurityQuestion>) :
    KeeperRecordField()

@Serializable
@SerialName("multiline")
data class Multiline(var label: String? = null, var required: Boolean? = null, var privacyScreen: Boolean? = null, val value: MutableList<String>) : KeeperRecordField()

@Serializable
@SerialName("email")
data class Email(var label: String? = null, var required: Boolean? = null, var privacyScreen: Boolean? = null, val value: MutableList<String>) : KeeperRecordField()

@Serializable
@SerialName("cardRef")
data class CardRef(var label: String? = null, var required: Boolean? = null, var privacyScreen: Boolean? = null, val value: MutableList<String>) : KeeperRecordField()

@Serializable
@SerialName("addressRef")
data class AddressRef(var label: String? = null, var required: Boolean? = null, var privacyScreen: Boolean? = null, val value: MutableList<String>) : KeeperRecordField()

@Serializable
@SerialName("pinCode")
data class PinCode(var label: String? = null, var required: Boolean? = null, val value: MutableList<String>) : KeeperRecordField()

@Serializable
data class Phone(
    val region: String? = null,
    val number: String? = null,
    val ext: String? = null,
    val type: String? = null
)

@Serializable
@SerialName("phone")
data class Phones(val label: String? = null, var required: Boolean? = null, var privacyScreen: Boolean? = null, val value: List<Phone>) : KeeperRecordField()

@Serializable
@SerialName("secret")
data class HiddenField(val label: String? = null, var required: Boolean? = null, val value: List<String>) : KeeperRecordField()

@Serializable
@SerialName("note")
data class SecureNote(val label: String? = null, var required: Boolean? = null, var privacyScreen: Boolean? = null, val value: List<String>) : KeeperRecordField()

@Serializable
@SerialName("accountNumber")
data class AccountNumber(val label: String? = null, var required: Boolean? = null, var privacyScreen: Boolean? = null, val value: List<String>) : KeeperRecordField()

@Serializable
data class PaymentCard(
    var cardNumber: String? = null,
    var cardExpirationDate: String? = null,
    var cardSecurityCode: String? = null
)

@Serializable
@SerialName("paymentCard")
data class PaymentCards(val label: String? = null, var required: Boolean? = null, var privacyScreen: Boolean? = null, val value: MutableList<PaymentCard>) : KeeperRecordField()

@Serializable
data class BankAccount(
    var accountType: String? = null,
    var routingNumber: String? = null,
    var accountNumber: String? = null,
    var otherType: String? = null
)

@Serializable
@SerialName("bankAccount")
data class BankAccounts(val label: String? = null, var required: Boolean? = null, var privacyScreen: Boolean? = null, val value: MutableList<BankAccount>) : KeeperRecordField()

@Serializable
data class KeyPair(
    val publicKey: String? = null,
    val privateKey: String? = null,
)

@Serializable
@SerialName("keyPair")
data class KeyPairs(val label: String? = null, var required: Boolean? = null, var privacyScreen: Boolean? = null, val value: MutableList<KeyPair>) : KeeperRecordField()

@Serializable
data class Host(
    val hostName: String? = null,
    val port: String? = null,
)

@Serializable
@SerialName("host")
data class Hosts(val label: String? = null, var required: Boolean? = null, var privacyScreen: Boolean? = null, val value: MutableList<Host>) : KeeperRecordField()

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
data class Addresses(val label: String? = null, var required: Boolean? = null, var privacyScreen: Boolean? = null, val value: MutableList<Address>) : KeeperRecordField()

@Serializable
data class KeeperFileData(
    val title: String,
    val name: String,
    val type: String,
    val size: Long,
    val lastModified: Long
)