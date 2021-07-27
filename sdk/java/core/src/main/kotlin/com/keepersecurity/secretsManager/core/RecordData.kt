@file:Suppress("unused")

package com.keepersecurity.secretsManager.core

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class KeeperRecordData(
    val title: String,
    val type: String,
    val fields: List<Field>,
    val custom: List<Field>,
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

    fun getField(clazz: Class<*>): Any? {
        return try {
            fields.first { x -> x.javaClass == clazz }
        } catch (e: Exception) {
            null
        }
    }

    fun getCustomField(clazz: Class<*>): Any? {
        return try {
            custom.first { x -> x.javaClass == clazz }
        } catch (e: Exception) {
            null
        }
    }
}

@Serializable
sealed class Field

@Serializable
@SerialName("login")
data class Login(val value: MutableList<String>) : Field()

@Serializable
@SerialName("password")
data class Password(val value: MutableList<String>) : Field()

@Serializable
@SerialName("url")
data class Url(var label: String? = null, val value: MutableList<String>) : Field()

@Serializable
@SerialName("fileRef")
data class FileRef(val value: MutableList<String>) : Field()

@Serializable
@SerialName("oneTimeCode")
data class OneTimeCode(val value: MutableList<String>) : Field()

@Serializable
data class Name(var first: String? = null, var middle: String? = null, var last: String? = null)

@Serializable
@SerialName("name")
data class Names(val label: String? = null, val value: MutableList<Name>) : Field()

@Serializable
@SerialName("birthDate")
data class BirthDate(val value: MutableList<Long>) : Field()

@Serializable
@SerialName("date")
data class Date(var label: String? = null, val value: MutableList<Long>) : Field()

@Serializable
@SerialName("text")
data class Text(var label: String? = null, var value: MutableList<String>) : Field()

@Serializable
data class SecurityQuestion(var question: String? = null, var answer: String? = null)

@Serializable
@SerialName("securityQuestion")
data class SecurityQuestions(var label: String? = null, val value: MutableList<SecurityQuestion>) : Field()

@Serializable
@SerialName("multiline")
data class Multiline(var label: String? = null, val value: MutableList<String>) : Field()

@Serializable
@SerialName("email")
data class Email(var label: String? = null, val value: MutableList<String>) : Field()

@Serializable
@SerialName("cardRef")
data class CardRef(var label: String? = null, val value: MutableList<String>) : Field()

@Serializable
@SerialName("addressRef")
data class AddressRef(var label: String? = null, val value: MutableList<String>) : Field()

@Serializable
@SerialName("pinCode")
data class PinCode(var label: String? = null, val value: MutableList<String>) : Field()

@Serializable
data class Phone(
    val region: String? = null,
    val number: String? = null,
    val ext: String? = null,
    val type: String? = null
)

@Serializable
@SerialName("phone")
data class Phones(val label: String? = null, val value: List<Phone>) : Field()

@Serializable
@SerialName("secret")
data class HiddenField(val label: String? = null, val value: List<String>) : Field()