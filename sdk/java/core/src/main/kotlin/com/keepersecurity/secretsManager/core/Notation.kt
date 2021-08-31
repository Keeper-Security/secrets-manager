package com.keepersecurity.secretsManager.core

import kotlinx.serialization.SerialName
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

fun getValue(secrets: KeeperSecrets, notation: String): String {

    var query = notation
    val schemaNotation = query.split("://")
    if (schemaNotation.size > 1) {
        if (schemaNotation[0] != "keeper") {
            throw Exception("Invalid notation schema: ${schemaNotation[0]}")
        }
        query = query.slice(9 until query.length)
    }
    val queryParts = query.split('/')
    if (queryParts.size < 3) {
        throw Exception("invalid notation $notation")
    }
    val record = secrets.getRecordByUid(queryParts[0]) ?: throw Error("Record ${queryParts[0]} not found")
    val fields: List<KeeperRecordField> =
        when (queryParts[1]) {
            "field" -> record.data.fields
            "custom_field" -> record.data.custom ?: listOf()
            else -> throw Exception("Expected /field or /custom_field but found /${queryParts[1]}")
        }

    fun fieldType(field: KeeperRecordField): String {
        return (field::class.annotations.find { x -> x is SerialName } as SerialName).value
    }

    fun findField(fieldName: String): KeeperRecordField {
        return fields.find { x -> x.lbl == fieldName || fieldType(x) == fieldName }
            ?: throw Exception("Field ${fieldName} not found in the record ${record.recordUid}")
    }

    if (queryParts[2].endsWith("[]")) {
        val field = findField(queryParts[2].slice(0..queryParts[2].length - 2))
        return getFieldJsonValue(field)
    }

    val fieldParts = queryParts[2]
        .replace(Regex("""[\[\]]"""), "/")
        .split('/')
        .filter { x -> x.isNotEmpty() }

    val field = findField(fieldParts[0])

    if (fieldParts.size == 1) {
        return getFieldStringValue(field, 0)
    }
    val fieldValueIdx = fieldParts[1].toIntOrNull()
    if (fieldValueIdx == null) {
        TODO()
    }
//    if (fieldValueIdx < 0 || fieldValueIdx >= )

    if (fieldParts.size == 2) {
        return getFieldStringValue(field, fieldValueIdx)
    }
    TODO()
}

fun getFieldStringValue(field: KeeperRecordField, valueIdx: Int): String {
    return when (field) {
        is AccountNumber -> field.value[valueIdx]
        is AddressRef -> field.value[valueIdx]
        is Addresses -> Json.encodeToString(field.value[valueIdx])
        is BankAccounts -> Json.encodeToString(field.value[valueIdx])
        is BirthDate -> field.value[valueIdx].toString()
        is CardRef -> field.value[valueIdx]
        is Date -> field.value[valueIdx].toString()
        is Email -> field.value[valueIdx]
        is ExpirationDate -> field.value[valueIdx].toString()
        is FileRef -> field.value[valueIdx]
        is HiddenField -> field.value[valueIdx]
        is Hosts -> Json.encodeToString(field.value[valueIdx])
        is KeyPairs -> field.value[valueIdx].toString()
        is LicenseNumber -> field.value[valueIdx]
        is Login -> field.value[valueIdx]
        is Multiline -> field.value[valueIdx]
        is Names -> Json.encodeToString(field.value[valueIdx])
        is OneTimeCode -> field.value[valueIdx]
        is OneTimePassword -> field.value[valueIdx]
        is Password -> field.value[valueIdx]
        is PaymentCards -> Json.encodeToString(field.value[valueIdx])
        is Phones -> Json.encodeToString(field.value[valueIdx])
        is PinCode -> field.value[valueIdx]
        is SecureNote -> field.value[valueIdx]
        is SecurityQuestions -> Json.encodeToString(field.value[valueIdx])
        is Text -> field.value[valueIdx]
        is Url -> field.value[valueIdx]
    }
}

fun getFieldJsonValue(field: KeeperRecordField): String {
    return Json.encodeToString(field)
}