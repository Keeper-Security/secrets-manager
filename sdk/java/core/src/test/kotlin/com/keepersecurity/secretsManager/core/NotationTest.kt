package com.keepersecurity.secretsManager.core

import kotlinx.serialization.ExperimentalSerializationApi
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.fail

internal class NotationTest {

    private val recordUID = "k9qMpcO0aszz9w3li5XbaQ"

    private val recordData = KeeperRecordData(
        "My Record 1",
        "login",
        listOf(
            Login(value = mutableListOf("My Login 1")),
            Password(value = mutableListOf("My Password 1"))
        ),
        listOf(
            Text(label = "My Custom 1", value = mutableListOf("custom1")),
            Text(label = "My Custom 1", value = mutableListOf("custom1")),
            Text(label = "My Custom 2", value = mutableListOf("one", "two", "three")),
            Phones(
                label = "phone", value = mutableListOf(
                    Phone(number = "555-5555555", ext = "22"),
                    Phone(number = "777-7777777", ext = "77"),
                    Phone(number = "888-8888888", ext = "", type = "Home"),
                    Phone(number = "555-5555555", type = "Work")
                )
            ),
            Names(label = "name", value = mutableListOf(Name("Jenny", "X", "Smith")))
        )
    )

    private val secrets = KeeperSecrets(listOf(KeeperRecord(ByteArray(0), recordUID, data = recordData)))

    @ExperimentalSerializationApi
    @Test
    fun notationsWork() {
        var value: String

        value = getValue(secrets, "keeper://${recordUID}/field/login")
        assertEquals("My Login 1", value)

        value = getValue(secrets, "${recordUID}/field/login")
        assertEquals("My Login 1", value)

        value = getValue(secrets, "keeper://${recordUID}/field/login[0]")
        assertEquals("My Login 1", value)

        try {
            value = getValue(secrets, "keeper://${recordUID}/field/login[1]")
            fail("Getting wrong index did not throw")
        } catch (e: Exception) {
            assertEquals("Index 1 out of bounds for length 1", e.message.toString())
        }
        value = getValue(secrets, "keeper://${recordUID}/field/login[]")
        assertEquals("[\"My Login 1\"]", value)

        value = getValue(secrets, "keeper://${recordUID}/custom_field/My Custom 1")
        assertEquals("custom1", value)

        value = getValue(secrets, "keeper://${recordUID}/custom_field/My Custom 2")
        assertEquals("one", value)

        value = getValue(secrets, "keeper://${recordUID}/custom_field/My Custom 2[1]")
        assertEquals("two", value)

        value = getValue(secrets, "keeper://${recordUID}/custom_field/My Custom 2[]")
        assertEquals("[\"one\",\"two\",\"three\"]", value)

        value = getValue(secrets, "keeper://${recordUID}/custom_field/phone[0][number]")
        assertEquals("555-5555555", value)

        value = getValue(secrets, "keeper://${recordUID}/custom_field/phone[1][number]")
        assertEquals("777-7777777", value)

        value = getValue(secrets, "keeper://${recordUID}/custom_field/phone[2]")
        assertEquals("{\"number\":\"888-8888888\",\"ext\":\"\",\"type\":\"Home\"}", value)

        value = getValue(secrets, "keeper://${recordUID}/custom_field/name[first]")
        assertEquals("Jenny", value)

        value = getValue(secrets, "keeper://${recordUID}/custom_field/name[last]")
        assertEquals("Smith", value)
    }

}