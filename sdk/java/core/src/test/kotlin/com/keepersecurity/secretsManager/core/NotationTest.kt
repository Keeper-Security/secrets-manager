package com.keepersecurity.secretsManager.core

import kotlin.test.Test
import kotlin.test.assertEquals

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

    val secrets = KeeperSecrets(listOf(KeeperRecord(ByteArray(0), recordUID, data = recordData)))

    @Test
    fun notationsWork() {
        var value: String

//        value = getValue(secrets, "keeper://${recordUID}/field/login")
//        assertEquals("My Login 1", value)
//
//        value = getValue(secrets, "${recordUID}/field/login")
//        assertEquals("My Login 1", value)

        value = getValue(secrets, "keeper://${recordUID}/field/login[0]")
        assertEquals("My Login 1", value)
    }

}