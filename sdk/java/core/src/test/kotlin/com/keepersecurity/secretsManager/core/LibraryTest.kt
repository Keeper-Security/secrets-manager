package com.keepersecurity.secretsManager.core

import kotlin.test.Test
import kotlin.test.assertEquals

class LibraryTest {
    @Test fun testSomeLibraryMethod() {
        assertEquals(postQuery("get_secret").statusCode, 401)
    }
}
