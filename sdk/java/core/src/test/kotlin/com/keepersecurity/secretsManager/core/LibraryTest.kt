package com.keepersecurity.secretsManager.core

import kotlin.test.Test
import kotlin.test.assertTrue

class LibraryTest {
    @Test fun testSomeLibraryMethod() {
        val classUnderTest = SecretsManager()
        assertTrue(classUnderTest.doSomething(), "someLibraryMethod should return 'true'")
    }
}
