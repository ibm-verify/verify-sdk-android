/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */
package com.ibm.security.verifysdk.authentication

import org.junit.Assert.assertEquals
import org.junit.Test

internal class CodeChallengeMethodTest {

    @Test
    fun values() {
        assertEquals("PLAIN", CodeChallengeMethod.PLAIN.toString())
        assertEquals("PLAIN", CodeChallengeMethod.PLAIN.name)
        assertEquals("S256", CodeChallengeMethod.S256.toString())
        assertEquals("S256", CodeChallengeMethod.S256.name)
    }

    @Test
    fun valueOf() {
        assertEquals(CodeChallengeMethod.PLAIN, CodeChallengeMethod.valueOf("PLAIN"))
        assertEquals(CodeChallengeMethod.S256, CodeChallengeMethod.valueOf("S256"))
    }
}