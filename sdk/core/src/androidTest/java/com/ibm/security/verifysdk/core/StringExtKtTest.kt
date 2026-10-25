/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */
package com.ibm.security.verifysdk.core

import com.ibm.security.verifysdk.core.extension.camelToSnakeCase
import com.ibm.security.verifysdk.core.extension.decodeBase32
import com.ibm.security.verifysdk.core.extension.snakeToCamelCase
import com.ibm.security.verifysdk.core.extension.toNumberOrDefault
import com.ibm.security.verifysdk.core.extension.toNumberOrNull
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import java.nio.charset.StandardCharsets

internal class StringExtKtTest {

    @Test
    fun toNumberOrNull() {
        assertEquals(42, "42".toNumberOrNull())
        assertEquals(4200000000, "4200000000".toLong().toString().toNumberOrNull())
        assertEquals(42.42424242, "42.42424242".toDouble().toString().toNumberOrNull())
        assertEquals(null, "".toNumberOrNull())
    }

    @Test
    fun toNumberOrDefault() {
        assertEquals(42, "42".toNumberOrDefault(99))
        assertEquals(4200000000, "4200000000".toLong().toString().toNumberOrDefault(99))
        assertEquals(42.42424242, "42.42424242".toDouble().toString().toNumberOrDefault(99))
        assertEquals(99, "".toNumberOrDefault(99))
    }

    @Test
    fun camelToSnakeCase() {
        assertEquals("user_name", "userName".camelToSnakeCase())
        assertEquals("client_id_value", "clientIdValue".camelToSnakeCase())
    }

    @Test
    fun snakeToCamelCase() {
        assertEquals("userName", "user_name".snakeToCamelCase())
        assertEquals("clientIdValue", "client_id_value".snakeToCamelCase())
    }

    @Test
    fun decodeBase32_rfc4648TestVectors() {
        assertEquals("", String("".decodeBase32(), StandardCharsets.UTF_8))
        assertEquals("f", String("MY======".decodeBase32(), StandardCharsets.UTF_8))
        assertEquals("fo", String("MZXW====".decodeBase32(), StandardCharsets.UTF_8))
        assertEquals("foo", String("MZXW6===".decodeBase32(), StandardCharsets.UTF_8))
        assertEquals("foob", String("MZXW6YQ=".decodeBase32(), StandardCharsets.UTF_8))
        assertEquals("fooba", String("MZXW6YTB".decodeBase32(), StandardCharsets.UTF_8))
        assertEquals("foobar", String("MZXW6YTBOI======".decodeBase32(), StandardCharsets.UTF_8))
    }

    @Test
    fun decodeBase32_unpaddedInputs() {
        assertEquals("f", String("MY".decodeBase32(), StandardCharsets.UTF_8))
        assertEquals("fo", String("MZXW".decodeBase32(), StandardCharsets.UTF_8))
        assertEquals("foo", String("MZXW6".decodeBase32(), StandardCharsets.UTF_8))
        assertEquals("foob", String("MZXW6YQ".decodeBase32(), StandardCharsets.UTF_8))
        assertEquals("foobar", String("MZXW6YTBOI".decodeBase32(), StandardCharsets.UTF_8))
    }

    @Test
    fun decodeBase32_lowercaseInputs() {
        assertEquals("foobar", String("mzxw6ytboi======".decodeBase32(), StandardCharsets.UTF_8))
        assertEquals("foobar", String("mzxw6ytboi".decodeBase32(), StandardCharsets.UTF_8))
        assertEquals("foo", String("mzxw6".decodeBase32(), StandardCharsets.UTF_8))
    }

    @Test
    fun decodeBase32_dashedInputs() {
        assertEquals("foobar", String("MZXW-6YTB-OI======".decodeBase32(), StandardCharsets.UTF_8))
        assertEquals("foobar", String("mzxw-6ytb-oi".decodeBase32(), StandardCharsets.UTF_8))
        assertEquals("foobar", String("M-Z-X-W-6-Y-T-B-O-I".decodeBase32(), StandardCharsets.UTF_8))
    }

    @Test
    fun decodeBase32_spacedInputs() {
        assertEquals("foobar", String("MZXW 6YTB OI".decodeBase32(), StandardCharsets.UTF_8))
        assertEquals("foobar", String("  MZXW6YTBOI  ".decodeBase32(), StandardCharsets.UTF_8))
        assertEquals("foobar", String("\tMZXW\n6YTB\r\nOI\t".decodeBase32(), StandardCharsets.UTF_8))
    }

    @Test
    fun decodeBase32_combinedFormatting() {
        val raw = "JBSWY3DPEHPK3PXP"
        val formatted = "  jbsw-y3dp \t ehpk-3pxp== \n"
        assertArrayEquals(raw.decodeBase32(), formatted.decodeBase32())
    }

    @Test
    fun decodeBase32_invalidCharacters_shouldThrowIllegalArgumentException() {
        val exceptionWith8 = assertThrows(IllegalArgumentException::class.java) {
            "MZXW6YT8".decodeBase32()
        }
        assertEquals("Invalid character in Base32 string: '8'", exceptionWith8.message)

        val exceptionWith9 = assertThrows(IllegalArgumentException::class.java) {
            "MZXW6YT9".decodeBase32()
        }
        assertEquals("Invalid character in Base32 string: '9'", exceptionWith9.message)

        val exceptionWith0 = assertThrows(IllegalArgumentException::class.java) {
            "MZXW6YT0".decodeBase32()
        }
        assertEquals("Invalid character in Base32 string: '0'", exceptionWith0.message)

        val exceptionWith1 = assertThrows(IllegalArgumentException::class.java) {
            "MZXW6YT1".decodeBase32()
        }
        assertEquals("Invalid character in Base32 string: '1'", exceptionWith1.message)

        val exceptionWithSpecial = assertThrows(IllegalArgumentException::class.java) {
            "MZXW6!@#".decodeBase32()
        }
        assertEquals("Invalid character in Base32 string: '!'", exceptionWithSpecial.message)
    }
}
