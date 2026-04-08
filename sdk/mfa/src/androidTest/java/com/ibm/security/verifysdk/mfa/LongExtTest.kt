/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.mfa

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.nio.ByteBuffer

/**
 * Basic test cases for Long extension functions.
 */
@RunWith(AndroidJUnit4::class)
class LongExtTest {

    @Test
    fun testToByteArrayZero() {
        val value = 0L
        val bytes = value.toByteArray()
        
        assertEquals(8, bytes.size)
        assertTrue(bytes.all { it == 0.toByte() })
    }

    @Test
    fun testToByteArrayPositive() {
        val value = 12345L
        val bytes = value.toByteArray()
        
        assertEquals(8, bytes.size)
        
        // Verify round-trip conversion
        val buffer = ByteBuffer.wrap(bytes)
        assertEquals(value, buffer.getLong())
    }

    @Test
    fun testToByteArrayNegative() {
        val value = -12345L
        val bytes = value.toByteArray()
        
        assertEquals(8, bytes.size)
        
        // Verify round-trip conversion
        val buffer = ByteBuffer.wrap(bytes)
        assertEquals(value, buffer.getLong())
    }

    @Test
    fun testToByteArrayMaxValue() {
        val value = Long.MAX_VALUE
        val bytes = value.toByteArray()
        
        assertEquals(8, bytes.size)
        
        // Verify round-trip conversion
        val buffer = ByteBuffer.wrap(bytes)
        assertEquals(value, buffer.getLong())
    }

    @Test
    fun testToByteArrayMinValue() {
        val value = Long.MIN_VALUE
        val bytes = value.toByteArray()
        
        assertEquals(8, bytes.size)
        
        // Verify round-trip conversion
        val buffer = ByteBuffer.wrap(bytes)
        assertEquals(value, buffer.getLong())
    }

    @Test
    fun testToByteArrayOne() {
        val value = 1L
        val bytes = value.toByteArray()
        
        assertEquals(8, bytes.size)
        assertEquals(1.toByte(), bytes[7])
        
        // All other bytes should be 0
        for (i in 0..6) {
            assertEquals(0.toByte(), bytes[i])
        }
    }

    @Test
    fun testToByteArrayConsistency() {
        val value = 999999L
        val bytes1 = value.toByteArray()
        val bytes2 = value.toByteArray()
        
        assertArrayEquals(bytes1, bytes2)
    }

    @Test
    fun testToByteArrayDifferentValues() {
        val value1 = 100L
        val value2 = 200L
        
        val bytes1 = value1.toByteArray()
        val bytes2 = value2.toByteArray()
        
        assertFalse(bytes1.contentEquals(bytes2))
    }

    @Test
    fun testToByteArrayTimestamp() {
        // Test with a typical timestamp value
        val timestamp = System.currentTimeMillis()
        val bytes = timestamp.toByteArray()
        
        assertEquals(8, bytes.size)
        
        // Verify round-trip conversion
        val buffer = ByteBuffer.wrap(bytes)
        assertEquals(timestamp, buffer.getLong())
    }

    @Test
    fun testToByteArrayBigEndian() {
        val value = 0x0102030405060708L
        val bytes = value.toByteArray()
        
        // ByteBuffer uses big-endian by default
        assertEquals(0x01.toByte(), bytes[0])
        assertEquals(0x02.toByte(), bytes[1])
        assertEquals(0x03.toByte(), bytes[2])
        assertEquals(0x04.toByte(), bytes[3])
        assertEquals(0x05.toByte(), bytes[4])
        assertEquals(0x06.toByte(), bytes[5])
        assertEquals(0x07.toByte(), bytes[6])
        assertEquals(0x08.toByte(), bytes[7])
    }
}
