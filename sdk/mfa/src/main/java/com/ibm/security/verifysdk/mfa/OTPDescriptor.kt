/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.mfa

import com.ibm.security.verifysdk.core.extension.decodeBase32
import java.time.Instant
import java.util.Date
import java.util.Locale
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

interface OTPDescriptor {
    var secret: String
    val digits: Int
    val algorithm: HashAlgorithmType

    companion object {
        fun remainingTime(interval: Double = 30.0): Int {
            val currentTimeRemaining = (Instant.now().epochSecond % interval).toInt()
            return interval.toInt() - currentTimeRemaining
        }
    }

    fun generatePasscode(counter: Long): String {

        val digitsPower = intArrayOf(1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000)
        val mac: Mac = Mac.getInstance(algorithm.toString())
        val macKey = SecretKeySpec(
            (secret.replace(" ".toRegex(), "")).decodeBase32(),
            algorithm.toString()
        )
        mac.init(macKey)
        val hmacResult: ByteArray = mac.doFinal(counter.toByteArray())
        val offset: Int = hmacResult[hmacResult.size - 1].toInt() and 0x0f
        var binary: Int = hmacResult[offset].toInt() and 0x7f shl 24
        binary = binary or (hmacResult[offset + 1].toInt() and 0xff shl 16)
        binary = binary or (hmacResult[offset + 2].toInt() and 0xff shl 8)
        binary = binary or (hmacResult[offset + 3].toInt() and 0xff)

        return String.format(Locale.getDefault(), "%0" + digits + "d", (binary % digitsPower[digits]))
    }
}

