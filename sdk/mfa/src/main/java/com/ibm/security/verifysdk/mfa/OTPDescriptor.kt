/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.mfa

import com.ibm.security.verifysdk.core.extension.decodeBase32
import java.util.Locale
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.time.Clock
import kotlin.time.ExperimentalTime

interface OTPDescriptor {
    var secret: String
    val digits: Int
    val algorithm: HashAlgorithmType

    companion object {
        @OptIn(ExperimentalTime::class)
        fun remainingTime(interval: Double = 30.0): Int {
            val currentTimeRemaining = (Clock.System.now().epochSeconds % interval).toInt()
            return interval.toInt() - currentTimeRemaining
        }
    }

    /**
     * Generates a one-time passcode for the given counter value.
     *
     * @param counter The counter or time step value.
     * @return The formatted numeric passcode.
     * @throws MFAServiceException.General if the secret key is invalid or empty.
     */
    fun generatePasscode(counter: Long): String {

        val digitsPower = intArrayOf(1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000)
        val decodedSecret = try {
            val bytes = secret.decodeBase32()
            if (bytes.isEmpty()) {
                throw MFAServiceException.General("Secret key cannot be empty.")
            }
            bytes
        } catch (e: MFAServiceException) {
            throw e
        } catch (e: IllegalArgumentException) {
            throw MFAServiceException.General("Invalid Base32 secret key.", e)
        } catch (e: Exception) {
            throw MFAServiceException.General("Failed to decode secret key.", e)
        }

        return try {
            val mac: Mac = Mac.getInstance(algorithm.toString())
            val macKey = SecretKeySpec(
                decodedSecret,
                algorithm.toString()
            )
            mac.init(macKey)
            val hmacResult: ByteArray = mac.doFinal(counter.toByteArray())
            val offset: Int = hmacResult[hmacResult.size - 1].toInt() and 0x0f
            var binary: Int = hmacResult[offset].toInt() and 0x7f shl 24
            binary = binary or (hmacResult[offset + 1].toInt() and 0xff shl 16)
            binary = binary or (hmacResult[offset + 2].toInt() and 0xff shl 8)
            binary = binary or (hmacResult[offset + 3].toInt() and 0xff)

            String.format(Locale.getDefault(), "%0" + digits + "d", (binary % digitsPower[digits]))
        } catch (e: Exception) {
            throw MFAServiceException.General("Failed to generate passcode.", e)
        }
    }
}

