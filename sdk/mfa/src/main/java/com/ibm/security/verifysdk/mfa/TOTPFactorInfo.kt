/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.mfa

import com.ibm.security.verifysdk.core.serializer.UUIDSerializer
import kotlinx.serialization.Serializable
import java.util.UUID
import kotlin.time.Clock
import kotlin.time.ExperimentalTime

/**
 * Represents information about a Time-based One-Time Password (TOTP) factor.
 *
 * This data class provides details necessary for generating and managing TOTP-based authentication factors.
 *
 * @param id The unique identifier for the TOTP factor.
 * @param displayName The display name for the TOTP factor.
 * @param secret The secret key used for generating TOTP codes.
 * @param algorithm The hash algorithm used for generating TOTP codes.
 * @param digits The number of digits in the generated TOTP codes. Reducing the number of digits for
 *  *                  OTP validation below 6 presents a potential security risk.
 * @param period The time period, in seconds, for which TOTP codes are valid.
 */
@Serializable
data class TOTPFactorInfo(
    @Serializable(with = UUIDSerializer::class)
    override val id: UUID = UUID.randomUUID(),
    override val displayName: String = "Time-based one-time password (TOTP)",
    override var secret: String,
    @Serializable(with = HashAlgorithmTypeSerializer::class)
    override val algorithm: HashAlgorithmType = HashAlgorithmType.SHA1,
    override val digits: Int = 6,
    val period: Int = 30
) : Factor, OTPDescriptor {

    init {
        require(period in 10..300) { "Period must be between 10 and 300 (inclusive)." }
        require(digits > 0) { "Digits must be > 0" }

        // The request to support digits < 6 was submitted by a customer (see CI-145331).
        require(digits <= 6 || digits == 8) { " Digits must be 1, 2, 3, 4, 5, 6 or 8"}
    }

    /**
     * Generates a TOTP passcode based on the current time interval.
     *
     * @return The generated TOTP passcode.
     */
    @OptIn(ExperimentalTime::class)
    @SuppressWarnings
    fun generatePasscode(): String {
        return generatePasscode(Clock.System.now().epochSeconds)
    }

    @SuppressWarnings
    override fun generatePasscode(counter: Long): String {
        return super.generatePasscode(counter = counter / period)
    }
}