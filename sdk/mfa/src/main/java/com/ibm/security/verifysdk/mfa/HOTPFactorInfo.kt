/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.mfa

import com.ibm.security.verifysdk.core.serializer.UUIDSerializer
import kotlinx.serialization.Serializable
import java.util.UUID

/**
 * Represents information about an HMAC-based One-Time Password (HOTP) factor.
 *
 * This data class provides details necessary for generating and managing HOTP-based authentication factors.
 *
 * @param id The unique identifier for the HOTP factor.
 * @param displayName The display name for the HOTP factor.
 * @param secret The secret key used for generating HOTP codes.
 * @param algorithm The hash algorithm used for generating HOTP codes.
 * @param digits The number of digits in the generated HOTP codes. Reducing the number of digits for
 *                        OTP validation below 6 presents a potential security risk.
 * @param _counter The counter value used for generating HOTP codes. Defaults to 1.
 */
@Serializable
data class HOTPFactorInfo(
    @Serializable(with = UUIDSerializer::class)
    override val id: UUID = UUID.randomUUID(),
    override val displayName: String = "HMAC-based one-time password (HOTP)",
    override var secret: String,
    @Serializable(with = HashAlgorithmTypeSerializer::class)
    override val algorithm: HashAlgorithmType = HashAlgorithmType.SHA1,
    override val digits: Int = 6,
    private var _counter: Int = 0
) : Factor, OTPDescriptor {

    val counter: Int
        get() = _counter

    init {
        require(_counter >= 0) { "Counter must be >= 0" }
        require(digits > 0) { "Digits must be > 0" }

        // The request to support digits < 6 was submitted by a customer (see CI-145331).
        require(digits <= 6 || digits == 8) { " Digits must be 1, 2, 3, 4, 5, 6 or 8"}
    }

    fun generatePasscode(): String {
        val result = generatePasscode(counter.toLong())
        _counter++
        return result
    }
}