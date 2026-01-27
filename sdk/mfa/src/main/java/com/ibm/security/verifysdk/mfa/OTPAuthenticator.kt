/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.mfa

import kotlinx.serialization.InternalSerializationApi
import kotlinx.serialization.Serializable
import java.util.UUID

@OptIn(InternalSerializationApi::class)
@Serializable
data class OTPAuthenticator(
    override val id: String = UUID.randomUUID().toString(),
    override var serviceName: String,
    override var accountName: String,
    override val allowedFactors: List<FactorType>
) : AuthenticatorDescriptor {

    init {
        require(
            allowedFactors.filterIsInstance<FactorType.Hotp>()
                .isNotEmpty() || allowedFactors.filterIsInstance<FactorType.Totp>().isNotEmpty()
        ) {
            "Only TOTP and HOTP factors are allowed."
        }
    }

    companion object {
        fun fromQRScan(fromQRScan: String): OTPAuthenticator? {
            val dictionary: MutableMap<String, String> = mutableMapOf()
            val pattern = "otpauth://([ht]otp)/([^\\?]+)\\?(.*)"
            val regex = Regex(pattern)
            val matchResult = regex.find(fromQRScan) ?: return null
            val type = EnrollableType.valueOf(matchResult.groupValues[1].uppercase())
            val label = matchResult.groupValues[2].removePercentEncoding()
            val fields = label.split(":")
            val serviceName = fields[0]
            val accountName =
                if (fields.size > 1) fields.drop(1).joinToString(":").trim() else fields[0]
            val parameters = matchResult.groupValues[3].split("&")
            for (parameter in parameters) {
                val pair = parameter.split("=")
                if (pair.size == 2) {
                    dictionary[pair[0]] = pair[1].removePercentEncoding()
                }
            }
            val secret = dictionary["secret"] ?: return null
            val algorithm = HashAlgorithmType.fromString(dictionary["algorithm"] ?: "sha1")
            val digits = dictionary["digits"]?.toIntOrNull()?.takeIf { it == 6 || it == 8 } ?: 6

            val value = when (type) {
                EnrollableType.HOTP -> dictionary["counter"]?.toIntOrNull() ?: 0
                EnrollableType.TOTP -> dictionary["period"]?.toIntOrNull()
                    ?.takeIf { it in 10..300 }
                    ?: 30 // seconds - default period

                else -> null
            } ?: return null

            val allowedFactors = when (type) {
                EnrollableType.TOTP -> listOf(
                    FactorType.Totp(
                        TOTPFactorInfo(
                            secret = secret,
                            digits = digits,
                            algorithm = algorithm,
                            period = value
                        )
                    )
                )

                EnrollableType.HOTP -> listOf(
                    FactorType.Hotp(
                        HOTPFactorInfo(
                            secret = secret,
                            digits = digits,
                            algorithm = algorithm,
                            _counter = value
                        )
                    )
                )

                else -> emptyList()
            }

            return OTPAuthenticator(
                serviceName = serviceName,
                accountName = accountName,
                allowedFactors = allowedFactors
            )
        }

        private fun String.removePercentEncoding(): String {
            return java.net.URLDecoder.decode(this, "UTF-8")
        }
    }
}