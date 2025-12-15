/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */
package com.ibm.security.verifysdk.fido2.api

import android.security.keystore.KeyProperties
import androidx.biometric.BiometricPrompt
import androidx.biometric.BiometricPrompt.PromptInfo.Builder
import androidx.fragment.app.FragmentActivity
import com.fasterxml.jackson.dataformat.cbor.databind.CBORMapper
import com.ibm.security.verifysdk.core.extension.base64UrlEncode
import com.ibm.security.verifysdk.core.extension.sha256
import com.ibm.security.verifysdk.core.helper.BaseApi
import com.ibm.security.verifysdk.core.helper.KeystoreHelper
import com.ibm.security.verifysdk.core.helper.NetworkHelper
import com.ibm.security.verifysdk.core.serializer.DefaultJson
import com.ibm.security.verifysdk.fido2.BiometricAuthenticationException
import com.ibm.security.verifysdk.fido2.COSEKey
import com.ibm.security.verifysdk.fido2.model.AssertionOptions
import com.ibm.security.verifysdk.fido2.model.AssertionResultResponse
import com.ibm.security.verifysdk.fido2.model.AttestationOptions
import com.ibm.security.verifysdk.fido2.model.AttestationResultResponse
import com.ibm.security.verifysdk.fido2.model.AuthenticatorAssertionResponse
import com.ibm.security.verifysdk.fido2.model.AuthenticatorAttestationResponse
import com.ibm.security.verifysdk.fido2.model.ClientDataJsonAssertion
import com.ibm.security.verifysdk.fido2.model.ClientDataJsonAttestation
import com.ibm.security.verifysdk.fido2.model.PublicKeyCredentialCreationOptions
import com.ibm.security.verifysdk.fido2.model.PublicKeyCredentialRequestOptions
import com.ibm.security.verifysdk.fido2.model.ResponseAssertion
import com.ibm.security.verifysdk.fido2.model.ResponseAttestation
import io.ktor.client.HttpClient
import io.ktor.http.HttpMethod
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.suspendCancellableCoroutine
import java.net.URL
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.PublicKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.util.concurrent.Executor
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlin.math.max
import kotlin.math.min
import kotlin.time.Clock
import kotlin.time.ExperimentalTime

/**
 * A class providing methods for FIDO2 operations.
 * This class contains functionalities related to key pair generation, attestation, and assertion
 * processes using biometric authentication.
 */
@OptIn(
    ExperimentalUnsignedTypes::class,
    ExperimentalCoroutinesApi::class,
    ExperimentalStdlibApi::class,
)
class Fido2Api : BaseApi() {

    /**
     * Creates a new key pair in the Android KeyStore.
     *
     * This method generates a new key pair in the Android KeyStore with the specified
     * attributes and options.
     *
     * @param keyName The name to associate with the generated key pair.
     * @param authenticationRequired A flag indicating whether user authentication is required
     *                               for using the key.
     * @param invalidatedByBiometricEnrollment A flag indicating whether the key should be invalidated
     *                                          if biometric enrollment changes.
     *
     * @return The public key of the generated key pair.
     */
    fun createKeyPair(
        keyName: String,
        authenticationRequired: Boolean = true,
        invalidatedByBiometricEnrollment: Boolean = false
    ): PublicKey {

        return KeystoreHelper.createKeyPair(
            keyName,
            algorithm = KeyProperties.KEY_ALGORITHM_EC,
            purpose = KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
            authenticationRequired = authenticationRequired,
            invalidatedByBiometricEnrollment = invalidatedByBiometricEnrollment
        )
    }

    /**
     * Initiates the attestation process with the specified options.
     *
     * This function sends a request to the server to initiate the attestation process
     * with the provided attestation options.
     *
     * @param httpClient The [HttpClient] used to make the network request.
     * @param attestationOptionsUrl The URL to send the attestation options request to.
     * @param authorization The authorization header value to be included in the request.
     * @param attestationOptions The options for the attestation process.
     *
     * @return A Result wrapping the PublicKeyCredentialCreationOptions received from the server
     *         if the attestation process is successful, or a failure if an error occurs during
     *         the process.
     */
    suspend fun initiateAttestation(
        attestationOptionsUrl: String,
        authorization: String,
        attestationOptions: AttestationOptions,
        httpClient: HttpClient = NetworkHelper.getInstance
    ): Result<PublicKeyCredentialCreationOptions> {

        return performRequest(
            httpClient = httpClient,
            url = URL(attestationOptionsUrl),
            accessToken = authorization,
            body = attestationOptions,
            method = HttpMethod.Post
        )
    }

    /**
     * Sends the attestation result to the server.
     *
     * This function sends the attestation result, represented by the
     * AuthenticatorAttestationResponse, to the specified URL on the server.
     *
     * @param httpClient The [HttpClient] used to make the network request.
     * @param attestationResultUrl The URL to send the attestation result to.
     * @param authorization The authorization header value to be included in the request.
     * @param authenticatorAttestationResponse The response containing the attestation result.
     *
     * @return A Result wrapping the AttestationResultResponse received from the server
     *         if the operation is successful, or a failure if an error occurs during
     *         the process.
     */
    suspend fun sendAttestation(
        attestationResultUrl: String,
        authorization: String,
        authenticatorAttestationResponse: AuthenticatorAttestationResponse,
        httpClient: HttpClient = NetworkHelper.getInstance
    ): Result<AttestationResultResponse> {

        return performRequest(
            httpClient = httpClient,
            url = URL(attestationResultUrl),
            accessToken = authorization,
            body = authenticatorAttestationResponse,
            method = HttpMethod.Post
        )
    }

    /**
     * Sends the assertion result to the server.
     *
     * This function sends the assertion result, represented by the
     * AuthenticatorAssertionResponse, to the specified URL on the server.
     *
     * @param httpClient The [HttpClient] used to make the network request.
     * @param assertionResultUrl The URL to send the assertion result to.
     * @param authorization The authorization header value to be included in the request.
     * @param authenticatorAssertionResponse The response containing the assertion result.
     *
     * @return A Result wrapping the AssertionResultResponse received from the server
     *         if the operation is successful, or a failure if an error occurs during
     *         the process.
     */
    suspend fun sendAssertion(
        assertionResultUrl: String,
        authorization: String,
        authenticatorAssertionResponse: AuthenticatorAssertionResponse,
        httpClient: HttpClient = NetworkHelper.getInstance
    ): Result<AssertionResultResponse> {

        return performRequest(
            httpClient = httpClient,
            url = URL(assertionResultUrl),
            accessToken = authorization,
            body = authenticatorAssertionResponse,
            method = HttpMethod.Post
        )
    }

    /**
     * Initiates the assertion process with the specified options.
     *
     * This function sends a request to the server to initiate the assertion process
     * with the provided assertion options.
     *
     * @param httpClient The [HttpClient] used to make the network request.
     * @param assertionOptionsUrl The URL to send the assertion options request to.
     * @param authorization The authorization header value to be included in the request.
     * @param assertionOptions The options for the assertion process.
     *
     * @return A Result wrapping the PublicKeyCredentialRequestOptions received from the server
     *         if the assertion process is successful, or a failure if an error occurs during
     *         the process.
     */
    suspend fun initiateAssertion(
        assertionOptionsUrl: String,
        authorization: String,
        assertionOptions: AssertionOptions,
        httpClient: HttpClient = NetworkHelper.getInstance
    ): Result<PublicKeyCredentialRequestOptions> {

        return performRequest(
            httpClient = httpClient,
            url = URL(assertionOptionsUrl),
            accessToken = authorization,
            body = assertionOptions,
            method = HttpMethod.Post
        )
    }

    /**
     * Converts a byte array to an unsigned fixed-length byte array.
     *
     * This function takes a byte array and converts it to an unsigned fixed-length byte array.
     * If the input byte array is shorter than the specified fixed length, it is padded with zeroes
     * at the beginning. If it is longer, the excess bytes are truncated from the beginning.
     *
     * @param arr The input byte array to be converted.
     * @param fixedLength The desired length of the output byte array.
     *
     * @return The converted unsigned fixed-length byte array.
     */
    private fun toUnsignedFixedLength(arr: ByteArray, fixedLength: Int): ByteArray {
        val fixed = ByteArray(fixedLength)
        val offset = fixedLength - arr.size
        val copyLength = min(arr.size, fixedLength)
        System.arraycopy(arr, max(-offset, 0), fixed, max(offset, 0), copyLength)
        return fixed
    }

    /**
     * Retrieves an EC key in COSE (CBOR Object Signing and Encryption) format from the Android KeyStore.
     *
     * This function retrieves an EC key in COSE format from the Android KeyStore using the provided key name.
     * It fetches the public key, extracts its coordinates, and constructs a COSEKey object with
     * the appropriate attributes.
     *
     * @param keyName The name of the key in the Android KeyStore.
     * @return The COSEKey instance representing the EC key retrieved from the KeyStore.
     */
    private fun getCoseKey(keyName: String): COSEKey {
        val ecPublicKey = KeystoreHelper.getPublicKey(keyName) as ECPublicKey
        val point = ecPublicKey.w
        val x: ByteArray = toUnsignedFixedLength(point.affineX.toByteArray(), 32)
        val y: ByteArray = toUnsignedFixedLength(point.affineY.toByteArray(), 32)
        return COSEKey(2, -7, 1, x, y)
    }

    /**
     * Builds an AuthenticatorAttestationResponse for the given parameters.
     *
     * This function constructs an AuthenticatorAttestationResponse, which represents
     * the response from the authenticator during the attestation process. It is used
     * to attest to the creation of a new public key credential. The response includes
     * various data such as client data, attestation statement, and authenticator data.
     *
     * @param activity The FragmentActivity instance to display UI prompts.
     * @param executor The Executor instance to run asynchronous tasks.
     * @param promptInfoBuilder The PromptInfo.Builder instance to build the biometric
     *                          authentication dialog.
     * @param aaGuid The AAGUID (Authenticator Attestation Globally Unique Identifier).
     * @param keyName The name of the key in the Android KeyStore.
     * @param flags The flags indicating the capabilities and status of the authenticator.
     * @param options The PublicKeyCredentialCreationOptions containing the parameters for
     *                creating the public key credential.
     * @param nickName The nickname associated with the authenticator.
     *
     * @return The constructed AuthenticatorAttestationResponse.
     */
    @OptIn(ExperimentalTime::class)
    suspend fun buildAuthenticatorAttestationResponse(
        activity: FragmentActivity,
        executor: Executor,
        promptInfoBuilder: Builder,
        aaGuid: String,
        keyName: String,
        flags: Byte,
        options: PublicKeyCredentialCreationOptions,
        nickName: String
    ): AuthenticatorAttestationResponse {

        val clientDataJson = ClientDataJsonAttestation(
            "webauthn.create",
            options.challenge,
            "https://${options.rp.id!!}",
            false,
        )

        val id = keyName.sha256().hexToByteArray()
        val clientDataString = DefaultJson.encodeToString(clientDataJson)

        // Build authenticatorData
        val authenticatorDataParams = mutableListOf<Byte>()
        authenticatorDataParams.addAll(options.rp.id!!.sha256().hexToByteArray().toList())
        authenticatorDataParams.add(flags)

        val now = Clock.System.now().epochSeconds
        val counter = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(now.toInt()).array()
        authenticatorDataParams.addAll(counter.toList())

        // Build attestedCredentialData
        val attestedCredentialData = mutableListOf<Byte>()
        attestedCredentialData.addAll(aaGuid.replace("-", "").hexToByteArray().toList())

        val length = byteArrayOf(
            ((id.size shr 8) and 0xFF).toByte(),
            (id.size and 0xFF).toByte()
        )

        attestedCredentialData.addAll(length.toList())
        // Add the credentialId
        attestedCredentialData.addAll(id.toList())

        val coseKey = getCoseKey(keyName)
        attestedCredentialData.addAll(coseKey.toByteArray.toList())

        // Add attestedCredential to authenticatorData
        authenticatorDataParams.addAll(attestedCredentialData)

        val attestationStatement = buildAttestationStatement(
            activity = activity,
            executor = executor,
            promptInfoBuilder = promptInfoBuilder,
            keyName = keyName,
            clientDataString = clientDataString,
            authenticatorData = authenticatorDataParams.toByteArray(),
        )

        val attestedObject = HashMap<String, Any>()
        attestedObject["fmt"] = "packed"
        attestedObject["attStmt"] = attestationStatement
        attestedObject["authData"] = authenticatorDataParams.toByteArray()

        return AuthenticatorAttestationResponse(
            id.base64UrlEncode(),
            id.base64UrlEncode(),
            ResponseAttestation(
                clientDataString.base64UrlEncode(),
                CBORMapper().writeValueAsBytes(attestedObject).toUByteArray().base64UrlEncode()
            ),
            "public-key",
            nickName
        )
    }

    /**
     * Builds the attestation statement for the given parameters.
     *
     * This function constructs the attestation statement for the attestation process.
     * It includes the algorithm identifier and the signature generated by biometric
     * authentication of the attestation data. The signature is computed over a combination
     * of authenticator data and client data hash.
     *
     * @param activity The FragmentActivity instance to display UI prompts.
     * @param executor The Executor instance to run asynchronous tasks.
     * @param promptInfoBuilder The PromptInfo.Builder instance to build the biometric
     *      *                          authentication dialog.
     * @param keyName The name of the key in the Android KeyStore.
     * @param clientDataString The string representation of the client data in the attestation process.
     * @param authenticatorData The authenticator data.
     *
     * @return The map representing the attestation statement, including the algorithm identifier
     *         and the signature generated by biometric authentication.
     */
    private suspend fun buildAttestationStatement(
        activity: FragmentActivity,
        executor: Executor,
        promptInfoBuilder: Builder,
        keyName: String,
        clientDataString: String,
        authenticatorData: ByteArray
    ): Map<String, Any> {

        val result = HashMap<String, Any>()
        result["alg"] = -7

        val dataToSign = mutableListOf<Byte>()
        dataToSign.addAll(authenticatorData.toList())
        dataToSign.addAll(clientDataString.sha256().hexToByteArray().toList())

        invokeBiometricAuthentication(
            keyName = keyName,
            activity = activity,
            executor = executor,
            promptInfoBuilder = promptInfoBuilder
        ).let { authenticationResult ->
            when (authenticationResult) {
                is BiometricPromptResult.Success -> {
                    authenticationResult.data.cryptoObject?.let { cryptoObject ->
                        KeystoreHelper.signData(cryptoObject, dataToSign.toByteArray())
                            ?.let { sig ->
                                result["sig"] = sig
                            }
                    }
                }

                is BiometricPromptResult.Failure -> {
                    println("Error: ${authenticationResult.errorCode} - ${authenticationResult.errorMessage}")
                }
            }
        }
        return result
    }

    /**
     * Invokes biometric authentication for the given parameters.
     *
     * This function initiates biometric authentication using the provided key name
     * and displays a biometric prompt to the user for authentication. It returns the result
     * of the authentication process.
     *
     * @param activity The FragmentActivity instance to display the biometric prompt.
     * @param executor The Executor instance to run asynchronous tasks.
     * @param promptInfoBuilder The PromptInfo.Builder instance to build the biometric
     *      *      *            authentication dialog.
     * @param keyName The name of the key in the Android KeyStore.
     *
     * @return A BiometricPromptResult representing the result of the biometric authentication.
     */
    private suspend fun invokeBiometricAuthentication(
        activity: FragmentActivity,
        executor: Executor,
        promptInfoBuilder: Builder,
        keyName: String
    ): BiometricPromptResult<BiometricPrompt.AuthenticationResult> {
        return suspendCancellableCoroutine { continuation ->
            val biometricPrompt = BiometricPrompt(activity, executor,
                object : BiometricPrompt.AuthenticationCallback() {

                    override fun onAuthenticationSucceeded(
                        result: BiometricPrompt.AuthenticationResult
                    ) {
                        super.onAuthenticationSucceeded(result)
                        continuation.resume(BiometricPromptResult.Success(result), null)
                    }

                    override fun onAuthenticationError(
                        errorCode: Int,
                        errString: CharSequence
                    ) {
                        super.onAuthenticationError(errorCode, errString)
                        continuation.resume(
                            BiometricPromptResult.Failure(
                                errString.toString(),
                                errorCode
                            )
                        )
                    }

                    override fun onAuthenticationFailed() {
                        super.onAuthenticationFailed()
                        continuation.resumeWithException(BiometricAuthenticationException("Authentication failed"))

                    }
                })

            val signature = Signature.getInstance("SHA256withECDSA")
            val secretKey = KeystoreHelper.getPrivateKey(keyName = keyName)
            signature.initSign(secretKey)
            biometricPrompt.authenticate(
                promptInfoBuilder.build(),
                BiometricPrompt.CryptoObject(signature)
            )
        }
    }

    /**
     * Builds an AuthenticatorAssertionResponse for the given parameters.
     *
     * This function constructs an AuthenticatorAssertionResponse, which represents
     * the response from the authenticator during the assertion process. It is used
     * to attest to the authentication of an existing public key credential. The response
     * includes various data such as client data, authenticator data, and signature
     * generated by biometric authentication.
     *
     * @param activity The FragmentActivity instance to display UI prompts.
     * @param executor The Executor instance to run asynchronous tasks.
     * @param promptInfoBuilder The PromptInfo.Builder instance to build the biometric
     *                          authentication dialog.
     * @param keyName The name of the key in the Android KeyStore.
     * @param flags The flags indicating the capabilities and status of the authenticator.
     * @param options The PublicKeyCredentialRequestOptions containing the parameters for
     *                the assertion process.
     * @param message Optional additional message to include in the assertion.
     *
     * @return The constructed AuthenticatorAssertionResponse.
     */
    @OptIn(ExperimentalTime::class)
    suspend fun buildAuthenticatorAssertionResponse(
        activity: FragmentActivity,
        executor: Executor,
        promptInfoBuilder: Builder,
        keyName: String,
        flags: Byte,
        options: PublicKeyCredentialRequestOptions,
        message: String?
    ): AuthenticatorAssertionResponse {

        val clientDataJson = ClientDataJsonAssertion(
            "webauthn.get",
            options.challenge,
            "https://${options.rpId}"
        )

        val id = keyName.sha256().hexToByteArray()
        val clientDataString = DefaultJson.encodeToString(clientDataJson)

        val authenticatorDataParams = mutableListOf<Byte>()
        authenticatorDataParams.addAll(options.rpId.sha256().hexToByteArray().toList())
        authenticatorDataParams.add(flags)

        val now = kotlin.time.Clock.System.now().epochSeconds
        val counter = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(now.toInt()).array()
        authenticatorDataParams.addAll(counter.toList())

        message?.let {
            val extension = HashMap<String, Any>()
            extension["txAuthSimple"] = message
            authenticatorDataParams.addAll(CBORMapper().writeValueAsBytes(extension).toList())
        }

        val dataToSign = mutableListOf<Byte>()
        dataToSign.addAll(authenticatorDataParams.toList())
        dataToSign.addAll(clientDataString.sha256().hexToByteArray().toList())

        var sig = "".toByteArray()
        invokeBiometricAuthentication(
            keyName = keyName,
            activity = activity,
            executor = executor,
            promptInfoBuilder = promptInfoBuilder
        ).let { authenticationResult ->
            when (authenticationResult) {
                is BiometricPromptResult.Success -> {
                    authenticationResult.data.cryptoObject?.let { cryptoObject ->
                        KeystoreHelper.signData(cryptoObject, dataToSign.toByteArray())?.let {
                            sig = it
                        }
                    }
                }

                is BiometricPromptResult.Failure -> {
                    println("Error: ${authenticationResult.errorCode} - ${authenticationResult.errorMessage}")
                }
            }
        }

        return AuthenticatorAssertionResponse(
            id.base64UrlEncode(),
            id.base64UrlEncode(),
            ResponseAssertion(
                clientDataString.base64UrlEncode(),
                authenticatorDataParams.toByteArray().base64UrlEncode(),
                sig.base64UrlEncode()
            ),
            "public-key"
        )
    }

    /**
     * Represents the result of a biometric prompt operation.
     *
     * @param T The type of data associated with the result.
     */
    internal sealed class BiometricPromptResult<out T> {
        /**
         * Represents a successful biometric prompt operation.
         * @property data The data associated with the success.
         */
        data class Success<out T>(val data: T) : BiometricPromptResult<T>()

        /**
         * Represents a failed biometric prompt operation.
         * @property errorMessage The error message associated with the failure.
         * @property errorCode An optional error code associated with the failure.
         */
        data class Failure(val errorMessage: String, val errorCode: Int? = null) :
            BiometricPromptResult<Nothing>()
    }
}