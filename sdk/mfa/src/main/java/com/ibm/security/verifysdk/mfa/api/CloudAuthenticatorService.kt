/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.mfa.api

import android.util.Log
import com.ibm.security.verifysdk.authentication.model.TokenInfo
import com.ibm.security.verifysdk.core.AuthorizationException
import com.ibm.security.verifysdk.core.ErrorMessage
import com.ibm.security.verifysdk.core.extension.logDebug
import com.ibm.security.verifysdk.core.extension.logError
import com.ibm.security.verifysdk.core.extension.logInfo
import com.ibm.security.verifysdk.core.helper.NetworkHelper
import com.ibm.security.verifysdk.core.serializer.DefaultJson
import com.ibm.security.verifysdk.mfa.MFAAttributeInfo
import com.ibm.security.verifysdk.mfa.MFAServiceDescriptor
import com.ibm.security.verifysdk.mfa.MFAServiceException
import com.ibm.security.verifysdk.mfa.NextTransactionInfo
import com.ibm.security.verifysdk.mfa.PendingTransactionInfo
import com.ibm.security.verifysdk.mfa.TokenPersistenceCallback
import com.ibm.security.verifysdk.mfa.TransactionAttribute
import com.ibm.security.verifysdk.mfa.UserAction
import com.ibm.security.verifysdk.mfa.model.cloud.TransactionResult
import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.request.accept
import io.ktor.client.request.bearerAuth
import io.ktor.client.request.get
import io.ktor.client.request.parameter
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.request.url
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.content.TextContent
import io.ktor.http.contentType
import io.ktor.http.isSuccess
import kotlinx.coroutines.CancellationException
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.addJsonObject
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonObject
import java.net.URL
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.util.Locale
import java.util.UUID
import kotlin.time.ExperimentalTime

/**
 * Immutable cloud-based MFA authenticator service.
 *
 * ## Design Philosophy
 * This service is an **immutable value object** that represents a snapshot of authenticator
 * state at a specific point in time. It is NOT a traditional stateful service that maintains
 * and updates its state over time.
 *
 * ## Lifecycle Pattern
 * ```kotlin
 * // 1. Create service with current token and HTTP client
 * val service = CloudAuthenticatorService(
 *     _accessToken = authenticator.token.accessToken,
 *     _refreshUri = authenticator.refreshUri,
 *     _transactionUri = authenticator.transactionUri,
 *     _authenticatorId = authenticator.id,
 *     httpClient = NetworkHelper.getInstance,
 *     persistenceCallback = repository
 * )
 *
 * // 2. Use service for operations
 * service.nextTransaction()
 * service.completeTransaction(...)
 *
 * // 3. If token is refreshed, create NEW service
 * service.refreshToken(...).onSuccess { newToken ->
 *     // This service is now obsolete!
 *     // Create new service with new token:
 *     val newService = CloudAuthenticatorService(
 *         _accessToken = newToken.accessToken,  // New token
 *         _refreshUri = authenticator.refreshUri,
 *         _transactionUri = authenticator.transactionUri,
 *         _authenticatorId = authenticator.id,
 *         httpClient = NetworkHelper.getInstance,
 *         persistenceCallback = repository
 *     )
 *     // Use newService for subsequent operations
 * }
 * ```
 *
 * ## Why Immutable?
 *
 * ### Thread Safety
 * Immutability guarantees thread safety without synchronization:
 * - Multiple threads can safely call methods concurrently
 * - No race conditions or data corruption
 * - No need for locks or mutexes in the service
 *
 * ### Clear Semantics
 * Immutability makes the lifecycle explicit:
 * - Service represents a point-in-time snapshot
 * - When token changes, create new service
 * - No hidden state mutations
 * - Clear ownership and lifecycle
 *
 * ### Lightweight
 * Creating new instances is fast (~1ms):
 * - No expensive initialization
 * - No resource allocation
 * - Just property assignment
 *
 * ## Repository Pattern
 * The repository layer manages service lifecycle:
 * ```kotlin
 * suspend fun <T> executeWithTokenManagement(
 *     authenticator: MFAAuthenticatorDescriptor,
 *     operation: suspend (MFAServiceDescriptor) -> Result<T>
 * ): Result<T> {
 *     // 1. Check if token needs refresh
 *     if (authenticator.token.shouldRefresh()) {
 *         refreshAndSaveToken(authenticator)
 *     }
 *
 *     // 2. Create service with current token
 *     val service = createService(authenticator)
 *
 *     // 3. Execute operation
 *     val result = operation(service)
 *
 *     // 4. Handle 401 errors
 *     if (result.isFailure && is401Error(result)) {
 *         refreshAndSaveToken(authenticator)
 *         val newService = createService(authenticator)  // New instance!
 *         return operation(newService)
 *     }
 *
 *     return result
 * }
 * ```
 *
 * ## Terminology
 * This service is:
 * - ✅ **Immutable** - state cannot change
 * - ✅ **Thread-safe** - safe for concurrent use
 * - ✅ **Value object** - represents a snapshot
 * - ✅ **Short-lived** - created per operation or set of operations
 * - ❌ **NOT stateless** - holds immutable state
 * - ❌ **NOT long-lived** - recreated when token changes
 *
 * @property _accessToken The OAuth access token (immutable snapshot)
 * @property _refreshUri The endpoint URL for token refresh operations
 * @property _transactionUri The endpoint URL for transaction operations
 * @property _authenticatorId The unique identifier for this authenticator
 * @property httpClient The HTTP client for making network requests
 * @property persistenceCallback Optional callback for automatic token persistence
 *
 * @see MFAServiceDescriptor
 * @see TokenPersistenceCallback
 */
@OptIn(ExperimentalSerializationApi::class, ExperimentalTime::class)
class CloudAuthenticatorService(
    private val _accessToken: String,
    private val _refreshUri: URL,
    private val _transactionUri: URL,
    private val _authenticatorId: String,
    internal val httpClient: HttpClient,
    private val persistenceCallback: TokenPersistenceCallback? = null
) : MFAServiceDescriptor {

    companion object {
        private const val TAG = "CloudAuthService"
    }

    override val accessToken: String
        get() = _accessToken

    override val refreshUri: URL
        get() = _refreshUri

    override val transactionUri: URL
        get() = _transactionUri

    override val authenticatorId: String
        get() = _authenticatorId

    internal enum class TransactionFilter {
        NEXT_PENDING,
        PENDING_BY_IDENTIFIER;

        fun build(transactionId: String? = null): String =
            when (this) {
                NEXT_PENDING ->
                    """?filter=id,creationTime,transactionData,authenticationMethods,correlationEnabled,correlationValue,expiryTime,&search=state="PENDING"&sort=-creationTime"""

                PENDING_BY_IDENTIFIER ->
                    """?filter=id,creationTime,transactionData,authenticationMethods,correlationEnabled,correlationValue,expiryTime,&search=state="PENDING"&id="$transactionId""""
            }
    }

    /**
     * Refreshes the OAuth token with **CRITICAL** persistence guarantees.
     *
     * ## ⚠️ CRITICAL: Token Persistence
     *
     * This method implements **BLOCKING, ATOMIC** token persistence to prevent the
     * "hosed authenticator" scenario where the app crashes after token refresh but
     * before persistence, leaving the authenticator permanently broken.
     *
     * ### How It Works
     * 1. Makes network request to refresh endpoint
     * 2. Receives new access token from server
     * 3. **BLOCKS** until [persistenceCallback] completes
     * 4. Only returns success if persistence succeeds
     * 5. If persistence fails, entire refresh fails
     *
     * ### Why This Matters
     * Once the server sees a new token in an API call, it marks the old token as invalid.
     * If the new token isn't persisted before that happens, the authenticator becomes
     * permanently unusable because:
     * - Server has activated new token (old token now invalid)
     * - New token was never saved to database
     * - On app restart: old token loaded → all API calls fail with 401
     * - **Authenticator is permanently broken** (requires re-registration)
     *
     * ### Atomicity Guarantee
     * ```
     * Token Refresh = Network Call + Database Save
     * ```
     * Both must succeed, or the entire operation fails. This prevents partial state.
     *
     * ### Service Lifecycle
     * **IMPORTANT:** This service instance becomes obsolete after token refresh.
     * You must create a new service instance with the new token:
     * ```kotlin
     * service.refreshToken(...).onSuccess { newToken ->
     *     // This service is now obsolete!
     *     val newService = CloudAuthenticatorService(
     *         _accessToken = newToken.accessToken,  // New token
     *         _refreshUri = authenticator.refreshUri,
     *         _transactionUri = authenticator.transactionUri,
     *         _authenticatorId = authenticator.id,
     *         persistenceCallback = repository
     *     )
     *     // Use newService for subsequent operations
     * }
     * ```
     *
     * ### Synchronization
     * **Note:** Concurrent refresh prevention should be handled at the repository layer
     * using a Mutex to ensure only one refresh per authenticator at a time.
     *
     * @param refreshToken The refresh token to be used for obtaining a new access token.
     * @param accountName Optional account name to be included in the request attributes.
     * @param pushToken Optional push token (e.g., FCM token) to be included in the request.
     * @param additionalData Additional data to be included in the request (currently unused).
     *
     * @return A [Result] containing:
     *         - **Success:** New [TokenInfo] with updated access and refresh tokens.
     *                       Token has been persisted to database via callback.
     *         - **Failure:** Exception indicating why the refresh failed. This includes
     *                       persistence failures - if token can't be saved, refresh fails.
     *
     * @throws Exception if network request fails
     * @throws Exception if token persistence fails (via callback)
     *
     * @sample
     * ```kotlin
     * // Create service with current token and persistence callback
     * val service = CloudAuthenticatorService(
     *     _accessToken = authenticator.token.accessToken,
     *     _refreshUri = authenticator.refreshUri,
     *     _transactionUri = authenticator.transactionUri,
     *     _authenticatorId = authenticator.id,
     *     httpClient = NetworkHelper.getInstance,
     *     persistenceCallback = repository // Implements TokenPersistenceCallback
     * )
     *
     * // Refresh the token
     * service.refreshToken(
     *     refreshToken = authenticator.token.refreshToken,
     *     accountName = "user@example.com",
     *     pushToken = "fcm-token-abc123",
     *     additionalData = null
     * ).onSuccess { newToken ->
     *     println("Token refreshed successfully")
     *     println("New access token: ${newToken.accessToken}")
     *     println("Expires in: ${newToken.expiresIn} seconds")
     *
     *     // IMPORTANT: Create new service with new token
     *     val newService = CloudAuthenticatorService(
     *         _accessToken = newToken.accessToken,  // Use new token
     *         _refreshUri = authenticator.refreshUri,
     *         _transactionUri = authenticator.transactionUri,
     *         _authenticatorId = authenticator.id,
     *         httpClient = NetworkHelper.getInstance,
     *         persistenceCallback = repository
     *     )
     *
     *     // Use newService for subsequent operations
     *     newService.nextTransaction()
     * }.onFailure { error ->
     *     println("Token refresh failed: ${error.message}")
     *     // Handle error (e.g., re-authenticate user)
     * }
     * ```
     *
     * @see TokenInfo
     * @see TokenPersistenceCallback
     */
    override suspend fun refreshToken(
        refreshToken: String,
        accountName: String?,
        pushToken: String?,
        additionalData: Map<String, Any>?
    ): Result<TokenInfo> {
        return try {
            logDebug(TAG) { "Starting token refresh for authenticator $_authenticatorId" }
            
            val attributes = prepareAttributes(accountName, pushToken)
            val response = makeNetworkRequest(refreshToken, attributes)

            handleResponse(response).also { result ->
                result.onSuccess { newTokenInfo ->
                    logInfo(TAG) { "Token refreshed successfully for authenticator $_authenticatorId" }
                    
                    // CRITICAL: Persist token BEFORE returning success
                    // This ensures token is saved BEFORE any subsequent API call that would activate it on server
                    persistenceCallback?.let { callback ->
                        val persistResult = callback.onTokenRefreshed(authenticatorId, newTokenInfo)
                        persistResult.onFailure { error ->
                            logError(TAG) { "CRITICAL: Token persistence failed for authenticator $_authenticatorId: ${error.message}" }
                            // Return failure if persistence fails - token refresh is not complete without persistence
                            return Result.failure(Exception("Token refresh succeeded but persistence failed: ${error.message}", error))
                        }
                        logDebug(TAG) { "Token persisted successfully for authenticator $_authenticatorId" }
                    }
                }.onFailure { error ->
                    logError(TAG) { "Token refresh failed for authenticator $_authenticatorId: ${error.message}" }
                }
            }
        } catch (e: CancellationException) {
            // Coroutine was cancelled - this is normal, don't log as error
            // Re-throw to allow proper cancellation propagation
            throw e
        } catch (e: Throwable) {
            logError(TAG, e) { "Exception during token refresh for authenticator $_authenticatorId" }
            Result.failure(e)
        }
    }

    /**
     * Prepares the attributes map to be included in the request.
     *
     * @param accountName Optional account name to be included in the attributes.
     * @param pushToken Optional push token to be included in the attributes.
     * @return A mutable map of attributes with the provided account name and push token.
     */
    private fun prepareAttributes(
        accountName: String?,
        pushToken: String?
    ): MutableMap<String, Any> {
        return mutableMapOf<String, Any>().apply {
            putAll(MFAAttributeInfo.dictionary())
            remove("applicationName")
            accountName?.let { this["accountName"] = it }
            pushToken?.let { this["pushToken"] = it }
        }
    }

    /**
     * Makes a network request to refresh the token.
     *
     * @param refreshToken The refresh token to be included in the request.
     * @param attributes The attributes to be included in the request.
     * @param httpClient The HTTP client to use for the request.
     * @return The HTTP response from the server.
     */
    private suspend fun makeNetworkRequest(
        refreshToken: String,
        attributes: Map<String, Any>
    ): HttpResponse {
        // Build JSON manually to avoid serialization issues with Map<String, Any>
        val jsonBody = buildJsonObject {
            put("refreshToken", refreshToken)
            putJsonObject("attributes") {
                attributes.forEach { (key, value) ->
                    when (value) {
                        is String -> put(key, value)
                        is Boolean -> put(key, value)
                        is Int -> put(key, value)
                        is Long -> put(key, value)
                        is Double -> put(key, value)
                        is Float -> put(key, value)
                        else -> put(key, value.toString())
                    }
                }
            }
        }
        
        return httpClient.post {
            url(refreshUri.toString())
            accept(ContentType.Application.Json)
            parameter("metadataInResponse", true)
            setBody(TextContent(jsonBody.toString(), ContentType.Application.Json))
        }
    }

    /**
     * Handles the response from the token refresh request.
     *
     * @param response The HTTP response from the server.
     * @return A [Result] containing the new [TokenInfo] if the response indicates success, or an error if it fails.
     */
    private suspend fun handleResponse(response: HttpResponse): Result<TokenInfo> {
        return if (response.status.isSuccess()) {
            Result.success(DefaultJson.decodeFromString<TokenInfo>(response.bodyAsText()))
        } else {
            val errorResponse = response.body<ErrorMessage>()
            Result.failure(
                AuthorizationException(
                    response.status,
                    errorResponse.error,
                    errorResponse.errorDescription
                )
            )
        }
    }


    /**
     * Retrieves the next pending transaction from the server.
     *
     * @param transactionID The ID of the transaction to retrieve. If null, retrieves the next pending transaction.
     * @return A [Result] containing the [NextTransactionInfo] if successful, or an error if unsuccessful.
     */
    override suspend fun nextTransaction(
        transactionID: String?
    ): Result<NextTransactionInfo> {
        return try {
            val uri = nextTransactionBuildTransactionUri(transactionID)
            val response = nextTransactionMakeNetworkRequest(uri)

            nextTransactionHandleResponse(response)
        } catch (e: Throwable) {
            Result.failure(e)
        }
    }

    /**
     * Safely builds a URL by appending a path to a base URL.
     *
     * This helper ensures proper URL construction by:
     * - Removing trailing slashes from base URL
     * - Ensuring path starts with a slash
     * - Preventing double-slash issues
     *
     * @param baseUrl The base URL
     * @param path The path to append (with or without leading slash)
     * @return A properly constructed URL
     */
    private fun buildUrl(baseUrl: URL, path: String): URL {
        val baseStr = baseUrl.toString().trimEnd('/')
        val pathStr = if (path.startsWith('/')) path else "/$path"
        return URL("$baseStr$pathStr")
    }

    /**
     * Builds the URI for retrieving the next pending transaction.
     *
     * Uses safe URL construction to prevent malformed URLs from trailing slashes
     * or missing path separators. Validates that transaction ID is not blank.
     *
     * @param transactionID The ID of the transaction to retrieve. If null, retrieves the next pending transaction.
     * @return The URI for retrieving the next pending transaction.
     * @throws IllegalArgumentException if transactionID is blank (empty or whitespace only)
     */
    private fun nextTransactionBuildTransactionUri(transactionID: String?): URL {
        return if (transactionID != null) {
            require(transactionID.isNotBlank()) {
                "Transaction ID cannot be blank (empty or whitespace only)"
            }
            val encodedId = URLEncoder.encode(transactionID, StandardCharsets.UTF_8.name())
            buildUrl(transactionUri, TransactionFilter.PENDING_BY_IDENTIFIER.build(encodedId))
        } else {
            buildUrl(transactionUri, TransactionFilter.NEXT_PENDING.build())
        }
    }

    /**
     * Makes a network request using the given [uri] and returns the response.
     *
     * @param uri The URI to make the request to.
     * @return The HTTP response.
     */
    private suspend fun nextTransactionMakeNetworkRequest(
        uri: URL
    ): HttpResponse {
        return httpClient.get {
            url(uri.toString())
            contentType(ContentType.Application.Json)
            accept(ContentType.Application.Json)
            bearerAuth(accessToken)
        }
    }

    /**
     * Handles the response from the server after making a request to retrieve the next pending transaction.
     *
     * @param response The HTTP response from the server.
     * @return A [Result] containing the [NextTransactionInfo] if successful, or an error if unsuccessful.
     */
    private suspend fun nextTransactionHandleResponse(response: HttpResponse): Result<NextTransactionInfo> {
        return if (response.status.isSuccess()) {
            parsePendingTransaction(response)
        } else {
            Result.failure(MFAServiceException.General(response.bodyAsText()))
        }
    }

    override suspend fun completeTransaction(
        transaction: PendingTransactionInfo,
        userAction: UserAction,
        signedData: String
    ): Result<Unit> {

        return try {
            Log.d(TAG, "Completing transaction ${transaction.id} with action $userAction for authenticator $_authenticatorId")
            
            // Validate transaction hasn't expired
            transaction.expiryTime?.let { expiry ->
                if (kotlin.time.Clock.System.now() > expiry) {
                    Log.w(TAG, "Transaction ${transaction.id} has expired for authenticator $_authenticatorId")
                    return Result.failure(
                        MFAServiceException.General("Transaction ${transaction.id} has expired")
                    )
                }
            }

            val jsonBody = buildJsonArray {
                addJsonObject {
                    put("id", transaction.factorID.toString().lowercase(Locale.ROOT))
                    put("userAction", userAction.value)
                    if (userAction == UserAction.VERIFY) {
                        put("signedData", signedData)
                    } else {
                        put("signedData", JsonNull)
                    }
                }
            }

            val response = httpClient.post {
                url(transaction.postbackUri.toString())
                accept(ContentType.Application.Json)
                bearerAuth(accessToken)
                setBody(TextContent(jsonBody.toString(), ContentType.Application.Json))
            }

            if (response.status.isSuccess()) {
                Log.i(TAG, "Transaction ${transaction.id} completed successfully with action $userAction for authenticator $_authenticatorId")
                Result.success(Unit)
            } else {
                Log.e(TAG, "Failed to complete transaction ${transaction.id} for authenticator $_authenticatorId: ${response.bodyAsText()}")
                Result.failure(MFAServiceException.General(response.bodyAsText()))
            }
        } catch (e: Throwable) {
            Log.e(TAG, "Exception completing transaction ${transaction.id} for authenticator $_authenticatorId", e)
            return Result.failure(e)
        }
    }

    private suspend fun parsePendingTransaction(response: HttpResponse): Result<NextTransactionInfo> {

        return try {
            val responseBody = response.bodyAsText()
            val result: TransactionResult = try {
                DefaultJson.decodeFromString(responseBody)
            } catch (_: Exception) {
                return Result.failure(MFAServiceException.DecodingFailed())
            }

            if (result.count == 0) {
                Result.success(NextTransactionInfo(emptyList(), 0))
            } else {
                val transactions = createPendingTransactions(result)
                Result.success(NextTransactionInfo(transactions, result.count))
            }

        } catch (_: Throwable) {
            Result.failure(MFAServiceException.UnableToCreateTransaction())
        }
    }

    private fun createPendingTransactions(result: TransactionResult): List<PendingTransactionInfo> {
        val verifications = result.verifications ?: return emptyList()
        val now = kotlin.time.Clock.System.now()
        
        return verifications.mapNotNull { verificationInfo ->
            // Filter out expired transactions
            verificationInfo.expiryTime?.let { expiry ->
                if (now > expiry) {
                    Log.d(TAG, "Skipping expired transaction ${verificationInfo.id}")
                    return@mapNotNull null
                }
            }
            
            createPendingTransaction(verificationInfo)
        }
    }

    private fun createPendingTransaction(verificationInfo: TransactionResult.VerificationInfo): PendingTransactionInfo? {
        // 1. Get the postback to the transaction using safe URL construction.
        val postbackUri = buildUrl(transactionUri, verificationInfo.id)

        // 2. Get the message to display.
        val message = transactionMessage(verificationInfo.transactionInfo)

        // 3. Construct the factor that is used to look up the private key from the Keychain.
        val methodInfo = verificationInfo.methodInfo.firstOrNull() ?: return null

        // 4. Construct the transaction context information into additional data.
        val additionalData = createAdditionalData(verificationInfo)

        return PendingTransactionInfo(
            id = verificationInfo.id,
            message = message,
            postbackUri = postbackUri,
            factorID = UUID.fromString(methodInfo.id) ?: UUID.randomUUID(),
            factorType = methodInfo.subType,
            dataToSign = verificationInfo.transactionInfo,
            creationTime = verificationInfo.creationTime,
            expiryTime = verificationInfo.expiryTime,
            additionalData = additionalData
        )
    }

    /**
     * Calculates a correlation value from a transaction ID.
     *
     * The correlation value is a 2-digit number (00-99) derived from the transaction ID
     * by taking the first 8 characters, parsing them as hexadecimal, and calculating
     * modulo 100. This value is used to help users verify they are approving the correct
     * transaction by matching it with a value displayed in the requesting application.
     *
     * @param transactionId The transaction ID to calculate the correlation value from
     * @return A 2-digit string representation of the correlation value (00-99),
     *         or "00" if calculation fails
     */
    private fun calculateCorrelationValue(transactionId: String): String {
        return try {
            // Take first 8 characters of transaction ID
            val shortTransactionId = transactionId.substring(0, minOf(transactionId.length, 8))
            // Parse as hexadecimal and calculate modulo 100
            val correlationValue = shortTransactionId.toBigInteger(16).mod(100.toBigInteger())
            
            // Format with leading zero if less than 10
            if (correlationValue > 9.toBigInteger()) {
                correlationValue.toString()
            } else {
                "0${correlationValue}"
            }
        } catch (e: Exception) {
            "00"
        }
    }

    /**
     * Creates a map of transaction attributes from verification information.
     *
     * This method extracts and categorizes transaction data into well-known attributes
     * (IP address, user agent, type, location, etc.) and custom attributes.
     *
     * Uses kotlinx.serialization for type-safe parsing instead of org.json.
     *
     * @param verificationInfo The verification information containing transaction data
     * @return A map of transaction attributes with their values
     */
    private fun createAdditionalData(verificationInfo: TransactionResult.VerificationInfo): Map<TransactionAttribute, String> {
        val result: MutableMap<TransactionAttribute, String> = mutableMapOf()

        // Add the default type (of request) to the result. Might be overridden if specified in additionalData.
        result[TransactionAttribute.Type] = "Default request"

        // Handle correlation from VerificationInfo
        if (verificationInfo.correlationEnabled) {
            result[TransactionAttribute.Correlation] = verificationInfo.correlationValue
                ?: calculateCorrelationValue(verificationInfo.id)
        }

        // Parse transaction data using kotlinx.serialization
        val transactionData = try {
            DefaultJson.decodeFromString<com.ibm.security.verifysdk.mfa.model.cloud.TransactionData>(
                verificationInfo.transactionInfo
            )
        } catch (e: Exception) {
            Log.w(TAG, "Failed to parse transaction data from JSON", e)
            return result
        }

        // Extract standard fields
        transactionData.originIpAddress?.let {
            result[TransactionAttribute.IPAddress] = it
        }
        
        transactionData.originUserAgent?.let {
            result[TransactionAttribute.UserAgent] = it
        }

        // Process additional data items
        val customData = transactionData.additionalData?.filterNot { item ->
            when (item.name) {
                "type" -> {
                    result[TransactionAttribute.Type] = item.value
                    true // Remove from custom data
                }
                "originLocation" -> {
                    result[TransactionAttribute.Location] = item.value
                    true // Remove from custom data
                }
                "imageURL" -> {
                    result[TransactionAttribute.Image] = item.value
                    true // Remove from custom data
                }
                "denyReasonEnabled" -> {
                    result[TransactionAttribute.DenyReason] = item.value
                    true // Remove from custom data
                }
                else -> false // Keep in custom data
            }
        }

        // Add remaining custom data as JSON array
        if (!customData.isNullOrEmpty()) {
            result[TransactionAttribute.Custom] = DefaultJson.encodeToString(customData)
        }

        return result
    }

    /**
     * Extracts the transaction message from the transaction data JSON string.
     *
     * Uses kotlinx.serialization for type-safe parsing instead of org.json.
     *
     * @param value The JSON string containing transaction data
     * @return The message string, or "PendingRequestMessageDefault" if not found or parsing fails
     */
    private fun transactionMessage(value: String): String {
        return try {
            val data = DefaultJson.decodeFromString<com.ibm.security.verifysdk.mfa.model.cloud.TransactionData>(value)
            data.message ?: "PendingRequestMessageDefault"
        } catch (e: Exception) {
            Log.w(TAG, "Failed to parse transaction message from JSON", e)
            "PendingRequestMessageDefault"
        }
    }
}