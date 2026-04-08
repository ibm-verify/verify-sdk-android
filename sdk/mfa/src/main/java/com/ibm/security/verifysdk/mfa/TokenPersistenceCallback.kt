/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.mfa

import com.ibm.security.verifysdk.authentication.model.TokenInfo

/**
 * Callback interface for **CRITICAL** automatic token persistence after refresh.
 *
 * ## ⚠️ CRITICAL: Implementation Required
 *
 * **YOU MUST IMPLEMENT THIS INTERFACE** to prevent the "hosed authenticator" scenario
 * where tokens are lost after refresh, leaving authenticators permanently broken.
 *
 * ## Why This Matters
 *
 * When a token is refreshed:
 * 1. SDK receives new token from server
 * 2. **This callback is invoked BEFORE returning success**
 * 3. You MUST save the token to persistent storage
 * 4. Only after successful save does refresh complete
 * 5. If save fails, entire refresh fails (old token remains valid)
 *
 * ### The "Hosed Authenticator" Scenario
 *
 * **What happens if you don't persist the token:**
 * ```
 * 1. refreshToken() → new token received
 * 2. Callback not implemented or fails
 * 3. App uses new token in API call → server activates it
 * 4. App crashes before token is saved
 * 5. On restart: old token loaded from database
 * 6. All API calls fail with 401 (old token invalid)
 * 7. Authenticator is PERMANENTLY BROKEN
 * ```
 *
 * ## Implementation Example
 *
 * ```kotlin
 * class AuthenticatorRepository(
 *     private val database: Database
 * ) : TokenPersistenceCallback {
 *
 *     override suspend fun onTokenRefreshed(
 *         authenticatorId: String,
 *         newToken: TokenInfo
 *     ): Result<Unit> {
 *         return try {
 *             // 1. Get authenticator from database
 *             val authenticator = database.getAuthenticator(authenticatorId)
 *
 *             // 2. Update token
 *             authenticator.token = newToken
 *
 *             // 3. CRITICAL: Save to database
 *             database.updateAuthenticator(authenticator)
 *
 *             Log.d(TAG, "Token persisted successfully for $authenticatorId")
 *             Result.success(Unit)
 *         } catch (e: Exception) {
 *             Log.e(TAG, "CRITICAL: Token persistence failed", e)
 *             Result.failure(e)
 *         }
 *     }
 * }
 * ```
 *
 * ## Atomicity Guarantee
 *
 * The SDK guarantees that:
 * - This callback is invoked BEFORE refresh returns success
 * - If this callback fails, refresh fails
 * - Token is never used before being persisted
 * - Old token remains valid if persistence fails
 *
 * ## Thread Safety
 *
 * - This callback is invoked on a coroutine (suspend function)
 * - You can safely perform database operations
 * - Ensure your database operations are thread-safe
 * - Consider using a Mutex if needed for synchronization
 *
 * ## Error Handling
 *
 * **IMPORTANT:** Return `Result.failure()` if persistence fails:
 * ```kotlin
 * override suspend fun onTokenRefreshed(...): Result<Unit> {
 *     return try {
 *         database.save(token)
 *         Result.success(Unit)
 *     } catch (e: Exception) {
 *         // Return failure - this will fail the entire refresh
 *         Result.failure(e)
 *     }
 * }
 * ```
 *
 * ## Performance
 *
 * - This callback blocks the refresh operation
 * - Keep implementation fast (< 100ms recommended)
 * - Use efficient database operations
 * - Avoid network calls or heavy processing
 *
 * @see com.ibm.security.verifysdk.mfa.api.CloudAuthenticatorService.refreshToken
 * @see TokenInfo
 */
interface TokenPersistenceCallback {
    /**
     * Called when a token has been successfully refreshed.
     *
     * **CRITICAL:** This method MUST persist the new token to storage.
     * The SDK blocks until this method completes. If this method fails,
     * the entire token refresh operation fails.
     *
     * ### Implementation Requirements
     *
     * 1. **Persist to Database:** Save token to persistent storage (database, encrypted SharedPreferences)
     * 2. **Return Success:** Return `Result.success(Unit)` only if save succeeds
     * 3. **Return Failure:** Return `Result.failure(exception)` if save fails
     * 4. **Be Fast:** Complete in < 100ms (database write should be quick)
     * 5. **Be Reliable:** Use transactions if possible to ensure atomicity
     *
     * ### What NOT to Do
     *
     * - ❌ Don't just update in-memory state
     * - ❌ Don't ignore errors
     * - ❌ Don't return success if save fails
     * - ❌ Don't perform network calls
     * - ❌ Don't do heavy processing
     *
     * ### Example Implementation
     *
     * ```kotlin
     * override suspend fun onTokenRefreshed(
     *     authenticatorId: String,
     *     newToken: TokenInfo
     * ): Result<Unit> {
     *     return try {
     *         // Get authenticator
     *         val auth = database.getAuthenticator(authenticatorId)
     *             ?: return Result.failure(Exception("Authenticator not found"))
     *
     *         // Update token
     *         auth.token = newToken
     *
     *         // CRITICAL: Save to database
     *         val saveResult = database.updateAuthenticator(auth)
     *
     *         if (saveResult.isSuccess) {
     *             Result.success(Unit)
     *         } else {
     *             Result.failure(Exception("Database save failed"))
     *         }
     *     } catch (e: Exception) {
     *         Result.failure(e)
     *     }
     * }
     * ```
     *
     * @param authenticatorId The unique identifier of the authenticator whose token was refreshed.
     *                       Use this to locate the authenticator in your database.
     * @param newToken The new token information containing updated access and refresh tokens.
     *                This MUST be persisted to storage before returning success.
     *
     * @return A [Result] indicating:
     *         - **Success:** Token was successfully persisted to storage
     *         - **Failure:** Token persistence failed (refresh will fail)
     *
     * @see TokenInfo
     * @see com.ibm.security.verifysdk.mfa.api.CloudAuthenticatorService.refreshToken
     */
    suspend fun onTokenRefreshed(
        authenticatorId: String,
        newToken: TokenInfo
    ): Result<Unit>
}
