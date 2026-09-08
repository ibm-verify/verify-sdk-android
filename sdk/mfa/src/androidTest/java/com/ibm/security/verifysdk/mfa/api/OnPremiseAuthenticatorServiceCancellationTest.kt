/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.mfa.api

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.ibm.security.verifysdk.authentication.model.TokenInfo
import com.ibm.security.verifysdk.core.helper.ContextHelper
import com.ibm.security.verifysdk.mfa.PendingTransactionInfo
import com.ibm.security.verifysdk.mfa.TokenPersistenceCallback
import com.ibm.security.verifysdk.mfa.TransactionAttribute
import com.ibm.security.verifysdk.mfa.UserAction
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.net.URL
import java.util.UUID
import kotlin.time.Clock
import kotlin.time.ExperimentalTime

/**
 * Regression tests for RC-5: [OnPremiseAuthenticatorService.refreshToken] must not swallow
 * [CancellationException] by wrapping it in [Result.failure].
 *
 * ## Root cause (RC-5)
 *
 * `OnPremiseAuthenticatorService.refreshToken` has a single broad `catch (e: Throwable)` handler
 * that converts every exception — including [CancellationException] — into `Result.failure(e)`.
 * `CloudAuthenticatorService` correctly adds a `catch (e: CancellationException) { throw e }` guard
 * _before_ the broad catch, ensuring the coroutine machinery receives the cancellation signal.
 *
 * When `CancellationException` is silently swallowed:
 * 1. The coroutine's scope is cancelled externally (e.g. `viewModelScope` on screen navigation).
 * 2. The in-flight `refreshToken` call returns `Result.failure(CancellationException)` instead of
 *    throwing — the coroutine appears to have "succeeded normally".
 * 3. The caller sees a failure result but has no way to distinguish a real network error from a
 *    cancellation; it may retry, log the error, or simply ignore it.
 * 4. The refresh token has been sent to the server (the HTTP request was already in flight), so the
 *    server may have rotated the token.  If the response arrives after cancellation, nothing
 *    processes it — the old (now consumed) refresh token stays in storage.
 * 5. The next proactive or reactive refresh sends the consumed token → HTTP 400.
 *
 * ## Fix
 * Add `catch (e: CancellationException) { throw e }` _before_ `catch (e: Throwable)` in
 * `OnPremiseAuthenticatorService.refreshToken`, matching the pattern already present in
 * `CloudAuthenticatorService`.
 */
@RunWith(AndroidJUnit4::class)
class OnPremiseAuthenticatorServiceCancellationTest {

    @Before
    fun setup() {
        ContextHelper.init(InstrumentationRegistry.getInstrumentation().targetContext)
    }

    // ══════════════════════════════════════════════════════════════════════════
    // Helpers
    // ══════════════════════════════════════════════════════════════════════════

    /**
     * A [MockEngine] that suspends indefinitely — simulating a slow network call.
     * Used to let the parent scope be cancelled while the HTTP request is in flight.
     */
    private fun hangingEngine(requestStarted: CompletableDeferred<Unit>): MockEngine = MockEngine { _ ->
        requestStarted.complete(Unit)
        // Suspend forever — this will be interrupted when the coroutine is cancelled.
        awaitCancellation()
        // Unreachable, satisfies the compiler.
        respond(
            content = "",
            status = HttpStatusCode.OK,
            headers = headersOf(HttpHeaders.ContentType, "application/json")
        )
    }

    /**
     * A [MockEngine] that immediately returns a successful token refresh response.
     * Used in tests that need the network call to complete before cancellation is tested
     * at a later point in the execution path.
     */
    private fun successEngine(): MockEngine = MockEngine { _ ->
        respond(
            content = """
                {
                  "access_token": "new_access_token",
                  "refresh_token": "new_refresh_token",
                  "scope": "mmfaAuthn",
                  "authenticator_id": "test_authenticator_id",
                  "token_type": "bearer",
                  "expires_in": 3600
                }
            """.trimIndent(),
            status = HttpStatusCode.OK,
            headers = headersOf(HttpHeaders.ContentType, "application/json;charset=UTF-8")
        )
    }

    private fun buildService(
        engine: MockEngine,
        persistenceCallback: TokenPersistenceCallback? = null,
    ) = OnPremiseAuthenticatorService(
        _accessToken = "access_token",
        _refreshUri = URL("https://example.com/mga/sps/oauth/oauth20/token"),
        _transactionUri = URL("https://example.com/scim/Me"),
        _clientId = "AuthenticatorClient",
        _authenticatorId = "test_authenticator_id",
        httpClient = HttpClient(engine),
        persistenceCallback = persistenceCallback
    )

    // ══════════════════════════════════════════════════════════════════════════
    // RC-5 regression tests
    // ══════════════════════════════════════════════════════════════════════════

    /**
     * Verifies that [CancellationException] is **thrown**, not returned as [Result.failure].
     *
     * The test sets up a hanging engine so the HTTP call never completes, then cancels the
     * coroutine scope mid-request.  After the fix, the call-site should observe a thrown
     * [CancellationException]; before the fix, it would observe `Result.failure` carrying
     * a [CancellationException] — breaking structured concurrency.
     */
    @Test
    fun refreshTokenThrowsCancellationExceptionWhenParentScopeIsCancelledMidRequest() = runTest {
        val requestStarted = CompletableDeferred<Unit>()
        val engine = hangingEngine(requestStarted)
        val service = buildService(engine)

        var resultFromCall: Result<TokenInfo>? = null
        var caughtThrown: Throwable? = null

        val job = launch {
            try {
                resultFromCall = service.refreshToken(
                    refreshToken = "old_refresh_token",
                    accountName = "user@example.com",
                    pushToken = null,
                    additionalData = null
                )
            } catch (e: CancellationException) {
                caughtThrown = e
                throw e // Re-throw so structured concurrency can unwind the scope.
            }
        }

        requestStarted.await()
        job.cancel(CancellationException("test: scope cancelled while request was in flight"))
        job.join()
        engine.close()

        // After the fix: CancellationException must be thrown (not returned as Result.failure).
        assertNotNull("CancellationException must be thrown from refreshToken", caughtThrown)
        assertTrue(
            "Thrown exception must be CancellationException",
            caughtThrown is CancellationException
        )

        // The Result must not have been set — the method must have thrown, not returned.
        assertNull(
            "refreshToken must not return a Result when CancellationException occurs; " +
                    "returning Result.failure(CancellationException) breaks structured concurrency",
            resultFromCall
        )
    }

    /**
     * Negative control: verifies that a genuine network error returns [Result.failure]
     * (not thrown) so ordinary error handling is unaffected by the CancellationException fix.
     */
    @Test
    fun refreshTokenReturnsFailureForNetworkErrors() = runTest {
        val errorEngine = MockEngine { _ ->
            respond(
                content = """{"error": "invalid_grant", "error_description": "Token expired"}""",
                status = HttpStatusCode.BadRequest,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }
        val service = buildService(errorEngine)

        var resultFromCall: Result<TokenInfo>? = null
        var caughtThrown: Throwable? = null

        try {
            resultFromCall = service.refreshToken(
                refreshToken = "expired_refresh_token",
                accountName = "user@example.com",
                pushToken = null,
                additionalData = null
            )
        } catch (e: CancellationException) {
            caughtThrown = e
        }

        errorEngine.close()

        // A real server error must return Result.failure, not throw.
        assertNull("CancellationException must not be thrown for a network error", caughtThrown)
        assertNotNull("Result must be returned for network errors", resultFromCall)
        val r1 = checkNotNull(resultFromCall)
        assertTrue("Result must be failure for HTTP 400", r1.isFailure)
        assertFalse(
            "Returned failure must not be a CancellationException",
            r1.exceptionOrNull() is CancellationException
        )
    }

    /**
     * Verifies that [CancellationException] thrown by the [TokenPersistenceCallback] (e.g.
     * when the coroutine scope is cancelled mid-persistence) is also re-thrown rather than
     * wrapped in [Result.failure].
     *
     * This covers the case where the network call completes successfully but the DB write
     * (which the callback performs) is cancelled: the server has already rotated the token,
     * so we must propagate the cancellation and not silently return a failure that the caller
     * would interpret as a network error.
     */
    @Test
    fun refreshTokenRethrowsCancellationExceptionFromPersistenceCallback() = runTest {
        val callback = object : TokenPersistenceCallback {
            override suspend fun onTokenRefreshed(
                authenticatorId: String,
                newToken: TokenInfo
            ): Result<Unit> {
                throw CancellationException("test: DB write cancelled mid-persistence")
            }
        }

        val service = buildService(successEngine(), persistenceCallback = callback)

        var caughtThrown: Throwable? = null
        var resultFromCall: Result<TokenInfo>? = null

        try {
            resultFromCall = service.refreshToken(
                refreshToken = "valid_refresh_token",
                accountName = "user@example.com",
                pushToken = null,
                additionalData = null
            )
        } catch (e: CancellationException) {
            caughtThrown = e
        }

        assertNotNull(
            "CancellationException from the persistence callback must propagate as a throw",
            caughtThrown
        )
        assertNull(
            "refreshToken must not return a Result when persistence callback throws CancellationException",
            resultFromCall
        )
    }

    // ══════════════════════════════════════════════════════════════════════════
    // nextTransaction cancellation tests
    // ══════════════════════════════════════════════════════════════════════════

    /**
     * Verifies that [CancellationException] is **thrown** from [OnPremiseAuthenticatorService.nextTransaction],
     * not returned as [Result.failure].
     *
     * The hanging engine simulates a slow network call. When the parent scope is cancelled
     * while the GET is in flight, the fix ensures the CE propagates rather than being silently
     * wrapped in [Result.failure] (which would give the caller no way to distinguish cancellation
     * from a genuine server error).
     */
    @Test
    fun nextTransactionThrowsCancellationExceptionWhenParentScopeIsCancelledMidRequest() = runTest {
        val requestStarted = CompletableDeferred<Unit>()
        val engine = hangingEngine(requestStarted)
        val service = buildService(engine)

        var resultFromCall: Result<*>? = null
        var caughtThrown: Throwable? = null

        val job = launch {
            try {
                resultFromCall = service.nextTransaction()
            } catch (e: CancellationException) {
                caughtThrown = e
                throw e
            }
        }

        requestStarted.await()
        job.cancel(CancellationException("test: scope cancelled while nextTransaction was in flight"))
        job.join()
        engine.close()

        assertNotNull("CancellationException must be thrown from nextTransaction", caughtThrown)
        assertTrue(
            "Thrown exception must be CancellationException",
            caughtThrown is CancellationException
        )
        assertNull(
            "nextTransaction must not return a Result when CancellationException occurs",
            resultFromCall
        )
    }

    /**
     * Negative control: a genuine server error (HTTP 503) must return [Result.failure],
     * not throw, so ordinary error handling is unaffected.
     */
    @Test
    fun nextTransactionReturnsFailureForServerErrors() = runTest {
        val engine = MockEngine { _ ->
            respond(
                content = """{"error":"service_unavailable"}""",
                status = HttpStatusCode.ServiceUnavailable,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }
        val service = buildService(engine)

        var resultFromCall: Result<*>? = null
        var caughtThrown: Throwable? = null

        try {
            resultFromCall = service.nextTransaction()
        } catch (e: CancellationException) {
            caughtThrown = e
        }

        engine.close()

        assertNull("CancellationException must not be thrown for a server error", caughtThrown)
        assertNotNull("Result must be returned for server errors", resultFromCall)
        val r2 = checkNotNull(resultFromCall)
        assertTrue("Result must be failure for HTTP 503", r2.isFailure)
        assertFalse(
            "Returned failure must not be a CancellationException",
            r2.exceptionOrNull() is CancellationException
        )
    }

    // ══════════════════════════════════════════════════════════════════════════
    // completeTransaction cancellation tests
    // ══════════════════════════════════════════════════════════════════════════

    /**
     * Verifies that [CancellationException] is **thrown** from
     * [OnPremiseAuthenticatorService.completeTransaction], not returned as [Result.failure].
     */
    @OptIn(ExperimentalTime::class)
    @Test
    fun completeTransactionThrowsCancellationExceptionWhenParentScopeIsCancelledMidRequest() = runTest {
        val requestStarted = CompletableDeferred<Unit>()
        val engine = hangingEngine(requestStarted)
        val service = buildService(engine)

        val pendingTransaction = PendingTransactionInfo(
            id = "txn-001-0000-0000-0000-000000000001",
            message = "Approve login",
            postbackUri = URL("https://example.com/mga/sps/apiauthsvc?MmfaTransactionId=txn-001"),
            factorID = UUID(0, 0),
            factorType = "userPresence",
            dataToSign = "",
            creationTime = Clock.System.now(),
            expiryTime = null,
            additionalData = emptyMap()
        )

        var resultFromCall: Result<*>? = null
        var caughtThrown: Throwable? = null

        val job = launch {
            try {
                resultFromCall = service.completeTransaction(
                    transaction = pendingTransaction,
                    userAction = UserAction.VERIFY,
                    signedData = ""
                )
            } catch (e: CancellationException) {
                caughtThrown = e
                throw e
            }
        }

        requestStarted.await()
        job.cancel(CancellationException("test: scope cancelled while completeTransaction was in flight"))
        job.join()
        engine.close()

        assertNotNull("CancellationException must be thrown from completeTransaction", caughtThrown)
        assertTrue(
            "Thrown exception must be CancellationException",
            caughtThrown is CancellationException
        )
        assertNull(
            "completeTransaction must not return a Result when CancellationException occurs",
            resultFromCall
        )
    }

    /**
     * Negative control: a genuine server error (HTTP 500) must return [Result.failure],
     * not throw.
     */
    @OptIn(ExperimentalTime::class)
    @Test
    fun completeTransactionReturnsFailureForServerErrors() = runTest {
        val engine = MockEngine { _ ->
            respond(
                content = """{"error":"internal_error"}""",
                status = HttpStatusCode.InternalServerError,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }
        val service = buildService(engine)

        val pendingTransaction = PendingTransactionInfo(
            id = "txn-002-0000-0000-0000-000000000002",
            message = "Approve login",
            postbackUri = URL("https://example.com/mga/sps/apiauthsvc?MmfaTransactionId=txn-002"),
            factorID = UUID(0, 0),
            factorType = "userPresence",
            dataToSign = "",
            creationTime = Clock.System.now(),
            expiryTime = null,
            additionalData = emptyMap()
        )

        var resultFromCall: Result<*>? = null
        var caughtThrown: Throwable? = null

        try {
            resultFromCall = service.completeTransaction(
                transaction = pendingTransaction,
                userAction = UserAction.VERIFY,
                signedData = ""
            )
        } catch (e: CancellationException) {
            caughtThrown = e
        }

        engine.close()

        assertNull("CancellationException must not be thrown for a server error", caughtThrown)
        assertNotNull("Result must be returned for server errors", resultFromCall)
        val r3 = checkNotNull(resultFromCall)
        assertTrue("Result must be failure for HTTP 500", r3.isFailure)
        assertFalse(
            "Returned failure must not be a CancellationException",
            r3.exceptionOrNull() is CancellationException
        )
    }

    // ══════════════════════════════════════════════════════════════════════════
    // remove() cancellation tests
    // ══════════════════════════════════════════════════════════════════════════

    /**
     * Verifies that [CancellationException] is **thrown** from
     * [OnPremiseAuthenticatorService.remove], not returned as [Result.failure].
     */
    @Test
    fun removeThrowsCancellationExceptionWhenParentScopeIsCancelledMidRequest() = runTest {
        val requestStarted = CompletableDeferred<Unit>()
        val engine = hangingEngine(requestStarted)
        val service = buildService(engine)

        var resultFromCall: Result<*>? = null
        var caughtThrown: Throwable? = null

        val job = launch {
            try {
                resultFromCall = service.remove()
            } catch (e: CancellationException) {
                caughtThrown = e
                throw e
            }
        }

        requestStarted.await()
        job.cancel(CancellationException("test: scope cancelled while remove was in flight"))
        job.join()
        engine.close()

        assertNotNull("CancellationException must be thrown from remove", caughtThrown)
        assertTrue(
            "Thrown exception must be CancellationException",
            caughtThrown is CancellationException
        )
        assertNull(
            "remove must not return a Result when CancellationException occurs",
            resultFromCall
        )
    }

    /**
     * Negative control: a genuine server error (HTTP 400) from [remove] must return
     * [Result.failure], not throw.
     */
    @Test
    fun removeReturnsFailureForServerErrors() = runTest {
        val engine = MockEngine { _ ->
            respond(
                content = """{"error":"bad_request","detail":"Authenticator not found"}""",
                status = HttpStatusCode.BadRequest,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }
        val service = buildService(engine)

        var resultFromCall: Result<*>? = null
        var caughtThrown: Throwable? = null

        try {
            resultFromCall = service.remove()
        } catch (e: CancellationException) {
            caughtThrown = e
        }

        engine.close()

        assertNull("CancellationException must not be thrown for a server error", caughtThrown)
        assertNotNull("Result must be returned for server errors", resultFromCall)
        val r4 = checkNotNull(resultFromCall)
        assertTrue("Result must be failure for HTTP 400", r4.isFailure)
        assertFalse(
            "Returned failure must not be a CancellationException",
            r4.exceptionOrNull() is CancellationException
        )
    }
}
