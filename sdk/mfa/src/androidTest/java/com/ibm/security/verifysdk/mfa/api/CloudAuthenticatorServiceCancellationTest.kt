/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.mfa.api

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.ibm.security.verifysdk.core.helper.ContextHelper
import com.ibm.security.verifysdk.mfa.PendingTransactionInfo
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
 * Regression tests verifying that [CloudAuthenticatorService] does not swallow
 * [CancellationException] in its network-facing methods.
 *
 * ## Covered methods
 * - [CloudAuthenticatorService.nextTransaction]
 * - [CloudAuthenticatorService.completeTransaction]
 * - [CloudAuthenticatorService.login]
 *
 * The [refreshToken] CE behaviour is already tested in [CloudAuthenticatorServiceTest].
 * This file mirrors the structure of [OnPremiseAuthenticatorServiceCancellationTest] for
 * symmetric regression coverage on the cloud service.
 *
 * ## Why CE must not be swallowed
 *
 * Each of these methods has a broad `catch (e: Throwable)` handler that converts every
 * exception into [Result.failure]. Without an explicit CE guard before that handler:
 *
 * 1. The coroutine scope is cancelled externally (e.g. `viewModelScope` on navigation).
 * 2. The in-flight call returns `Result.failure(CancellationException)` instead of throwing —
 *    structured concurrency is silently broken.
 * 3. For [completeTransaction], the HTTP request may already have been delivered (PUT on
 *    postback URI), so the server has processed the transaction. A silent failure causes
 *    the caller to retry unnecessarily or report a false error to the user.
 */
@RunWith(AndroidJUnit4::class)
class CloudAuthenticatorServiceCancellationTest {

    @Before
    fun setup() {
        ContextHelper.init(InstrumentationRegistry.getInstrumentation().targetContext)
    }

    // ══════════════════════════════════════════════════════════════════════════
    // Helpers
    // ══════════════════════════════════════════════════════════════════════════

    /**
     * A [MockEngine] that suspends indefinitely — simulating a slow network call.
     * Signals [requestStarted] as soon as the request arrives, then suspends until
     * the coroutine is cancelled.
     */
    private fun hangingEngine(requestStarted: CompletableDeferred<Unit>): MockEngine =
        MockEngine { _ ->
            requestStarted.complete(Unit)
            awaitCancellation()
            // Unreachable — satisfies the compiler.
            respond(
                content = "",
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }

    private fun buildService(engine: MockEngine): CloudAuthenticatorService =
        CloudAuthenticatorService(
            _accessToken = "test_access_token",
            _refreshUri = URL("https://example.com/v1.0/authenticators/refresh"),
            _transactionUri = URL("https://example.com/v1.0/authenticators/transactions"),
            _authenticatorId = "test_authenticator_id",
            httpClient = HttpClient(engine)
        )

    @OptIn(ExperimentalTime::class)
    private fun buildPendingTransaction(id: String = "txn-cloud-001-aabbcc"): PendingTransactionInfo =
        PendingTransactionInfo(
            id = id,
            message = "Approve login",
            postbackUri = URL("https://example.com/v1.0/authenticators/transactions/$id"),
            factorID = UUID(0, 0),
            factorType = "userPresence",
            dataToSign = "",
            creationTime = Clock.System.now(),
            expiryTime = null,
            additionalData = emptyMap()
        )

    // ══════════════════════════════════════════════════════════════════════════
    // nextTransaction cancellation tests
    // ══════════════════════════════════════════════════════════════════════════

    /**
     * Verifies that [CancellationException] is **thrown** from
     * [CloudAuthenticatorService.nextTransaction], not returned as [Result.failure].
     *
     * Before the fix the broad `catch (e: Throwable)` in [nextTransaction] captured the CE
     * and returned `Result.failure(CancellationException)`, silently breaking structured
     * concurrency.
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
     * Negative control: a genuine server error must return [Result.failure], not throw,
     * so ordinary error handling is unaffected by the CE fix.
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
        val r1 = checkNotNull(resultFromCall)
        assertTrue("Result must be failure for HTTP 503", r1.isFailure)
        assertFalse(
            "Returned failure must not be a CancellationException",
            r1.exceptionOrNull() is CancellationException
        )
    }

    // ══════════════════════════════════════════════════════════════════════════
    // completeTransaction cancellation tests
    // ══════════════════════════════════════════════════════════════════════════

    /**
     * Verifies that [CancellationException] is **thrown** from
     * [CloudAuthenticatorService.completeTransaction], not returned as [Result.failure].
     */
    @OptIn(ExperimentalTime::class)
    @Test
    fun completeTransactionThrowsCancellationExceptionWhenParentScopeIsCancelledMidRequest() = runTest {
        val requestStarted = CompletableDeferred<Unit>()
        val engine = hangingEngine(requestStarted)
        val service = buildService(engine)
        val transaction = buildPendingTransaction()

        var resultFromCall: Result<*>? = null
        var caughtThrown: Throwable? = null

        val job = launch {
            try {
                resultFromCall = service.completeTransaction(
                    transaction = transaction,
                    userAction = UserAction.VERIFY,
                    signedData = "signed_data_stub"
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
     * Negative control: a genuine HTTP 500 from the server must return [Result.failure],
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
        val transaction = buildPendingTransaction("txn-cloud-002-ddeeff")

        var resultFromCall: Result<*>? = null
        var caughtThrown: Throwable? = null

        try {
            resultFromCall = service.completeTransaction(
                transaction = transaction,
                userAction = UserAction.VERIFY,
                signedData = "signed_data_stub"
            )
        } catch (e: CancellationException) {
            caughtThrown = e
        }

        engine.close()

        assertNull("CancellationException must not be thrown for a server error", caughtThrown)
        assertNotNull("Result must be returned for server errors", resultFromCall)
        val r2 = checkNotNull(resultFromCall)
        assertTrue("Result must be failure for HTTP 500", r2.isFailure)
        assertFalse(
            "Returned failure must not be a CancellationException",
            r2.exceptionOrNull() is CancellationException
        )
    }

    // ══════════════════════════════════════════════════════════════════════════
    // login() cancellation tests
    // ══════════════════════════════════════════════════════════════════════════

    /**
     * Verifies that [CancellationException] is **thrown** from [CloudAuthenticatorService.login],
     * not returned as [Result.failure].
     *
     * [login] already has a CE guard in the source — this test pins that behaviour so
     * future refactors cannot accidentally remove it.
     */
    @Test
    fun loginThrowsCancellationExceptionWhenParentScopeIsCancelledMidRequest() = runTest {
        val requestStarted = CompletableDeferred<Unit>()
        val engine = hangingEngine(requestStarted)
        val service = buildService(engine)

        var resultFromCall: Result<*>? = null
        var caughtThrown: Throwable? = null

        val job = launch {
            try {
                resultFromCall = service.login(
                    qrLoginEndpoint = "https://example.com/v1.0/authenticators/login",
                    code = "qr_code_abc123"
                )
            } catch (e: CancellationException) {
                caughtThrown = e
                throw e
            }
        }

        requestStarted.await()
        job.cancel(CancellationException("test: scope cancelled while login was in flight"))
        job.join()
        engine.close()

        assertNotNull("CancellationException must be thrown from login", caughtThrown)
        assertTrue(
            "Thrown exception must be CancellationException",
            caughtThrown is CancellationException
        )
        assertNull(
            "login must not return a Result when CancellationException occurs",
            resultFromCall
        )
    }

    /**
     * Negative control: a genuine HTTP 400 from the server must return [Result.failure],
     * not throw.
     */
    @Test
    fun loginReturnsFailureForServerErrors() = runTest {
        val engine = MockEngine { _ ->
            respond(
                content = """{"error":"invalid_code","error_description":"The login code has expired"}""",
                status = HttpStatusCode.BadRequest,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }
        val service = buildService(engine)

        var resultFromCall: Result<*>? = null
        var caughtThrown: Throwable? = null

        try {
            resultFromCall = service.login(
                qrLoginEndpoint = "https://example.com/v1.0/authenticators/login",
                code = "expired_code"
            )
        } catch (e: CancellationException) {
            caughtThrown = e
        }

        engine.close()

        assertNull("CancellationException must not be thrown for a server error", caughtThrown)
        assertNotNull("Result must be returned for server errors", resultFromCall)
        val r3 = checkNotNull(resultFromCall)
        assertTrue("Result must be failure for HTTP 400", r3.isFailure)
        assertFalse(
            "Returned failure must not be a CancellationException",
            r3.exceptionOrNull() is CancellationException
        )
    }
}
