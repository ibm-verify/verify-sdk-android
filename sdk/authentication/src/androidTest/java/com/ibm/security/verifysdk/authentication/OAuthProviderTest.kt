package com.ibm.security.verifysdk.authentication

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.ibm.security.verifysdk.authentication.api.OAuthProvider
import com.ibm.security.verifysdk.core.helper.ErrorResponse
import com.ibm.security.verifysdk.core.helper.NetworkHelper
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.client.engine.mock.respondError
import io.ktor.client.engine.mock.toByteArray
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.plugins.logging.ANDROID
import io.ktor.client.plugins.logging.LogLevel
import io.ktor.client.plugins.logging.Logger
import io.ktor.client.plugins.logging.Logging
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import io.ktor.serialization.kotlinx.json.json
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.MissingFieldException
import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Ignore
import org.junit.Test
import org.junit.runner.RunWith
import org.slf4j.LoggerFactory
import java.net.MalformedURLException
import java.net.URL


@ExperimentalSerializationApi
@RunWith(AndroidJUnit4::class)
internal class OAuthProviderTest {

    @Suppress("unused")
    private val log: org.slf4j.Logger = LoggerFactory.getLogger(javaClass)

    companion object {

        private const val CLIENTID = "clientId"
        private const val CLIENTSECRET = "clientSecret"
        private var oAuthProvider = OAuthProvider(CLIENTID, CLIENTSECRET)
        private lateinit var mockEngine: MockEngine
        private lateinit var httpClient: HttpClient

        @BeforeClass
        @JvmStatic
        fun setUp() {
            oAuthProvider = OAuthProvider(CLIENTID, CLIENTSECRET)
            mockEngine = MockEngine { request ->
                respond("", HttpStatusCode.OK, headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString()))
            }
            httpClient = HttpClient(mockEngine) {
                install(Logging) {
                    logger = Logger.ANDROID
                    level = LogLevel.ALL
                }
                install(ContentNegotiation) {
                    json(Json {
                        isLenient = true
                        ignoreUnknownKeys = true
                    })
                }
            }
            NetworkHelper.initialize(httpClientEngine = mockEngine)
        }
    }

    @Before
    fun initialize() {
        mockEngine.config.requestHandlers.clear()
        oAuthProvider.additionalHeaders.clear()
        oAuthProvider.additionalParameters.clear()
    }

    @Test
    fun refresh_clientSecretIsNull_shouldReturnSuccess() = runTest {
        val oAuthProviderSecretNull = OAuthProvider(CLIENTID, null)
        mockEngine.config.addHandler { request ->
            if (request.method == HttpMethod.Post && request.url.encodedPath.trimEnd('/') == "/v1.0/authenticators/registration") {
                respond(responseRefreshOk, HttpStatusCode.OK, headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString()))
            } else {
                respondError(HttpStatusCode.NotFound)
            }
        }

        val result =
            oAuthProviderSecretNull.refresh(
                httpClient = httpClient,
                url = URL("http://localhost/v1.0/authenticators/registration"),
                refreshToken = "abc123def",
            )

        assertTrue(result.isSuccess)
        result.onSuccess { token ->
            assertEquals("Bearer", token.tokenType)
            assertEquals("A7y0nh0aaDpz8g0aTcVVBnr6veTocbYLpH7K8Jqn", token.accessToken)
            assertEquals(7200, token.expiresIn)
        }
    }

    @Test
    fun refresh_cancellationDuringRequest_shouldRethrowCancellationException() = runTest {
        val requestStarted = CompletableDeferred<Unit>()
        val client = HttpClient(MockEngine {
            requestStarted.complete(Unit)
            awaitCancellation()
        })
        var result: Result<*>? = null
        var cancellation: CancellationException? = null

        val job = launch {
            try {
                result = oAuthProvider.refresh(
                    httpClient = client,
                    url = URL("http://localhost/v1.0/authenticators/registration"),
                    refreshToken = "abc123def"
                )
            } catch (e: CancellationException) {
                cancellation = e
            }
        }

        requestStarted.await()
        job.cancel()
        job.join()
        client.close()

        assertTrue("refresh must rethrow cancellation", cancellation != null)
        assertTrue("refresh must not return a failure result for cancellation", result == null)
    }

    @Test
    fun refresh_withScope_shouldReturnSuccess() = runTest {
        mockEngine.config.addHandler { request ->
            if (request.method == HttpMethod.Post && request.url.encodedPath.trimEnd('/') == "/v1.0/authenticators/registration") {
                respond(responseRefreshOk, HttpStatusCode.OK, headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString()))
            } else {
                respondError(HttpStatusCode.NotFound)
            }
        }

        val result =
            oAuthProvider.refresh(
                httpClient = httpClient,
                url = URL("http://localhost/v1.0/authenticators/registration"),
                "abc123def",
                scope = arrayOf("name", "age")
            )

        assertTrue(result.isSuccess)
        result.onSuccess { token ->
            assertEquals("Bearer", token.tokenType)
            assertEquals("A7y0nh0aaDpz8g0aTcVVBnr6veTocbYLpH7K8Jqn", token.accessToken)
            assertEquals(7200, token.expiresIn)
        }
    }

    @Test
    fun refresh_happyPath_shouldReturnSuccess() = runTest {
        mockEngine.config.addHandler { request ->
            if (request.method == HttpMethod.Post && request.url.encodedPath.trimEnd('/') == "/v1.0/authenticators/registration") {
                respond(responseRefreshOk, HttpStatusCode.OK, headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString()))
            } else {
                respondError(HttpStatusCode.NotFound)
            }
        }

        val result =
            oAuthProvider.refresh(
                httpClient = httpClient,
                url = URL("http://localhost/v1.0/authenticators/registration"),
                "abc123def",
                scope = arrayOf("name", "age")
            )

        assertTrue(result.isSuccess)
        result.onSuccess { token ->
            assertEquals("Bearer", token.tokenType)
            assertEquals("A7y0nh0aaDpz8g0aTcVVBnr6veTocbYLpH7K8Jqn", token.accessToken)
            assertEquals(7200, token.expiresIn)
        }
    }

    @Test
    fun refresh_emptyBody_shouldReturnFailure() = runTest {
        mockEngine.config.addHandler { request ->
            if (request.method == HttpMethod.Post && request.url.encodedPath.trimEnd('/') == "/v1.0/authenticators/registration") {
                respond(responseRefreshFailed, HttpStatusCode.BadRequest, headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString()))
            } else {
                respondError(HttpStatusCode.NotFound)
            }
        }

        val result =
            oAuthProvider.refresh(
                httpClient = httpClient,
                url = URL("http://localhost/v1.0/authenticators/registration"),
                refreshToken = ""
            )

        assertTrue(result.isFailure)

        result.onFailure { throwable ->
            assertTrue(throwable is ErrorResponse)
            assertEquals(HttpStatusCode.BadRequest, (throwable as ErrorResponse).statusCode)
            assertTrue(throwable.responseBody?.contains("CSIAK2802E") ?: false)
        }
    }

    @Test
    fun authorize_codeHappyPath_shouldReturnSuccess() = runTest {
        mockEngine.config.addHandler { request ->
            if (request.method == HttpMethod.Post && request.url.encodedPath.trimEnd('/') == "/oauth2/token") {
                respond(responseAuthorizeOk, HttpStatusCode.OK, headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString()))
            } else {
                respondError(HttpStatusCode.NotFound)
            }
        }

        val result =
            oAuthProvider.authorize(
                url = URL("http://localhost/oauth2/token"),
                redirectUrl = "https://callback",
                authorizationCode = "authorizationCode",
                codeVerifier = "codeVerifier",
                scope = arrayOf("name", "age")
            )

        assertTrue(result.isSuccess)
        result.onSuccess { token ->
            assertEquals("A7y0nh0aaDpz8g0aTcVVBnr6veTocbYLpH7K8Jqn", token.accessToken)
        }
    }

    @Test
    fun authorize_codeVerifierIsNull_shouldReturnSuccess() = runTest {
        mockEngine.config.addHandler { request ->
            if (request.method == HttpMethod.Post && request.url.encodedPath.trimEnd('/') == "/oauth2/token") {
                respond(responseAuthorizeOk, HttpStatusCode.OK, headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString()))
            } else {
                respondError(HttpStatusCode.NotFound)
            }
        }

        val result =
            oAuthProvider.authorize(
                url = URL("http://localhost/oauth2/token"),
                redirectUrl = "https://callback",
                authorizationCode = "authorizationCode",
                codeVerifier = null,
                scope = arrayOf("name", "age")
            )

        assertTrue(result.isSuccess)
        result.onSuccess { token ->
            assertEquals("A7y0nh0aaDpz8g0aTcVVBnr6veTocbYLpH7K8Jqn", token.accessToken)
        }
    }

    @Test
    fun authorize_codeClientSecretIsNull_shouldReturnSuccess() = runTest {
        val oAuthProviderSecretNull =
            OAuthProvider(CLIENTID, null)
        mockEngine.config.addHandler { request ->
            if (request.method == HttpMethod.Post && request.url.encodedPath.trimEnd('/') == "/oauth2/token") {
                respond(responseAuthorizeOk, HttpStatusCode.OK, headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString()))
            } else {
                respondError(HttpStatusCode.NotFound)
            }
        }
        val result =
            oAuthProviderSecretNull.authorize(
                url = URL("http://localhost:4444/oauth2/token"),
                redirectUrl = "https://callback",
                authorizationCode = "authorizationCode",
                codeVerifier = "codeVerifier",
                scope = arrayOf("name", "age")
            )

        mockEngine.requestHistory.last().let { requestData ->
            val requestBody = requestData.body.toByteArray().toString(Charsets.UTF_8)
            assertTrue(requestBody.contains("code_verifier=codeVerifier"))
            assertTrue(requestBody.contains("grant_type=authorization_code"))
            assertTrue(requestBody.contains("scope=name+age"))
        }

        assertTrue(result.isSuccess)
        result.onSuccess { token ->
            assertEquals("A7y0nh0aaDpz8g0aTcVVBnr6veTocbYLpH7K8Jqn", token.accessToken)
        }
    }

    @Test
    fun authorize_codeServerError_shouldReturnFailure() = runTest {
        mockEngine.config.addHandler { request ->
            if (request.method == HttpMethod.Post && request.url.encodedPath.trimEnd('/') == "/oauth2/token") {
                respond("", HttpStatusCode.InternalServerError, headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString()))
            } else {
                respondError(HttpStatusCode.NotFound)
            }
        }
        val result =
            oAuthProvider.authorize(
                url = URL("http://localhost:4444/oauth2/token"),
                redirectUrl = "https://callback",
                authorizationCode = "authorizationCode",
                codeVerifier = "codeVerifier",
                scope = arrayOf("name", "age")
            )

        assertTrue(result.isFailure)
        result.onFailure { it ->
            assertTrue(it is ErrorResponse)
        }
    }

    @Test
    fun authorize_codeEmptyBody_shouldReturnFailure() = runTest {
        mockEngine.config.addHandler { request ->
            if (request.method == HttpMethod.Post && request.url.encodedPath.trimEnd('/') == "/oauth2/token") {
                respond("", HttpStatusCode.OK, headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString()))
            } else {
                respondError(HttpStatusCode.NotFound)
            }
        }
        val result =
            oAuthProvider.authorize(
                url = URL("http://localhost:4444/oauth2/token"),
                redirectUrl = "https://callback",
                authorizationCode = "authorizationCode",
                codeVerifier = "codeVerifier",
                scope = arrayOf("name", "age")
            )

        mockEngine.requestHistory.last().let { requestData ->
            val requestBody = requestData.body.toByteArray().toString(Charsets.UTF_8)
            assertTrue(requestBody.contains("code_verifier=codeVerifier"))
            assertTrue(requestBody.contains("grant_type=authorization_code"))
            assertTrue(requestBody.contains("scope=name+age"))
        }

        assertTrue(result.isFailure)
        result.onFailure {
            assertTrue(
                it.message.toString()
                    .contains("Expected start of the object '{', but had 'EOF' instead")
            )
        }
    }


    @Test
    fun authorize_credsHappyPath_shouldReturnSuccess() = runTest {
        mockEngine.config.addHandler { request ->
            if (request.method == HttpMethod.Post && request.url.encodedPath.trimEnd('/') == "/oauth2/token") {
                respond(responseAuthorizeOk, HttpStatusCode.OK, headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString()))
            } else {
                respondError(HttpStatusCode.NotFound)
            }
        }
        val result =
            oAuthProvider.authorize(
                url = URL("http://localhost:44444/oauth2/token"),
                username = "username",
                password = "password",
                scope = arrayOf("name", "age")
            )

        mockEngine.requestHistory.last().let { requestData ->
            val requestBody = requestData.body.toByteArray().toString(Charsets.UTF_8)
            assertTrue(requestBody.contains("client_id=clientId"))
            assertTrue(requestBody.contains("client_secret=clientSecret"))
            assertTrue(requestBody.contains("username=username"))
            assertTrue(requestBody.contains("grant_type=password"))
            assertTrue(requestBody.contains("scope=name+age"))
        }

        assertTrue(result.isSuccess)
        result.onSuccess { token ->
            assertEquals("A7y0nh0aaDpz8g0aTcVVBnr6veTocbYLpH7K8Jqn", token.accessToken)
        }
    }

    @Test
    fun authorize_credsWithScope_shouldReturnSuccess() = runTest {
        mockEngine.config.addHandler { request ->
            if (request.method == HttpMethod.Post && request.url.encodedPath.trimEnd('/') == "/oauth2/token") {
                respond(responseAuthorizeOk, HttpStatusCode.OK, headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString()))
            } else {
                respondError(HttpStatusCode.NotFound)
            }
        }
        val result =
            oAuthProvider.authorize(
                url = URL("http://localhost:44444/oauth2/token"),
                username = "username",
                password = "password",
                scope = arrayOf("name", "age")
            )

        mockEngine.requestHistory.last().let { requestData ->
            val requestBody = requestData.body.toByteArray().toString(Charsets.UTF_8)
            assertTrue(requestBody.contains("client_id=clientId"))
            assertTrue(requestBody.contains("client_secret=clientSecret"))
            assertTrue(requestBody.contains("username=username"))
            assertTrue(requestBody.contains("grant_type=password"))
            assertTrue(requestBody.contains("scope=name+age"))
        }

        assertTrue(result.isSuccess)
        result.onSuccess { token ->
            assertEquals("A7y0nh0aaDpz8g0aTcVVBnr6veTocbYLpH7K8Jqn", token.accessToken)
        }
    }

    @Test
    @Ignore
    fun authorize_credsClientSecretIsNull_shouldReturnSuccess() = runTest {
        val oAuthProviderSecretNull =
            OAuthProvider(CLIENTID, null)

        mockEngine.config.addHandler { request ->
            if (request.method == HttpMethod.Post && request.url.encodedPath.trimEnd('/') == "/oauth2/token") {
                respond(responseAuthorizeOk, HttpStatusCode.OK, headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString()))
            } else {
                respondError(HttpStatusCode.NotFound)
            }
        }

        val result =
            oAuthProviderSecretNull.authorize(
                url = URL("http://localhost:44444/oauth2/token"),
                username = "username",
                password = "password",
                scope = arrayOf("name", "age")
            )

        mockEngine.requestHistory.last().let { requestData ->
            val requestBody = requestData.body.toByteArray().toString(Charsets.UTF_8)
            assertTrue(requestBody.contains("client_id=clientId"))
            assertTrue(requestBody.contains("client_secret=&"))
            assertTrue(requestBody.contains("username=username"))
            assertTrue(requestBody.contains("grant_type=password"))
            assertTrue(requestBody.contains("scope=name+age"))
        }

        assertTrue(result.isSuccess)
        result.onSuccess { token ->
            assertEquals("A7y0nh0aaDpz8g0aTcVVBnr6veTocbYLpH7K8Jqn", token.accessToken)
        }
    }

    @Test
    fun authorize_credsEmptyBody_shouldReturnFailure() = runTest {
        mockEngine.config.addHandler { request ->
            if (request.method == HttpMethod.Post && request.url.encodedPath.trimEnd('/') == "/oauth2/token") {
                respond("", HttpStatusCode.OK, headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString()))
            } else {
                respondError(HttpStatusCode.NotFound)
            }
        }
        val result =
            oAuthProvider.authorize(
                url = URL("http://localhost:44444/oauth2/token"),
                username = "username",
                password = "password"
            )

        assertTrue(result.isFailure)
        result.onFailure {
            assertTrue(
                it.message.toString()
                    .contains("Expected start of the object '{', but had 'EOF' instead")
            )
        }
    }

    @Test
    fun authorize_credsServerError_shouldReturnFailure() = runTest {
        mockEngine.config.addHandler { request ->
            if (request.method == HttpMethod.Post && request.url.encodedPath.trimEnd('/') == "/oauth2/token") {
                respond("", HttpStatusCode.InternalServerError, headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString()))
            } else {
                respondError(HttpStatusCode.NotFound)
            }
        }

        val result =
            oAuthProvider.authorize(
                url = URL("http://localhost:44444/oauth2/token"),
                username = "username",
                password = "password"
            )

        assertTrue(result.isFailure)
        result.onFailure { throwable ->
            assertTrue(throwable is ErrorResponse)
            assertEquals(HttpStatusCode.InternalServerError, (throwable as ErrorResponse).statusCode)
        }
    }


    @Test
    fun authorize_credsResponseUnknownJson_shouldReturnSuccess() = runTest {
        mockEngine.config.addHandler { request ->
            if (request.method == HttpMethod.Post && request.url.encodedPath.trimEnd('/') == "/oauth2/token") {
                respond(responseAuthorizeOk, HttpStatusCode.OK, headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString()))
            } else {
                respondError(HttpStatusCode.NotFound)
            }
        }
        val result =
            oAuthProvider.authorize(
                url = URL("http://localhost:44444/oauth2/token"),
                username = "username",
                password = "password"
            )

        assertTrue(result.isSuccess)
        result.onSuccess {
            assertEquals("A7y0nh0aaDpz8g0aTcVVBnr6veTocbYLpH7K8Jqn", it.accessToken)
            assertEquals(7200, it.expiresIn)
        }
    }

    @Test
    fun discover_serverError_shouldReturnFailure() = runTest {

        mockEngine.config.addHandler { request ->
            if (request.method == HttpMethod.Get && request.url.encodedPath.trimEnd('/') == "/.well-known/openid-configuration") {
                respond("{}", HttpStatusCode.InternalServerError, headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString()))
            } else {
                respondError(HttpStatusCode.NotFound)
            }
        }
        val result =
            oAuthProvider.discover(
                url = URL("http://localhost:44444/.well-known/openid-configuration")
            )

        assertTrue(result.isFailure)
        result.onFailure { it ->
            assertTrue(it is ErrorResponse)
        }
    }


    @Test
    fun discover_happyPath_shouldReturnSuccess() = runTest {
        mockEngine.config.addHandler { request ->
            if (request.method == HttpMethod.Get && request.url.encodedPath.trimEnd('/') == "/.well-known/openid-configuration") {
                respond(responseDiscoveryOk, HttpStatusCode.OK, headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString()))
            } else {
                respondError(HttpStatusCode.NotFound)
            }
        }
        val result =
            oAuthProvider.discover(
                url = URL("http://localhost:44444/.well-known/openid-configuration")
            )

        assertTrue(result.isSuccess)
        result.onSuccess {
            assertEquals(13, it.idTokenSigningAlgValuesSupported.size)
            assertEquals("https://sdk.verify.ibm.com/oauth2/token", it.tokenEndpoint)
        }
    }

    @Test
    fun discover_wrongUrlPath_shouldReturnFailure() = runTest {

        val result = oAuthProvider.discover(
            url = URL("https://localhost")
        )
        assertTrue(result.isFailure)
        result.onFailure {
            assertTrue(it is MalformedURLException)
        }
    }

    @Test
    fun discover_fieldsMissingInResponse_shouldReturnFailure() = runTest {
        mockEngine.config.addHandler { request ->
            if (request.method == HttpMethod.Get && request.url.encodedPath.trimEnd('/') == "/.well-known/openid-configuration") {
                respond("{\"foo\":\"bar\"}", HttpStatusCode.OK, headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString()))
            } else {
                respondError(HttpStatusCode.NotFound)
            }
        }
        val result =
            oAuthProvider.discover(
                url = URL("http://localhost:44444/.well-known/openid-configuration")
            )

        assertTrue(result.isFailure)
        result.onFailure {
            assertTrue(it is MissingFieldException)
            assertTrue(it.message?.contains("but they were missing at path") ?: false)
        }
    }

    @Test
    fun constructor_withAdditionalData_shouldReturnInstance() {

        val headers = HashMap<String, String>()
        headers["key1"] = "value1"

        val parameters = HashMap<String, String>()
        parameters["key2"] = "value2"

        val oAuthProvider = OAuthProvider(CLIENTID, CLIENTSECRET, headers, parameters)
        assertEquals(1, oAuthProvider.additionalHeaders.size)
        assertEquals(1, oAuthProvider.additionalParameters.size)
        assertEquals("value1", oAuthProvider.additionalHeaders["key1"])
        assertEquals("value2", oAuthProvider.additionalParameters["key2"])
    }

    @Test
    fun constructor_withAdditionalDataAsNull_shouldReturnInstance() {

        val oAuthProvider = OAuthProvider(CLIENTID, CLIENTSECRET, null, null)
        assertEquals(0, oAuthProvider.additionalHeaders.size)
        assertEquals(0, oAuthProvider.additionalParameters.size)
    }

    @Test
    fun getAdditionalHeaders() {
        assertEquals(0, oAuthProvider.additionalHeaders.size)
    }

    @Test
    fun setAdditionalHeaders() {
        assertEquals(0, oAuthProvider.additionalHeaders.size)
        oAuthProvider.additionalHeaders["key1"] = "value1"
        assertEquals(1, oAuthProvider.additionalHeaders.size)
        assertEquals("value1", oAuthProvider.additionalHeaders["key1"])

        val headers = HashMap<String, String>()
        headers["key2"] = "value2"
        oAuthProvider.additionalHeaders = headers
        assertEquals(1, oAuthProvider.additionalHeaders.size)
        assertEquals("value2", oAuthProvider.additionalHeaders["key2"])
    }

    @Test
    fun getAdditionalParameters() {
        assertEquals(0, oAuthProvider.additionalParameters.size)
    }

    @Test
    fun setAdditionalParameters() {
        assertEquals(0, oAuthProvider.additionalParameters.size)
        oAuthProvider.additionalParameters["key1"] = "value1"
        assertEquals(1, oAuthProvider.additionalParameters.size)
        assertEquals("value1", oAuthProvider.additionalParameters["key1"])

        val parameters = HashMap<String, String>()
        parameters["key2"] = "value2"
        oAuthProvider.additionalParameters = parameters
        assertEquals(1, oAuthProvider.additionalParameters.size)
        assertEquals("value2", oAuthProvider.additionalParameters["key2"])
    }


    @Test
    fun getClientId() {
        assertEquals("clientId", oAuthProvider.clientId)
    }

    @Test
    fun getClientSecret() {
        assertEquals("clientSecret", oAuthProvider.clientSecret)
    }

    // -------------------------------------------------------------------------
    // buildAuthorizeUri — double-slash regression tests
    // -------------------------------------------------------------------------

    @Test
    fun buildAuthorizeUri_pathWithLeadingSlash_shouldNotProduceDoubleSlash() {
        // java.net.URL.getPath() always returns a leading '/' (e.g. "/authorize").
        // Uri.Builder.appendEncodedPath() inserts a '/' separator, so naively passing
        // url.path produced "https://host//authorize". trimStart('/') fixes this.
        val url = URL("https://auth.example.com/authorize")
        val uri = oAuthProvider.buildAuthorizeUri(url, "myapp://callback")
        val uriString = uri.toString()

        // indexOf("//", 7) skips the "https://" at position 0-7
        assertTrue("URI must not contain '//' after the scheme", uriString.indexOf("//", 7) == -1)
        assertTrue("URI must start with 'https://auth.example.com'", uriString.startsWith("https://auth.example.com"))
        assertTrue("URI must contain '/authorize'", uriString.contains("/authorize"))
    }

    @Test
    fun buildAuthorizeUri_deepPath_shouldNotProduceDoubleSlash() {
        val url = URL("https://example.com/oauth2/authorize")
        val uri = oAuthProvider.buildAuthorizeUri(url, "myapp://callback")
        val uriString = uri.toString()

        assertTrue("URI must not contain '//' after the scheme", uriString.indexOf("//", 7) == -1)
        assertTrue("path must be '/oauth2/authorize'", uriString.contains("/oauth2/authorize"))
    }

    @Test
    fun buildAuthorizeUri_requiredQueryParams_shouldBePresent() {
        val url = URL("https://example.com/authorize")
        val uri = oAuthProvider.buildAuthorizeUri(url, "myapp://callback")
        val uriString = uri.toString()

        assertTrue(uriString.contains("response_type=code"))
        assertTrue(uriString.contains("client_id=clientId"))
        assertTrue(uriString.contains("redirect_uri=myapp%3A%2F%2Fcallback"))
        assertTrue(uriString.contains("scope=openid"))
    }

    @Test
    fun buildAuthorizeUri_withCodeChallenge_shouldIncludePkceParams() {
        val url = URL("https://example.com/authorize")
        val uri = oAuthProvider.buildAuthorizeUri(
            url,
            "myapp://callback",
            codeChallenge = "abc123",
            method = CodeChallengeMethod.S256
        )
        val uriString = uri.toString()

        assertTrue(uriString.contains("code_challenge=abc123"))
        assertTrue(uriString.contains("code_challenge_method=S256"))
    }

    @Test
    fun buildAuthorizeUri_withState_shouldIncludeStateParam() {
        val url = URL("https://example.com/authorize")
        val uri = oAuthProvider.buildAuthorizeUri(url, "myapp://callback", state = "randomState42")
        assertTrue(uri.toString().contains("state=randomState42"))
    }

    @Test
    fun buildAuthorizeUri_scopeWithoutOpenid_shouldAppendOpenid() {
        val url = URL("https://example.com/authorize")
        val uri = oAuthProvider.buildAuthorizeUri(url, "myapp://callback", scope = arrayOf("profile", "email"))
        val uriString = uri.toString()

        assertTrue("scope must contain 'openid'", uriString.contains("openid"))
        assertTrue("scope must contain 'profile'", uriString.contains("profile"))
        assertTrue("scope must contain 'email'", uriString.contains("email"))
    }

    // -------------------------------------------------------------------------
    // ephemeralSession property
    // -------------------------------------------------------------------------

    @Test
    fun ephemeralSession_defaultsToFalse() {
        val provider = OAuthProvider("clientId")
        assertEquals(false, provider.ephemeralSession)
    }

    @Test
    fun ephemeralSession_canBeSetToTrue() {
        val provider = OAuthProvider("clientId")
        provider.ephemeralSession = true
        assertEquals(true, provider.ephemeralSession)
    }

    @Test
    fun ephemeralSession_doesNotAffectAuthorizeUri() {
        // ephemeralSession is forwarded to AuthenticationActivity via an Intent extra and
        // applied to CustomTabsIntent.Builder.setEphemeralBrowsingEnabled(). It must not
        // alter the authorize URI itself.
        val url = URL("https://example.com/authorize")

        val providerDefault = OAuthProvider("clientId")
        val uriDefault = providerDefault.buildAuthorizeUri(url, "myapp://callback")

        val providerEphemeral = OAuthProvider("clientId")
        providerEphemeral.ephemeralSession = true
        val uriEphemeral = providerEphemeral.buildAuthorizeUri(url, "myapp://callback")

        assertEquals(
            "Authorize URI must be identical regardless of ephemeralSession value",
            uriDefault.toString(),
            uriEphemeral.toString()
        )
    }

    @Test
    fun ephemeralSession_requiredOAuthParamsStillPresent() {
        // Smoke test: all required OAuth parameters remain present when ephemeralSession is true.
        val url = URL("https://example.com/authorize")
        val provider = OAuthProvider("clientId")
        provider.ephemeralSession = true
        val uriString = provider.buildAuthorizeUri(url, "myapp://callback").toString()

        assertTrue(uriString.contains("response_type=code"))
        assertTrue(uriString.contains("client_id=clientId"))
        assertTrue(uriString.contains("redirect_uri=myapp%3A%2F%2Fcallback"))
        assertTrue(uriString.contains("scope=openid"))
    }

    // ══════════════════════════════════════════════════════════════════════════
    // authorize() cancellation tests
    // ══════════════════════════════════════════════════════════════════════════

    /**
     * Verifies that [CancellationException] is **thrown** from
     * [OAuthProvider.authorize] (authorization-code overload), not returned as [Result.failure].
     *
     * Before the fix, `authorize` had a broad `catch (e: Throwable)` with no CE guard,
     * so a scope cancellation mid-POST would silently break structured concurrency.
     */
    @Test
    fun authorize_codeFlow_cancellationDuringRequest_shouldRethrowCancellationException() = runTest {
        val requestStarted = CompletableDeferred<Unit>()
        val client = HttpClient(MockEngine {
            requestStarted.complete(Unit)
            awaitCancellation()
        })
        var result: Result<*>? = null
        var cancellation: CancellationException? = null

        val job = launch {
            try {
                result = oAuthProvider.authorize(
                    httpClient = client,
                    url = URL("https://example.com/oauth2/token"),
                    redirectUrl = "myapp://callback",
                    authorizationCode = "authCode123",
                    codeVerifier = "verifier123"
                )
            } catch (e: CancellationException) {
                cancellation = e
            }
        }

        requestStarted.await()
        job.cancel()
        job.join()
        client.close()

        assertTrue("authorize (code flow) must rethrow cancellation", cancellation != null)
        assertTrue("authorize (code flow) must not return a failure result for cancellation", result == null)
    }

    /**
     * Verifies that [CancellationException] is **thrown** from
     * [OAuthProvider.authorize] (resource-owner password-credentials overload), not returned as
     * [Result.failure].
     */
    @Test
    fun authorize_passwordFlow_cancellationDuringRequest_shouldRethrowCancellationException() = runTest {
        val requestStarted = CompletableDeferred<Unit>()
        val client = HttpClient(MockEngine {
            requestStarted.complete(Unit)
            awaitCancellation()
        })
        var result: Result<*>? = null
        var cancellation: CancellationException? = null

        val job = launch {
            try {
                result = oAuthProvider.authorize(
                    httpClient = client,
                    url = URL("https://example.com/oauth2/token"),
                    username = "testuser@example.com",
                    password = "secret"
                )
            } catch (e: CancellationException) {
                cancellation = e
            }
        }

        requestStarted.await()
        job.cancel()
        job.join()
        client.close()

        assertTrue("authorize (password flow) must rethrow cancellation", cancellation != null)
        assertTrue("authorize (password flow) must not return a failure result for cancellation", result == null)
    }

    private val responseDiscoveryOk = """
        {
           "request_parameter_supported":true,
           "introspection_endpoint":"https://sdk.verify.ibm.com/oauth2/introspect",
           "claims_parameter_supported":true,
           "scopes_supported":[
              "openid",
              "profile",
              "email",
              "phone"
           ],
           "issuer":"https://sdk.verify.ibm.com/oauth2",
           "id_token_encryption_enc_values_supported":[
              "none",
              "A128GCM",
              "A192GCM",
              "A256GCM"
           ],
           "userinfo_encryption_enc_values_supported":[
              "none"
           ],
           "authorization_endpoint":"https://sdk.verify.ibm.com/oauth2/authorize",
           "request_object_encryption_enc_values_supported":[
              "none"
           ],
           "device_authorization_endpoint":"https://sdk.verify.ibm.com/oauth2/device_authorization",
           "userinfo_signing_alg_values_supported":[
              "none"
           ],
           "claims_supported":[
              "realmName",
              "preferred_username",
              "given_name",
              "uid",
              "upn",
              "groupIds",
              "employee_id",
              "name",
              "tenantId",
              "mobile_number",
              "department",
              "family_name",
              "job_title",
              "email",
              "iss"
           ],
           "claim_types_supported":[
              "normal"
           ],
           "token_endpoint_auth_methods_supported":[
              "client_secret_basic",
              "client_secret_post",
              "client_secret_jwt",
              "private_key_jwt"
           ],
           "response_modes_supported":[
              "query",
              "fragment",
              "form_post"
           ],
           "token_endpoint":"https://sdk.verify.ibm.com/oauth2/token",
           "response_types_supported":[
              "code",
              "none",
              "token",
              "id_token",
              "token id_token",
              "code id_token",
              "code token",
              "code token id_token"
           ],
           "user_authorization_endpoint":"https://sdk.verify.ibm.com/oauth2/user_authorization",
           "request_uri_parameter_supported":false,
           "userinfo_encryption_alg_values_supported":[
              "none"
           ],
           "grant_types_supported":[
              "authorization_code",
              "implicit",
              "client_credentials",
              "password",
              "refresh_token",
              "urn:ietf:params:oauth:grant-type:jwt-bearer",
              "urn:ietf:params:oauth:grant-type:device_code",
              "policyauth"
           ],
           "revocation_endpoint":"https://sdk.verify.ibm.com/oauth2/revoke",
           "userinfo_endpoint":"https://sdk.verify.ibm.com/oauth2/userinfo",
           "id_token_encryption_alg_values_supported":[
              "none",
              "RSA-OAEP",
              "RSA-OAEP-256"
           ],
           "jwks_uri":"https://sdk.verify.ibm.com/oauth2/jwks",
           "subject_types_supported":[
              "public"
           ],
           "id_token_signing_alg_values_supported":[
              "none",
              "HS256",
              "HS384",
              "HS512",
              "RS256",
              "RS384",
              "RS512",
              "PS256",
              "PS384",
              "PS512",
              "ES256",
              "ES384",
              "ES512"
           ],
           "registration_endpoint":"https://sdk.verify.ibm.com/oauth2/client_registration",
           "request_object_signing_alg_values_supported":[
              "none"
           ],
           "request_object_encryption_alg_values_supported":[
              "none"
           ]
        }
        """.trimIndent().trim('\n')

    private val responseAuthorizeOk = """
        {
           "access_token":"A7y0nh0aaDpz8g0aTcVVBnr6veTocbYLpH7K8Jqn",
           "grant_id":"3cd86861-9e2e-4741-b828-0910beb2f5c9",
           "token_type":"Bearer",
           "expires_in":7200
        }
        """.trimIndent().trim('\n')

    private val responseRefreshOk = """
        {
           "access_token":"A7y0nh0aaDpz8g0aTcVVBnr6veTocbYLpH7K8Jqn",
           "grant_id":"3cd86861-9e2e-4741-b828-0910beb2f5c9",
           "token_type":"Bearer",
           "expires_in":7200
        }
        """.trimIndent().trim('\n')

    private val responseRefreshFailed = """
        {
          "messageId": "CSIAK2802E",
          "messageDescription": "The required JSON property [$/attributes] is missing from the request."
        }
        """.trimIndent().trim('\n')
}