package com.ibm.security.verifysdk.authentication

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.ibm.security.verifysdk.authentication.api.OAuthProvider
import com.ibm.security.verifysdk.core.helper.ErrorResponse
import com.ibm.security.verifysdk.core.helper.NetworkHelper
import com.ibm.security.verifysdk.testutils.ApiMockEngine
import io.ktor.client.engine.mock.toByteArray
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.MissingFieldException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Ignore
import org.junit.Test
import org.junit.runner.RunWith
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.net.MalformedURLException
import java.net.URL


@ExperimentalSerializationApi
@RunWith(AndroidJUnit4::class)
internal class OAuthProviderTest {

    @Suppress("unused")
    private val log: Logger = LoggerFactory.getLogger(javaClass)

    companion object {

        private const val CLIENTID = "clientId"
        private const val CLIENTSECRET = "clientSecret"
        private var oAuthProvider = OAuthProvider(CLIENTID, CLIENTSECRET)
        private var apiMockEngine = ApiMockEngine()

        @BeforeClass
        @JvmStatic
        fun setUp() {
            oAuthProvider = OAuthProvider(CLIENTID, CLIENTSECRET)
            NetworkHelper.initialize(httpClientEngine = apiMockEngine.get())
        }
    }

    @Before
    fun initialize() {
        apiMockEngine.get().config.requestHandlers.clear()
        oAuthProvider.additionalHeaders.clear()
        oAuthProvider.additionalParameters.clear()
    }

    @Test
    fun refresh_clientSecretIsNull_shouldReturnSuccess() = runTest {
        val oAuthProviderSecretNull = OAuthProvider(CLIENTID, null)
        apiMockEngine.addMockResponse(
            method = HttpMethod.Post,
            urlPath = "/v1.0/authenticators/registration",
            httpCode = HttpStatusCode.OK,
            responseBody = responseRefreshOk
        )

        val result =
            oAuthProviderSecretNull.refresh(
                httpClient = apiMockEngine.getEngine(),
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
    fun refresh_withScope_shouldReturnSuccess() = runTest {
        apiMockEngine.addMockResponse(
            method = HttpMethod.Post,
            urlPath = "/v1.0/authenticators/registration",
            httpCode = HttpStatusCode.OK,
            responseBody = responseRefreshOk
        )

        val result =
            oAuthProvider.refresh(
                httpClient = apiMockEngine.getEngine(),
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
        apiMockEngine.addMockResponse(
            method = HttpMethod.Post,
            urlPath = "/v1.0/authenticators/registration",
            httpCode = HttpStatusCode.OK,
            responseBody = responseRefreshOk
        )

        val result =
            oAuthProvider.refresh(
                httpClient = apiMockEngine.getEngine(),
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
        apiMockEngine.addMockResponse(
            method = HttpMethod.Post,
            urlPath = "/v1.0/authenticators/registration",
            httpCode = HttpStatusCode.BadRequest,
            responseBody = responseRefreshFailed
        )

        val result =
            oAuthProvider.refresh(
                httpClient = apiMockEngine.getEngine(),
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
        apiMockEngine.addMockResponse(
            method = HttpMethod.Post,
            urlPath = "/oauth2/token",
            httpCode = HttpStatusCode.OK,
            responseBody = responseAuthorizeOk
        )

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
        apiMockEngine.addMockResponse(
            method = HttpMethod.Post,
            urlPath = "/oauth2/token",
            httpCode = HttpStatusCode.OK,
            responseBody = responseAuthorizeOk
        )

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
        apiMockEngine.addMockResponse(
            method = HttpMethod.Post,
            urlPath = "/oauth2/token",
            httpCode = HttpStatusCode.OK,
            responseBody = responseAuthorizeOk
        )
        val result =
            oAuthProviderSecretNull.authorize(
                url = URL("http://localhost:4444/oauth2/token"),
                redirectUrl = "https://callback",
                authorizationCode = "authorizationCode",
                codeVerifier = "codeVerifier",
                scope = arrayOf("name", "age")
            )

        apiMockEngine.get().requestHistory.last().let { requestData ->
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
        apiMockEngine.addMockResponse(
            method = HttpMethod.Post,
            urlPath = "/oauth2/token",
            httpCode = HttpStatusCode.InternalServerError,
            responseBody = ""
        )
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
        apiMockEngine.addMockResponse(
            HttpMethod.Post,
            "/oauth2/token",
            HttpStatusCode.OK,
            responseBody = ""
        )
        val result =
            oAuthProvider.authorize(
                url = URL("http://localhost:4444/oauth2/token"),
                redirectUrl = "https://callback",
                authorizationCode = "authorizationCode",
                codeVerifier = "codeVerifier",
                scope = arrayOf("name", "age")
            )

        apiMockEngine.get().requestHistory.last().let { requestData ->
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
        apiMockEngine.addMockResponse(
            HttpMethod.Post,
            "/oauth2/token",
            HttpStatusCode.OK,
            responseBody = responseAuthorizeOk
        )
        val result =
            oAuthProvider.authorize(
                url = URL("http://localhost:44444/oauth2/token"),
                username = "username",
                password = "password",
                scope = arrayOf("name", "age")
            )

        apiMockEngine.get().requestHistory.last().let { requestData ->
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
        apiMockEngine.addMockResponse(
            HttpMethod.Post,
            "/oauth2/token",
            HttpStatusCode.OK,
            responseBody = responseAuthorizeOk
        )
        val result =
            oAuthProvider.authorize(
                url = URL("http://localhost:44444/oauth2/token"),
                username = "username",
                password = "password",
                scope = arrayOf("name", "age")
            )

        apiMockEngine.get().requestHistory.last().let { requestData ->
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

        apiMockEngine.addMockResponse(
            HttpMethod.Post,
            "/oauth2/token",
            HttpStatusCode.OK,
            responseBody = responseAuthorizeOk
        )

        val result =
            oAuthProviderSecretNull.authorize(
                url = URL("http://localhost:44444/oauth2/token"),
                username = "username",
                password = "password",
                scope = arrayOf("name", "age")
            )

        apiMockEngine.get().requestHistory.last().let { requestData ->
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
        apiMockEngine.addMockResponse(
            HttpMethod.Post,
            "/oauth2/token",
            HttpStatusCode.OK,
            responseBody = ""
        )
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
        apiMockEngine.addMockResponse(
            HttpMethod.Post,
            "/oauth2/token",
            HttpStatusCode.InternalServerError,
            responseBody = ""
        )

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
        apiMockEngine.addMockResponse(
            HttpMethod.Post,
            "/oauth2/token",
            HttpStatusCode.OK,
            responseBody = responseAuthorizeOk
        )
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

        apiMockEngine.addMockResponse(
            HttpMethod.Get,
            "Server error",
            HttpStatusCode.InternalServerError,
            responseBody = "{}"
        )
        val result =
            oAuthProvider.discover(
                url = URL("http://localhost:44444/.well-known/openid-configuration")
            )

        assertTrue(result.isFailure)
        result.onFailure { it ->
            assertTrue(it is IllegalStateException)
        }
    }


    @Test
    fun discover_happyPath_shouldReturnSuccess() = runTest {
        apiMockEngine.addMockResponse(
            HttpMethod.Get,
            "/.well-known/openid-configuration",
            HttpStatusCode.OK,
            responseBody = responseDiscoveryOk
        )
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
        apiMockEngine.addMockResponse(
            HttpMethod.Get,
            "/.well-known/openid-configuration",
            HttpStatusCode.OK,
            responseBody = "{\"foo\":\"bar\"}"
        )
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