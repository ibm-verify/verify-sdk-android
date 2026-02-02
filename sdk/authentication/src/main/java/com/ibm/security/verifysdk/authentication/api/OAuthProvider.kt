/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */
package com.ibm.security.verifysdk.authentication.api

import android.app.Activity
import android.content.Intent
import android.net.Uri
import androidx.activity.ComponentActivity
import androidx.activity.result.contract.ActivityResultContracts
import com.ibm.security.verifysdk.authentication.AuthenticationActivity
import com.ibm.security.verifysdk.authentication.CodeChallengeMethod
import com.ibm.security.verifysdk.authentication.DPoPHelper
import com.ibm.security.verifysdk.authentication.model.OIDCMetadataInfo
import com.ibm.security.verifysdk.authentication.model.TokenInfo
import com.ibm.security.verifysdk.core.AuthenticationException
import com.ibm.security.verifysdk.core.AuthorizationException
import com.ibm.security.verifysdk.core.helper.BaseApi
import com.ibm.security.verifysdk.core.helper.NetworkHelper
import io.ktor.client.HttpClient
import io.ktor.http.ContentType
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.http.formUrlEncode
import kotlinx.coroutines.suspendCancellableCoroutine
import org.slf4j.LoggerFactory
import java.net.MalformedURLException
import java.net.URL
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.SSLContext
import kotlin.coroutines.resume


/**
 * The OAuthProvider enables third-party applications to obtain limited access to an HTTP service,
 * either on behalf of a resource owner by orchestrating an approval interaction between the
 * resource owner and the HTTP service, or by allowing the third-party application to obtain access
 * on its own behalf.
 *
 * To use this library, the following attributes must be overridden in the `build.gradle` file
 * to specify the custom scheme that will be used for the OAuth2 redirect
 * {@see https://developer.android.com/guide/topics/manifest/data-element}:
 * - auth_redirect_scheme
 * - auth_redirect_host
 * - auth_redirect_path
 *
 * @since 3.0.0
 */
@Suppress("unused")
class OAuthProvider(val clientId: String, val clientSecret: String? = null) : BaseApi() {

    private val log = LoggerFactory.getLogger(javaClass)

    /**
     * If set to `true`, SSL validation checks will be disabled.
     *
     * Be careful when turning this on, as it will be valid for all subsequent calls until set
     * to `false`. If set to `false`, to engine will always be the default provided.
     *
     * @version 3.0.0
     */
    var ignoreSsl: Boolean = false
        set(value) {
            field = value

            if (value) {
                NetworkHelper.trustManager = NetworkHelper.insecureTrustManager()
                NetworkHelper.sslContext = SSLContext.getInstance("TLS").apply {
                    init(
                        null,
                        arrayOf(NetworkHelper.trustManager),
                        java.security.SecureRandom()
                    )
                }
                NetworkHelper.hostnameVerifier = HostnameVerifier { _, _ -> true }
            } else {
                NetworkHelper.trustManager = null
                NetworkHelper.sslContext = null
                NetworkHelper.hostnameVerifier = null
            }
            NetworkHelper.initialize()
        }

    /**
     * If set to `true`, DPoP (Demonstrating Proof-of-Possession) headers will be included
     * in token requests and token refresh requests.
     *
     * When enabled, a DPoP proof token will be automatically generated and included in the
     * "DPoP" header for OAuth 2.0 token endpoint requests.
     *
     * @version 3.1.0
     */
    var useDPoP: Boolean = false

    /**
     * The key alias to use for DPoP key storage in the Android KeyStore.
     *
     * Defaults to [DPoPHelper.DEFAULT_KEY_ALIAS]. Set this to a custom value if you want
     * to use a different key for DPoP operations.
     *
     * @version 3.1.0
     */
    var dpopKeyAlias: String = DPoPHelper.DEFAULT_KEY_ALIAS

    var additionalHeaders: MutableMap<String, String> = mutableMapOf()
    var additionalParameters: MutableMap<String, String> = mutableMapOf()

    constructor(
        clientId: String,
        clientSecret: String? = null,
        additionalHeaders: Map<String, String>? = null,
        additionalParameters: Map<String, String>?,
    ) : this(clientId, clientSecret) {
        additionalHeaders?.let {
            this.additionalHeaders = it.toMutableMap()
        }

        additionalParameters?.let {
            this.additionalParameters = it.toMutableMap()
        }
    }

    /**
     * Discover the authorization service configuration from a compliant OpenID Connect endpoint.
     *
     * @param   httpClient The [HttpClient] used to make the network request.
     * @param   url  The `URL` for the OpenID Connect service provider issuer.
     *
     * @return
     *
     */
    suspend fun discover(
        httpClient: HttpClient = NetworkHelper.getInstance,
        url: URL
    ): Result<OIDCMetadataInfo> {

        return try {
            if (url.path.endsWith(".well-known/openid-configuration", ignoreCase = true).not()) {
                return Result.failure(MalformedURLException("The URL does not end with the .well-known/openid-configuration path component."))
            }

            performRequest(
                httpClient = httpClient,
                url = url
            )
        } catch (e: Throwable) {
            Result.failure(e)
        }
    }

    /**
     * Launches Chrome Custom Tabs to initiate the authorization code (AZN) flow using optional
     * Proof Key for Code Exchange (PKCE).
     *
     * @param   url   The `URL` to the authorize endpoint for the OpenID Connect service provider
     *                  issuer.
     * @param   redirectUrl  The redirect `URL` that is registered with the OpenID Connect service provider.
     * @param   codeChallenge   A challenge derived from a code verifier for support PKCE operations.
     * @param   method  The hash method used to derive code challenge.
     * @param   scope  The scope of the access request. Default is **openid**.
     * @param   state  An opaque value used by the client to maintain state between the request and
     *                  callback.  The authorization server includes this value when redirecting
     *                  back to the client.
     * @param   activity  The activity invoking this method.
     *
     * @return  [Result] with the `code` to be used in the subsequent authorization request or
     *                  with `Throwable` in case of an error.
     */
    suspend fun authorizeWithBrowser(
        url: URL,
        redirectUrl: String,
        codeChallenge: String? = null,
        method: CodeChallengeMethod = CodeChallengeMethod.PLAIN,
        scope: Array<String>? = null,
        state: String? = null,
        activity: ComponentActivity
    ): Result<String> {

        return try {
            val uriBuilder = Uri.Builder()
            var myScope = scope ?: arrayOf("openid")

            uriBuilder.scheme((url.protocol))
                .encodedAuthority(url.authority)
                .appendEncodedPath(url.path)
                .appendQueryParameter("response_type", "code")
                .appendQueryParameter("client_id", clientId)
                .appendQueryParameter("redirect_uri", redirectUrl)

            codeChallenge?.let {
                uriBuilder.appendQueryParameter("code_challenge", codeChallenge)
                uriBuilder.appendQueryParameter("code_challenge_method", method.name)
            }

            if (myScope.contains("openid").not()) {
                myScope = myScope.plus("openid")
            }
            uriBuilder.appendQueryParameter("scope", myScope.joinToString(" "))

            state?.let { uriBuilder.appendQueryParameter("state", it) }
            additionalParameters.forEach {
                uriBuilder.appendQueryParameter(it.key, it.value)
            }

            val intent = Intent(activity, AuthenticationActivity::class.java)
            intent.putExtra("url", uriBuilder.build().toString())

            suspendCancellableCoroutine { continuation ->
                val getCode = activity.activityResultRegistry.register(
                    "code",
                    ActivityResultContracts.StartActivityForResult()
                ) { result ->
                    if (result.resultCode == Activity.RESULT_OK) {
                        result.data?.getStringExtra("code")?.let {
                            continuation.resume(Result.success(it), null)
                        } ?: run {
                            continuation.resume(
                                Result.failure(
                                    AuthorizationException(
                                        HttpStatusCode.OK,
                                        "ISVSDKOP01",
                                        "Authorization code not found"
                                    )
                                )
                            )
                        }
                    } else {
                        continuation.resume(
                            Result.failure(
                                AuthenticationException(
                                    HttpStatusCode.OK,
                                    "ISVSDKOP02",
                                    "Authentication canceled"
                                )
                            )
                        )
                    }
                }
                getCode.launch(intent)

                continuation.invokeOnCancellation {
                    getCode.unregister()
                }
            }
        } catch (e: Throwable) {
            Result.failure(e)
        }
    }

    /**
     * The authorization code is obtained by using an authorization server as an intermediary
     * between the client and resource owner.
     *
     * @param   httpClient  The [HttpClient] used to make the network request.
     * @param   url  The `URL` for the OpenID Connect service provider issuer.
     * @param   redirectUrl  The redirect URL that is registered with the OpenID Connect service
     *                      provider. This parameter is required when the code was obtained through
     *                      `authorizeWithBrowser`. Can be null if not required by the authorization server.
     * @param   authorizationCode  The authorization code received from the authorization server.
     * @param   codeVerifier  The PKCE code verifier used to redeem the authorization code.
     * @param   scope  The scope of the access request.
     *
     * @return
     */
    suspend fun authorize(
        httpClient: HttpClient = NetworkHelper.getInstance,
        url: URL,
        redirectUrl: String? = null,
        authorizationCode: String,
        codeVerifier: String? = null,
        scope: Array<String>? = null
    ): Result<TokenInfo> {

        return try {
            val formData = mutableMapOf(
                "client_id" to clientId,
                "code" to authorizationCode,
                "code_verifier" to (codeVerifier ?: ""),
                "grant_type" to "authorization_code",
                "redirect_uri" to (redirectUrl ?: "")
            )

            clientSecret?.let {
                formData["client_secret"] = it
            }

            codeVerifier?.let {
                formData["code_verifier"] = it
            }

            scope?.let {
                formData["scope"] = it.joinToString(separator = " ")
            }

            val headers = additionalHeaders.toMutableMap()
            if (useDPoP) {
                val dpopToken = DPoPHelper.generateDPoPToken(
                    htu = url.toString(),
                    htm = "POST",
                    accessToken = null,
                    keyAlias = dpopKeyAlias
                )
                headers["DPoP"] = dpopToken
            }

            performRequest<TokenInfo>(
                httpClient = httpClient,
                method = HttpMethod.Post,
                url = url,
                headers = headers,
                contentType = ContentType.Application.FormUrlEncoded,
                body = (formData.toList() + additionalParameters.toList()).formUrlEncode()
            )
        } catch (e: Throwable) {
            Result.failure(e)
        }
    }

    /**
     * Asynchronously authorizes a user by making a request to the provided URL using the given credentials.
     *
     * This function sends a POST request to the authorization server with the specified username,
     * password, and optional scope. It returns a [Result] containing a [TokenInfo] object if the
     * authorization is successful, or an exception if an error occurs.
     *
     * @param httpClient The [HttpClient] used to make the network request.
     * @param url The [URL] of the authorization endpoint.
     * @param username The username used for authentication.
     * @param password The password used for authentication.
     * @param scope An optional array of scopes to request authorization for. If no scopes are provided,
     *              an empty scope will be used.
     * @return A [Result] containing a [TokenInfo] object if authorization is successful, or an
     *         exception if the request fails.
     */
    suspend fun authorize(
        httpClient: HttpClient = NetworkHelper.getInstance,
        url: URL,
        username: String,
        password: String,
        scope: Array<String>? = null
    ): Result<TokenInfo> {

        return try {
            val formData = mutableMapOf(
                "client_id" to clientId,
                "username" to username,
                "password" to password,
                "grant_type" to "password",
            )

            clientSecret?.let {
                formData["client_secret"] = it
            }

            scope?.let {
                formData["scope"] = it.joinToString(separator = " ")
            }

            val headers = additionalHeaders.toMutableMap()
            if (useDPoP) {
                val dpopToken = DPoPHelper.generateDPoPToken(
                    htu = url.toString(),
                    htm = "POST",
                    accessToken = null,
                    keyAlias = dpopKeyAlias
                )
                headers["DPoP"] = dpopToken
            }

            performRequest<TokenInfo>(
                httpClient = httpClient,
                method = HttpMethod.Post,
                url = url,
                headers = headers,
                contentType = ContentType.Application.FormUrlEncoded,
                body = (formData.toList() + additionalParameters.toList()).formUrlEncode()
            )
        } catch (e: Throwable) {
            Result.failure(e)
        }
    }

    /**
     * Refresh tokens are issued to the client by the authorization server and are used to obtain a
     * new access token when the current access token becomes invalid or expires, or to obtain
     * additional access tokens with identical or narrower scope.
     *
     * Because refresh tokens are typically long-lasting credentials used to request additional
     * access tokens, the refresh token is bound to the client to which it was issued.
     *
     * @param   httpClient The [HttpClient] used to make the network request.
     * @param   url  The `URL` for the OpenID Connect service provider issuer.
     * @param   refreshToken  The refresh token previously issued by the authorization server.
     * @param   scope  The scope of the access request.  The requested scope must not include any
     *                  scope not originally granted by the resource owner, and if omitted is
     *                  treated as equal to the scope originally granted by the resource owner.
     *
     * @return
     */
    suspend fun refresh(
        httpClient: HttpClient = NetworkHelper.getInstance,
        url: URL,
        refreshToken: String,
        scope: Array<String>? = null
    ): Result<TokenInfo> {

        return try {
            val formData = mutableMapOf(
                "client_id" to clientId,
                "refresh_token" to refreshToken,
                "grant_type" to "refresh_token",
            )

            clientSecret?.let {
                formData["client_secret"] = it
            }

            scope?.let {
                formData["scope"] = it.joinToString(separator = " ")
            }

            val headers = additionalHeaders.toMutableMap()
            if (useDPoP) {
                val dpopToken = DPoPHelper.generateDPoPToken(
                    htu = url.toString(),
                    htm = "POST",
                    accessToken = null,
                    keyAlias = dpopKeyAlias
                )
                headers["DPoP"] = dpopToken
            }

            performRequest<TokenInfo>(
                httpClient = httpClient,
                method = HttpMethod.Post,
                url = url,
                headers = headers,
                contentType = ContentType.Application.FormUrlEncoded,
                body = (formData.toList() + additionalParameters.toList()).formUrlEncode()
            )
        } catch (e: Throwable) {
            Result.failure(e)
        }
    }
}
