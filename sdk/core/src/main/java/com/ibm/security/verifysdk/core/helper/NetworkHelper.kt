/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.core.helper

import com.ibm.security.verifysdk.core.BuildConfig
import io.ktor.client.HttpClient
import io.ktor.client.HttpClientConfig
import io.ktor.client.engine.HttpClientEngine
import io.ktor.client.engine.okhttp.OkHttp
import io.ktor.client.plugins.HttpTimeout
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.plugins.logging.ANDROID
import io.ktor.client.plugins.logging.LogLevel
import io.ktor.client.plugins.logging.Logger
import io.ktor.client.plugins.logging.Logging
import io.ktor.serialization.kotlinx.json.json
import kotlinx.serialization.json.Json
import okhttp3.CertificatePinner
import okhttp3.Dns
import okhttp3.Interceptor
import okhttp3.OkHttpClient
import okhttp3.logging.HttpLoggingInterceptor
import java.util.concurrent.TimeUnit
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.SSLContext
import javax.net.ssl.X509TrustManager
import kotlin.coroutines.cancellation.CancellationException

@Suppress("MemberVisibilityCanBePrivate")
object NetworkHelper {

    @Volatile
    private var client: HttpClient? = null
    
    @Volatile
    private var defaultClient: HttpClient? = null

    var connectTimeoutMillis: Long = 15000L
    var requestTimeoutMillis: Long = 15000L
    var readTimeOutMillis: Long = 15000L
    var logLevel = LogLevel.HEADERS
    var logger = Logger.ANDROID
    var followRedirects = true
    var followSslRedirects = true
    var customInterceptor: Interceptor? = null
    var customLoggingInterceptor: HttpLoggingInterceptor? = null
    var certificatePinner: CertificatePinner? = null

    /**
     * Controls whether SSL certificate bypass is allowed for authenticators with self-signed certificates.
     *
     * ## Two-Level Security Model
     *
     * This flag works in conjunction with the per-authenticator `ignoreSSLCertificate` flag to provide
     * two levels of security control:
     *
     * 1. **App-Level Permission** (`allowInsecureSSL`): Controls whether the application is allowed
     *    to bypass SSL validation at all. This is a global permission that must be explicitly enabled
     *    by the application developer.
     *
     * 2. **Authenticator-Level Need** (`ignoreSSLCertificate`): Indicates whether a specific
     *    authenticator requires SSL bypass (typically from QR code `"options":"ignoreSslCerts=true"`).
     *
     * **Both conditions must be true** for SSL bypass to occur for a specific authenticator.
     *
     * ## Security Warning
     *
     * Enabling this in production exposes your application to man-in-the-middle attacks.
     * Only enable this if you need to connect to OnPremise servers with self-signed certificates
     * that you trust.
     *
     * ## Default Behavior
     *
     * - **Default**: `false` (SSL bypass disabled - secure default)
     * - All authenticators use standard SSL certificate validation
     * - Attempting to use an authenticator with `ignoreSSLCertificate=true` will fail
     *
     * ## Usage Example
     *
     * ```kotlin
     * class MyApplication : Application() {
     *     override fun onCreate() {
     *         super.onCreate()
     *
     *         // Enable SSL bypass capability for OnPrem authenticators
     *         NetworkHelper.allowInsecureSSL = true
     *     }
     * }
     * ```
     *
     * ## When to Enable
     *
     * Enable this flag only when:
     * - You need to connect to OnPremise IBM Verify Access servers
     * - Those servers use self-signed certificates
     * - You trust those servers and their network environment
     * - You understand the security implications
     *
     * @see createInsecureClient
     */
    var allowInsecureSSL: Boolean = false

    /**
     * Optional Certificate Transparency (CT) interceptor for this SDK's HTTP client.
     *
     * When set, the provided interceptor enforces Certificate Transparency checks for
     * applicable HTTPS connections made by this SDK. These checks are performed in
     * addition to normal TLS certificate validation.
     *
     * Certificate Transparency helps detect mis-issued publicly trusted certificates
     * by requiring certificates to include valid Signed Certificate Timestamps (SCTs)
     * from accepted public CT logs.
     *
     * Security note:
     * CT enforcement is typically fail-closed. If a certificate does not provide
     * valid CT proof when required, the connection may be rejected even if the TLS
     * certificate chain is otherwise valid.
     *
     * SDK best practice:
     * This SDK uses the interceptor approach because it is scoped to this SDK's HTTP
     * client. The Java Security Provider approach
     * ({@code installCertificateTransparencyProvider(...)}) is generally not
     * recommended for SDKs because it applies process-wide and may conflict with the
     * host application's networking or CT configuration.
     *
     * Example:
     * {@code
     * import com.appmattus.certificatetransparency.certificateTransparencyInterceptor
     *
     * NetworkHelper.certificateTransparencyInterceptor = certificateTransparencyInterceptor {
     *     // Exclude any subdomain, but not the apex domain itself
     *     -"*.appmattus.com"
     *
     *     // Exclude a specific domain
     *     -"example.com"
     *
     *     // Re-include a specific subdomain
     *     +"allowed.appmattus.com"
     * }
     * }
     *
     * Future:
     * If Android provides suitable built-in Certificate Transparency enforcement for
     * this use case, this property can be set to {@code null} to disable SDK-level
     * CT interception.
     *
     * Default: {@code null} (disabled)
     */
    var certificateTransparencyInterceptor: Interceptor? = null
        set(value) {
            if (field != value) {
                field = value
                invalidateClient()
            }
        }
    
    var sslContext: SSLContext? = null
    var hostnameVerifier: HostnameVerifier? = null
        set(value) {
            if (field != value) {
                field = value
                invalidateClient()
            }
        }

    var trustManager: X509TrustManager? = null
        set(value) {
            if (field != value) {
                field = value
                invalidateClient()
            }
        }

    var customDnsResolver: Dns? = null
        set(value) {
            if (field != value) {
                field = value
                invalidateClient()
            }
        }

    /**
     * Returns the singleton HttpClient instance.
     *
     * Uses lazy initialization for better performance - the client is only created
     * when first accessed. If a custom client has been set via [initialize], that
     * client is returned instead.
     *
     * Thread-safe: Synchronized to prevent race conditions and ensure proper
     * initialization of defaultClient.
     */
    val getInstance: HttpClient
        @Synchronized
        get() {
            if (client != null) return client!!
            if (defaultClient == null) {
                defaultClient = buildClient(null)
            }
            return defaultClient!!
        }

    /**
     * Initializes the HttpClient with a custom client or engine.
     *
     * @param customClient A pre-configured HttpClient to use instead of the default.
     * @param httpClientEngine A custom HttpClientEngine to use for building the client.
     */
    @Synchronized
    fun initialize(customClient: HttpClient? = null, httpClientEngine: HttpClientEngine? = null) {
        client = customClient ?: buildClient(httpClientEngine)
    }

    @Synchronized
    private fun invalidateClient() {
        client?.close()
        client = null
        defaultClient?.close()
        defaultClient = null
    }

    private fun buildClient(httpClientEngine: HttpClientEngine?): HttpClient {

        if (!BuildConfig.DEBUG && logLevel == LogLevel.ALL) {
            println("LogLevel.All should not be used in production!")
        }

        return httpClientEngine?.let { engine ->
            HttpClient(engine) {
                configureClient()
            }
        } ?: HttpClient(OkHttp) {
            engine {
                config {
                    followRedirects(this@NetworkHelper.followRedirects)
                    followSslRedirects(this@NetworkHelper.followSslRedirects)
                    customInterceptor?.let { addInterceptor(it) }
                    customLoggingInterceptor?.let { addInterceptor(it) }
                }
                preconfigured = createOkHttpClient()
            }
            configureClient()
        }
    }

    private fun HttpClientConfig<*>.configureClient() {
        install(Logging) {
            logger = this@NetworkHelper.logger
            level = this@NetworkHelper.logLevel
        }
        install(ContentNegotiation) {
            json(Json {
                explicitNulls = false
                encodeDefaults = true
                ignoreUnknownKeys = true
                isLenient = true
            })
        }
        install(HttpTimeout) {
            connectTimeoutMillis = this@NetworkHelper.connectTimeoutMillis
            requestTimeoutMillis = this@NetworkHelper.requestTimeoutMillis
        }
    }

    internal fun createOkHttpClient(): OkHttpClient {
        return OkHttpClient.Builder().apply {
            readTimeout(readTimeOutMillis, TimeUnit.MILLISECONDS)
            certificatePinner?.let { certificatePinner(it) }
            certificateTransparencyInterceptor?.let { addNetworkInterceptor(it) }
            sslContext?.let { sslContext ->
                trustManager?.let {
                    sslSocketFactory(sslContext.socketFactory, it)
                }
            }
            hostnameVerifier?.let { hostnameVerifier(it) }
            customDnsResolver?.let { dns(it) }
        }.build()
    }

    /**
     * Creates an HttpClient with SSL certificate validation disabled.
     *
     * ## Two-Level Security Check
     *
     * This method enforces the two-level security model:
     * 1. Checks [allowInsecureSSL] flag (app-level permission)
     * 2. Should only be called for authenticators with `ignoreSSLCertificate=true` (authenticator-level need)
     *
     * ## Security Warning
     *
     * **WARNING**: This creates an HTTP client that accepts ALL SSL certificates, including:
     * - Self-signed certificates
     * - Expired certificates
     * - Certificates with mismatched hostnames
     * - Certificates from untrusted Certificate Authorities
     *
     * This exposes your application to man-in-the-middle attacks. Only use this when:
     * - Connecting to trusted OnPremise IBM Verify Access servers
     * - Those servers use self-signed certificates
     * - You control or trust the network environment
     *
     * ## Usage
     *
     * This method is called internally by the SDK when an authenticator with `ignoreSSLCertificate=true`
     * is used. Application developers should not call this method directly.
     *
     * ```kotlin
     * // Internal SDK usage (in MFAServiceController or OnPremiseRegistrationProvider)
     * val clientToUse = if (authenticator.ignoreSSLCertificate) {
     *     NetworkHelper.createInsecureClient()  // Only if allowInsecureSSL=true
     * } else {
     *     httpClient  // Use secure client
     * }
     * ```
     *
     * @return HttpClient configured to accept all SSL certificates
     * @throws IllegalStateException if [allowInsecureSSL] is false
     *
     * @see allowInsecureSSL
     * @see insecureTrustManager
     */
    fun createInsecureClient(): HttpClient {
        if (!allowInsecureSSL) {
            throw IllegalStateException(
                "SSL bypass is disabled. To enable SSL bypass for self-signed certificates, " +
                "set NetworkHelper.allowInsecureSSL = true in your application initialization. " +
                "WARNING: This should only be used with trusted OnPremise servers. " +
                "See NetworkHelper.allowInsecureSSL documentation for details."
            )
        }

        val trustManager = insecureTrustManager()
        val sslContext = SSLContext.getInstance("TLS").apply {
            init(null, arrayOf(trustManager), java.security.SecureRandom())
        }

        val insecureOkHttpClient = OkHttpClient.Builder().apply {
            readTimeout(readTimeOutMillis, TimeUnit.MILLISECONDS)
            sslSocketFactory(sslContext.socketFactory, trustManager)
            hostnameVerifier { _, _ -> true } // Accept all hostnames
            followRedirects(followRedirects)
            followSslRedirects(followSslRedirects)
            customInterceptor?.let { addInterceptor(it) }
            customLoggingInterceptor?.let { addInterceptor(it) }
        }.build()

        return HttpClient(OkHttp) {
            engine {
                preconfigured = insecureOkHttpClient
            }
            configureClient()
        }
    }

    fun insecureTrustManager(): X509TrustManager {
        return object : X509TrustManager {
            override fun checkClientTrusted(
                chain: Array<out java.security.cert.X509Certificate>?,
                authType: String?
            ) {
            }

            override fun checkServerTrusted(
                chain: Array<out java.security.cert.X509Certificate>?,
                authType: String?
            ) {
            }

            override fun getAcceptedIssuers(): Array<java.security.cert.X509Certificate> = arrayOf()
        }
    }

    /**
     * Closes the current HttpClient and releases its resources.
     *
     * This method is necessary because NetworkHelper is a singleton that lives for the
     * entire app lifecycle. Without explicit cleanup, the HttpClient would never be closed
     * even though it implements Closeable.
     *
     * **When to call:**
     * - During app shutdown or cleanup
     * - When experiencing memory pressure
     * - After changing configuration properties (automatically called by property setters)
     * - When you want to force recreation of the client
     *
     * **Note:** The client will be automatically recreated on next access via [getInstance].
     *
     * **Example:**
     * ```kotlin
     * // Clean up resources during app shutdown
     * override fun onDestroy() {
     *     super.onDestroy()
     *     NetworkHelper.closeClient()
     * }
     * ```
     */
    @Synchronized
    fun closeClient() {
        client?.close()
        client = null
        defaultClient?.close()
        defaultClient = null
    }
}


inline fun <R> safeRunCatching(block: () -> R): Result<R> {
    return try {
        Result.success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: Exception) {
        Result.failure(e)
    }
}

inline suspend fun <R> safeRunCatchingSuspend(block: suspend () -> R): Result<R> {
    return try {
        Result.success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: Exception) {
        Result.failure(e)
    }
}
