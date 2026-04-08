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
    var logLevel = LogLevel.ALL
    var logger = Logger.ANDROID
    var followRedirects = true
    var followSslRedirects = true
    var customInterceptor: Interceptor? = null
    var customLoggingInterceptor: HttpLoggingInterceptor? = null
    var certificatePinner: CertificatePinner? = null

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

    fun insecureTrustManager(): X509TrustManager {

        if (!BuildConfig.DEBUG) {
            throw IllegalStateException("Insecure Trust Manager should not be used in production!")
        }

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
