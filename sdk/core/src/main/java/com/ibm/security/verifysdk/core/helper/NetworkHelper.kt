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

    val getInstance: HttpClient
        get() = client ?: synchronized(this) {
            client ?: buildClient(null).also { client = it }
        }

    @Synchronized
    fun initialize(customClient: HttpClient? = null, httpClientEngine: HttpClientEngine? = null) {
        client = customClient ?: buildClient(httpClientEngine)
    }

    @Synchronized
    private fun invalidateClient() {
        client?.close()
        client = null
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

    fun closeClient() {
        client?.close()
        client = null
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
