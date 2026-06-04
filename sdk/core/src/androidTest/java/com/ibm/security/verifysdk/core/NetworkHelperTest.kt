package com.ibm.security.verifysdk.core

import com.ibm.security.verifysdk.core.helper.NetworkHelper
import io.ktor.client.HttpClient
import okhttp3.CertificatePinner
import okhttp3.Dns
import okhttp3.Interceptor
import okhttp3.logging.HttpLoggingInterceptor
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.InetAddress
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.X509TrustManager

@Suppress("KotlinConstantConditions")
internal class NetworkHelperTest {

    @Test
    fun test_followSslRedirects() {
        NetworkHelper.followSslRedirects = true
        assertEquals(true, NetworkHelper.followSslRedirects)
        NetworkHelper.followSslRedirects = false
        assertEquals(false, NetworkHelper.followSslRedirects)
    }

    @Test
    fun test_customLoggingInterceptor() {

        NetworkHelper.customLoggingInterceptor = null
        assertEquals(null, NetworkHelper.customLoggingInterceptor)

        val loggingInterceptor =
            HttpLoggingInterceptor().setLevel(HttpLoggingInterceptor.Level.BASIC)
        NetworkHelper.customLoggingInterceptor = loggingInterceptor

        assertEquals(loggingInterceptor, NetworkHelper.customLoggingInterceptor)
    }

    @Test
    fun test_customInterceptor() {

        val interceptor =
            Interceptor { chain: Interceptor.Chain ->
                val originalRequest = chain.request()
                val requestWithUserAgent = originalRequest.newBuilder()
                    .header("User-Agent", "com.ibm.security.verifysdk")
                    .build()
                chain.proceed(requestWithUserAgent)
            }

        NetworkHelper.customInterceptor = null
        assertEquals(null, NetworkHelper.customInterceptor)
        NetworkHelper.customInterceptor = interceptor
        assertEquals(interceptor, NetworkHelper.customInterceptor)
    }

    @Test
    fun test_certificatePinner() {

        val certificatePinner = CertificatePinner.Builder().build()

        NetworkHelper.certificatePinner = null
        assertEquals(null, NetworkHelper.certificatePinner)
        NetworkHelper.certificatePinner = certificatePinner
        assertEquals(certificatePinner, NetworkHelper.certificatePinner)
    }

    @Test
    fun test_readTimeOut() {
        NetworkHelper.readTimeOutMillis = 42
        assertEquals(42, NetworkHelper.readTimeOutMillis)
        NetworkHelper.readTimeOutMillis = 24
        assertEquals(24, NetworkHelper.readTimeOutMillis)
    }

    @Test
    fun test_connectionTimeOut() {
        NetworkHelper.connectTimeoutMillis = 42
        assertEquals(42, NetworkHelper.connectTimeoutMillis)
        NetworkHelper.connectTimeoutMillis = 24
        assertEquals(24, NetworkHelper.connectTimeoutMillis)
    }

    @Test
    fun test_requestTimeOut() {
        NetworkHelper.requestTimeoutMillis = 42
        assertEquals(42, NetworkHelper.requestTimeoutMillis)
        NetworkHelper.requestTimeoutMillis = 24
        assertEquals(24, NetworkHelper.requestTimeoutMillis)
    }

    @Test
    fun getNetworkApi() {
        NetworkHelper.closeClient()
        val client = NetworkHelper.getInstance
        assertTrue(client.hashCode() != 0)
        client.close()
        NetworkHelper.closeClient()
    }

    @Test
    fun test_getInstance_returnsSameDefaultClientUntilInvalidated() {
        NetworkHelper.closeClient()

        val firstClient = NetworkHelper.getInstance
        val secondClient = NetworkHelper.getInstance

        assertSame(firstClient, secondClient)

        firstClient.close()
        NetworkHelper.closeClient()
    }

    @Test
    fun test_closeClient_recreatesDefaultClientOnNextAccess() {
        NetworkHelper.closeClient()

        val firstClient = NetworkHelper.getInstance
        NetworkHelper.closeClient()
        val secondClient = NetworkHelper.getInstance

        assertNotSame(firstClient, secondClient)

        firstClient.close()
        secondClient.close()
        NetworkHelper.closeClient()
    }

    @Test
    fun test_closeClient_canBeCalledRepeatedly() {
        NetworkHelper.closeClient()
        NetworkHelper.closeClient()

        val client = NetworkHelper.getInstance
        assertNotNull(client)

        client.close()
        NetworkHelper.closeClient()
    }

    @Test
    fun test_initialize_customClientOverridesDefaultInstance() {
        NetworkHelper.closeClient()
        val customClient = HttpClient()

        NetworkHelper.initialize(customClient = customClient)

        val resolvedClient = NetworkHelper.getInstance
        assertSame(customClient, resolvedClient)

        customClient.close()
        NetworkHelper.closeClient()
    }

    @Test
    fun test_allowInsecureSSL_flagCanBeToggled() {
        val originalValue = NetworkHelper.allowInsecureSSL
        try {
            NetworkHelper.allowInsecureSSL = false
            assertEquals(false, NetworkHelper.allowInsecureSSL)

            NetworkHelper.allowInsecureSSL = true
            assertEquals(true, NetworkHelper.allowInsecureSSL)
        } finally {
            NetworkHelper.allowInsecureSSL = originalValue
        }
    }

    @Test
    fun test_createInsecureClient_throwsWhenAllowInsecureSSLDisabled() {
        val originalValue = NetworkHelper.allowInsecureSSL
        try {
            NetworkHelper.allowInsecureSSL = false

            try {
                NetworkHelper.createInsecureClient()
                throw AssertionError("Expected createInsecureClient to throw when insecure SSL is disabled")
            } catch (e: IllegalStateException) {
                assertTrue(e.message?.contains("SSL bypass is disabled") == true)
            }
        } finally {
            NetworkHelper.allowInsecureSSL = originalValue
            NetworkHelper.closeClient()
        }
    }

    @Test
    fun test_createInsecureClient_returnsDedicatedClientWhenAllowInsecureSSLEnabled() {
        val originalValue = NetworkHelper.allowInsecureSSL
        NetworkHelper.closeClient()

        try {
            NetworkHelper.allowInsecureSSL = true

            val defaultClient = NetworkHelper.getInstance
            val insecureClient = NetworkHelper.createInsecureClient()
            val secondInsecureClient = NetworkHelper.createInsecureClient()

            assertNotSame(defaultClient, insecureClient)
            assertNotSame(insecureClient, secondInsecureClient)

            insecureClient.close()
            secondInsecureClient.close()
            defaultClient.close()
        } finally {
            NetworkHelper.allowInsecureSSL = originalValue
            NetworkHelper.closeClient()
        }
    }

    @Test
    fun test_certificateTransparencyInterceptor_changeInvalidatesClient() {
        NetworkHelper.closeClient()
        val originalInterceptor = NetworkHelper.certificateTransparencyInterceptor
        val interceptor = Interceptor { chain -> chain.proceed(chain.request()) }

        try {
            val firstClient = NetworkHelper.getInstance
            NetworkHelper.certificateTransparencyInterceptor = interceptor
            val secondClient = NetworkHelper.getInstance

            assertNotSame(firstClient, secondClient)

            firstClient.close()
            secondClient.close()
        } finally {
            NetworkHelper.certificateTransparencyInterceptor = originalInterceptor
            NetworkHelper.closeClient()
        }
    }

    @Test
    fun test_certificateTransparencyInterceptor_sameValueDoesNotInvalidateClient() {
        NetworkHelper.closeClient()
        val originalInterceptor = NetworkHelper.certificateTransparencyInterceptor
        val interceptor = Interceptor { chain -> chain.proceed(chain.request()) }

        try {
            NetworkHelper.certificateTransparencyInterceptor = interceptor
            val firstClient = NetworkHelper.getInstance
            NetworkHelper.certificateTransparencyInterceptor = interceptor
            val secondClient = NetworkHelper.getInstance

            assertSame(firstClient, secondClient)

            firstClient.close()
        } finally {
            NetworkHelper.certificateTransparencyInterceptor = originalInterceptor
            NetworkHelper.closeClient()
        }
    }

    @Test
    fun test_hostnameVerifier_changeInvalidatesClient() {
        NetworkHelper.closeClient()
        val originalVerifier = NetworkHelper.hostnameVerifier
        val verifier = HostnameVerifier { _, _ -> true }

        try {
            val firstClient = NetworkHelper.getInstance
            NetworkHelper.hostnameVerifier = verifier
            val secondClient = NetworkHelper.getInstance

            assertNotSame(firstClient, secondClient)

            firstClient.close()
            secondClient.close()
        } finally {
            NetworkHelper.hostnameVerifier = originalVerifier
            NetworkHelper.closeClient()
        }
    }

    @Test
    fun test_hostnameVerifier_sameValueDoesNotInvalidateClient() {
        NetworkHelper.closeClient()
        val originalVerifier = NetworkHelper.hostnameVerifier
        val verifier = HostnameVerifier { _, _ -> true }

        try {
            NetworkHelper.hostnameVerifier = verifier
            val firstClient = NetworkHelper.getInstance
            NetworkHelper.hostnameVerifier = verifier
            val secondClient = NetworkHelper.getInstance

            assertSame(firstClient, secondClient)

            firstClient.close()
        } finally {
            NetworkHelper.hostnameVerifier = originalVerifier
            NetworkHelper.closeClient()
        }
    }

    @Test
    fun test_trustManager_changeInvalidatesClient() {
        NetworkHelper.closeClient()
        val originalTrustManager = NetworkHelper.trustManager
        val trustManager = object : X509TrustManager {
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

        try {
            val firstClient = NetworkHelper.getInstance
            NetworkHelper.trustManager = trustManager
            val secondClient = NetworkHelper.getInstance

            assertNotSame(firstClient, secondClient)

            firstClient.close()
            secondClient.close()
        } finally {
            NetworkHelper.trustManager = originalTrustManager
            NetworkHelper.closeClient()
        }
    }

    @Test
    fun test_trustManager_sameValueDoesNotInvalidateClient() {
        NetworkHelper.closeClient()
        val originalTrustManager = NetworkHelper.trustManager
        val trustManager = object : X509TrustManager {
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

        try {
            NetworkHelper.trustManager = trustManager
            val firstClient = NetworkHelper.getInstance
            NetworkHelper.trustManager = trustManager
            val secondClient = NetworkHelper.getInstance

            assertSame(firstClient, secondClient)

            firstClient.close()
        } finally {
            NetworkHelper.trustManager = originalTrustManager
            NetworkHelper.closeClient()
        }
    }

    @Test
    fun test_customDnsResolver_changeInvalidatesClient() {
        NetworkHelper.closeClient()
        val originalDns = NetworkHelper.customDnsResolver
        val dns = Dns { hostname -> listOf(InetAddress.getByName(hostname)) }

        try {
            val firstClient = NetworkHelper.getInstance
            NetworkHelper.customDnsResolver = dns
            val secondClient = NetworkHelper.getInstance

            assertNotSame(firstClient, secondClient)

            firstClient.close()
            secondClient.close()
        } finally {
            NetworkHelper.customDnsResolver = originalDns
            NetworkHelper.closeClient()
        }
    }

    @Test
    fun test_customDnsResolver_sameValueDoesNotInvalidateClient() {
        NetworkHelper.closeClient()
        val originalDns = NetworkHelper.customDnsResolver
        val dns = Dns { hostname -> listOf(InetAddress.getByName(hostname)) }

        try {
            NetworkHelper.customDnsResolver = dns
            val firstClient = NetworkHelper.getInstance
            NetworkHelper.customDnsResolver = dns
            val secondClient = NetworkHelper.getInstance

            assertSame(firstClient, secondClient)

            firstClient.close()
        } finally {
            NetworkHelper.customDnsResolver = originalDns
            NetworkHelper.closeClient()
        }
    }

    @Test
    fun test_insecureTrustManager_returnsEmptyAcceptedIssuersAndDoesNotThrow() {
        val trustManager = NetworkHelper.insecureTrustManager()

        assertTrue(trustManager.getAcceptedIssuers().isEmpty())
        trustManager.checkClientTrusted(null, null)
        trustManager.checkServerTrusted(null, null)
    }
}