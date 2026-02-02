/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.core

import android.os.Build
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.filters.SmallTest
import com.ibm.security.verifysdk.core.helper.KeystoreHelper
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Ignore
import org.junit.Test
import org.junit.runner.RunWith
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.security.KeyStoreException
import java.util.Locale
import java.util.UUID

@RunWith(AndroidJUnit4::class)
@SmallTest
internal class KeystoreHelperTest {

    private lateinit var log: Logger

    private val supportedAlgorithms: ArrayList<String> =
        arrayListOf("SHA1withRSA", "SHA256withRSA", "SHA512withRSA")

    @Before
    fun setUp() {
        log = LoggerFactory.getLogger(javaClass)
    }

    @Test
    fun getKeystoreType() {
        assertEquals("AndroidKeyStore", KeystoreHelper.keystoreType)
    }

    @Test
    fun setKeystoreType() {
        val newKeystoreType = "BouncyCastle"
        KeystoreHelper.keystoreType = newKeystoreType
        assertEquals(newKeystoreType, KeystoreHelper.keystoreType)
    }

    @Test(expected = KeyStoreException::class)
    fun setKeystoreType_unknownType_shouldThrowException() {
        val newKeystoreType = "unknownKeyStoreType"
        KeystoreHelper.keystoreType = newKeystoreType
    }

    @Test
    fun getKeySize() {
        assertEquals(2048, KeystoreHelper.keySize)
    }

    @Test
    fun setKeySize() {
        val previousKeysize = KeystoreHelper.keySize
        val newKeysize = 4096
        KeystoreHelper.keySize = newKeysize
        assertEquals(newKeysize, KeystoreHelper.keySize)
        KeystoreHelper.keySize = previousKeysize
    }

    @Test
    fun createKeyPair_happyPath_shouldReturnPublicKey() {

        for (algorithm in supportedAlgorithms) {
            val keyName = String.format(Locale.getDefault(),"myTestKey-%s", UUID.randomUUID().toString())
            val publicKey = KeystoreHelper.createKeyPair(keyName, algorithm, KeyProperties.PURPOSE_SIGN,)
            assertEquals("X.509", publicKey.format)
        }
    }

    @Test
    @Ignore("Fails - fix build first")
    fun createKeyPair_happyPathOverwriteDefaultsCase2of4_shouldReturnPublicKey() {

        val authenticationRequired = true
        val invalidatedByBiometricEnrollment = true

        for (algorithm in supportedAlgorithms) {
            val keyName = String.format(Locale.getDefault(),"myTestKey-%s", UUID.randomUUID().toString())
            val publicKey = KeystoreHelper.createKeyPair(
                keyName,
                algorithm,
                KeyProperties.PURPOSE_SIGN,
                authenticationRequired,
                invalidatedByBiometricEnrollment
            )
            assertEquals("X.509", publicKey.format)
        }
    }

    @Test
    fun createKeyPair_happyPathOverwriteDefaultsCase3of4_shouldReturnPublicKey() {

        val authenticationRequired = false
        val invalidatedByBiometricEnrollment = true

        for (algorithm in supportedAlgorithms) {
            val keyName = String.format(Locale.getDefault(),"myTestKey-%s", UUID.randomUUID().toString())
            val publicKey = KeystoreHelper.createKeyPair(
                keyName,
                algorithm,
                KeyProperties.PURPOSE_SIGN,
                authenticationRequired,
                invalidatedByBiometricEnrollment
            )
            assertEquals("X.509", publicKey.format)
        }
    }

    @Test
    @Ignore("Fails - fix build first")
    fun createKeyPair_happyPathOverwriteDefaultsCase4of4_shouldReturnPublicKey() {

        val authenticationRequired = true
        val invalidatedByBiometricEnrollment = false

        for (algorithm in supportedAlgorithms) {
            val keyName = String.format(Locale.getDefault(),"myTestKey-%s", UUID.randomUUID().toString())
            val publicKey = KeystoreHelper.createKeyPair(
                keyName,
                algorithm,
                KeyProperties.PURPOSE_SIGN,
                authenticationRequired,
                invalidatedByBiometricEnrollment
            )
            assertEquals("X.509", publicKey.format)
        }
    }

    @Test
    fun createKeyPair_happyPathSdkQ_shouldReturnPublicKey() {

        val sdkVersion = Build.VERSION.SDK_INT
        TestHelper.setFinalStatic(
            Build.VERSION::class.java.getField("SDK_INT"),
            Build.VERSION_CODES.Q
        )
        for (algorithm in supportedAlgorithms) {
            val keyName = String.format(Locale.getDefault(),"myTestKey-%s", UUID.randomUUID().toString())
            val publicKey = KeystoreHelper.createKeyPair(keyName, algorithm, KeyProperties.PURPOSE_SIGN)
            assertEquals("X.509", publicKey.format)
        }
        TestHelper.setFinalStatic(
            Build.VERSION::class.java.getField("SDK_INT"),
            sdkVersion
        )
    }

    @Test
    fun createKeyPair_happyPathSdkM_shouldReturnPublicKey() {

        val sdkVersion = Build.VERSION.SDK_INT
        TestHelper.setFinalStatic(
            Build.VERSION::class.java.getField("SDK_INT"),
            Build.VERSION_CODES.M
        )
        for (algorithm in supportedAlgorithms) {
            val keyName = String.format(Locale.getDefault(),"myTestKey-%s", UUID.randomUUID().toString())
            val publicKey = KeystoreHelper.createKeyPair(keyName, algorithm, KeyProperties.PURPOSE_SIGN)
            assertEquals("X.509", publicKey.format)
        }
        TestHelper.setFinalStatic(
            Build.VERSION::class.java.getField("SDK_INT"),
            sdkVersion
        )
    }

    @Test
    fun createKeyPair_overwriteExistingKey_shouldReturnNewPublicKey() {

        val keyName = String.format(Locale.getDefault(),"myTestKey-%s", UUID.randomUUID().toString())
        val algorithm = supportedAlgorithms[0]
        KeystoreHelper.createKeyPair(keyName, algorithm, KeyProperties.PURPOSE_SIGN)
        val publicKeyFirst = KeystoreHelper.exportPublicKey(keyName)
        KeystoreHelper.createKeyPair(keyName, algorithm, KeyProperties.PURPOSE_SIGN)
        val publicKeySecond = KeystoreHelper.exportPublicKey(keyName)
        assertNotEquals(publicKeyFirst, publicKeySecond)
    }

    @Test(expected = UnsupportedOperationException::class)
    fun createKeyPair_unsupportedAlgorithm_shouldThrowException() {
        val keyName = String.format(Locale.getDefault(),"myTestKey-%s", UUID.randomUUID().toString())
        KeystoreHelper.createKeyPair(keyName, "unsupportedAlgorithm", KeyProperties.PURPOSE_SIGN)
        assertFalse(true)
    }

    @Test
    fun deleteKeyPair() {
        val keyName = String.format(Locale.getDefault(),"myTestKey-%s", UUID.randomUUID().toString())
        val algorithm = supportedAlgorithms[0]
        KeystoreHelper.createKeyPair(keyName, algorithm, KeyProperties.PURPOSE_SIGN)
        assertTrue(KeystoreHelper.exists(keyName))
        KeystoreHelper.deleteKeyPair(keyName)
        assertTrue(KeystoreHelper.exists(keyName).not())
    }

    @Test
    fun exportPublicKey() {
        val keyName = String.format(Locale.getDefault(),"myTestKey-%s", UUID.randomUUID().toString())
        val algorithm = supportedAlgorithms[0]
        KeystoreHelper.createKeyPair(keyName, algorithm,KeyProperties.PURPOSE_SIGN)

        val publicKey = KeystoreHelper.exportPublicKey(keyName)
        assertNotNull(publicKey)
        assertNotNull(publicKey)
        publicKey?.let {
            assert(publicKey.startsWith("MIIB"))
        }
    }

    @Test
    fun exportPublicKey_unknownKey_shouldReturnNull() {

        val keyName = String.format(Locale.getDefault(),"unknownKey-%s", UUID.randomUUID().toString())
        val publicKey = KeystoreHelper.exportPublicKey(keyName)
        assertNull(publicKey)
    }

    @Test
    fun exists() {
        val keyName = String.format(Locale.getDefault(),"myTestKey-%s", UUID.randomUUID().toString())
        assertTrue(KeystoreHelper.exists(keyName).not())
        KeystoreHelper.createKeyPair(keyName, supportedAlgorithms[0], KeyProperties.PURPOSE_SIGN)
        assertTrue(KeystoreHelper.exists(keyName))
    }

    @Test
    fun signData_happyPath_shouldReturnData() {
        val keyName = String.format(Locale.getDefault(),"myTestKey-%s", UUID.randomUUID().toString())
        val algorithm = supportedAlgorithms[0]
        KeystoreHelper.createKeyPair(keyName, algorithm, KeyProperties.PURPOSE_SIGN)

        val signedData = KeystoreHelper.signData(keyName, algorithm, "dataToSign")
        assertNotNull(signedData)
        signedData?.let {
            assert(it.isNotEmpty())
        }
    }

    @Test
    fun signData_overwriteDefaults_shouldReturnData() {
        val keyName = String.format(Locale.getDefault(),"myTestKey-%s", UUID.randomUUID().toString())
        val algorithm = supportedAlgorithms[0]
        KeystoreHelper.createKeyPair(keyName, algorithm, KeyProperties.PURPOSE_SIGN)

        val signedData = KeystoreHelper.signData(keyName, algorithm, "dataToSign", Base64.URL_SAFE)
        assertNotNull(signedData)
        signedData?.let {
            assert(it.isNotEmpty())
        }
    }

    @Test
    fun signData_unknownKey_shouldReturnNull() {
        val keyName = String.format(Locale.getDefault(),"unknownKey-%s", UUID.randomUUID().toString())
        val algorithm = supportedAlgorithms[0]

        val signedData = KeystoreHelper.signData(keyName, algorithm, "dataToSign", Base64.URL_SAFE)
        assertNull(signedData)
    }
}