/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.mfa

import android.content.Context
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class MFAAttributeInfoTest {

    private lateinit var context: Context

    @Before
    fun setup() {
        context = InstrumentationRegistry.getInstrumentation().targetContext
        MFAAttributeInfo.init(context)
    }

    @Test
    fun init_shouldReturnMFAAttributeInfo() {
        // When
        val result = MFAAttributeInfo.init(context)

        // Then
        assertNotNull(result)
        assertEquals(MFAAttributeInfo, result)
    }

    @Test
    fun dictionary_shouldReturnMapWithAllAttributes() {
        // When
        val attributes = MFAAttributeInfo.dictionary()

        // Then
        assertNotNull(attributes)
        assertTrue(attributes.isNotEmpty())
    }

    @Test
    fun dictionary_shouldContainApplicationId() {
        // When
        val attributes = MFAAttributeInfo.dictionary()

        // Then
        assertTrue(attributes.containsKey("applicationId"))
        assertNotNull(attributes["applicationId"])
        assertTrue(attributes["applicationId"] is String)
    }

    @Test
    fun dictionary_shouldContainApplicationName() {
        // When
        val attributes = MFAAttributeInfo.dictionary()

        // Then
        assertTrue(attributes.containsKey("applicationName"))
        assertNotNull(attributes["applicationName"])
        assertTrue(attributes["applicationName"] is String)
    }

    @Test
    fun dictionary_shouldContainApplicationVersion() {
        // When
        val attributes = MFAAttributeInfo.dictionary()

        // Then
        assertTrue(attributes.containsKey("applicationVersion"))
        assertNotNull(attributes["applicationVersion"])
        assertTrue(attributes["applicationVersion"] is String)
    }

    @Test
    fun dictionary_shouldContainDeviceName() {
        // When
        val attributes = MFAAttributeInfo.dictionary()

        // Then
        assertTrue(attributes.containsKey("deviceName"))
        assertNotNull(attributes["deviceName"])
        assertTrue(attributes["deviceName"] is String)
    }

    @Test
    fun dictionary_shouldContainPlatformType() {
        // When
        val attributes = MFAAttributeInfo.dictionary()

        // Then
        assertTrue(attributes.containsKey("platformType"))
        assertEquals("Android", attributes["platformType"])
    }

    @Test
    fun dictionary_shouldContainDeviceType() {
        // When
        val attributes = MFAAttributeInfo.dictionary()

        // Then
        assertTrue(attributes.containsKey("deviceType"))
        assertNotNull(attributes["deviceType"])
        assertTrue(attributes["deviceType"] is String)
    }

    @Test
    fun dictionary_shouldContainDeviceId() {
        // When
        val attributes = MFAAttributeInfo.dictionary()

        // Then
        assertTrue(attributes.containsKey("deviceId"))
        assertNotNull(attributes["deviceId"])
        assertTrue(attributes["deviceId"] is String)
    }

    @Test
    fun dictionary_shouldContainOsVersion() {
        // When
        val attributes = MFAAttributeInfo.dictionary()

        // Then
        assertTrue(attributes.containsKey("osVersion"))
        assertNotNull(attributes["osVersion"])
        assertTrue(attributes["osVersion"] is String)
    }

    @Test
    fun dictionary_shouldContainFaceSupport() {
        // When
        val attributes = MFAAttributeInfo.dictionary()

        // Then
        assertTrue(attributes.containsKey("faceSupport"))
        assertNotNull(attributes["faceSupport"])
        assertTrue(attributes["faceSupport"] is Boolean)
    }

    @Test
    fun dictionary_shouldContainDeviceInsecure() {
        // When
        val attributes = MFAAttributeInfo.dictionary()

        // Then
        assertTrue(attributes.containsKey("deviceInsecure"))
        assertNotNull(attributes["deviceInsecure"])
        assertTrue(attributes["deviceInsecure"] is Boolean)
    }

    @Test
    fun dictionary_shouldContainFingerprintSupport() {
        // When
        val attributes = MFAAttributeInfo.dictionary()

        // Then
        assertTrue(attributes.containsKey("fingerprintSupport"))
        assertNotNull(attributes["fingerprintSupport"])
        assertTrue(attributes["fingerprintSupport"] is Boolean)
    }

    @Test
    fun dictionary_shouldContainFrontCameraSupport() {
        // When
        val attributes = MFAAttributeInfo.dictionary()

        // Then
        assertTrue(attributes.containsKey("frontCameraSupport"))
        assertNotNull(attributes["frontCameraSupport"])
        assertTrue(attributes["frontCameraSupport"] is Boolean)
    }

    @Test
    fun dictionary_shouldContainVerifySdkVersion() {
        // When
        val attributes = MFAAttributeInfo.dictionary()

        // Then
        assertTrue(attributes.containsKey("verifySdkVersion"))
        assertNotNull(attributes["verifySdkVersion"])
        assertTrue(attributes["verifySdkVersion"] is String)
    }

    @Test
    fun dictionary_shouldContainExactly13Keys() {
        // When
        val attributes = MFAAttributeInfo.dictionary()

        // Then
        assertEquals(13, attributes.size)
    }

    @Test
    fun dictionary_withSnakeCaseFalse_shouldUseCamelCase() {
        // When
        val attributes = MFAAttributeInfo.dictionary(snakeCaseKey = false)

        // Then
        assertTrue(attributes.containsKey("applicationId"))
        assertTrue(attributes.containsKey("applicationName"))
        assertTrue(attributes.containsKey("applicationVersion"))
        assertTrue(attributes.containsKey("deviceName"))
        assertTrue(attributes.containsKey("platformType"))
        assertTrue(attributes.containsKey("deviceType"))
        assertTrue(attributes.containsKey("deviceId"))
        assertTrue(attributes.containsKey("osVersion"))
        assertTrue(attributes.containsKey("faceSupport"))
        assertTrue(attributes.containsKey("deviceInsecure"))
        assertTrue(attributes.containsKey("fingerprintSupport"))
        assertTrue(attributes.containsKey("frontCameraSupport"))
        assertTrue(attributes.containsKey("verifySdkVersion"))
    }

    @Test
    fun dictionary_withSnakeCaseTrue_shouldUseSnakeCase() {
        // When
        val attributes = MFAAttributeInfo.dictionary(snakeCaseKey = true)

        // Then
        assertTrue(attributes.containsKey("application_id"))
        assertTrue(attributes.containsKey("application_name"))
        assertTrue(attributes.containsKey("application_version"))
        assertTrue(attributes.containsKey("device_name"))
        assertTrue(attributes.containsKey("platform_type"))
        assertTrue(attributes.containsKey("device_type"))
        assertTrue(attributes.containsKey("device_id"))
        assertTrue(attributes.containsKey("os_version"))
        assertTrue(attributes.containsKey("face_support"))
        assertTrue(attributes.containsKey("device_insecure"))
        assertTrue(attributes.containsKey("fingerprint_support"))
        assertTrue(attributes.containsKey("front_camera_support"))
        assertTrue(attributes.containsKey("verify_sdk_version"))
    }

    @Test
    fun dictionary_withSnakeCaseTrue_shouldNotContainCamelCaseKeys() {
        // When
        val attributes = MFAAttributeInfo.dictionary(snakeCaseKey = true)

        // Then
        assertFalse(attributes.containsKey("applicationId"))
        assertFalse(attributes.containsKey("applicationName"))
        assertFalse(attributes.containsKey("applicationVersion"))
        assertFalse(attributes.containsKey("deviceName"))
        assertFalse(attributes.containsKey("platformType"))
        assertFalse(attributes.containsKey("deviceType"))
        assertFalse(attributes.containsKey("deviceId"))
        assertFalse(attributes.containsKey("osVersion"))
        assertFalse(attributes.containsKey("faceSupport"))
        assertFalse(attributes.containsKey("deviceInsecure"))
        assertFalse(attributes.containsKey("fingerprintSupport"))
        assertFalse(attributes.containsKey("frontCameraSupport"))
        assertFalse(attributes.containsKey("verifySdkVersion"))
    }

    @Test
    fun dictionary_deviceId_shouldBePersistent() {
        // Given
        val attributes1 = MFAAttributeInfo.dictionary()
        val deviceId1 = attributes1["deviceId"] as String

        // When
        val attributes2 = MFAAttributeInfo.dictionary()
        val deviceId2 = attributes2["deviceId"] as String

        // Then
        assertEquals(deviceId1, deviceId2)
    }

    @Test
    fun dictionary_deviceId_shouldBeValidUUID() {
        // When
        val attributes = MFAAttributeInfo.dictionary()
        val deviceId = attributes["deviceId"] as String

        // Then
        // UUID format: 8-4-4-4-12 characters
        val uuidPattern = Regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
        assertTrue(deviceId.matches(uuidPattern))
    }

    @Test
    fun dictionary_applicationId_shouldMatchPackageName() {
        // When
        val attributes = MFAAttributeInfo.dictionary()
        val applicationId = attributes["applicationId"] as String

        // Then
        assertEquals(context.packageName, applicationId)
    }

    @Test
    fun dictionary_platformType_shouldBeAndroid() {
        // When
        val attributes = MFAAttributeInfo.dictionary()
        val platformType = attributes["platformType"] as String

        // Then
        assertEquals("Android", platformType)
    }

    @Test
    fun dictionary_osVersion_shouldNotBeEmpty() {
        // When
        val attributes = MFAAttributeInfo.dictionary()
        val osVersion = attributes["osVersion"] as String

        // Then
        assertTrue(osVersion.isNotEmpty())
    }

    @Test
    fun dictionary_verifySdkVersion_shouldNotBeEmpty() {
        // When
        val attributes = MFAAttributeInfo.dictionary()
        val sdkVersion = attributes["verifySdkVersion"] as String

        // Then
        assertTrue(sdkVersion.isNotEmpty())
    }

    @Test
    fun dictionary_multipleCalls_shouldReturnConsistentData() {
        // When
        val attributes1 = MFAAttributeInfo.dictionary()
        val attributes2 = MFAAttributeInfo.dictionary()

        // Then
        assertEquals(attributes1["applicationId"], attributes2["applicationId"])
        assertEquals(attributes1["applicationName"], attributes2["applicationName"])
        assertEquals(attributes1["applicationVersion"], attributes2["applicationVersion"])
        assertEquals(attributes1["deviceName"], attributes2["deviceName"])
        assertEquals(attributes1["platformType"], attributes2["platformType"])
        assertEquals(attributes1["deviceType"], attributes2["deviceType"])
        assertEquals(attributes1["deviceId"], attributes2["deviceId"])
        assertEquals(attributes1["osVersion"], attributes2["osVersion"])
        assertEquals(attributes1["verifySdkVersion"], attributes2["verifySdkVersion"])
    }

    @Test
    fun dictionary_camelCaseAndSnakeCase_shouldHaveSameValues() {
        // When
        val camelCase = MFAAttributeInfo.dictionary(snakeCaseKey = false)
        val snakeCase = MFAAttributeInfo.dictionary(snakeCaseKey = true)

        // Then
        assertEquals(camelCase["applicationId"], snakeCase["application_id"])
        assertEquals(camelCase["applicationName"], snakeCase["application_name"])
        assertEquals(camelCase["applicationVersion"], snakeCase["application_version"])
        assertEquals(camelCase["deviceName"], snakeCase["device_name"])
        assertEquals(camelCase["platformType"], snakeCase["platform_type"])
        assertEquals(camelCase["deviceType"], snakeCase["device_type"])
        assertEquals(camelCase["deviceId"], snakeCase["device_id"])
        assertEquals(camelCase["osVersion"], snakeCase["os_version"])
        assertEquals(camelCase["faceSupport"], snakeCase["face_support"])
        assertEquals(camelCase["deviceInsecure"], snakeCase["device_insecure"])
        assertEquals(camelCase["fingerprintSupport"], snakeCase["fingerprint_support"])
        assertEquals(camelCase["frontCameraSupport"], snakeCase["front_camera_support"])
        assertEquals(camelCase["verifySdkVersion"], snakeCase["verify_sdk_version"])
    }

    @Test
    fun dictionary_booleanValues_shouldBeValidBooleans() {
        // When
        val attributes = MFAAttributeInfo.dictionary()

        // Then
        val faceSupport = attributes["faceSupport"]
        val deviceInsecure = attributes["deviceInsecure"]
        val fingerprintSupport = attributes["fingerprintSupport"]
        val frontCameraSupport = attributes["frontCameraSupport"]

        assertTrue(faceSupport is Boolean)
        assertTrue(deviceInsecure is Boolean)
        assertTrue(fingerprintSupport is Boolean)
        assertTrue(frontCameraSupport is Boolean)
    }

    @Test
    fun init_multipleCallsWithSameContext_shouldReturnSameInstance() {
        // When
        val result1 = MFAAttributeInfo.init(context)
        val result2 = MFAAttributeInfo.init(context)

        // Then
        assertEquals(result1, result2)
        assertEquals(MFAAttributeInfo, result1)
        assertEquals(MFAAttributeInfo, result2)
    }
}
