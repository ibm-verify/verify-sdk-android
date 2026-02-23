/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.mfa

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.content.edit
import com.ibm.security.verifysdk.core.helper.ContextHelper
import com.scottyab.rootbeer.RootBeer
import java.util.Locale
import java.util.UUID

/**
 * Provides device and application attribute information for MFA operations.
 *
 * This singleton object collects various device, application, and security-related attributes
 * that are used during MFA registration and authentication processes. The attributes include
 * device identifiers, hardware capabilities, application metadata, and security status.
 *
 * ## Usage
 *
 * Before using this object, ensure that [ContextHelper] has been initialized in your
 * application's `onCreate()` method:
 *
 * ```kotlin
 * class MyApplication : Application() {
 *     override fun onCreate() {
 *         super.onCreate()
 *         ContextHelper.init(this)
 *     }
 * }
 * ```
 *
 * Then retrieve device attributes as needed:
 *
 * ```kotlin
 * // Get attributes with camelCase keys
 * val attributes = MFAAttributeInfo.dictionary()
 *
 * // Get attributes with snake_case keys (for API compatibility)
 * val snakeCaseAttributes = MFAAttributeInfo.dictionary(snakeCaseKey = true)
 * ```
 *
 * ## Collected Attributes
 *
 * The following attributes are collected:
 * - **Device Information**: name, model, type, unique device ID
 * - **Platform Information**: OS type, OS version, SDK version
 * - **Application Information**: bundle ID, name, version
 * - **Hardware Capabilities**: front camera, fingerprint sensor, face recognition
 * - **Security Status**: root/jailbreak detection
 *
 * ## Device ID Persistence
 *
 * A unique device ID is generated on first access and persisted in SharedPreferences.
 * This ID remains consistent across app launches unless the app data is cleared.
 *
 * @see ContextHelper
 */
object MFAAttributeInfo {

    /**
     * The application context retrieved from [ContextHelper].
     *
     * @throws IllegalStateException if [ContextHelper] has not been initialized
     */
    private val applicationContext: Context
        get() = ContextHelper.context

    private val name: String
        get() = Build.MODEL

    private val model: String
        get() = Build.MANUFACTURER

    private val operatingSystem: String
        get() = "Android"

    private val operatingSystemVersion: String
        get() = Build.VERSION.RELEASE

    private val deviceInsecure: Boolean
        get() = RootBeer(applicationContext).isRooted

    private val deviceID: String
        get() {
            val deviceIDKey = "deviceId"
            val sharedPrefs = applicationContext.getSharedPreferences(
                applicationBundleIdentifier,
                Context.MODE_PRIVATE
            )
            val storedDeviceID = sharedPrefs.getString(deviceIDKey, null)

            return if (storedDeviceID != null) {
                storedDeviceID
            } else {
                val newDeviceID = UUID.randomUUID().toString()
                sharedPrefs.edit { putString(deviceIDKey, newDeviceID) }
                newDeviceID
            }
        }

    private val hasFrontCamera: Boolean
        get() = applicationContext.packageManager.hasSystemFeature(PackageManager.FEATURE_CAMERA_FRONT)

    private val hasFaceID: Boolean
        get() {
            return applicationContext.packageManager.hasSystemFeature(PackageManager.FEATURE_FACE)
        }

    private val hasTouchID: Boolean
        get() = applicationContext.packageManager.hasSystemFeature(PackageManager.FEATURE_FINGERPRINT)

    private val applicationBundleIdentifier: String
        get() = applicationContext.packageName

    private val applicationName: String
        get() {
            val applicationInfo = applicationContext.packageManager.getApplicationInfo(
                applicationContext.packageName,
                0
            )
            return applicationContext.packageManager.getApplicationLabel(applicationInfo).toString()
        }

    private val applicationVersion: String
        get() = applicationContext.packageManager.getPackageInfo(
            applicationContext.packageName,
            0
        ).versionName ?: "Unknown"


    private val frameworkVersion: String
        get() = BuildConfig.VERSION_NAME

    /**
     * Returns a dictionary of device and application attributes.
     *
     * This method collects all available device, application, and security attributes
     * and returns them as a map. The keys can be formatted in either camelCase or
     * snake_case depending on the API requirements.
     *
     * @param snakeCaseKey If `true`, keys are formatted in snake_case (e.g., "device_name").
     *                     If `false` (default), keys are formatted in camelCase (e.g., "deviceName").
     *
     * @return A map containing the following attributes:
     * - `applicationId` / `application_id`: The application's package name
     * - `applicationName` / `application_name`: The application's display name
     * - `applicationVersion` / `application_version`: The application's version name
     * - `deviceName` / `device_name`: The device model name (e.g., "Pixel 3a")
     * - `platformType` / `platform_type`: Always "Android"
     * - `deviceType` / `device_type`: The device manufacturer (e.g., "Google")
     * - `deviceId` / `device_id`: A persistent unique device identifier (UUID)
     * - `osVersion` / `os_version`: The Android OS version (e.g., "10")
     * - `faceSupport` / `face_support`: Boolean indicating face recognition support
     * - `deviceInsecure` / `device_insecure`: Boolean indicating if device is rooted
     * - `fingerprintSupport` / `fingerprint_support`: Boolean indicating fingerprint sensor support
     * - `frontCameraSupport` / `front_camera_support`: Boolean indicating front camera availability
     * - `verifySdkVersion` / `verify_sdk_version`: The IBM Verify SDK version
     *
     * @throws IllegalStateException if [ContextHelper] has not been initialized
     *
     * @sample
     * ```kotlin
     * // Get attributes with camelCase keys
     * val attrs = MFAAttributeInfo.dictionary()
     * val deviceId = attrs["deviceId"] as String
     *
     * // Get attributes with snake_case keys
     * val snakeAttrs = MFAAttributeInfo.dictionary(snakeCaseKey = true)
     * val deviceId = snakeAttrs["device_id"] as String
     * ```
     */
    fun dictionary(snakeCaseKey: Boolean = false): Map<String, Any> {
        return mapOf(
            (if (snakeCaseKey) "applicationId".toSnakeCase() else "applicationId") to applicationBundleIdentifier,
            (if (snakeCaseKey) "applicationName".toSnakeCase() else "applicationName") to applicationName,
            (if (snakeCaseKey) "applicationVersion".toSnakeCase() else "applicationVersion") to applicationVersion,
            (if (snakeCaseKey) "deviceName".toSnakeCase() else "deviceName") to name,
            (if (snakeCaseKey) "platformType".toSnakeCase() else "platformType") to operatingSystem,
            (if (snakeCaseKey) "deviceType".toSnakeCase() else "deviceType") to model,
            (if (snakeCaseKey) "deviceId".toSnakeCase() else "deviceId") to deviceID,
            (if (snakeCaseKey) "osVersion".toSnakeCase() else "osVersion") to operatingSystemVersion,
            (if (snakeCaseKey) "faceSupport".toSnakeCase() else "faceSupport") to hasFaceID,
            (if (snakeCaseKey) "deviceInsecure".toSnakeCase() else "deviceInsecure") to deviceInsecure,
            (if (snakeCaseKey) "fingerprintSupport".toSnakeCase() else "fingerprintSupport") to hasTouchID,
            (if (snakeCaseKey) "frontCameraSupport".toSnakeCase() else "frontCameraSupport") to hasFrontCamera,
            (if (snakeCaseKey) "verifySdkVersion".toSnakeCase() else "verifySdkVersion") to frameworkVersion
        )
    }

    private fun String.toSnakeCase(): String {
        return this.replace(Regex("([a-z0-9])([A-Z])"), "$1_$2").lowercase(Locale.getDefault())
    }
}
