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
import kotlin.time.Clock
import kotlin.time.Duration.Companion.seconds

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

    // Cache duration for root check (1 minute = 60 seconds)
    private val ROOT_CHECK_CACHE_DURATION = 60.seconds
    
    // Cached root check result with timestamp
    @Volatile
    private var lastRootCheck: Pair<Long, Boolean>? = null

    // Lazily computed static attributes (computed once and cached)
    private val staticAttributes: Map<String, Any> by lazy {
        mapOf(
            "deviceName" to Build.MODEL,
            "deviceType" to Build.MANUFACTURER,
            "platformType" to "Android",
            "osVersion" to Build.VERSION.RELEASE,
            "applicationId" to applicationBundleIdentifier,
            "applicationName" to applicationName,
            "applicationVersion" to applicationVersion,
            "deviceId" to deviceID,
            "frontCameraSupport" to hasFrontCamera,
            "fingerprintSupport" to hasTouchID,
            "faceSupport" to hasFaceID,
            "verifySdkVersion" to BuildConfig.VERSION_NAME
        )
    }

    /**
     * Checks if the device is rooted/insecure with caching.
     *
     * Root detection is expensive (checks multiple indicators), so we cache
     * the result for 1 minute to improve performance while still detecting
     * changes reasonably quickly.
     */
    private val deviceInsecure: Boolean
        get() {
            val now = Clock.System.now()
            val cached = lastRootCheck
            
            return if (cached != null && (now.epochSeconds - cached.first) < ROOT_CHECK_CACHE_DURATION.inWholeSeconds) {
                // Return cached result if still valid
                cached.second
            } else {
                // Perform fresh root check
                val isRooted = RootBeer(applicationContext).isRooted
                lastRootCheck = Pair(now.epochSeconds, isRooted)
                isRooted
            }
        }

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
        get() = applicationContext.packageManager.hasSystemFeature(PackageManager.FEATURE_FACE)

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
        // Get cached static attributes
        val attributes = if (snakeCaseKey) {
            // Convert keys to snake_case if requested
            staticAttributes.mapKeys { (key, _) -> key.toSnakeCase() }
        } else {
            staticAttributes
        }.toMutableMap()
        
        // Add fresh deviceInsecure check (cached for 1 minute)
        val insecureKey = if (snakeCaseKey) "device_insecure" else "deviceInsecure"
        attributes[insecureKey] = deviceInsecure
        
        return attributes
    }
    
    /**
     * Invalidates the root check cache, forcing a fresh check on next access.
     *
     * This can be useful in testing scenarios or when you want to force
     * an immediate re-check of root status.
     */
    fun invalidateRootCheckCache() {
        lastRootCheck = null
    }

    private fun String.toSnakeCase(): String {
        return this.replace(Regex("([a-z0-9])([A-Z])"), "$1_$2").lowercase(Locale.getDefault())
    }
}
