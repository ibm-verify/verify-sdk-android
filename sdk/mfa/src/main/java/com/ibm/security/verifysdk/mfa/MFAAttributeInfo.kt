/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.mfa

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.content.edit
import com.scottyab.rootbeer.RootBeer
import java.util.Locale
import java.util.UUID

object MFAAttributeInfo {

    private lateinit var applicationContext: Context

    fun init(context: Context): MFAAttributeInfo {
        this.applicationContext = context
        return this
    }

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
