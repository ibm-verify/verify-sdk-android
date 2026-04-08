/*
 * Copyright contributors to the IBM Verify Adaptive SDK for Android project
 */

package com.ibm.security.verifysdk.adaptive

import android.content.Context
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.ProcessLifecycleOwner
import java.util.Date
import java.util.UUID

// TODO: Handle TasStop on app termination (or handle on app stop, and TasStart on onResume)

/**
 * The context by which Policy Driven Authentication is managed.
 *
 * @since 3.0.0
 */
object AdaptiveContext : DefaultLifecycleObserver {
    /** The session identifier for the hosting application. */
    var sessionId: String = UUID.randomUUID().toString()

    /**
     * The interval in seconds to renew the session identifier. Default is 3,600 (1 hour).
     *
     * This will occur when the application is opened from the background.
     */
    var renewSessionIdInterval: Int = 3600

    /**
     * The timestamp of when the session ID was generated.
     *
     * This is updated whenever a new session ID is generated after the application is opened from
     * the background.
     */
    var renewSessionIdTimestamp: Date = Date()

    /** An instance of `AdaptiveCollection` implementation. */
    var collectionService: AdaptiveCollectionService? = null

    /** Initializes a new instance of `AdaptiveContext`. */
    init {
        // Add an observer ot listen for changes in the application lifecycle, such as when the
        // application is opened from the background.
        ProcessLifecycleOwner.get().lifecycle.addObserver(this)
    }

    /**
     * Starts the collection operation.
     *
     * @param context The [Context] of the Android application using this SDK.
     * @throws Exception The `vendorCollection` class variable has not been initialised.
     *
     * Example usage:
     * ```
     * AdaptiveContext.vendorCollection = MyCollectionClass() // Custom class implementing the `AdaptiveCollection` interface.
     * AdaptiveContext.start(applicationContext) // Starts the collection process
     * ```
     */
    @Throws(Exception::class)
    fun start(context: Context) {
        if (collectionService == null) {
            throw Exception("An instance of AdaptiveCollection was not assigned to AdaptiveContext.vendorCollection.")
        }
        collectionService!!.start(context = context, sessionId = this.sessionId)
    }

    /**
     * Stops the collection operation.
     *
     * @throws Exception The `vendorCollection` class variable has not been initialised.
     *
     * Example usage:
     * ```
     * AdaptiveContext.vendorCollection = MyCollectionClass() // Custom class implementing the `AdaptiveCollection` interface.
     * AdaptiveContext.start(applicationContext) // Starts the collection process
     * ...
     * AdaptiveContext.stop() // Stops the collection process
     * ```
     */
    @Throws(Exception::class)
    fun stop() {
        if (collectionService == null) {
            throw Exception("An instance of AdaptiveCollection was not assigned to AdaptiveContext.vendorCollection.")
        }
        collectionService!!.stop()
    }

    /**
     * Called when the implementing application starts.
     *
     * The implementing application is observed, and this function is called when the application
     * starts. This includes the first launch, as well as bringing the application to the
     * foreground. If the session ID has expired upon starting, a new session ID is generated, and
     * the session is reset.
     */
    @Throws(Exception::class)
    override fun onStart(owner: LifecycleOwner) {
        resetSession()
    }

    internal fun resetSession() {
        // Check if the session ID has expired, based on session ID interval, and the timestamp at
        // which the session ID was generated. If so, create a new session ID.
        if (Date().time - renewSessionIdTimestamp.time > renewSessionIdInterval * 1000) {
            val oldSessionId = sessionId
            sessionId = UUID.randomUUID().toString()
            renewSessionIdTimestamp = Date()

            println(
                "creating a new session identifier." +
                        "\n\told: $oldSessionId" +
                        "\n\tnew: $sessionId" +
                        "\n\texpires: ${Date(renewSessionIdTimestamp.time + renewSessionIdInterval * 1000)}"
            )

            try {
                collectionService?.reset(sessionId = this.sessionId)
            } catch (e: Exception) {
                println("Error: ${e.localizedMessage}")
            }
        }
    }
}

/**
 * The [AdaptiveCollectionService] is implemented by risk vendors to commence the collection of mobile device data.
 * ```
 * class MyCollectionClass: AdaptiveCollection {
 *     override fun start(context: Context, sessionId: String) {
 *         // The vendor operation to start collecting device data.
 *     }
 *
 *     override fun stop() {
 *         // The vendor operation to stop collecting device data.
 *     }
 *
 *     override fun reset(sessionId: String) {
 *         // The vendor operation to reset collecting device data.
 *     }
 * }
 *
 * // Assign the risk collection to the field.
 * AdaptiveContext.vendorCollection = MyCollectionClass() // Custom class implementing the `AdaptiveCollection` interface.
 *
 * AdaptiveContext.start(applicationContext) // Starts the collection process
 * ```
 *
 * @since 3.0.0
 */
interface AdaptiveCollectionService {
    /** The identifier of the vendor. */
    val vendorId: String

    /** The client identifier. */
    val clientId: String

    /** The client key. */
    val clientKey: String

    /**
     * Starts the collection operation.
     *
     * This operation associates the [sessionId] with Adaptive authentication.
     *
     * @param sessionId The session identifier for the hosting application.
     */
    fun start(context: Context, sessionId: String)

    /**
     * Stop the collection operation.
     */
    fun stop()

    /**
     * Resets the collection operation.
     *
     * @param sessionId The session identifier for the hosting application.
     */
    fun reset(sessionId: String)
}
