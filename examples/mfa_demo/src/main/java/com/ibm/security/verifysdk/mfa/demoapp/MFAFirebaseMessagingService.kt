/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */
package com.ibm.security.verifysdk.mfa.demoapp

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.core.app.NotificationCompat
import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import androidx.core.content.edit

/**
 * Firebase Cloud Messaging service for handling push notifications in the MFA Demo app.
 * 
 * This service receives push notifications from Firebase and displays them to the user.
 * It also handles FCM token registration and updates.
 */
class MFAFirebaseMessagingService : FirebaseMessagingService() {

    private val log: Logger = LoggerFactory.getLogger(javaClass.name)

    companion object {
        private const val CHANNEL_ID = "mfa_notifications"
        private const val CHANNEL_NAME = "MFA Notifications"
        private const val CHANNEL_DESCRIPTION = "Notifications for MFA transactions"
        private const val NOTIFICATION_ID = 1001
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    /**
     * Called when a new FCM token is generated.
     * This happens on initial app install and whenever the token is refreshed.
     * 
     * @param token The new FCM registration token
     */
    override fun onNewToken(token: String) {
        super.onNewToken(token)
        log.info("New FCM token generated: $token")
        
        // Save the token to SharedPreferences
        saveFcmToken(token)
        
        // Send the token to your server for registration. This happens when the IBM Verify
        // MFA SDK performs an OAuth token refresh flow. The FCM token is picked up from
        // SharedPreferences, where it is stored ^^.
    }

    /**
     * Called when a message is received from Firebase Cloud Messaging.
     * 
     * @param remoteMessage The message received from FCM
     */
    override fun onMessageReceived(remoteMessage: RemoteMessage) {
        super.onMessageReceived(remoteMessage)
        
        log.info("Message received from: ${remoteMessage.from}")
        
        // Check if message contains a notification payload
        remoteMessage.notification?.let { notification ->
            log.info("Notification title: ${notification.title}")
            log.info("Notification body: ${notification.body}")

            if (remoteMessage.data.isEmpty()) {
                showNotification(
                    title = notification.title ?: "MFA Transaction",
                    message = notification.body ?: "You have a pending transaction"
                )
            }
        }
        
        // Check if message contains a data payload
        if (remoteMessage.data.isNotEmpty()) {
            log.info("Message data payload: ${remoteMessage.data}")
            
            // Handle data payload
            handleDataPayload(remoteMessage.data)
        }
    }

    /**
     * Handle the data payload from the push notification.
     * This can be used to trigger specific actions based on the notification content.
     * 
     * @param data The data payload from the notification
     */
    private fun handleDataPayload(data: Map<String, String>) {
        // Extract relevant information from the data payload
        val transactionId = data["transactionId"]
        val authenticatorId = data["authenticatorId"]
        val message = data["message"]
        
        log.info("Transaction ID: $transactionId")
        log.info("Authenticator ID: $authenticatorId")
        log.info("Message: $message")
        
        // Trigger immediate action in MainActivity if we have the required data
        if (transactionId != null && authenticatorId != null) {
            log.info("Triggering immediate transaction handling in MainActivity")
            triggerImmediateAction(transactionId, authenticatorId)
        } else {
            log.warn("Missing transactionId or authenticatorId, showing notification only")
            // Show notification with the data
            showNotification(
                title = data["title"] ?: "MFA Transaction",
                message = message ?: "You have a pending transaction"
            )
        }
    }
    
    /**
     * Trigger an immediate action in MainActivity by starting it with intent extras.
     * This bypasses the notification and directly opens the app to handle the transaction.
     *
     * @param transactionId The transaction ID from the push notification
     * @param authenticatorId The authenticator ID from the push notification
     */
    private fun triggerImmediateAction(transactionId: String, authenticatorId: String) {
        val intent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP
            putExtra(Constants.EXTRA_TRANSACTION_ID, transactionId)
            putExtra(Constants.EXTRA_AUTHENTICATOR_ID, authenticatorId)
            putExtra(Constants.EXTRA_HANDLE_TRANSACTION, true)
        }
        
        startActivity(intent)
        log.info("Started MainActivity with transaction data")
    }

    /**
     * Display a notification to the user.
     * 
     * @param title The notification title
     * @param message The notification message
     */
    private fun showNotification(title: String, message: String) {
        // Create an intent to open the MainActivity when notification is tapped
        val intent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
        }
        
        val pendingIntent = PendingIntent.getActivity(
            this,
            0,
            intent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        
        // Build the notification
        val notificationBuilder = NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.mipmap.ic_launcher)
            .setContentTitle(title)
            .setContentText(message)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true)
            .setContentIntent(pendingIntent)
            .setStyle(NotificationCompat.BigTextStyle().bigText(message))
        
        // Show the notification
        val notificationManager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        notificationManager.notify(NOTIFICATION_ID, notificationBuilder.build())
    }

    /**
     * Create a notification channel for Android O and above.
     * This is required for notifications to be displayed on newer Android versions.
     */
    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            CHANNEL_ID,
            CHANNEL_NAME,
            NotificationManager.IMPORTANCE_HIGH
        ).apply {
            description = CHANNEL_DESCRIPTION
            enableLights(true)
            enableVibration(true)
        }

        val notificationManager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        notificationManager.createNotificationChannel(channel)

        log.info("Notification channel created: $CHANNEL_ID")
    }

    /**
     * Save the FCM token to SharedPreferences for later use.
     * 
     * @param token The FCM token to save
     */
    private fun saveFcmToken(token: String) {
        val prefs = getSharedPreferences(Constants.PREFS_NAME, Context.MODE_PRIVATE)
        prefs.edit { putString(Constants.KEY_FCM_TOKEN, token) }
        log.info("FCM token saved to SharedPreferences")
    }
}
