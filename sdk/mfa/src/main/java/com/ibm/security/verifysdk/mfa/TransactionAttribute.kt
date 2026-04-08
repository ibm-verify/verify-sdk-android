/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.mfa

import kotlinx.serialization.Serializable

/**
 * Represents additional attributes that can be associated with a transaction.
 *
 * These attributes provide contextual information about the transaction request,
 * including network details, correlation data, and user interaction requirements.
 */
@Serializable
enum class TransactionAttribute(val rawValue: String) {
    /** The IP address from which the transaction originated */
    IPAddress("ipAddress"),
    
    /** The geographic location of the transaction origin */
    Location("location"),
    
    /** URL to an image associated with the transaction */
    Image("image"),
    
    /** The user agent string of the client making the transaction request */
    UserAgent("userAgent"),
    
    /** The type of transaction being performed */
    Type("type"),
    
    /** Custom attribute for application-specific data */
    Custom("custom"),
    
    /**
     * The correlation value for the transaction, typically a 2-digit number (00-99).
     * This value is set when correlationEnabled is true in the transaction extras.
     * If correlationValue is provided, it is used directly; otherwise, it is calculated
     * from the transaction ID. Used primarily with OnPremise authenticators.
     */
    Correlation("correlation"),
    
    /**
     * Indicates whether the user can provide a reason when denying the transaction.
     * Used primarily with OnPremise authenticators.
     */
    DenyReason("denyReason")
}