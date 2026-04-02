/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.core.extension

import android.util.Log
import org.slf4j.Logger

/**
 * Extension functions for efficient logging with lazy evaluation.
 *
 * These extensions prevent string concatenation when the log level is disabled,
 * improving performance in production builds.
 *
 * ## Usage Example
 * ```kotlin
 * // Instead of:
 * Log.d(TAG, "Processing transaction ${transaction.id} for user ${user.name}")
 *
 * // Use:
 * logDebug(TAG) { "Processing transaction ${transaction.id} for user ${user.name}" }
 * ```
 *
 * The lambda is only evaluated if the log level is enabled, avoiding unnecessary
 * string allocations and concatenations.
 */

/**
 * Logs a debug message with lazy evaluation.
 *
 * @param tag The log tag
 * @param message Lambda that produces the log message (only evaluated if debug logging is enabled)
 */
inline fun logDebug(tag: String, message: () -> String) {
    if (Log.isLoggable(tag, Log.DEBUG)) {
        Log.d(tag, message())
    }
}

/**
 * Logs an info message with lazy evaluation.
 *
 * @param tag The log tag
 * @param message Lambda that produces the log message (only evaluated if info logging is enabled)
 */
inline fun logInfo(tag: String, message: () -> String) {
    if (Log.isLoggable(tag, Log.INFO)) {
        Log.i(tag, message())
    }
}

/**
 * Logs a warning message with lazy evaluation.
 *
 * @param tag The log tag
 * @param message Lambda that produces the log message (only evaluated if warn logging is enabled)
 */
inline fun logWarn(tag: String, message: () -> String) {
    if (Log.isLoggable(tag, Log.WARN)) {
        Log.w(tag, message())
    }
}

/**
 * Logs an error message with lazy evaluation.
 *
 * @param tag The log tag
 * @param message Lambda that produces the log message (only evaluated if error logging is enabled)
 */
inline fun logError(tag: String, message: () -> String) {
    if (Log.isLoggable(tag, Log.ERROR)) {
        Log.e(tag, message())
    }
}

/**
 * Logs an error message with exception and lazy evaluation.
 *
 * @param tag The log tag
 * @param throwable The exception to log
 * @param message Lambda that produces the log message (only evaluated if error logging is enabled)
 */
inline fun logError(tag: String, throwable: Throwable, message: () -> String) {
    if (Log.isLoggable(tag, Log.ERROR)) {
        Log.e(tag, message(), throwable)
    }
}

/**
 * SLF4J Logger extension for entering method logging.
 *
 * Logs method entry at TRACE level with lazy evaluation.
 */
inline fun Logger.entering(lazyMessage: () -> String = { "" }) {
    if (isTraceEnabled) {
        val message = lazyMessage()
        trace(if (message.isEmpty()) "Entering" else "Entering: $message")
    }
}

/**
 * SLF4J Logger extension for exiting method logging.
 *
 * Logs method exit at TRACE level with lazy evaluation.
 */
inline fun Logger.exiting(lazyMessage: () -> String = { "" }) {
    if (isTraceEnabled) {
        val message = lazyMessage()
        trace(if (message.isEmpty()) "Exiting" else "Exiting: $message")
    }
}

/**
 * SLF4J Logger extension for debug logging with lazy evaluation.
 */
inline fun Logger.debugLazy(lazyMessage: () -> String) {
    if (isDebugEnabled) {
        debug(lazyMessage())
    }
}

/**
 * SLF4J Logger extension for info logging with lazy evaluation.
 */
inline fun Logger.infoLazy(lazyMessage: () -> String) {
    if (isInfoEnabled) {
        info(lazyMessage())
    }
}

/**
 * SLF4J Logger extension for warn logging with lazy evaluation.
 */
inline fun Logger.warnLazy(lazyMessage: () -> String) {
    if (isWarnEnabled) {
        warn(lazyMessage())
    }
}

/**
 * SLF4J Logger extension for error logging with lazy evaluation.
 */
inline fun Logger.errorLazy(lazyMessage: () -> String) {
    if (isErrorEnabled) {
        error(lazyMessage())
    }
}

/**
 * SLF4J Logger extension for error logging with exception and lazy evaluation.
 */
inline fun Logger.errorLazy(throwable: Throwable, lazyMessage: () -> String) {
    if (isErrorEnabled) {
        error(lazyMessage(), throwable)
    }
}