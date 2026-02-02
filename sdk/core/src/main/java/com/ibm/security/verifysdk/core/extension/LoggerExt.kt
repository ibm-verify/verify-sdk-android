/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.core.extension

import org.slf4j.Logger
import org.slf4j.event.Level
import java.util.Locale

private const val unsupportedLevelMessage =
    "Log level {} is not supported. See https://developer.android.com/reference/android/util/Log#summary"

/**
 * Creates a log message in the format
 *
 *      Entry class={} method={}
 *
 * @param level  The log level for the message. Default is `Level.INFO`.
 *
 * @since 3.0.0
 */
fun Logger.entering(level: Level = Level.INFO) {

    val message = "Entry class={} method={}"
    var ste: StackTraceElement = Thread.currentThread().stackTrace[4]

    /*  Handles the case when a `level` parameter is provided and no additional internal function
        call with the default value is required.
     */
    if (ste.methodName.equals("invoke")) {
        ste = Thread.currentThread().stackTrace[3]
    }

    when (level) {
        Level.TRACE -> trace(message, ste.className, ste.methodName)
        Level.DEBUG -> debug(message, ste.className, ste.methodName)
        Level.INFO -> info(message, ste.className, ste.methodName)
        Level.WARN -> warn(message, ste.className, ste.methodName)
        Level.ERROR -> error(message, ste.className, ste.methodName)
    }
}

/**
 * Creates a log message in the format
 *
 *      Exit class={} method={}
 *
 * @param level  The log level for the message. Default is `Level.INFO`.
 *
 * @since 3.0.0
 */
fun Logger.exiting(level: Level = Level.INFO) {

    val message = "Exit class={} method={}"
    var ste: StackTraceElement = Thread.currentThread().stackTrace[4]

    /*  Handles the case when a `level` parameter is provided and no additional internal function
        call with the default value is required.
    */
    if (ste.methodName.equals("invoke")) {
        ste = Thread.currentThread().stackTrace[3]
    }

    when (level) {
        Level.TRACE -> trace(message, ste.className, ste.methodName)
        Level.DEBUG -> debug(message, ste.className, ste.methodName)
        Level.INFO -> info(message, ste.className, ste.methodName)
        Level.WARN -> warn(message, ste.className, ste.methodName)
        Level.ERROR -> error(message, ste.className, ste.methodName)
    }
}

/**
 * Creates a log message with the name and ID of the current thread.
 *
 * @param level  The log level for the message. Default is `Level.INFO`.
 *
 * @since 3.0.0
 */
fun Logger.threadInfo(level: Level = Level.INFO) {

    val message =
        String.format(Locale.getDefault(),"threadName=${Thread.currentThread().name}; threadId=${Thread.currentThread().id};")

    when (level) {
        Level.TRACE -> trace(message)
        Level.DEBUG -> debug(message)
        Level.INFO -> info(message)
        Level.WARN -> warn(message)
        Level.ERROR -> error(message)
    }
}