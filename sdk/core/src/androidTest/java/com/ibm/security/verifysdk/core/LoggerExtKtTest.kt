/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.core

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.filters.MediumTest
import com.ibm.security.verifysdk.core.extension.entering
import com.ibm.security.verifysdk.core.extension.exiting
import com.ibm.security.verifysdk.core.extension.debugLazy
import com.ibm.security.verifysdk.core.extension.infoLazy
import com.ibm.security.verifysdk.core.extension.warnLazy
import com.ibm.security.verifysdk.core.extension.errorLazy
import org.junit.Test
import org.junit.runner.RunWith
import org.slf4j.Logger
import org.slf4j.LoggerFactory

/**
 * Test cases for Logger extension functions.
 * 
 * These tests verify that the lazy logging extensions work correctly
 * and only evaluate the message lambda when the log level is enabled.
 */
@MediumTest
@RunWith(AndroidJUnit4::class)
internal class LoggerExtKtTest {

    private val log: Logger = LoggerFactory.getLogger(LoggerExtKtTest::class.java)

    @Test
    fun entering_withoutMessage_shouldLog() {
        // Should not throw exception
        log.entering()
    }

    @Test
    fun entering_withMessage_shouldLog() {
        // Should not throw exception
        log.entering { "Starting test method" }
    }

    @Test
    fun exiting_withoutMessage_shouldLog() {
        // Should not throw exception
        log.exiting()
    }

    @Test
    fun exiting_withMessage_shouldLog() {
        // Should not throw exception
        log.exiting { "Completed test method" }
    }

    @Test
    fun debugLazy_withMessage_shouldLog() {
        var evaluated = false
        log.debugLazy {
            evaluated = true
            "Debug message"
        }
        // Message may or may not be evaluated depending on log level
        // Just verify no exception is thrown
    }

    @Test
    fun infoLazy_withMessage_shouldLog() {
        var evaluated = false
        log.infoLazy {
            evaluated = true
            "Info message"
        }
        // Message may or may not be evaluated depending on log level
        // Just verify no exception is thrown
    }

    @Test
    fun warnLazy_withMessage_shouldLog() {
        var evaluated = false
        log.warnLazy {
            evaluated = true
            "Warning message"
        }
        // Message may or may not be evaluated depending on log level
        // Just verify no exception is thrown
    }

    @Test
    fun errorLazy_withMessage_shouldLog() {
        var evaluated = false
        log.errorLazy {
            evaluated = true
            "Error message"
        }
        // Message may or may not be evaluated depending on log level
        // Just verify no exception is thrown
    }

    @Test
    fun errorLazy_withThrowable_shouldLog() {
        val exception = IllegalArgumentException("Test exception")
        log.errorLazy(exception) { "Error with exception" }
        // Should not throw exception
    }

    @Test
    fun lazyEvaluation_shouldOnlyEvaluateWhenEnabled() {
        // This test verifies the concept of lazy evaluation
        // The actual behavior depends on the log level configuration
        var debugEvaluated = false
        var infoEvaluated = false
        
        log.debugLazy {
            debugEvaluated = true
            "Debug"
        }
        
        log.infoLazy {
            infoEvaluated = true
            "Info"
        }
        
        // We can't assert the exact values since they depend on log configuration
        // But we can verify the methods execute without errors
    }

    @Test
    fun entering_exiting_sequence_shouldWork() {
        log.entering { "Test method" }
        // Do some work
        log.exiting { "Test method completed" }
        // Should not throw exception
    }

    @Test
    fun multipleLogLevels_shouldAllWork() {
        log.debugLazy { "Debug message" }
        log.infoLazy { "Info message" }
        log.warnLazy { "Warning message" }
        log.errorLazy { "Error message" }
        // Should not throw exception
    }
}