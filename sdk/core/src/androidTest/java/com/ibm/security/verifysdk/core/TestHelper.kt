/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.core

import android.util.Log
import java.io.BufferedReader
import java.io.IOException
import java.io.InputStreamReader
import java.lang.reflect.Field
import java.util.Locale

class TestHelper {

    companion object {

        private val TAG = TestHelper::class.java.canonicalName!!

        fun getLogsAfterTestStart(testName: String): StringBuilder {

            val stringBuilder = StringBuilder()

            // Process ID to filter the messages
            val currentProcessId = android.os.Process.myPid().toString()
            val startMessage = String.format(
                Locale.getDefault(),
                "%s%s",
                Constants.TEST_HELPER_START_MESSAGE,
                testName
            )
            val command = arrayOf("logcat", "-d", "-v", "threadtime")
            var isRecording = false

            var bufferReader: BufferedReader? = null

            try {
                val process: Process = Runtime.getRuntime().exec(command)
                bufferReader = BufferedReader(InputStreamReader(process.inputStream))

                val iterator = bufferReader.buffered().lineSequence().iterator()
                while (iterator.hasNext()) {
                    val line = iterator.next()
                    if (line.contains(currentProcessId)) {
                        if (line.contains(startMessage)) {
                            isRecording = true
                        }
                        if (isRecording) {
                            stringBuilder.append(line).append("\n")
                        }
                    }
                }
            } catch (e: IOException) {
                Log.e(TAG, "Failed to run logcat command", e)
            } finally {
                bufferReader?.let {
                    try {
                        it.close()
                    } catch (e: IOException) {
                        Log.e(TAG, "Failed to closed buffered reader", e)
                    }
                }
            }

            return stringBuilder
        }

        fun setFinalStatic(field: Field, newValue: Any) {
            field.isAccessible = true
            field.set(null, newValue)
        }
    }

}