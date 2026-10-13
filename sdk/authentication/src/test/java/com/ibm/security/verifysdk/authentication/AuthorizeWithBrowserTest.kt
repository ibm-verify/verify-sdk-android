//
// Copyright contributors to the IBM Verify Authentication SDK for Android project
//
package com.ibm.security.verifysdk.authentication

import android.app.Activity
import android.content.Intent
import androidx.activity.ComponentActivity
import com.ibm.security.verifysdk.authentication.api.OAuthProvider
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import java.net.URL

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class AuthorizeWithBrowserTest {

    private val provider = OAuthProvider("test-client-id", "test-client-secret")
    private val authUrl = URL("https://example.com/oauth2/authorize")
    private val redirectUrl = "com.ibm.verify://oauth2redirect"

    private fun createActivity(): ComponentActivity {
        return Robolectric.buildActivity(ComponentActivity::class.java).setup().get()
    }

    @Test
    fun `authorizeWithBrowser unregisters launcher upon receiving result to prevent double delivery`() = runTest {
        val activity = createActivity()
        val shadowActivity = shadowOf(activity)

        val deferredResult = async {
            provider.authorizeWithBrowser(
                url = authUrl,
                redirectUrl = redirectUrl,
                activity = activity
            )
        }

        testScheduler.runCurrent()

        val startedActivity = shadowActivity.nextStartedActivityForResult
        assertNotNull("Activity should have been started by launcher", startedActivity)
        val requestCode = startedActivity.requestCode

        val resultIntent = Intent().apply {
            putExtra("code", "auth_code_123")
        }

        // First result dispatch
        val firstDispatched = activity.activityResultRegistry.dispatchResult(requestCode, Activity.RESULT_OK, resultIntent)
        assertTrue("First dispatch should be handled by registry", firstDispatched)

        val result = deferredResult.await()
        assertTrue(result.isSuccess)
        assertEquals("auth_code_123", result.getOrNull())

        // Dispatching a second result should be safely ignored and not throw IllegalStateException: Already resumed
        val secondIntent = Intent().apply {
            putExtra("code", "auth_code_duplicate")
        }
        activity.activityResultRegistry.dispatchResult(requestCode, Activity.RESULT_OK, secondIntent)
        assertEquals("auth_code_123", result.getOrNull())
    }

    @Test
    fun `authorizeWithBrowser consumes a pending result delivered during registration without failing`() = runTest {
        val activity = createActivity()
        val shadowActivity = shadowOf(activity)

        // First call completes normally and unregisters its launcher.
        val first = async {
            provider.authorizeWithBrowser(url = authUrl, redirectUrl = redirectUrl, activity = activity)
        }
        testScheduler.runCurrent()
        val firstRequestCode = shadowActivity.nextStartedActivityForResult.requestCode
        activity.activityResultRegistry.dispatchResult(
            firstRequestCode, Activity.RESULT_OK, Intent().putExtra("code", "first_code")
        )
        assertEquals("first_code", first.await().getOrNull())

        // A result arrives while no callback is registered; the registry keeps it as pending
        // and replays it synchronously on the next register("code"), as it does after recreation.
        activity.activityResultRegistry.dispatchResult(
            firstRequestCode, Activity.RESULT_OK, Intent().putExtra("code", "pending_code")
        )

        val second = async {
            provider.authorizeWithBrowser(url = authUrl, redirectUrl = redirectUrl, activity = activity)
        }
        testScheduler.runCurrent()

        assertTrue("Pending result should complete the call immediately", second.isCompleted)
        val result = second.await()
        assertTrue("Expected success but got ${result.exceptionOrNull()}", result.isSuccess)
        assertEquals("pending_code", result.getOrNull())
        assertNull("Browser must not be launched when a pending result was consumed",
            shadowActivity.nextStartedActivityForResult)
    }

    @Test
    fun `authorizeWithBrowser rethrows CancellationException when coroutine is cancelled`() = runTest {
        val activity = createActivity()
        val shadowActivity = shadowOf(activity)

        var caughtCancellation: CancellationException? = null
        var returnedResult: Result<String>? = null

        val job = launch {
            try {
                returnedResult = provider.authorizeWithBrowser(
                    url = authUrl,
                    redirectUrl = redirectUrl,
                    activity = activity
                )
            } catch (e: CancellationException) {
                caughtCancellation = e
            }
        }

        testScheduler.runCurrent()

        val startedActivity = shadowActivity.nextStartedActivityForResult
        assertNotNull("Activity should have been started by launcher", startedActivity)
        val requestCode = startedActivity.requestCode

        // Cancel while waiting for browser result
        job.cancelAndJoin()

        // Cancellation must be rethrown, not swallowed and wrapped in Result.failure
        assertNotNull("CancellationException must be rethrown upon coroutine cancellation", caughtCancellation)
        assertEquals("Result should not be returned when cancelled", null, returnedResult)

        // Dispatching after cancellation should be safely ignored and not crash
        val cancelIntent = Intent().apply {
            putExtra("code", "auth_code_after_cancel")
        }
        activity.activityResultRegistry.dispatchResult(requestCode, Activity.RESULT_OK, cancelIntent)
    }

    @Test
    fun `AuthenticationActivity saves and restores state across activity recreation`() {
        val intent = Intent().apply {
            putExtra("url", "https://example.com/authorize")
            putExtra("ephemeralSession", false)
        }
        val controller = Robolectric.buildActivity(AuthenticationActivity::class.java, intent).setup()
        val activity = controller.get()

        // Simulate onNewIntent receiving code
        val redirectIntent = Intent().apply {
            data = android.net.Uri.parse("com.ibm.verify://oauth2redirect?code=sample_auth_code_123")
        }
        controller.newIntent(redirectIntent)

        // Save instance state
        val bundle = android.os.Bundle()
        controller.saveInstanceState(bundle)

        // Recreate activity with saved state
        val recreatedController = Robolectric.buildActivity(AuthenticationActivity::class.java, intent)
            .create(bundle)
            .start()
            .restoreInstanceState(bundle)
            .resume()

        val recreatedActivity = recreatedController.get()
        assertTrue("Recreated activity should finish and return result", recreatedActivity.isFinishing)
    }
}
