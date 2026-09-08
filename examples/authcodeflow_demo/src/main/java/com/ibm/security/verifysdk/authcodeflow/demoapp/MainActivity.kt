/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */
package com.ibm.security.verifysdk.authcodeflow.demoapp

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import com.ibm.security.verifysdk.authcodeflow.demoapp.ui.theme.AuthCodeFlowDemoTheme
import com.ibm.security.verifysdk.authentication.CodeChallengeMethod
import com.ibm.security.verifysdk.authentication.PKCEHelper
import com.ibm.security.verifysdk.authentication.api.OAuthProvider
import com.ibm.security.verifysdk.core.helper.NetworkHelper
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.net.URL

/**
 * Main activity for the Authorization Code Flow demo application.
 *
 * This activity demonstrates OAuth 2.0 authorization code flow with optional PKCE
 * (Proof Key for Code Exchange) support using the IBM Verify SDK.
 */
class MainActivity : ComponentActivity() {

    private val coroutineScope = CoroutineScope(Dispatchers.Main)
    private lateinit var oAuthProvider: OAuthProvider
    private lateinit var host: String
    private lateinit var clientId: String
    private lateinit var clientIdOpenBanking: String
    private lateinit var redirect: String
    private val log: Logger = LoggerFactory.getLogger(MainActivity::class.java)

    /**
     * Called when the activity is starting.
     *
     * Loads configuration from assets, initializes the OAuth provider, and sets up
     * the Compose UI with the authentication screen.
     *
     * @param savedInstanceState If the activity is being re-initialized after previously
     *                          being shut down, this Bundle contains the data it most
     *                          recently supplied. Otherwise it is null.
     */
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Load configuration from assets
        loadConfig()
        oAuthProvider = OAuthProvider(clientId = clientId)

        enableEdgeToEdge()
        setContent {
            AuthCodeFlowDemoTheme {
                AuthCodeFlowScreen(
                    host = host,
                    clientId = clientId,
                    redirect = redirect,
                    onAuthenticate = { usePKCE, useEphemeralSession, onCodeReceived ->
                        authenticateWithBrowser(usePKCE, useEphemeralSession, onCodeReceived)
                    }
                )
            }
        }
    }

    /**
     * Loads OAuth configuration from the config.properties file in assets.
     *
     * Reads the following properties:
     * - host: The OAuth server hostname
     * - clientId: The OAuth client identifier
     * - clientIdOpenBanking: Optional client ID for open banking (falls back to clientId)
     * - redirect: The redirect URI for OAuth callbacks
     *
     * @throws IllegalStateException if required properties are missing
     * @throws RuntimeException if the config.properties file cannot be loaded
     */
    private fun loadConfig() {
        val properties = java.util.Properties()
        try {
            assets.open("config.properties").use { inputStream ->
                properties.load(inputStream)
            }
            host = properties.getProperty("host")
                ?: throw IllegalStateException("host not found in config.properties")
            clientId = properties.getProperty("clientId")
                ?: throw IllegalStateException("clientId not found in config.properties")
            clientIdOpenBanking = properties.getProperty("clientIdOpenBanking")
                ?: clientId  // Fallback to regular clientId if not specified
            redirect = properties.getProperty("redirect")
                ?: throw IllegalStateException("redirect not found in config.properties")
        } catch (e: Exception) {
            throw RuntimeException(
                "Failed to load config.properties. " +
                        "Please copy config.properties.sample to config.properties and configure your values.",
                e
            )
        }
    }

    /**
     * Initiates OAuth authentication flow using the system browser.
     *
     * This method performs the following steps:
     * 1. Generates PKCE code verifier and challenge if PKCE is enabled
     * 2. Launches browser-based authorization with the OAuth provider
     * 3. Receives the authorization code via callback
     * 4. If PKCE is enabled, exchanges the code for tokens using the code verifier
     *
     * @param usePKCE Whether to use PKCE (Proof Key for Code Exchange) for enhanced security
     * @param onCodeReceived Callback function invoked when the authorization code is received
     */
    private fun authenticateWithBrowser(
        usePKCE: Boolean,
        useEphemeralSession: Boolean,
        onCodeReceived: (String) -> Unit
    ) {
        coroutineScope.launch {
            val authorizeEndpoint = "https://$host/oauth2/authorize"
            val tokenEndpoint = "https://$host/oauth2/token"

            oAuthProvider = OAuthProvider(clientId = clientId)
            oAuthProvider.ephemeralSession = useEphemeralSession
            if (useEphemeralSession) {
                oAuthProvider.additionalParameters["prompt"] = "login"
            }

            val codeVerifier = if (usePKCE) PKCEHelper.generateCodeVerifier() else null
            val codeChallenge = codeVerifier?.let { PKCEHelper.generateCodeChallenge(it) }

            oAuthProvider.authorizeWithBrowser(
                URL(authorizeEndpoint),
                redirect,
                codeChallenge = codeChallenge,
                method = if (usePKCE) CodeChallengeMethod.S256 else CodeChallengeMethod.PLAIN,
                scope = arrayOf("openid"),
                state = null,
                activity = this@MainActivity
            ).onSuccess { code ->
                log.info("--> Authorization code: $code")
                onCodeReceived(code)

                if (usePKCE) {
                    oAuthProvider.authorize(
                        httpClient = NetworkHelper.getInstance,
                        url = URL(tokenEndpoint),
                        redirectUrl = redirect,
                        code,
                        codeVerifier
                    )
                        .onSuccess { token ->
                            log.info("--> Token: $token")
                        }
                        .onFailure {
                            log.error("--> Error: $it")
                        }
                }
            }
                .onFailure {
                    log.error("--> Error: $it")
                }
        }
    }
}

/**
 * Composable function that displays the Authorization Code Flow demo screen.
 *
 * This screen provides:
 * - Configuration display (host, client ID, redirect URI)
 * - PKCE toggle switch
 * - Ephemeral Session toggle switch
 * - Authentication button to initiate the OAuth flow
 * - Authorization code display field
 *
 * @param host The OAuth server hostname
 * @param clientId The OAuth client identifier
 * @param redirect The redirect URI for OAuth callbacks
 * @param versionName App version name shown in the top bar; defaults to the running package info
 * @param versionCode App version code shown in the top bar; defaults to the running package info
 * @param onAuthenticate Callback function to initiate authentication, receives:
 *                       - usePKCE: Boolean indicating whether to use PKCE
 *                       - useEphemeralSession: Boolean indicating whether to use an ephemeral browser session
 *                       - onCodeReceived: Callback to handle the received authorization code
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AuthCodeFlowScreen(
    host: String,
    clientId: String,
    redirect: String,
    versionName: String? = null,
    versionCode: Int? = null,
    onAuthenticate: (Boolean, Boolean, (String) -> Unit) -> Unit
) {
    var usePKCE by remember { mutableStateOf(true) }
    var useEphemeralSession by remember { mutableStateOf(false) }
    var authorizationCode by remember { mutableStateOf("") }

    val context = androidx.compose.ui.platform.LocalContext.current
    val resolvedVersionName = versionName
        ?: context.packageManager.getPackageInfo(context.packageName, 0).versionName
    val resolvedVersionCode = versionCode
        ?: context.packageManager.getPackageInfo(context.packageName, 0).longVersionCode.toInt()

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text("IBM Verify SDK Auth Code Flow Demo")
                        Text(
                            text = "$resolvedVersionName ($resolvedVersionCode)",
                            style = MaterialTheme.typography.labelSmall
                        )
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.primaryContainer,
                    titleContentColor = MaterialTheme.colorScheme.onPrimaryContainer
                )
            )
        }
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .padding(horizontal = 16.dp, vertical = 8.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            // Configuration Card
            Card(
                modifier = Modifier.fillMaxWidth(),
                elevation = CardDefaults.cardElevation(defaultElevation = 4.dp)
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Text(
                        text = "Configuration",
                        style = MaterialTheme.typography.titleMedium
                    )

                    OutlinedTextField(
                        value = host,
                        onValueChange = {},
                        label = { Text("Host") },
                        readOnly = true,
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true
                    )

                    OutlinedTextField(
                        value = clientId,
                        onValueChange = {},
                        label = { Text("Client ID") },
                        readOnly = true,
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true
                    )

                    OutlinedTextField(
                        value = redirect,
                        onValueChange = {},
                        label = { Text("Redirect URI") },
                        readOnly = true,
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true
                    )
                }
            }

            // Settings Card
            Card(
                modifier = Modifier.fillMaxWidth(),
                elevation = CardDefaults.cardElevation(defaultElevation = 4.dp)
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(4.dp)
                ) {
                    Text(
                        text = "Settings",
                        style = MaterialTheme.typography.titleMedium
                    )

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = "Use PKCE",
                            style = MaterialTheme.typography.bodyMedium
                        )
                        Switch(
                            checked = usePKCE,
                            onCheckedChange = { usePKCE = it }
                        )
                    }

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = "Force login",
                                style = MaterialTheme.typography.bodyMedium
                            )
                            Text(
                                text = "No shared cookies or history",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                        Switch(
                            checked = useEphemeralSession,
                            onCheckedChange = { useEphemeralSession = it }
                        )
                    }
                }
            }

            // Authenticate button
            Button(
                onClick = {
                    onAuthenticate(usePKCE, useEphemeralSession) { code ->
                        authorizationCode = code
                    }
                },
                modifier = Modifier
                    .fillMaxWidth()
                    .height(48.dp)
            ) {
                Text("Authenticate with Browser")
            }

            // Authorization Code Card
            Card(
                modifier = Modifier.fillMaxWidth(),
                elevation = CardDefaults.cardElevation(defaultElevation = 4.dp)
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Text(
                        text = "Authorization Code",
                        style = MaterialTheme.typography.titleMedium
                    )

                    OutlinedTextField(
                        value = authorizationCode,
                        onValueChange = { authorizationCode = it },
                        label = { Text("Authorization Code") },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = false,
                        minLines = 2,
                        maxLines = 3
                    )
                }
            }
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Compose Previews
// ──────────────────────────────────────────────────────────────────────────────

/**
 * Preview of [AuthCodeFlowScreen] using the light theme with all toggles off and
 * an empty authorization code field — the default state when the app first opens.
 */
@Preview(
    name = "Auth Code Flow – Light",
    showBackground = true,
    showSystemUi = true,
    device = "spec:width=411dp,height=891dp,dpi=420"
)
@Composable
private fun AuthCodeFlowScreenPreviewLight() {
    AuthCodeFlowDemoTheme(darkTheme = false) {
        AuthCodeFlowScreen(
            host = "sdk.verify.ibm.com",
            clientId = "abc123clientId",
            redirect = "verifydemo://callback",
            versionName = "1.0.0",
            versionCode = 1,
            onAuthenticate = { _, _, _ -> }
        )
    }
}

/**
 * Preview of [AuthCodeFlowScreen] using the dark theme with PKCE on, ephemeral
 * session on, and a sample authorization code already populated.
 */
@Preview(
    name = "Auth Code Flow – Dark (PKCE + Ephemeral + code)",
    showBackground = true,
    showSystemUi = true,
    device = "spec:width=411dp,height=891dp,dpi=420"
)
@Composable
private fun AuthCodeFlowScreenPreviewDark() {
    AuthCodeFlowDemoTheme(darkTheme = true) {
        AuthCodeFlowScreen(
            host = "sdk.verify.ibm.com",
            clientId = "abc123clientId",
            redirect = "verifydemo://callback",
            versionName = "1.0.0",
            versionCode = 1,
            onAuthenticate = { _, _, _ -> }
        )
    }
}

