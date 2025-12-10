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

class MainActivity : ComponentActivity() {

    private val coroutineScope = CoroutineScope(Dispatchers.Main)
    private lateinit var oAuthProvider: OAuthProvider
    private lateinit var host: String
    private lateinit var clientId: String
    private lateinit var redirect: String
    private val log: Logger = LoggerFactory.getLogger(MainActivity::class.java)

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
                    onAuthenticate = { usePKCE ->
                        authenticateWithBrowser(usePKCE)
                    }
                )
            }
        }
    }

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

    private fun authenticateWithBrowser(usePKCE: Boolean) {
        coroutineScope.launch {
            val issuer = "https://$host/v1.0/endpoint/default/authorize"
            val tokenEndpoint = "https://$host/v1.0/endpoint/default/token"

            val codeVerifier = if (usePKCE) PKCEHelper.generateCodeVerifier() else null
            val codeChallenge = codeVerifier?.let { PKCEHelper.generateCodeChallenge(it) }

            oAuthProvider.authorizeWithBrowser(
                URL(issuer),
                redirect,
                codeChallenge = codeChallenge,
                method = if (usePKCE) CodeChallengeMethod.S256 else CodeChallengeMethod.PLAIN,
                scope = arrayOf("openid"),
                state = "init",
                activity = this@MainActivity
            ).onSuccess { code ->
                log.info("--> Authorization code: $code")
                if (usePKCE) {
                    oAuthProvider.authorize(
                        httpClient = NetworkHelper.getInstance,
                        url = URL(tokenEndpoint),
                        redirectUrl = URL(redirect),
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

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AuthCodeFlowScreen(
    host: String,
    clientId: String,
    redirect: String,
    onAuthenticate: (Boolean) -> Unit
) {
    var usePKCE by remember { mutableStateOf(true) }
    var authorizationCode by remember { mutableStateOf("") }
    
    val context = androidx.compose.ui.platform.LocalContext.current
    val versionName = context.packageManager.getPackageInfo(context.packageName, 0).versionName
    val versionCode = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
        context.packageManager.getPackageInfo(context.packageName, 0).longVersionCode.toInt()
    } else {
        @Suppress("DEPRECATION")
        context.packageManager.getPackageInfo(context.packageName, 0).versionCode
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text("IBM Verify SDK Auth Code Flow Demo")
                        Text(
                            text = "$versionName ($versionCode)",
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
                .padding(16.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(16.dp)
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
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Text(
                        text = "Configuration",
                        style = MaterialTheme.typography.titleLarge
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

            // PKCE Settings Card
            Card(
                modifier = Modifier.fillMaxWidth(),
                elevation = CardDefaults.cardElevation(defaultElevation = 4.dp)
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Text(
                        text = "PKCE Settings",
                        style = MaterialTheme.typography.titleLarge
                    )

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = "Use PKCE",
                            style = MaterialTheme.typography.bodyLarge
                        )
                        Switch(
                            checked = usePKCE,
                            onCheckedChange = { usePKCE = it }
                        )
                    }
                }
            }

            // Authenticate button
            Button(
                onClick = { onAuthenticate(usePKCE) },
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
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Text(
                        text = "Authorization Code",
                        style = MaterialTheme.typography.titleLarge
                    )

                    OutlinedTextField(
                        value = authorizationCode,
                        onValueChange = { authorizationCode = it },
                        label = { Text("Authorization Code") },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = false,
                        minLines = 3,
                        maxLines = 5
                    )
                }
            }
        }
    }
}

