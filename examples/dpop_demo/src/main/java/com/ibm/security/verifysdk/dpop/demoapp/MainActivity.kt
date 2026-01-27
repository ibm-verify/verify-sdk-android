package com.ibm.security.verifysdk.dpop.demoapp

import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.livedata.observeAsState
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.lifecycleScope
import com.ibm.security.verifysdk.authentication.DPoPHelper
import com.ibm.security.verifysdk.authentication.model.TokenInfo
import com.ibm.security.verifysdk.core.helper.ContextHelper
import com.ibm.security.verifysdk.core.helper.NetworkHelper as CoreNetworkHelper
import com.ibm.security.verifysdk.dpop.demoapp.ui.theme.DPoPDemoTheme
import io.ktor.client.call.body
import io.ktor.client.request.accept
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.request.url
import io.ktor.http.ContentType
import io.ktor.http.contentType
import io.ktor.http.formUrlEncode
import io.ktor.http.isSuccess
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : ComponentActivity() {

    companion object {
        const val TAG = "DPoP-Demo"
        const val DPOP_KEY_ALIAS = "rsa-dpop-demo-key.com.ibm.security.verifysdk.dpop"
    }

    private lateinit var customNetworkHelper: NetworkHelper
    private lateinit var tokenInfo: TokenInfo

    // Change these parameters according to your IBM Verify tenant
    private val tenant = "verify.ice.ibmcloud.com" // without protocol
    private val clientId = "b29c2bc2-a7ae-4cf7-b437-46d28f7a0121"
    private val clientSecret = "ZXBpYHG4gm"
    private val resourceServer = "10.0.2.2" // without protocol and port
    private val resourceServerPort = "8080"

    private val tokenEndpoint = String.format("https://%s/oauth2/token", tenant)
    private val resourceEndpoint =
        String.format("https://%s:%s/validate-token", resourceServer, resourceServerPort)

    private val accessToken = MutableLiveData("...")
    private val tokenValidation = MutableLiveData("...")

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            DPoPDemoTheme {
                Config()
            }
        }

        ContextHelper.init(applicationContext)
        
        // Use custom NetworkHelper only for resource server with custom SSL
        customNetworkHelper = NetworkHelper(resourceServer)
    }

    @OptIn(ExperimentalMaterial3Api::class)
    @Composable
    fun Config() {

        val token: String? by accessToken.observeAsState()
        val validation: String? by tokenValidation.observeAsState()
        
        val versionName = packageManager.getPackageInfo(packageName, 0).versionName
        val versionCode =
            packageManager.getPackageInfo(packageName, 0).longVersionCode.toInt()

        Scaffold(
            topBar = {
                TopAppBar(
                    title = {
                        Column {
                            Text("IBM Verify SDK DPoP Demo")
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
        ) { paddingValues ->
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(paddingValues)
                    .padding(16.dp)
                    .verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(16.dp)
            ) {
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
                            modifier = Modifier.fillMaxWidth(),
                            singleLine = true,
                            value = tokenEndpoint,
                            readOnly = true,
                            onValueChange = {},
                            label = { Text("Token Endpoint") }
                        )

                        OutlinedTextField(
                            modifier = Modifier.fillMaxWidth(),
                            singleLine = true,
                            value = resourceEndpoint,
                            readOnly = true,
                            onValueChange = {},
                            label = { Text("Resource Endpoint") }
                        )

                        OutlinedTextField(
                            modifier = Modifier.fillMaxWidth(),
                            singleLine = true,
                            value = clientId,
                            readOnly = true,
                            onValueChange = {},
                            label = { Text("Client ID") }
                        )

                        OutlinedTextField(
                            modifier = Modifier.fillMaxWidth(),
                            singleLine = true,
                            value = clientSecret,
                            readOnly = true,
                            onValueChange = {},
                            label = { Text("Client Secret") }
                        )
                    }
                }

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
                            text = "Token Information",
                            style = MaterialTheme.typography.titleLarge
                        )

                        OutlinedTextField(
                            modifier = Modifier.fillMaxWidth(),
                            singleLine = true,
                            value = token ?: "...",
                            readOnly = true,
                            onValueChange = {},
                            label = { Text("Access Token") }
                        )

                        OutlinedTextField(
                            modifier = Modifier.fillMaxWidth(),
                            singleLine = true,
                            value = validation ?: "...",
                            readOnly = true,
                            onValueChange = {},
                            label = { Text("Token Validation") }
                        )
                    }
                }

                Spacer(modifier = Modifier.weight(1f))

                Button(
                    onClick = {
                        lifecycleScope.launch {
                            withContext(Dispatchers.IO) { requestDpopToken() }
                        }
                    },
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(48.dp),
                    enabled = (token == "...")
                ) {
                    Text("Request DPoP Token")
                }
                
                Button(
                    onClick = { validateToken() },
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(48.dp),
                    enabled = (token != "..."),
                ) {
                    Text("Validate DPoP Token")
                }
            }
        }
    }

    @Preview(showBackground = true)
    @Composable
    fun ConfigPreview() {
        DPoPDemoTheme {
            Config()
        }
    }

    private fun validateToken() {
        lifecycleScope.launch {
            withContext(Dispatchers.IO) {
                try {
                    // Generate DPoP proof token using the SDK's DPoPHelper
                    val dpopProof = DPoPHelper.generateDPoPToken(
                        htu = resourceEndpoint,
                        htm = "GET",
                        accessToken = tokenInfo.accessToken,
                        keyAlias = DPOP_KEY_ALIAS
                    )
                    
                    Log.d(TAG, "DPoP proof generated for token validation")

                    // Use custom NetworkHelper for resource server with custom SSL
                    val response = customNetworkHelper.client.get(resourceEndpoint) {
                        header("Authorization", "DPoP ${tokenInfo.accessToken}")
                        header("DPoP", dpopProof)
                    }

                    if (response.status.isSuccess()) {
                        Log.d(TAG, "DPoP token validation successful")
                        tokenValidation.postValue("${response.status.value} - DPoP token validation successful")
                    } else {
                        Log.d(TAG, "DPoP token validation failed: ${response.status}")
                        tokenValidation.postValue("${response.status.value} - DPoP token validation failed")
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "Error validating DPoP token: ${e.message}", e)
                    tokenValidation.postValue("Error: ${e.message}")
                }
            }
        }
    }

    private suspend fun requestDpopToken(): Result<TokenInfo> {

        return try {
            val formData = mutableMapOf(
                "client_id" to clientId,
                "client_secret" to clientSecret,
                "grant_type" to "client_credentials",
                "scope" to "openid"
            )

            // Generate DPoP proof token using the SDK's DPoPHelper
            val dpopProof = DPoPHelper.generateDPoPToken(
                htu = tokenEndpoint,
                htm = "POST",
                accessToken = null,
                keyAlias = DPOP_KEY_ALIAS
            )
            
            Log.d(TAG, "DPoP proof generated for token request")

            // Use Core SDK NetworkHelper for IBM Verify OAuth server
            val response = CoreNetworkHelper.getInstance.post {
                url(tokenEndpoint)
                header("DPoP", dpopProof)
                accept(ContentType.Application.Json)
                contentType(ContentType.Application.FormUrlEncoded)
                setBody(formData.toList().formUrlEncode())
            }

            if (response.status.isSuccess()) {
                tokenInfo = response.body()
                accessToken.postValue(tokenInfo.accessToken)
                Log.d(TAG, "DPoP token received successfully")
                Result.success(tokenInfo)
            } else {
                throw (Exception("HTTP error: ${response.status}"))
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error requesting DPoP token: ${e.message}", e)
            throw (e)
        }
    }
}