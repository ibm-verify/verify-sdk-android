/*
 * Copyright contributors to the IBM Verify Digital Credentials Sample App for Android project
 */

package com.ibm.security.verifysdk.dc.demoapp.ui.credential

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.calculateEndPadding
import androidx.compose.foundation.layout.calculateStartPadding
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AddCircle
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.adaptive.ExperimentalMaterial3AdaptiveApi
import androidx.compose.material3.adaptive.layout.AnimatedPane
import androidx.compose.material3.adaptive.navigation.NavigableListDetailPaneScaffold
import androidx.compose.material3.adaptive.navigation.rememberListDetailPaneScaffoldNavigator
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.ibm.security.verifysdk.dc.demoapp.QrScanContract
import com.ibm.security.verifysdk.dc.demoapp.data.WalletManager
import com.ibm.security.verifysdk.dc.demoapp.ui.AddUrlDialog
import com.ibm.security.verifysdk.dc.demoapp.ui.StatusDialog
import com.ibm.security.verifysdk.dc.demoapp.ui.WalletViewModel
import com.ibm.security.verifysdk.dc.model.CredentialPreviewInfo
import com.ibm.security.verifysdk.dc.serializer.CredentialSerializer
import com.ibm.security.verifysdk.dc.model.CredentialFormat.Companion.serialName
import kotlinx.coroutines.launch
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import org.json.JSONObject
import java.net.URL

@OptIn(ExperimentalMaterial3AdaptiveApi::class, ExperimentalMaterial3Api::class)
@Composable
fun CredentialScreen(
    walletViewModel: WalletViewModel,
    innerPadding: PaddingValues
) {
    val coroutineScope = rememberCoroutineScope()
    val navigator = rememberListDetailPaneScaffoldNavigator<Any>()

    var showAddDialog by remember { mutableStateOf(false) }
    var showPreviewDialog by remember { mutableStateOf(false) }
    var credentialUrl by remember { mutableStateOf("") }

    var showErrorDialog by remember { mutableStateOf(false) }
    var errorMessage by remember { mutableStateOf("") }
    var errorTitle by remember { mutableStateOf("") }

    val wallets by walletViewModel.allWallets.collectAsState()
    val wallet = wallets.firstOrNull()
    val walletManager = wallet?.let { WalletManager(it, walletViewModel) }

    val credentials = wallet?.wallet?.credentials ?: emptyList()

    var credentialPreviewInfo by remember {
        mutableStateOf(
            CredentialPreviewInfo(
                id = "",
                label = "",
                url = "",
                comment = "",
                jsonRepresentation = JsonObject(mapOf())
            )
        )
    }

    var scannedQr by remember { mutableStateOf<String?>(null) }

    val qrScannerLauncher =
        rememberLauncherForActivityResult(contract = QrScanContract()) { result ->
            scannedQr = result
            result?.let {
                val json = JSONObject(it)
                credentialUrl = json.getString("url")
                coroutineScope.launch {
                    walletManager?.previewInvitation(URL(credentialUrl))
                        ?.onSuccess { data ->
                            credentialPreviewInfo = data as CredentialPreviewInfo
                            showPreviewDialog = true
                        }
                        ?.onFailure {
                            errorTitle = "Error"
                            errorMessage = "Failed to fetch data: ${it.message}"
                            showErrorDialog = true
                        }
                }
                showAddDialog = false
            }
        }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        "Credentials",
                        style = MaterialTheme.typography.headlineLarge,
                        fontWeight = FontWeight.Bold
                    )
                },
                actions = {
                    walletManager?.let {
                        IconButton(onClick = { showAddDialog = true }) {
                            Icon(
                                Icons.Default.AddCircle, contentDescription = "Add Credential",
                                modifier = Modifier.size(48.dp)
                            )
                        }
                    }
                }
            )
        }
    ) { scaffoldPadding ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(
                    top = scaffoldPadding.calculateTopPadding(),
                    bottom = 100.dp,
                    start = scaffoldPadding.calculateStartPadding(LocalLayoutDirection.current),
                    end = scaffoldPadding.calculateEndPadding(LocalLayoutDirection.current)
                )
        ) {
            Column(
                modifier = Modifier.fillMaxSize() // Allow Column to take the full space
            ) {
                NavigableListDetailPaneScaffold(
                    navigator = navigator,
                    listPane = {
                        LazyColumn(modifier = Modifier.padding(16.dp)) {
                            items(credentials) { credential ->
                                CredentialListItem(credential, navigator)
                            }
                        }
                    },
                    detailPane = {
                        AnimatedPane {
                            Column(
                                modifier = Modifier
                                    .fillMaxSize()
                                    .padding(16.dp)
                            ) {
                                val credential = navigator.currentDestination?.contentKey?.toString()
                                    ?.takeIf { it.isNotEmpty() && it != "null" }
                                    ?.let {
                                        Json.decodeFromString(CredentialSerializer, it)
                                    }

                                if (credential == null) {
                                    Text(
                                        "No attributes found",
                                        style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold)
                                    )
                                } else {
                                    CredentialInfo("ID", credential.id)
                                    CredentialInfo("Format", credential.format.serialName)
                                    CredentialInfo("State", credential.state.value)
                                    CredentialInfo("Role", credential.role.value)
                                    CredentialInfo("Issuer DID", credential.issuerDid)

                                    Spacer(modifier = Modifier.width(16.dp))

                                    Text(
                                        "Technical details",
                                        style = MaterialTheme.typography.titleLarge.copy(fontWeight = FontWeight.Bold)
                                    )
                                    Spacer(modifier = Modifier.height(8.dp))

                                    val scrollState = rememberScrollState()
                                    Box(
                                        modifier = Modifier
                                            .fillMaxWidth()
                                            .weight(1f)
                                            .border(
                                                1.dp,
                                                MaterialTheme.colorScheme.onSurface.copy(alpha = 0.5f),
                                                RoundedCornerShape(8.dp)
                                            )
                                            .padding(8.dp)
                                    ) {
                                        Column(
                                            modifier = Modifier
                                                .verticalScroll(scrollState)
                                                .fillMaxWidth()
                                        ) {
                                            Text(
                                                text = credential.jsonRepresentation.toString(),
                                                style = MaterialTheme.typography.bodySmall.copy(
                                                    fontFamily = FontFamily.Monospace
                                                )
                                            )
                                        }
                                    }
                                }
                            }
                        }
                    },
                    modifier = Modifier.weight(1f) // Fix: Allows scrolling without infinite size issue
                )

                AddUrlDialog(
                    showAddDialog,
                    "Credential",
                    credentialUrl,
                    onUrlChange = { credentialUrl = it },
                    onDismiss = { showAddDialog = false
                                credentialUrl = ""
                                },
                    onSubmit = {
                        val urlToLoad = credentialUrl
                        credentialUrl = ""

                        coroutineScope.launch {
                            walletManager?.previewInvitation(URL(urlToLoad))
                                ?.onSuccess { data ->
                                    credentialPreviewInfo = data as CredentialPreviewInfo
                                    showPreviewDialog = true
                                }
                                ?.onFailure {
                                    errorTitle = "Error"
                                    errorMessage = "Failed to fetch data: ${it.message}"
                                    showErrorDialog = true
                                }
                        }
                        showAddDialog = false
                    },
                    onScanQrClick = { qrScannerLauncher.launch(Unit) }
                )

                CredentialPreviewDialog(
                    showPreviewDialog,
                    credentialPreviewInfo.jsonRepresentation,
                    onAccept = {
                        showPreviewDialog = false
                        coroutineScope.launch {
                            walletManager?.addCredential(credentialPreviewInfo)
                                ?.onSuccess { credentialInfo ->
                                    walletViewModel.updateCredentials(
                                        walletManager.walletEntity,
                                        (walletManager.walletEntity.wallet.credentials + credentialInfo).toMutableList()
                                    )
                                }
                                ?.onFailure {
                                    errorTitle = "Error"
                                    errorMessage =
                                        "Something went wrong: ${it.message ?: "Unknown error"}"
                                    showErrorDialog = true
                                }
                        }
                    },
                    onReject = {
                        showPreviewDialog = false
                    }
                )

                StatusDialog(
                    showErrorDialog,
                    title = errorTitle,
                    message = errorMessage,
                    onDismiss = { showErrorDialog = false }
                )
            }
        }
    }
}