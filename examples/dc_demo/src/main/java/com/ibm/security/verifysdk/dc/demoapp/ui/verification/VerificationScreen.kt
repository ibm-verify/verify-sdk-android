/*
 * Copyright contributors to the IBM Verify Digital Credentials Sample App for Android project
 */

package com.ibm.security.verifysdk.dc.demoapp.ui.verification

import android.annotation.SuppressLint
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AddCircle
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.navigation.NavController
import com.ibm.security.verifysdk.dc.demoapp.MainActivity.Screen
import com.ibm.security.verifysdk.dc.demoapp.QrScanContract
import com.ibm.security.verifysdk.dc.demoapp.data.WalletManager
import com.ibm.security.verifysdk.dc.demoapp.ui.AddUrlDialog
import com.ibm.security.verifysdk.dc.demoapp.ui.StatusDialog
import com.ibm.security.verifysdk.dc.demoapp.ui.WalletViewModel
import com.ibm.security.verifysdk.dc.model.VerificationInfo
import com.ibm.security.verifysdk.dc.ExperimentalDigitalCredentialsSdk
import kotlinx.coroutines.launch
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.json.JSONObject
import java.net.URL
import java.time.ZoneId
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter

@OptIn(
    ExperimentalMaterial3Api::class, ExperimentalDigitalCredentialsSdk::class,
    ExperimentalMaterial3AdaptiveApi::class, ExperimentalSerializationApi::class
)
@SuppressLint("UnusedMaterial3ScaffoldPaddingParameter")
@Composable
fun VerificationScreen(
    walletViewModel: WalletViewModel,
    innerPadding: PaddingValues,
    navController: NavController
) {

    val coroutineScope = rememberCoroutineScope()
    val navigator = rememberListDetailPaneScaffoldNavigator<Any>()

    var showAddDialog by remember { mutableStateOf(false) }
    var verificationUrl by remember { mutableStateOf("") }
    var showErrorDialog by remember { mutableStateOf(false) }
    var errorMessage by remember { mutableStateOf("") }
    var errorTitle by remember { mutableStateOf("") }

    val wallets by walletViewModel.allWallets.collectAsState()
    val wallet = wallets.firstOrNull()
    val walletManager = wallet?.let { WalletManager(it, walletViewModel) }

    val verifications = wallet?.wallet?.verifications ?: emptyList()

    var scannedQr by remember { mutableStateOf<String?>(null) }

    val qrScannerLauncher =
        rememberLauncherForActivityResult(contract = QrScanContract()) { result ->
            scannedQr = result
            result?.let {
                val json = JSONObject(it)
                verificationUrl = json.getString("url")
                coroutineScope.launch {
                    walletManager?.previewInvitation(URL(verificationUrl))
                        ?.onSuccess { verificationPreview ->
                            val jsonData = Json.encodeToString(verificationPreview)
                            navController.currentBackStackEntry
                                ?.savedStateHandle
                                ?.set("verificationPreview", jsonData)

                            navController.navigate(Screen.VerificationRequest.route)
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
                        "Verifications",
                        style = MaterialTheme.typography.headlineLarge,
                        fontWeight = FontWeight.Bold
                    )
                },
                actions = {
                    walletManager?.let {
                        IconButton(onClick = { showAddDialog = true }) {
                            Icon(
                                Icons.Default.AddCircle,
                                contentDescription = "Add Verification",
                                modifier = Modifier.size(48.dp)
                            )
                        }
                    }
                }
            )
        }
    ) { scaffoldPadding ->

        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(scaffoldPadding)
        ) {
            NavigableListDetailPaneScaffold(
                navigator = navigator,
                listPane = {
                    LazyColumn(
                        modifier = Modifier
                            .padding(16.dp)
                            .padding(bottom = 100.dp)
                    ) {
                        items(verifications) { verification ->
                            VerificationListItem(verification, navigator)
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
                            val verification = navigator.currentDestination?.contentKey?.toString()
                                ?.takeIf { it.isNotEmpty() && it != "null" }
                                ?.let { Json.decodeFromString<VerificationInfo>(it) }

                            if (verification == null) {
                                Text(
                                    "No attributes found",
                                    style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold)
                                )
                            } else {
                                val id = verification.id
                                val state = verification.state.value
                                val role = verification.role.value
                                val issuerDid = verification.verifierDid

                                val descriptor =
                                    verification.proofRequest?.mdoc?.presentationDefinition?.inputDescriptors?.getOrNull(
                                        0
                                    )
                                val name = descriptor?.name ?: "unknown"
                                val purpose = descriptor?.purpose ?: "unknown"
                                val signed =
                                    verification.info?.jsonObject?.get("validityInfo")?.jsonObject?.get(
                                        "signed"
                                    )?.jsonPrimitive?.content?.let {
                                        val parsed = ZonedDateTime.parse(it)
                                        val localTime =
                                            parsed.withZoneSameInstant(ZoneId.systemDefault())
                                        val formatter =
                                            DateTimeFormatter.ofPattern("dd MMMM yyyy, hh:mm a")
                                        localTime.format(formatter)
                                    } ?: "unknown"

                                LabelValueRow(
                                    "ID", id
                                )
                                VerificationDetailsDivider()
                                LabelValueRow(
                                    "State", state
                                )
                                VerificationDetailsDivider()
                                LabelValueRow(
                                    "Role", role
                                )
                                VerificationDetailsDivider()
                                LabelValueRow(
                                    "Issuer DID", issuerDid
                                )
                                VerificationDetailsDivider()
                                VerificationDetailsDivider()
                                LabelValueRow(
                                    "Name", name
                                )
                                VerificationDetailsDivider()
                                LabelValueRow(
                                    "Purpose", purpose
                                )
                                VerificationDetailsDivider()
                                LabelValueRow(
                                    "Signed", signed
                                )
                                Spacer(modifier = Modifier.width(16.dp))
                            }
                        }
                    }
                }
            )
        }

        AddUrlDialog(
            showAddDialog,
            "Verification",
            verificationUrl,
            onUrlChange = { verificationUrl = it },
            onDismiss = {
                verificationUrl = ""
                showAddDialog = false
            },
            onSubmit = {
                val urlToLoad = verificationUrl
                verificationUrl = ""

                coroutineScope.launch {
                    walletManager?.previewInvitation(URL(urlToLoad))
                        ?.onSuccess { verificationPreview ->
                            val jsonData = Json.encodeToString(verificationPreview)
                            navController.currentBackStackEntry
                                ?.savedStateHandle
                                ?.set("verificationPreview", jsonData)

                            navController.navigate(Screen.VerificationRequest.route)
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

        StatusDialog(
            showErrorDialog,
            title = errorTitle,
            message = errorMessage,
            onDismiss = { showErrorDialog = false }
        )
    }
}

@Composable
fun VerificationDetailsDivider() {
    HorizontalDivider(
        modifier = Modifier.padding(vertical = 4.dp),
        thickness = 1.dp,
        color = Color.Gray
    )
}