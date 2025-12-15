/*
 * Copyright contributors to the IBM Verify Digital Credentials Sample App for Android project
 */

package com.ibm.security.verifysdk.dc.demoapp.ui.credential

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.adaptive.ExperimentalMaterial3AdaptiveApi
import androidx.compose.material3.adaptive.layout.ListDetailPaneScaffoldRole
import androidx.compose.material3.adaptive.navigation.ThreePaneScaffoldNavigator
import androidx.compose.runtime.Composable
import androidx.compose.runtime.rememberCoroutineScope
import kotlinx.coroutines.launch
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.ibm.security.verifysdk.core.serializer.DefaultJson
import com.ibm.security.verifysdk.dc.demoapp.ui.ViewDescriptor
import com.ibm.security.verifysdk.dc.demoapp.ui.verification.LabelValueRow
import com.ibm.security.verifysdk.dc.model.CredentialDescriptor
import com.ibm.security.verifysdk.dc.serializer.CredentialSerializer
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.decodeFromJsonElement

@OptIn(ExperimentalMaterial3AdaptiveApi::class)
@Composable
fun CredentialListItem(
    credential: CredentialDescriptor,
    navigator: ThreePaneScaffoldNavigator<Any>
) {
    val coroutineScope = rememberCoroutineScope()
    val itemView = remember(credential.jsonRepresentation) {
        credential.jsonRepresentation?.let { DefaultJson.decodeFromJsonElement<ViewDescriptor>(it) }
    }

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clickable {
                coroutineScope.launch {
                    navigator.navigateTo(
                        pane = ListDetailPaneScaffoldRole.Detail,
                        contentKey = Json.encodeToString(CredentialSerializer, credential)
                    )
                }
            }
    ) {
        HorizontalDivider(
            modifier = Modifier
                .fillMaxWidth()
                .padding(vertical = 4.dp),
            thickness = 1.dp,
            color = Color.Gray
        )
        itemView?.ShowCredential(modifier = Modifier)
    }
}

@Composable
fun CredentialInfo(label: String, value: String) {
    LabelValueRow(label = label, value = value, valueTextSizeReduction = 2)
    HorizontalDivider(
        modifier = Modifier.padding(vertical = 4.dp),
        thickness = 1.dp,
        color = Color.Gray
    )
}

@Composable
fun CredentialPreviewDialog(
    showDialog: Boolean,
    jsonRepresentation: JsonElement?,
    onAccept: () -> Unit,
    onReject: () -> Unit
) {
    if (!showDialog) return

    var errorMessage by remember { mutableStateOf<String?>(null) }

    val previewData = try {
        DefaultJson.decodeFromJsonElement<ViewDescriptor>(
            jsonRepresentation ?: buildJsonObject { }
        )
    } catch (e: Exception) {
        errorMessage = "Failed to parse credential: ${e.message ?: e.toString()}"
        null
    }

    // Show error dialog if parsing failed
    errorMessage?.let {
        AlertDialog(
            onDismissRequest = { errorMessage = null },
            title = { Text("Error") },
            text = { Text(it) },
            confirmButton = {
                Button(onClick = {
                    errorMessage = null
                    onReject()
                }) {
                    Text("OK")
                }
            }
        )
        return
    }

    // Show credential preview dialog if parsing was successful
    if (previewData != null) {
        AlertDialog(
            onDismissRequest = {},
            title = { Text("Credential Preview") },
            text = { previewData.ShowCredential(Modifier) },
            confirmButton = { Button(onClick = onAccept) { Text("Accept") } },
            dismissButton = { Button(onClick = onReject) { Text("Cancel") } }
        )
    }
}

@Composable
internal fun LabelValueInCard(
    label: String,
    value: String,
    modifier: Modifier = Modifier,
    textColor: Color = Color.Black
) {
    Row(
        modifier = modifier,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(
            text = "$label:",
            style = MaterialTheme.typography.bodyMedium.copy(fontWeight = FontWeight.Bold),
            color = textColor,
            overflow = TextOverflow.Ellipsis
        )
        Spacer(modifier = Modifier.width(8.dp))
        Text(
            text = value,
            style = MaterialTheme.typography.bodyMedium.copy(color = Color.White),
            color = textColor,
            overflow = TextOverflow.Ellipsis
        )
    }
}