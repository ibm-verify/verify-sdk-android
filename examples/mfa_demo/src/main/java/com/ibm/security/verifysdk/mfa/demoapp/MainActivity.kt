/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */
package com.ibm.security.verifysdk.mfa.demoapp

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.core.content.edit
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.lifecycleScope
import com.google.zxing.integration.android.IntentIntegrator
import com.google.zxing.integration.android.IntentResult
import com.ibm.security.verifysdk.core.extension.threadInfo
import com.ibm.security.verifysdk.core.helper.ContextHelper
import com.ibm.security.verifysdk.mfa.EnrollableType
import com.ibm.security.verifysdk.mfa.FactorType
import com.ibm.security.verifysdk.mfa.MFAAuthenticatorDescriptor
import com.ibm.security.verifysdk.mfa.MFARegistrationController
import com.ibm.security.verifysdk.mfa.MFAServiceController
import com.ibm.security.verifysdk.mfa.MFAServiceDescriptor
import com.ibm.security.verifysdk.mfa.UserAction
import com.ibm.security.verifysdk.mfa.completeTransaction
import com.ibm.security.verifysdk.mfa.demoapp.Constants.FACTOR_TYPE_FACE
import com.ibm.security.verifysdk.mfa.demoapp.Constants.FACTOR_TYPE_FINGERPRINT
import com.ibm.security.verifysdk.mfa.demoapp.Constants.KEY_AUTHENTICATOR
import com.ibm.security.verifysdk.mfa.demoapp.Constants.KEY_AUTHENTICATOR_TYPE
import com.ibm.security.verifysdk.mfa.demoapp.Constants.PREFS_NAME
import com.ibm.security.verifysdk.mfa.demoapp.Constants.TYPE_CLOUD
import com.ibm.security.verifysdk.mfa.demoapp.Constants.TYPE_ONPREM
import com.ibm.security.verifysdk.mfa.demoapp.ui.theme.MFADemoTheme
import com.ibm.security.verifysdk.mfa.model.cloud.CloudAuthenticator
import com.ibm.security.verifysdk.mfa.model.onprem.OnPremiseAuthenticator
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.serialization.InternalSerializationApi
import kotlinx.serialization.json.Json
import kotlinx.serialization.modules.SerializersModule
import kotlinx.serialization.modules.polymorphic
import kotlinx.serialization.modules.subclass
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.util.concurrent.Executor

/**
 * UI state data class for better state management
 */
data class MFADemoUiState(
    val authenticatorName: String = "",
    val serviceName: String = "",
    val transactionMessage: String = "",
    val transactionFactorType: String = "",
    val hasAuthenticator: Boolean = false,
    val hasTransaction: Boolean = false,
    val isLoading: Boolean = false,
    val errorMessage: String? = null,
    val successMessage: String? = null,
    val showDeleteConfirmation: Boolean = false
)

@OptIn(InternalSerializationApi::class)
class MainActivity : FragmentActivity() {

    private val log: Logger = LoggerFactory.getLogger(javaClass.name)
    private var mfaAuthenticatorDescriptor: MFAAuthenticatorDescriptor? = null
    private var mfaService: MFAServiceDescriptor? = null
    private lateinit var biometricPrompt: BiometricPrompt
    private lateinit var promptInfo: BiometricPrompt.PromptInfo

    private var uiState by mutableStateOf(MFADemoUiState())

    @OptIn(InternalSerializationApi::class)
    private val json = Json {
        ignoreUnknownKeys = true
        prettyPrint = true
        serializersModule = SerializersModule {
            polymorphic(FactorType::class) {
                subclass(FactorType.Totp::class)
                subclass(FactorType.Hotp::class)
                subclass(FactorType.Face::class)
                subclass(FactorType.Fingerprint::class)
                subclass(FactorType.UserPresence::class)
            }
        }
    }


    private val requestPermissionLauncher =
        registerForActivityResult(
            ActivityResultContracts.RequestPermission()
        ) { isGranted: Boolean ->
            if (isGranted) {
                startQRCodeScanning()
            } else {
                log.debug("Permission denied")
            }
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        ContextHelper.init(applicationContext)

        setupBiometricPrompt()

        loadAuthenticator()

        setContent {
            MFADemoTheme {
                MFADemoScreen(
                    uiState = uiState,
                    onScanQRCode = { requestCamera() },
                    onCheckTransactions = { checkPendingTransaction() },
                    onApproveTransaction = { handleApproveTransaction() },
                    onDenyTransaction = { completeTransaction(UserAction.DENY) },
                    onDeleteAuthenticator = { updateUiState { copy(showDeleteConfirmation = true) } },
                    onConfirmDelete = { confirmDeleteAuthenticator() },
                    onDismissDeleteDialog = { updateUiState { copy(showDeleteConfirmation = false) } },
                    onDismissError = { updateUiState { copy(errorMessage = null) } },
                    onDismissSuccess = { updateUiState { copy(successMessage = null) } }
                )
            }
        }
    }

    /**
     * Helper function to update UI state efficiently
     */
    private inline fun updateUiState(update: MFADemoUiState.() -> MFADemoUiState) {
        uiState = uiState.update()
    }

    private fun setupBiometricPrompt() {
        val executor: Executor = ContextCompat.getMainExecutor(this)

        biometricPrompt = BiometricPrompt(
            this, executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    super.onAuthenticationError(errorCode, errString)
                    log.error("Biometric authentication error: $errString")
                    updateUiState {
                        copy(errorMessage = getString(R.string.error_biometric_auth, errString))
                    }
                }

                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    log.info("Biometric authentication succeeded")
                    completeTransaction(UserAction.VERIFY)
                }

                override fun onAuthenticationFailed() {
                    super.onAuthenticationFailed()
                    log.error("Biometric authentication failed")
                    updateUiState {
                        copy(errorMessage = getString(R.string.error_biometric_failed))
                    }
                }
            })

        promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle(getString(R.string.biometric_title))
            .setSubtitle(getString(R.string.biometric_subtitle))
            .setNegativeButtonText(getString(R.string.biometric_negative_button))
            .build()
    }

    private fun handleApproveTransaction() {
        if (requiresBiometricAuth()) {
            biometricPrompt.authenticate(promptInfo)
        } else {
            completeTransaction(UserAction.VERIFY)
        }
    }

    private fun requiresBiometricAuth(): Boolean {
        val authenticator = mfaAuthenticatorDescriptor ?: return false
        val service = mfaService ?: return false

        return when (authenticator) {
            is CloudAuthenticator -> {
                val factorType = authenticator.allowedFactors.firstOrNull {
                    it.id == service.currentPendingTransaction?.factorID
                }
                factorType is FactorType.Face || factorType is FactorType.Fingerprint
            }

            is OnPremiseAuthenticator -> {
                val factorTypeName = service.currentPendingTransaction?.factorType
                factorTypeName?.contains(FACTOR_TYPE_FACE, ignoreCase = true) == true ||
                        factorTypeName?.contains(FACTOR_TYPE_FINGERPRINT, ignoreCase = true) == true
            }

            else -> false
        }
    }

    private fun requestCamera() {
        when (PackageManager.PERMISSION_GRANTED) {
            ContextCompat.checkSelfPermission(
                applicationContext,
                android.Manifest.permission.CAMERA
            ) -> {
                startQRCodeScanning()
            }

            else -> {
                requestPermissionLauncher.launch(
                    android.Manifest.permission.CAMERA
                )
            }
        }
    }

    private fun startQRCodeScanning() {
        val integrator = IntentIntegrator(this)
        integrator.setPrompt(getString(R.string.qr_scanner_prompt))
        integrator.setOrientationLocked(false)
        integrator.setTorchEnabled(false)
        integrator.initiateScan()
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        val intentResult: IntentResult? =
            IntentIntegrator.parseActivityResult(requestCode, resultCode, data)
        if (intentResult != null && intentResult.contents != null) {
            val qrCode = intentResult.contents
            log.info("data: $qrCode")
            lifecycleScope.launch {
                updateUiState { copy(isLoading = true, errorMessage = null) }

                try {
                    withContext(Dispatchers.IO) {
                        log.threadInfo()
                        val result = MFARegistrationController(qrCode)
                            .initiate("IBM Verify SDK", false)
                            .onSuccess {
                                log.info("Success: ${it.accountName}")
                            }
                            .onFailure {
                                log.error("Failure: $it")
                                throw it
                            }

                        val mfaRegistrationProvider = result.getOrThrow()
                        log.threadInfo()
                        log.info("Available enrollments: ${mfaRegistrationProvider.countOfAvailableEnrollments}")

                        var nextEnrollment = mfaRegistrationProvider.nextEnrollment()
                        while (nextEnrollment != null) {
                            if (nextEnrollment.enrollableType != EnrollableType.FACE) {
                                mfaRegistrationProvider.enroll()
                            }
                            nextEnrollment = mfaRegistrationProvider.nextEnrollment()
                        }

                        mfaRegistrationProvider.finalize()
                            .onSuccess {
                                log.info("Success: $it")
                                mfaAuthenticatorDescriptor = it
                                saveAuthenticator(it)
                                updateAuthenticatorInfo()
                                updateUiState {
                                    copy(successMessage = getString(R.string.success_authenticator_registered))
                                }
                            }
                            .onFailure {
                                log.error("Failure: $it")
                                throw it
                            }
                    }
                } catch (e: Exception) {
                    log.error("QR code registration failed", e)
                    updateUiState {
                        copy(
                            errorMessage = getString(
                                R.string.error_registration_failed,
                                e.message ?: getString(R.string.error_unknown)
                            )
                        )
                    }
                } finally {
                    updateUiState { copy(isLoading = false) }
                }
            }
        }
    }

    private fun checkPendingTransaction() {
        val authenticator = mfaAuthenticatorDescriptor
        if (authenticator == null) {
            updateUiState { copy(errorMessage = getString(R.string.error_no_authenticator)) }
            return
        }

        mfaService = MFAServiceController(authenticator).initiate()

        lifecycleScope.launch {
            updateUiState { copy(isLoading = true, errorMessage = null) }

            try {
                withContext(Dispatchers.IO) {
                    mfaService?.nextTransaction()
                        ?.onSuccess { nextTransactionInfo ->
                            log.info("Success: $nextTransactionInfo")
                            val message = mfaService?.currentPendingTransaction?.message
                                ?: "No transaction message"

                            val factorType = when (authenticator) {
                                is CloudAuthenticator -> {
                                    authenticator.allowedFactors.firstOrNull {
                                        it.id == mfaService?.currentPendingTransaction?.factorID
                                    }?.displayName ?: "Unknown"
                                }

                                is OnPremiseAuthenticator -> {
                                    mfaService?.currentPendingTransaction?.factorType ?: "Unknown"
                                }

                                else -> "Unknown"
                            }

                            updateUiState {
                                copy(
                                    transactionMessage = message,
                                    transactionFactorType = factorType,
                                    hasTransaction = true
                                )
                            }
                        }
                        ?.onFailure {
                            log.info("Failure: $it")
                            updateUiState {
                                copy(
                                    transactionMessage = "",
                                    transactionFactorType = "",
                                    hasTransaction = false,
                                    errorMessage = getString(R.string.error_no_pending_transactions)
                                )
                            }
                        }
                }
            } catch (e: Exception) {
                log.error("Failed to check transactions", e)
                updateUiState {
                    copy(
                        errorMessage = getString(
                            R.string.error_check_transactions_failed,
                            e.message ?: getString(R.string.error_unknown)
                        )
                    )
                }
            } finally {
                updateUiState { copy(isLoading = false) }
            }
        }
    }

    private fun completeTransaction(userAction: UserAction) {
        val authenticator = mfaAuthenticatorDescriptor
        val service = mfaService

        if (authenticator == null || service == null) {
            updateUiState { copy(errorMessage = getString(R.string.error_no_active_transaction)) }
            return
        }

        lifecycleScope.launch {
            updateUiState { copy(isLoading = true, errorMessage = null) }

            try {
                withContext(Dispatchers.IO) {
                    when (authenticator) {
                        is CloudAuthenticator -> {
                            val factorType = authenticator.allowedFactors.firstOrNull {
                                it.id == service.currentPendingTransaction?.factorID
                            }

                            if (factorType != null) {
                                service.completeTransaction(userAction, factorType)
                                    .onSuccess {
                                        log.info("Success: ${service.currentPendingTransaction?.message}")
                                    }
                                    .onFailure {
                                        log.error("Failure: $it")
                                        throw it
                                    }
                            } else {
                                throw IllegalStateException(getString(R.string.error_no_matching_factor))
                            }
                        }

                        is OnPremiseAuthenticator -> {
                            val currentFactorType = service.currentPendingTransaction?.factorType
                            if (currentFactorType == null) {
                                throw IllegalStateException(getString(R.string.error_no_factor_type))
                            }

                            val matchingFactor =
                                authenticator.allowedFactors.firstOrNull { factor ->
                                    when (factor) {
                                        is FactorType.UserPresence -> {
                                            val keyParts = factor.value.keyName.split(".")
                                            keyParts.getOrNull(1)?.equals(
                                                currentFactorType,
                                                ignoreCase = true
                                            ) == true
                                        }

                                        is FactorType.Fingerprint -> {
                                            val keyParts = factor.value.keyName.split(".")
                                            keyParts.getOrNull(1)?.equals(
                                                currentFactorType,
                                                ignoreCase = true
                                            ) == true
                                        }

                                        is FactorType.Face -> {
                                            val keyParts = factor.value.keyName.split(".")
                                            keyParts.getOrNull(1)?.equals(
                                                currentFactorType,
                                                ignoreCase = true
                                            ) == true
                                        }

                                        else -> false
                                    }
                                }

                            if (matchingFactor != null) {
                                service.completeTransaction(userAction, matchingFactor)
                                    .onSuccess {
                                        log.info("Success: ${service.currentPendingTransaction?.message}")
                                    }
                                    .onFailure {
                                        log.error("Failure: $it")
                                        throw it
                                    }
                            } else {
                                throw IllegalStateException(
                                    getString(
                                        R.string.error_no_matching_factor_for_type,
                                        currentFactorType
                                    )
                                )
                            }
                        }

                        else -> {
                            throw IllegalStateException(getString(R.string.error_unknown_authenticator_type))
                        }
                    }
                }

                val successMsg = if (userAction == UserAction.VERIFY) {
                    getString(R.string.success_transaction_approved)
                } else {
                    getString(R.string.success_transaction_denied)
                }

                updateUiState {
                    copy(
                        transactionMessage = "",
                        transactionFactorType = "",
                        hasTransaction = false,
                        successMessage = successMsg
                    )
                }
            } catch (e: Exception) {
                log.error("Failed to complete transaction", e)
                updateUiState {
                    copy(
                        errorMessage = getString(
                            R.string.error_complete_transaction_failed,
                            e.message ?: getString(R.string.error_unknown)
                        )
                    )
                }
            } finally {
                updateUiState { copy(isLoading = false) }
            }
        }
    }

    private fun updateAuthenticatorInfo() {
        val authenticator = mfaAuthenticatorDescriptor ?: return

        val (name, service) = when (authenticator) {
            is CloudAuthenticator -> authenticator.accountName to authenticator.serviceName
            is OnPremiseAuthenticator -> authenticator.accountName to authenticator.serviceName
            else -> return
        }

        updateUiState {
            copy(
                authenticatorName = name,
                serviceName = service,
                hasAuthenticator = true
            )
        }
    }

    private fun saveAuthenticator(authenticator: MFAAuthenticatorDescriptor) {
        val prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val editor = prefs.edit()

        try {
            when (authenticator) {
                is CloudAuthenticator -> {
                    val jsonString = json.encodeToString(authenticator)
                    editor.putString(KEY_AUTHENTICATOR, jsonString)
                    editor.putString(KEY_AUTHENTICATOR_TYPE, TYPE_CLOUD)
                    log.info("Saved CloudAuthenticator to SharedPreferences")
                }

                is OnPremiseAuthenticator -> {
                    val jsonString = json.encodeToString(authenticator)
                    editor.putString(KEY_AUTHENTICATOR, jsonString)
                    editor.putString(KEY_AUTHENTICATOR_TYPE, TYPE_ONPREM)
                    log.info("Saved OnPremiseAuthenticator to SharedPreferences")
                }
            }
            editor.apply()
        } catch (e: Exception) {
            log.error("Failed to save authenticator: ${e.message}", e)
        }
    }

    private fun loadAuthenticator() {
        val prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val jsonString = prefs.getString(KEY_AUTHENTICATOR, null)
        val type = prefs.getString(KEY_AUTHENTICATOR_TYPE, null)

        if (jsonString != null && type != null) {
            try {
                mfaAuthenticatorDescriptor = when (type) {
                    TYPE_CLOUD -> json.decodeFromString<CloudAuthenticator>(jsonString)
                    TYPE_ONPREM -> json.decodeFromString<OnPremiseAuthenticator>(jsonString)
                    else -> {
                        log.error("Unknown authenticator type: $type")
                        updateUiState {
                            copy(
                                errorMessage = getString(
                                    R.string.error_unknown_authenticator_type_load,
                                    type
                                )
                            )
                        }
                        return
                    }
                }
                log.info("Loaded authenticator from SharedPreferences")
                updateAuthenticatorInfo()
            } catch (e: Exception) {
                log.error("Failed to load authenticator: ${e.message}", e)
                updateUiState {
                    copy(
                        errorMessage = getString(
                            R.string.error_load_authenticator_failed,
                            e.message ?: getString(R.string.error_unknown)
                        )
                    )
                }
            }
        } else {
            log.info("No saved authenticator found")
            updateUiState { copy(hasAuthenticator = false) }
        }
    }

    private fun confirmDeleteAuthenticator() {
        val prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        prefs.edit {
            remove(KEY_AUTHENTICATOR)
            remove(KEY_AUTHENTICATOR_TYPE)
        }

        mfaAuthenticatorDescriptor = null
        mfaService = null

        updateUiState {
            copy(
                authenticatorName = "",
                serviceName = "",
                transactionMessage = "",
                transactionFactorType = "",
                hasAuthenticator = false,
                hasTransaction = false
            )
        }

        updateUiState {
            copy(
                showDeleteConfirmation = false,
                successMessage = getString(R.string.success_authenticator_deleted)
            )
        }

        log.info("Deleted authenticator from SharedPreferences")
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MFADemoScreen(
    uiState: MFADemoUiState,
    onScanQRCode: () -> Unit,
    onCheckTransactions: () -> Unit,
    onApproveTransaction: () -> Unit,
    onDenyTransaction: () -> Unit,
    onDeleteAuthenticator: () -> Unit,
    onConfirmDelete: () -> Unit,
    onDismissDeleteDialog: () -> Unit,
    onDismissError: () -> Unit,
    onDismissSuccess: () -> Unit
) {
    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text("IBM Verify SDK MFA Demo")
                        Text(
                            text = "${BuildConfig.VERSION_NAME} (${BuildConfig.VERSION_CODE})",
                            style = MaterialTheme.typography.labelSmall
                        )
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.primaryContainer,
                    titleContentColor = MaterialTheme.colorScheme.onPrimaryContainer
                )
            )
        },
        floatingActionButton = {
            FloatingActionButton(
                onClick = onScanQRCode,
                containerColor = MaterialTheme.colorScheme.primary
            ) {
                Icon(
                    imageVector = Icons.Default.Add,
                    contentDescription = stringResource(R.string.content_desc_scan_qr)
                )
            }
        },
        snackbarHost = {
            uiState.errorMessage?.let { error ->
                androidx.compose.material3.Snackbar(
                    action = {
                        androidx.compose.material3.TextButton(onClick = onDismissError) {
                            Text(stringResource(R.string.button_dismiss))
                        }
                    },
                    modifier = Modifier.padding(16.dp),
                    containerColor = MaterialTheme.colorScheme.errorContainer,
                    contentColor = MaterialTheme.colorScheme.onErrorContainer
                ) {
                    Text(error)
                }
            }

            uiState.successMessage?.let { success ->
                androidx.compose.material3.Snackbar(
                    action = {
                        androidx.compose.material3.TextButton(onClick = onDismissSuccess) {
                            Text(stringResource(R.string.button_dismiss))
                        }
                    },
                    modifier = Modifier.padding(16.dp),
                    containerColor = MaterialTheme.colorScheme.primaryContainer,
                    contentColor = MaterialTheme.colorScheme.onPrimaryContainer
                ) {
                    Text(success)
                }
            }
        }
    ) { paddingValues ->
        Box(modifier = Modifier.fillMaxSize()) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(paddingValues)
                    .padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                AuthenticatorInfoCard(
                    authenticatorName = uiState.authenticatorName,
                    serviceName = uiState.serviceName
                )

                if (uiState.hasAuthenticator) {
                    Button(
                        onClick = onDeleteAuthenticator,
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(48.dp),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = MaterialTheme.colorScheme.error
                        )
                    ) {
                        Text(stringResource(R.string.button_delete_authenticator))
                    }

                    Spacer(modifier = Modifier.height(24.dp))
                }

                Button(
                    onClick = onCheckTransactions,
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(48.dp),
                    enabled = uiState.hasAuthenticator
                ) {
                    Text(stringResource(R.string.button_check_transactions))
                }

                TransactionInfoCard(
                    transactionMessage = uiState.transactionMessage,
                    transactionFactorType = uiState.transactionFactorType
                )

                TransactionActionButtons(
                    hasTransaction = uiState.hasTransaction,
                    onDeny = onDenyTransaction,
                    onApprove = onApproveTransaction
                )
            }

            if (uiState.isLoading) {
                LoadingOverlay()
            }
        }

        // Delete confirmation dialog
        if (uiState.showDeleteConfirmation) {
            AlertDialog(
                onDismissRequest = onDismissDeleteDialog,
                title = { Text(stringResource(R.string.dialog_delete_title)) },
                text = { Text(stringResource(R.string.dialog_delete_message)) },
                confirmButton = {
                    TextButton(onClick = onConfirmDelete) {
                        Text(stringResource(R.string.dialog_delete_confirm))
                    }
                },
                dismissButton = {
                    TextButton(onClick = onDismissDeleteDialog) {
                        Text(stringResource(R.string.dialog_delete_cancel))
                    }
                }
            )
        }
    }
}

/**
 * Extracted composable for Authenticator Information Card
 */
@Composable
fun AuthenticatorInfoCard(
    authenticatorName: String,
    serviceName: String
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
                text = stringResource(R.string.label_authenticator_info),
                style = MaterialTheme.typography.titleLarge
            )

            OutlinedTextField(
                value = authenticatorName,
                onValueChange = {},
                label = { Text(stringResource(R.string.label_authenticator_name)) },
                readOnly = true,
                modifier = Modifier.fillMaxWidth(),
                singleLine = true
            )

            OutlinedTextField(
                value = serviceName,
                onValueChange = {},
                label = { Text(stringResource(R.string.label_service_name)) },
                readOnly = true,
                modifier = Modifier.fillMaxWidth(),
                singleLine = true
            )
        }
    }
}

/**
 * Extracted composable for Transaction Information Card
 */
@Composable
fun TransactionInfoCard(
    transactionMessage: String,
    transactionFactorType: String
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
                text = stringResource(R.string.label_transaction_info),
                style = MaterialTheme.typography.titleLarge
            )

            OutlinedTextField(
                value = transactionMessage,
                onValueChange = {},
                label = { Text(stringResource(R.string.label_transaction_message)) },
                readOnly = true,
                modifier = Modifier.fillMaxWidth(),
                singleLine = true
            )

            OutlinedTextField(
                value = transactionFactorType,
                onValueChange = {},
                label = { Text(stringResource(R.string.label_factor_type)) },
                readOnly = true,
                modifier = Modifier.fillMaxWidth(),
                singleLine = true
            )
        }
    }
}

/**
 * Extracted composable for Transaction Action Buttons
 */
@Composable
fun TransactionActionButtons(
    hasTransaction: Boolean,
    onDeny: () -> Unit,
    onApprove: () -> Unit
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        Button(
            onClick = onDeny,
            modifier = Modifier
                .weight(1f)
                .height(48.dp),
            enabled = hasTransaction,
            colors = ButtonDefaults.buttonColors(
                containerColor = MaterialTheme.colorScheme.error
            )
        ) {
            Text(stringResource(R.string.button_deny))
        }

        @Preview(showBackground = true, name = "Light Mode")
        @Composable
        fun AuthenticatorInfoCardPreview() {
            MFADemoTheme {
                AuthenticatorInfoCard(
                    authenticatorName = "John Doe",
                    serviceName = "IBM Verify"
                )
            }
        }

        @Preview(
            showBackground = true,
            name = "Dark Mode",
            uiMode = android.content.res.Configuration.UI_MODE_NIGHT_YES
        )
        @Composable
        fun AuthenticatorInfoCardDarkPreview() {
            MFADemoTheme {
                AuthenticatorInfoCard(
                    authenticatorName = "John Doe",
                    serviceName = "IBM Verify"
                )
            }
        }

        @Preview(showBackground = true, name = "Light Mode")
        @Composable
        fun TransactionInfoCardPreview() {
            MFADemoTheme {
                TransactionInfoCard(
                    transactionMessage = "Login to IBM Cloud",
                    transactionFactorType = "User Presence"
                )
            }
        }

        @Preview(
            showBackground = true,
            name = "Dark Mode",
            uiMode = android.content.res.Configuration.UI_MODE_NIGHT_YES
        )
        @Composable
        fun TransactionInfoCardDarkPreview() {
            MFADemoTheme {
                TransactionInfoCard(
                    transactionMessage = "Login to IBM Cloud",
                    transactionFactorType = "User Presence"
                )
            }
        }

        @Preview(showBackground = true, name = "Enabled")
        @Composable
        fun TransactionActionButtonsEnabledPreview() {
            MFADemoTheme {
                TransactionActionButtons(
                    hasTransaction = true,
                    onDeny = {},
                    onApprove = {}
                )
            }
        }

        @Preview(showBackground = true, name = "Disabled")
        @Composable
        fun TransactionActionButtonsDisabledPreview() {
            MFADemoTheme {
                TransactionActionButtons(
                    hasTransaction = false,
                    onDeny = {},
                    onApprove = {}
                )
            }
        }

        @Preview(showBackground = true)
        @Composable
        fun LoadingOverlayPreview() {
            MFADemoTheme {
                LoadingOverlay()
            }
        }

        Button(
            onClick = onApprove,
            modifier = Modifier
                .weight(1f)
                .height(48.dp),
            enabled = hasTransaction
        ) {
            Text(stringResource(R.string.button_approve))
        }
    }
}

/**
 * Extracted composable for Loading Overlay
 */
@Composable
fun LoadingOverlay() {
    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(Color.Black.copy(alpha = 0.7f)),
        contentAlignment = Alignment.Center
    ) {
        CircularProgressIndicator(
            modifier = Modifier.size(64.dp),
            color = MaterialTheme.colorScheme.primary
        )
    }
}


