/*
 * Copyright contributors to the IBM Verify Digital Credentials Sample App for Android project
 */

package com.ibm.security.verifysdk.dc.demoapp.data

import com.ibm.security.verifysdk.authentication.model.shouldRefresh
import com.ibm.security.verifysdk.dc.WalletService
import com.ibm.security.verifysdk.dc.demoapp.BuildConfig
import com.ibm.security.verifysdk.dc.demoapp.ui.WalletViewModel
import com.ibm.security.verifysdk.dc.model.CredentialDescriptor
import com.ibm.security.verifysdk.dc.model.CredentialPreviewInfo
import com.ibm.security.verifysdk.dc.model.PreviewDescriptor
import com.ibm.security.verifysdk.dc.model.VerificationAction
import com.ibm.security.verifysdk.dc.model.VerificationInfo
import com.ibm.security.verifysdk.dc.model.VerificationPreviewInfo
import kotlinx.serialization.ExperimentalSerializationApi
import java.net.URL
import kotlin.time.ExperimentalTime

class WalletManager(val walletEntity: WalletEntity, private val viewModel: WalletViewModel) {

    @OptIn(ExperimentalSerializationApi::class, ExperimentalTime::class)
    private suspend fun refreshToken() {

        if (walletEntity.wallet.token.shouldRefresh().not()) {
            return
        }

        val walletService = WalletService(
            accessToken = walletEntity.wallet.token.accessToken,
            refreshUri = walletEntity.wallet.refreshUri,
            baseUri = walletEntity.wallet.baseUri,
            clientId = walletEntity.wallet.clientId,
            ignoreSsl = BuildConfig.DEBUG   // don't use this in production
        )

        val refreshToken = walletEntity.wallet.token.refreshToken

        walletService.refreshToken(refreshToken)
            .onSuccess { tokenInfo ->
                val updatedWallet = walletEntity.wallet.copy(token = tokenInfo)
                val updatedEntity = walletEntity.copy(wallet = updatedWallet)
                viewModel.update(updatedEntity)
            }
            .onFailure {
                throw (it)
            }
    }

    suspend fun processProofRequest(
        verificationInfo: VerificationPreviewInfo
    ): Result<VerificationInfo> {

        refreshToken()

        val walletService = WalletService(
            accessToken = walletEntity.wallet.token.accessToken,
            refreshUri = walletEntity.wallet.refreshUri,
            baseUri = walletEntity.wallet.baseUri,
            clientId = walletEntity.wallet.clientId,
            ignoreSsl = BuildConfig.DEBUG   // don't use this in production
        )

        return try {
            Result.success(
                walletService.processProofRequest(
                    verificationPreviewInfo = verificationInfo,
                    action = VerificationAction.SHARE
                )
            )
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    suspend fun previewInvitation(invitationUrl: URL): Result<PreviewDescriptor> {

        refreshToken()

        val walletService = WalletService(
            accessToken = walletEntity.wallet.token.accessToken,
            refreshUri = walletEntity.wallet.refreshUri,
            baseUri = walletEntity.wallet.baseUri,
            clientId = walletEntity.wallet.clientId,
            ignoreSsl = BuildConfig.DEBUG   // don't use this in production
        )

        return try {
            Result.success(walletService.previewInvitation(offerUrl = invitationUrl))
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    suspend fun previewVerification(verificationInfo: VerificationPreviewInfo): Result<VerificationInfo> {

        refreshToken()

        val walletService = WalletService(
            accessToken = walletEntity.wallet.token.accessToken,
            refreshUri = walletEntity.wallet.refreshUri,
            baseUri = walletEntity.wallet.baseUri,
            clientId = walletEntity.wallet.clientId,
            ignoreSsl = BuildConfig.DEBUG   // don't use this in production
        )

        return try {
            Result.success(walletService.processProofRequest(verificationPreviewInfo = verificationInfo))
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    suspend fun addCredential(credentialPreviewInfo: CredentialPreviewInfo): Result<CredentialDescriptor> {

        refreshToken()

        val walletService = WalletService(
            accessToken = walletEntity.wallet.token.accessToken,
            refreshUri = walletEntity.wallet.refreshUri,
            baseUri = walletEntity.wallet.baseUri,
            clientId = walletEntity.wallet.clientId,
            ignoreSsl = BuildConfig.DEBUG   // don't use this in production
        )

        return try {
            Result.success(walletService.processCredential(credentialPreviewInfo = credentialPreviewInfo))
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
}