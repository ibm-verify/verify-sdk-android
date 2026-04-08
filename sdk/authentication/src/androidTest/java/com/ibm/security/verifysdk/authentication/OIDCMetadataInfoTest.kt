/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.authentication

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.filters.SmallTest
import com.ibm.security.verifysdk.authentication.model.OIDCMetadataInfo
import com.ibm.security.verifysdk.core.serializer.DefaultJson
import kotlinx.serialization.json.Json
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

private val json = Json {
    encodeDefaults = true
    explicitNulls = false
    ignoreUnknownKeys = true
    isLenient = true
}

@RunWith(AndroidJUnit4::class)
@SmallTest
internal class OIDCMetadataInfoTest {

    private lateinit var oidcMetadata: OIDCMetadataInfo

    @Before
    fun initialize() {
        oidcMetadata = DefaultJson.decodeFromString(openidConfiguration)
    }

    @Test
    fun constructor_generated_shouldReturnObject() {

        for (c in OIDCMetadataInfo::class.java.constructors) {
            println(c.toString())
            if (c.isSynthetic && c.parameterCount == 36)
                if (c.parameterTypes.first().name.equals("java.lang.String")) {
                    val oidcMetadataInfo = c.newInstance(
                        "issuer",
                        "authorizationEndpoint",
                        "tokenEndpoint",
                        "userInfoEndpoint",
                        "jwksUri",
                        "registrationEndpoint",
                        arrayOf("responseTypeSupported"),
                        arrayOf("responseModesSupported"),
                        arrayOf("grantTypesSupported"),
                        arrayOf("subjectTypesSupported"),
                        arrayOf("idTokenSigningAlgValuesSupported"),
                        arrayOf("idTokenEncryptionAlgValuesSupported"),
                        arrayOf("idTokenEncryptionEncValuesSupported"),
                        arrayOf("userInfoSigningAlgValuesSupported"),
                        arrayOf("userInfoEncryptionAlgValuesSupported"),
                        arrayOf("userInfoEncryptionEncValueSupported"),
                        arrayOf("requestObjectSigningAlgValuesSupported"),
                        arrayOf("requestObjectEncryptionAlgValueSupported"),
                        arrayOf("requestObjectEncryptionEncValuesSupported"),
                        arrayOf("tokenEndpointAuthMethodsSupported"),
                        arrayOf("tokenEndpointAuthSigningAlgValuesSupported"),
                        arrayOf("displayValueSupported"),
                        arrayOf("claimTypesSupported"),
                        arrayOf("claimsSupported"),
                        "serviceDocumentationVal",
                        arrayOf("claimsLocalesSupported"),
                        arrayOf("uiLocalesSupported"),
                        true,
                        true,
                        true,
                        true,
                        "opPolicyUri",
                        "opToSUri",
                        42,
                        42,
                        null
                    ) as OIDCMetadataInfo

                    assertEquals("tokenEndpoint", oidcMetadataInfo.tokenEndpoint)
                }
        }
    }

    @Test
    fun constructor_withMandatoryData_shouldReturnObject() {

        val oidcMetadataInfo = OIDCMetadataInfo(
            issuer = "issuer",
            authorizationEndpoint = "authorizationEndpoint",
            tokenEndpoint = "tokenEndpoint",
            userinfoEndpoint = "userinfoEndpoint",
            jwksUri = "jwksUri",
            registrationEndpoint = "registrationEndpoint",
            responseTypesSupported = emptyArray(),
            responseModesSupported = emptyArray(),
            subjectTypesSupported = emptyArray(),
            idTokenSigningAlgValuesSupported = emptyArray(),
            claimsSupported = emptyArray()
        )

        assertEquals("tokenEndpoint", oidcMetadataInfo.tokenEndpoint)
        assertEquals("authorization_code", oidcMetadataInfo.grantTypesSupported[0])
    }


    @Test
    fun constructor_withData_happyPath_shouldReturnObject() {
        val oidcMetadataInfo = OIDCMetadataInfo(
            "issuer",
            "authorizationEndpoint",
            "tokenEndpoint",
            "userInfoEndpoint",
            "jwksUri",
            "registrationEndpoint",
            arrayOf("responseTypeSupported"),
            arrayOf("responseModesSupported"),
            arrayOf("grantTypesSupported"),
            arrayOf("subjectTypesSupported"),
            arrayOf("idTokenSigningAlgValuesSupported"),
            arrayOf("idTokenEncryptionAlgValuesSupported"),
            arrayOf("idTokenEncryptionEncValuesSupported"),
            arrayOf("userInfoSigningAlgValuesSupported"),
            arrayOf("userInfoEncryptionAlgValuesSupported"),
            arrayOf("userInfoEncryptionEncValueSupported"),
            arrayOf("requestObjectSigningAlgValuesSupported"),
            arrayOf("requestObjectEncryptionAlgValueSupported"),
            arrayOf("requestObjectEncryptionEncValuesSupported"),
            arrayOf("tokenEndpointAuthMethodsSupported"),
            arrayOf("tokenEndpointAuthSigningAlgValuesSupported"),
            arrayOf("displayValueSupported"),
            arrayOf("claimTypesSupported"),
            arrayOf("claimsSupported"),
            "serviceDocumentationVal",
            arrayOf("claimsLocalesSupported"),
            arrayOf("uiLocalesSupported"),
            claimsParameterSupported = true,
            requestParameterSupported = true,
            requestUriParameterSupported = true,
            requireRequestUriRegistration = true,
            "opPolicyUri",
            "opToSUri"
        )

        assertEquals("tokenEndpoint", oidcMetadataInfo.tokenEndpoint)
        assertEquals("opToSUri", oidcMetadataInfo.opToSUri)
    }

    @Test
    fun decodeAndEncodeInstance_shouldBeEqual() {

        val oidcMetadataInfo = json.decodeFromString<OIDCMetadataInfo>(openidConfiguration)
        val oidcMetadataInfoSerialized = json.encodeToString(oidcMetadataInfo)
        val oidcMetadataInfoDeserialized =
            json.decodeFromString<OIDCMetadataInfo>(oidcMetadataInfoSerialized)

        assertTrue("Encoding/decoding failed", oidcMetadataInfo == oidcMetadataInfoDeserialized)
    }

    @Test
    fun decodeAndEncodeInstance_withMinimal_shouldBeEqual() {

        val oidcMetadataInfo = json.decodeFromString<OIDCMetadataInfo>(openidConfigurationMinimal)
        val oidcMetadataInfoSerialized = json.encodeToString(oidcMetadataInfo)
        val oidcMetadataInfoDeserialized =
            json.decodeFromString<OIDCMetadataInfo>(oidcMetadataInfoSerialized)

        assertTrue("Encoding/decoding failed", oidcMetadataInfo == oidcMetadataInfoDeserialized)
    }

    @Test
    fun testHashCode() {
        assertEquals(684567978, oidcMetadata.hashCode())

        val oidcMetadataInfoEmpty =
            json.decodeFromString<OIDCMetadataInfo>(openidConfigurationEmpty)
        assertEquals(391047040, oidcMetadataInfoEmpty.hashCode())
    }

    @Test
    fun constructor_withSerializer_happyPath_shouldReturnObject() {
        val oidcMetadataInfo = json.decodeFromString<OIDCMetadataInfo>(openidConfiguration)
        assertEquals(
            "https://sdk.verify.ibm.com/oauth2/authorize",
            oidcMetadataInfo.authorizationEndpoint
        )
        assertEquals(15, oidcMetadataInfo.claimsSupported.size)
    }

    @Test
    fun getIssuer() {
        assertEquals("https://sdk.verify.ibm.com/oauth2", oidcMetadata.issuer)
    }

    @Test
    fun getAuthorizationEndpoint() {
        assertEquals(
            "https://sdk.verify.ibm.com/oauth2/authorize",
            oidcMetadata.authorizationEndpoint
        )
    }

    @Test
    fun getTokenEndpoint() {
        assertEquals(
            "https://sdk.verify.ibm.com/oauth2/token",
            oidcMetadata.tokenEndpoint
        )
    }

    @Test
    fun getUserinfoEndpoint() {
        assertEquals(
            "https://sdk.verify.ibm.com/oauth2/userinfo",
            oidcMetadata.userinfoEndpoint
        )
    }

    @Test
    fun getJwksUri() {
        assertEquals("https://sdk.verify.ibm.com/oauth2/jwks", oidcMetadata.jwksUri)
    }

    @Test
    fun getRegistrationEndpoint() {
        assertEquals(
            "https://sdk.verify.ibm.com/oauth2/client_registration",
            oidcMetadata.registrationEndpoint
        )
    }

    @Test
    fun getResponseTypesSupported() {
        assertEquals(8, oidcMetadata.responseTypesSupported.size)
    }

    @Test
    fun getResponseModesSupported() {
        assertEquals(3, oidcMetadata.responseModesSupported.size)
    }

    @Test
    fun getGrantTypesSupported() {
        assertEquals(8, oidcMetadata.grantTypesSupported.size)
    }

    @Test
    fun setGrantTypesSupported() {
        val lastIndex = oidcMetadata.grantTypesSupported.lastIndex
        assertEquals(8, oidcMetadata.grantTypesSupported.size)
        oidcMetadata.grantTypesSupported[lastIndex] = "grant type"
        assertEquals(8, oidcMetadata.grantTypesSupported.size)
        assertEquals("grant type", oidcMetadata.grantTypesSupported.last())
    }

    @Test
    fun getSubjectTypesSupported() {
        assertEquals(1, oidcMetadata.subjectTypesSupported.size)
    }

    @Test
    fun getIdTokenSigningAlgValuesSupported() {
        assertEquals(13, oidcMetadata.idTokenSigningAlgValuesSupported.size)
    }

    @Test
    fun getIdTokenEncryptionAlgValuesSupported() {
        assertEquals(3, oidcMetadata.idTokenEncryptionAlgValuesSupported.size)
    }

    @Test
    fun getIdTokenEncryptionEncValuesSupported() {
        assertEquals(4, oidcMetadata.idTokenEncryptionEncValuesSupported.size)
    }

    @Test
    fun setIdTokenEncryptionEncValuesSupported() {
        val lastIndex = oidcMetadata.idTokenEncryptionEncValuesSupported.lastIndex
        assertEquals(4, oidcMetadata.idTokenEncryptionEncValuesSupported.size)
        oidcMetadata.idTokenEncryptionEncValuesSupported[lastIndex] =
            "token encryption enc values supported"
        assertEquals(4, oidcMetadata.idTokenEncryptionEncValuesSupported.size)
        assertEquals(
            "token encryption enc values supported",
            oidcMetadata.idTokenEncryptionEncValuesSupported.last()
        )
    }

    @Test
    fun getUserinfoSigningAlgValuesSupported() {
        assertEquals(1, oidcMetadata.userinfoSigningAlgValuesSupported.size)
    }

    @Test
    fun setUserinfoSigningAlgValuesSupported() {
        val lastIndex = oidcMetadata.userinfoSigningAlgValuesSupported.lastIndex
        assertEquals(1, oidcMetadata.userinfoSigningAlgValuesSupported.size)
        oidcMetadata.userinfoSigningAlgValuesSupported[lastIndex] =
            "user info signing alg value supported"
        assertEquals(1, oidcMetadata.userinfoSigningAlgValuesSupported.size)
        assertEquals(
            "user info signing alg value supported",
            oidcMetadata.userinfoSigningAlgValuesSupported.last()
        )
    }

    @Test
    fun getUserinfoEncryptionAlgValuesSupported() {
        assertEquals(1, oidcMetadata.userinfoEncryptionAlgValuesSupported.size)
    }

    @Test
    fun setUserinfoEncryptionAlgValuesSupported() {
        val lastIndex = oidcMetadata.userinfoEncryptionAlgValuesSupported.lastIndex
        assertEquals(1, oidcMetadata.userinfoEncryptionAlgValuesSupported.size)
        oidcMetadata.userinfoEncryptionAlgValuesSupported[lastIndex] =
            "user info encryption alg value supported"
        assertEquals(1, oidcMetadata.userinfoEncryptionAlgValuesSupported.size)
        assertEquals(
            "user info encryption alg value supported",
            oidcMetadata.userinfoEncryptionAlgValuesSupported.last()
        )
    }

    @Test
    fun getUserinfoEncryptionEncValuesSupported() {
        assertEquals(1, oidcMetadata.userinfoEncryptionEncValuesSupported.size)
    }

    @Test
    fun setUserinfoEncryptionEncValuesSupported() {
        val lastIndex = oidcMetadata.userinfoEncryptionEncValuesSupported.lastIndex
        assertEquals(1, oidcMetadata.userinfoEncryptionEncValuesSupported.size)
        oidcMetadata.userinfoEncryptionEncValuesSupported[lastIndex] =
            "user info encryption enc value supported"
        assertEquals(1, oidcMetadata.userinfoEncryptionEncValuesSupported.size)
        assertEquals(
            "user info encryption enc value supported",
            oidcMetadata.userinfoEncryptionEncValuesSupported.last()
        )
    }

    @Test
    fun getRequestObjectSigningAlgValuesSupported() {
        assertEquals(1, oidcMetadata.requestObjectSigningAlgValuesSupported.size)
    }

    @Test
    fun setRequestObjectSigningAlgValuesSupported() {
        val lastIndex = oidcMetadata.requestObjectSigningAlgValuesSupported.lastIndex
        assertEquals(1, oidcMetadata.requestObjectSigningAlgValuesSupported.size)
        oidcMetadata.requestObjectSigningAlgValuesSupported[lastIndex] =
            "request object signing value supported"
        assertEquals(1, oidcMetadata.requestObjectSigningAlgValuesSupported.size)
        assertEquals(
            "request object signing value supported",
            oidcMetadata.requestObjectSigningAlgValuesSupported.last()
        )
    }

    @Test
    fun getRequestObjectEncryptionAlgValuesSupported() {
        assertEquals(1, oidcMetadata.requestObjectEncryptionAlgValuesSupported.size)
    }

    @Test
    fun setRequestObjectEncryptionAlgValuesSupported() {
        val lastIndex = oidcMetadata.requestObjectEncryptionAlgValuesSupported.lastIndex
        assertEquals(1, oidcMetadata.requestObjectEncryptionAlgValuesSupported.size)
        oidcMetadata.requestObjectEncryptionAlgValuesSupported[lastIndex] =
            "request object encryption alg value supported"
        assertEquals(1, oidcMetadata.requestObjectEncryptionAlgValuesSupported.size)
        assertEquals(
            "request object encryption alg value supported",
            oidcMetadata.requestObjectEncryptionAlgValuesSupported.last()
        )
    }

    @Test
    fun getRequestObjectEncryptionEncValuesSupported() {
        assertEquals(1, oidcMetadata.requestObjectEncryptionEncValuesSupported.size)
    }

    @Test
    fun setRequestObjectEncryptionEncValuesSupported() {
        val lastIndex = oidcMetadata.requestObjectEncryptionEncValuesSupported.lastIndex
        assertEquals(1, oidcMetadata.requestObjectEncryptionEncValuesSupported.size)
        oidcMetadata.requestObjectEncryptionEncValuesSupported[lastIndex] =
            "request object encryption enc value supported"
        assertEquals(1, oidcMetadata.requestObjectEncryptionEncValuesSupported.size)
        assertEquals(
            "request object encryption enc value supported",
            oidcMetadata.requestObjectEncryptionEncValuesSupported.last()
        )
    }

    @Test
    fun getTokenEndpointAuthMethodsSupported() {
        assertEquals(4, oidcMetadata.tokenEndpointAuthMethodsSupported.size)
    }

    @Test
    fun setTokenEndpointAuthMethodsSupported() {
        val lastIndex = oidcMetadata.tokenEndpointAuthMethodsSupported.lastIndex
        assertEquals(4, oidcMetadata.tokenEndpointAuthMethodsSupported.size)
        oidcMetadata.tokenEndpointAuthMethodsSupported[lastIndex] =
            "token endpoint auth method support"
        assertEquals(4, oidcMetadata.tokenEndpointAuthMethodsSupported.size)
        assertEquals(
            "token endpoint auth method support",
            oidcMetadata.tokenEndpointAuthMethodsSupported.last()
        )
    }

    @Test
    fun getTokenEndpointAuthSigningAlgValuesSupported() {
        assertEquals(null, oidcMetadata.tokenEndpointAuthSigningAlgValuesSupported?.size)
    }

    @Test
    fun getDisplayValuesSupported() {
        assertEquals(null, oidcMetadata.displayValuesSupported?.size)
    }

    @Test
    fun getClaimTypesSupported() {
        assertEquals(1, oidcMetadata.claimTypesSupported.size)
    }

    @Test
    fun setClaimTypesSupported() {
        val lastIndex = oidcMetadata.claimTypesSupported.lastIndex
        assertEquals(1, oidcMetadata.claimTypesSupported.size)
        oidcMetadata.claimTypesSupported[lastIndex] = "claim type support"
        assertEquals(1, oidcMetadata.claimTypesSupported.size)
        assertEquals("claim type support", oidcMetadata.claimTypesSupported.last())
    }

    @Test
    fun getClaimsSupported() {
        assertEquals(15, oidcMetadata.claimsSupported.size)
    }

    @Test
    fun setClaimsSupported() {
        val lastIndex = oidcMetadata.claimsSupported.lastIndex
        assertEquals(15, oidcMetadata.claimsSupported.size)
        oidcMetadata.claimsSupported[lastIndex] = "claim support"
        assertEquals(15, oidcMetadata.claimsSupported.size)
        assertEquals("claim support", oidcMetadata.claimsSupported.last())
    }

    @Test
    fun getServiceDocumentation() {
        assertEquals(null, oidcMetadata.serviceDocumentation)
    }

    @Test
    fun getClaimsLocalesSupported() {
        assertEquals(null, oidcMetadata.claimsLocalesSupported?.size)
    }

    @Test
    fun getUiLocalesSupported() {
        assertEquals(null, oidcMetadata.uiLocalesSupported?.size)
    }

    @Test
    fun getClaimsParameterSupported() {
        assertEquals(true, oidcMetadata.claimsParameterSupported)
    }

    @Test
    fun getRequestParameterSupported() {
        assertEquals(true, oidcMetadata.requestParameterSupported)
    }

    @Test
    fun getRequestUriParameterSupported() {
        assertEquals(false, oidcMetadata.requestUriParameterSupported)
    }

    @Test
    fun getRequireRequestUriRegistration() {
        assertEquals(false, oidcMetadata.requireRequestUriRegistration)
    }

    @Test
    fun getOpPolicyUri() {
        assertEquals(null, oidcMetadata.opPolicyUri)
    }

    @Test
    fun getOpToSUri() {
        assertEquals(null, oidcMetadata.opToSUri)
    }

    @Test
    fun equals_sameInstance_shouldReturnTrue() {
        val oidcMetadataInfoClone = oidcMetadata
        @Suppress("ReplaceCallWithBinaryOperator")
        assertTrue(oidcMetadataInfoClone.equals(oidcMetadata))
    }

    @Test
    fun equals_differentClass_shouldReturnFalse() {
        assertEquals(false, oidcMetadata.equals(1))
        assertEquals(false, oidcMetadata.equals(null))
    }

    @Test
    fun equals_areEqual_shouldReturnTrue() {
        val copyOIDCMetadataInfo = oidcMetadata.copy()
        assertTrue(oidcMetadata == copyOIDCMetadataInfo)
    }

    private fun changeAttributeValue(
        oidcMetadataInfo: OIDCMetadataInfo,
        attribute: String
    ): OIDCMetadataInfo {
        val a = JSONObject(json.encodeToString(oidcMetadataInfo))
        a.put(attribute, attribute) // dummy value
        return json.decodeFromString(a.toString())
    }

    private fun changeAttributeValue(
        oidcMetadataInfo: OIDCMetadataInfo,
        attribute: String,
        array: Array<String>
    ): OIDCMetadataInfo {
        val a = JSONObject(json.encodeToString(oidcMetadataInfo))
        a.put(attribute, JSONArray(array)) // dummy value
        return json.decodeFromString(a.toString())
    }

    private fun changeAttributeValue(
        oidcMetadataInfo: OIDCMetadataInfo,
        attribute: String,
        boolean: Boolean
    ): OIDCMetadataInfo {
        val a = JSONObject(json.encodeToString(oidcMetadataInfo))
        a.put(attribute, boolean)
        return json.decodeFromString(a.toString())
    }

    @Test
    fun equals_areDifferent_opPolicyUri_shouldReturnFalse() {
        val oidcMetadataInfoEmpty =
            json.decodeFromString<OIDCMetadataInfo>(openidConfigurationEmpty)
        assertFalse(oidcMetadata == oidcMetadataInfoEmpty)

        assertFalse(
            oidcMetadataInfoEmpty == changeAttributeValue(
                oidcMetadataInfoEmpty,
                "op_policy_uri"
            )
        )
    }

    @Test
    fun equals_areDifferent_opToSUri_shouldReturnFalse() {
        val oidcMetadataInfoEmpty =
            json.decodeFromString<OIDCMetadataInfo>(openidConfigurationEmpty)
        assertFalse(oidcMetadata == oidcMetadataInfoEmpty)

        assertFalse(
            oidcMetadataInfoEmpty == changeAttributeValue(
                oidcMetadataInfoEmpty,
                "op_tos_uri"
            )
        )
    }

    @Test
    fun equals_areDifferent_requireRequestUriRegistration_shouldReturnFalse() {
        val oidcMetadataInfoEmpty =
            json.decodeFromString<OIDCMetadataInfo>(openidConfigurationEmpty)
        assertFalse(oidcMetadata == oidcMetadataInfoEmpty)

        assertFalse(
            oidcMetadataInfoEmpty == changeAttributeValue(
                oidcMetadataInfoEmpty,
                "require_request_uri_registration",
                oidcMetadata.requireRequestUriRegistration.not()
            )
        )
    }

    @Test
    fun equals_areDifferent_requestUriParameterSupported_shouldReturnFalse() {
        val oidcMetadataInfoEmpty =
            json.decodeFromString<OIDCMetadataInfo>(openidConfigurationEmpty)
        assertFalse(oidcMetadata == oidcMetadataInfoEmpty)

        assertFalse(
            oidcMetadataInfoEmpty == changeAttributeValue(
                oidcMetadataInfoEmpty,
                "request_uri_parameter_supported",
                oidcMetadata.requestUriParameterSupported.not()
            )
        )
    }

    @Test
    fun equals_areDifferent_requestParameterSupported_shouldReturnFalse() {
        val oidcMetadataInfoEmpty =
            json.decodeFromString<OIDCMetadataInfo>(openidConfigurationEmpty)
        assertFalse(oidcMetadata == oidcMetadataInfoEmpty)

        assertFalse(
            oidcMetadataInfoEmpty == changeAttributeValue(
                oidcMetadataInfoEmpty,
                "request_parameter_supported",
                oidcMetadata.requestParameterSupported.not()
            )
        )
    }

    @Test
    fun equals_areDifferent_claimsParameterSupported_shouldReturnFalse() {
        val oidcMetadataInfoEmpty =
            json.decodeFromString<OIDCMetadataInfo>(openidConfigurationEmpty)
        assertFalse(oidcMetadata == oidcMetadataInfoEmpty)

        assertFalse(
            oidcMetadataInfoEmpty == changeAttributeValue(
                oidcMetadataInfoEmpty,
                "claims_parameter_supported",
                oidcMetadata.claimsParameterSupported.not()
            )
        )
    }

    @Test
    fun equals_areDifferent_serviceDocumentation_shouldReturnFalse() {
        val oidcMetadataInfoEmpty =
            json.decodeFromString<OIDCMetadataInfo>(openidConfigurationEmpty)
        assertFalse(oidcMetadata == oidcMetadataInfoEmpty)

        assertFalse(
            oidcMetadataInfoEmpty == changeAttributeValue(
                oidcMetadataInfoEmpty,
                "service_documentation"
            )
        )
    }

    @Test
    fun equals_areDifferent_registrationEndpoint_shouldReturnFalse() {
        val oidcMetadataInfoEmpty =
            json.decodeFromString<OIDCMetadataInfo>(openidConfigurationEmpty)
        assertFalse(oidcMetadata == oidcMetadataInfoEmpty)

        assertFalse(
            oidcMetadataInfoEmpty == changeAttributeValue(
                oidcMetadataInfoEmpty,
                "registration_endpoint"
            )
        )
    }

    @Test
    fun equals_areDifferent_jwksUri_shouldReturnFalse() {
        val oidcMetadataInfoEmpty =
            json.decodeFromString<OIDCMetadataInfo>(openidConfigurationEmpty)
        assertFalse(oidcMetadata == oidcMetadataInfoEmpty)

        assertFalse(
            oidcMetadataInfoEmpty == changeAttributeValue(
                oidcMetadataInfoEmpty,
                "jwks_uri"
            )
        )
    }

    @Test
    fun equals_areDifferent_userinfoEndpoint_shouldReturnFalse() {
        val oidcMetadataInfoEmpty =
            json.decodeFromString<OIDCMetadataInfo>(openidConfigurationEmpty)
        assertFalse(oidcMetadata == oidcMetadataInfoEmpty)

        assertFalse(
            oidcMetadataInfoEmpty == changeAttributeValue(
                oidcMetadataInfoEmpty,
                "userinfo_endpoint"
            )
        )
    }

    @Test
    fun equals_areDifferent_tokenEndpoint_shouldReturnFalse() {
        val oidcMetadataInfoEmpty =
            json.decodeFromString<OIDCMetadataInfo>(openidConfigurationEmpty)
        assertFalse(oidcMetadata == oidcMetadataInfoEmpty)

        assertFalse(
            oidcMetadataInfoEmpty == changeAttributeValue(
                oidcMetadataInfoEmpty,
                "token_endpoint"
            )
        )
    }

    @Test
    fun equals_areDifferent_authorizationEndpoint_shouldReturnFalse() {
        val oidcMetadataInfoEmpty =
            json.decodeFromString<OIDCMetadataInfo>(openidConfigurationEmpty)
        assertFalse(oidcMetadata == oidcMetadataInfoEmpty)

        assertFalse(
            oidcMetadataInfoEmpty == changeAttributeValue(
                oidcMetadataInfoEmpty,
                "authorization_endpoint"
            )
        )
    }

    @Test
    fun equals_areDifferent_responseTypesSupported_shouldReturnFalse() {
        val oidcMetadataInfoEmpty =
            json.decodeFromString<OIDCMetadataInfo>(openidConfigurationEmpty)
        assertFalse(oidcMetadata == oidcMetadataInfoEmpty)

        assertFalse(
            oidcMetadataInfoEmpty == changeAttributeValue(
                oidcMetadataInfoEmpty,
                "response_types_supported",
                arrayOf("response_types_supported")
            )
        )
    }

    @Test
    fun equals_areDifferent_responseModesSupported_shouldReturnFalse() {
        val oidcMetadataInfoEmpty =
            json.decodeFromString<OIDCMetadataInfo>(openidConfigurationEmpty)
        assertFalse(oidcMetadata == oidcMetadataInfoEmpty)

        assertFalse(
            oidcMetadataInfoEmpty == changeAttributeValue(
                oidcMetadataInfoEmpty,
                "response_modes_supported",
                arrayOf("response_modes_supported")
            )
        )
    }

    @Test
    fun equals_areDifferent_grantTypesSupported_shouldReturnFalse() {
        val oidcMetadataInfoEmpty =
            json.decodeFromString<OIDCMetadataInfo>(openidConfigurationEmpty)
        assertFalse(oidcMetadata == oidcMetadataInfoEmpty)

        assertFalse(
            oidcMetadataInfoEmpty == changeAttributeValue(
                oidcMetadataInfoEmpty,
                "grant_types_supported",
                arrayOf("grant_types_supported")
            )
        )
    }

    @Test
    fun equals_areDifferent_subjectTypesSupported_shouldReturnFalse() {
        val oidcMetadataInfoEmpty =
            json.decodeFromString<OIDCMetadataInfo>(openidConfigurationEmpty)
        assertFalse(oidcMetadata == oidcMetadataInfoEmpty)

        assertFalse(
            oidcMetadataInfoEmpty == changeAttributeValue(
                oidcMetadataInfoEmpty,
                "subject_types_supported",
                arrayOf("subject_types_supported")
            )
        )
    }

    @Test
    fun equals_areDifferent_idTokenSigningAlgValuesSupported_shouldReturnFalse() {
        val oidcMetadataInfoEmpty =
            json.decodeFromString<OIDCMetadataInfo>(openidConfigurationEmpty)
        assertFalse(oidcMetadata == oidcMetadataInfoEmpty)

        assertFalse(
            oidcMetadataInfoEmpty == changeAttributeValue(
                oidcMetadataInfoEmpty,
                "id_token_signing_alg_values_supported",
                arrayOf("id_token_signing_alg_values_supported")
            )
        )
    }

    @Test
    fun equals_areDifferent_idTokenEncryptionAlgValuesSupported_shouldReturnFalse() {
        val oidcMetadataInfoEmpty =
            json.decodeFromString<OIDCMetadataInfo>(openidConfigurationEmpty)
        assertFalse(oidcMetadata == oidcMetadataInfoEmpty)

        assertFalse(
            oidcMetadataInfoEmpty == changeAttributeValue(
                oidcMetadataInfoEmpty,
                "id_token_encryption_alg_values_supported",
                arrayOf("id_token_encryption_alg_values_supported")
            )
        )
    }

    @Test
    fun equals_areDifferent_userinfoSigningAlgValuesSupported_shouldReturnFalse() {
        val oidcMetadataInfoEmpty =
            json.decodeFromString<OIDCMetadataInfo>(openidConfigurationEmpty)
        assertFalse(oidcMetadata == oidcMetadataInfoEmpty)

        assertFalse(
            oidcMetadataInfoEmpty == changeAttributeValue(
                oidcMetadataInfoEmpty,
                "userinfo_signing_alg_values_supported",
                arrayOf("userinfo_signing_alg_values_supported")
            )
        )
    }

    @Test
    fun equals_areDifferent_userinfoEncryptionAlgValuesSupported_shouldReturnFalse() {
        val oidcMetadataInfoEmpty =
            json.decodeFromString<OIDCMetadataInfo>(openidConfigurationEmpty)
        assertFalse(oidcMetadata == oidcMetadataInfoEmpty)

        assertFalse(
            oidcMetadataInfoEmpty == changeAttributeValue(
                oidcMetadataInfoEmpty,
                "userinfo_encryption_alg_values_supported",
                arrayOf("userinfo_encryption_alg_values_supported")
            )
        )
    }

    @Test
    fun equals_areDifferent_userinfoEncryptionEncValuesSupported_shouldReturnFalse() {
        val oidcMetadataInfoEmpty =
            json.decodeFromString<OIDCMetadataInfo>(openidConfigurationEmpty)
        assertFalse(oidcMetadata == oidcMetadataInfoEmpty)

        assertFalse(
            oidcMetadataInfoEmpty == changeAttributeValue(
                oidcMetadataInfoEmpty,
                "userinfo_encryption_enc_values_supported",
                arrayOf("userinfo_encryption_enc_values_supported")
            )
        )
    }

    @Test
    fun equals_areDifferent_requestObjectSigningAlgValuesSupported_shouldReturnFalse() {
        val oidcMetadataInfoEmpty =
            json.decodeFromString<OIDCMetadataInfo>(openidConfigurationEmpty)
        assertFalse(oidcMetadata == oidcMetadataInfoEmpty)

        assertFalse(
            oidcMetadataInfoEmpty == changeAttributeValue(
                oidcMetadataInfoEmpty,
                "request_object_signing_alg_values_supported",
                arrayOf("request_object_signing_alg_values_supported")
            )
        )
    }

    @Test
    fun equals_areDifferent_requestObjectEncryptionAlgValuesSupported_shouldReturnFalse() {
        val oidcMetadataInfoEmpty =
            json.decodeFromString<OIDCMetadataInfo>(openidConfigurationEmpty)
        assertFalse(oidcMetadata == oidcMetadataInfoEmpty)

        assertFalse(
            oidcMetadataInfoEmpty == changeAttributeValue(
                oidcMetadataInfoEmpty,
                "request_object_encryption_alg_values_supported",
                arrayOf("request_object_encryption_alg_values_supported")
            )
        )
    }

    @Test
    fun equals_areDifferent_requestObjectEncryptionEncValuesSupported_shouldReturnFalse() {
        val oidcMetadataInfoEmpty =
            json.decodeFromString<OIDCMetadataInfo>(openidConfigurationEmpty)
        assertFalse(oidcMetadata == oidcMetadataInfoEmpty)

        assertFalse(
            oidcMetadataInfoEmpty == changeAttributeValue(
                oidcMetadataInfoEmpty,
                "request_object_encryption_enc_values_supported",
                arrayOf("request_object_encryption_enc_values_supported")
            )
        )
    }

    @Test
    fun equals_areDifferent_tokenEndpointAuthMethodsSupported_shouldReturnFalse() {
        val oidcMetadataInfoEmpty =
            json.decodeFromString<OIDCMetadataInfo>(openidConfigurationEmpty)
        assertFalse(oidcMetadata == oidcMetadataInfoEmpty)

        assertFalse(
            oidcMetadataInfoEmpty == changeAttributeValue(
                oidcMetadataInfoEmpty,
                "token_endpoint_auth_methods_supported",
                arrayOf("token_endpoint_auth_methods_supported")
            )
        )
    }

    @Test
    fun equals_areDifferent_claimTypesSupported_shouldReturnFalse() {
        val oidcMetadataInfoEmpty =
            json.decodeFromString<OIDCMetadataInfo>(openidConfigurationEmpty)
        assertFalse(oidcMetadata == oidcMetadataInfoEmpty)

        assertFalse(
            oidcMetadataInfoEmpty == changeAttributeValue(
                oidcMetadataInfoEmpty,
                "claim_types_supported",
                arrayOf("claim_types_supported")
            )
        )
    }


    @Test
    fun equals_areDifferent_claimsSupported_shouldReturnFalse() {
        val oidcMetadataInfoEmpty =
            json.decodeFromString<OIDCMetadataInfo>(openidConfigurationEmpty)
        assertFalse(oidcMetadata == oidcMetadataInfoEmpty)

        assertFalse(
            oidcMetadataInfoEmpty == changeAttributeValue(
                oidcMetadataInfoEmpty,
                "claims_supported",
                arrayOf("claims_supported")
            )
        )
    }

    @Test
    fun equals_areDifferent_idTokenEncryptionEncValuesSupported_shouldReturnFalse() {
        val oidcMetadataInfoEmpty =
            json.decodeFromString<OIDCMetadataInfo>(openidConfigurationEmpty)
        assertFalse(oidcMetadata == oidcMetadataInfoEmpty)

        assertFalse(
            oidcMetadataInfoEmpty == changeAttributeValue(
                oidcMetadataInfoEmpty,
                "id_token_encryption_enc_values_supported",
                arrayOf("id_token_encryption_enc_values_supported")
            )
        )
    }

    @Test
    fun equals_areDifferent_tokenEndpointAuthSigningAlgValuesSupported_shouldReturnFalse() {
        val oidcMetadataInfoEmpty =
            json.decodeFromString<OIDCMetadataInfo>(openidConfigurationEmpty)
        assertFalse(oidcMetadata == oidcMetadataInfoEmpty)

        assertFalse(
            oidcMetadataInfoEmpty == changeAttributeValue(
                oidcMetadataInfoEmpty,
                "token_endpoint_auth_signing_alg_values_supported",
                arrayOf("token_endpoint_auth_signing_alg_values_supported")
            )
        )

        val oidcMetadataInfoOnlyMandatory = OIDCMetadataInfo(
            issuer = "issuer",
            authorizationEndpoint = "authorizationEndpoint",
            tokenEndpoint = "tokenEndpoint",
            userinfoEndpoint = "userinfoEndpoint",
            jwksUri = "jwksUri",
            registrationEndpoint = "registrationEndpoint",
            responseTypesSupported = emptyArray(),
            responseModesSupported = emptyArray(),
            subjectTypesSupported = emptyArray(),
            idTokenSigningAlgValuesSupported = emptyArray(),
            claimsSupported = emptyArray()
        )

        val oidcMetadataInfoWithAttribute = OIDCMetadataInfo(
            issuer = "issuer",
            authorizationEndpoint = "authorizationEndpoint",
            tokenEndpoint = "tokenEndpoint",
            userinfoEndpoint = "userinfoEndpoint",
            jwksUri = "jwksUri",
            registrationEndpoint = "registrationEndpoint",
            responseTypesSupported = emptyArray(),
            responseModesSupported = emptyArray(),
            subjectTypesSupported = emptyArray(),
            idTokenSigningAlgValuesSupported = emptyArray(),
            claimsSupported = emptyArray(),
            tokenEndpointAuthSigningAlgValuesSupported = emptyArray()
        )

        assertFalse(oidcMetadataInfoOnlyMandatory == oidcMetadataInfoWithAttribute)
        assertFalse(oidcMetadataInfoWithAttribute == oidcMetadataInfoOnlyMandatory)
    }


    @Test
    fun equals_areDifferent_displayValuesSupported_shouldReturnFalse() {
        val oidcMetadataInfoEmpty =
            json.decodeFromString<OIDCMetadataInfo>(openidConfigurationEmpty)
        assertFalse(oidcMetadata == oidcMetadataInfoEmpty)

        assertFalse(
            oidcMetadataInfoEmpty == changeAttributeValue(
                oidcMetadataInfoEmpty,
                "display_values_supported",
                arrayOf("display_values_supported")
            )
        )

        val oidcMetadataInfoOnlyMandatory = OIDCMetadataInfo(
            issuer = "issuer",
            authorizationEndpoint = "authorizationEndpoint",
            tokenEndpoint = "tokenEndpoint",
            userinfoEndpoint = "userinfoEndpoint",
            jwksUri = "jwksUri",
            registrationEndpoint = "registrationEndpoint",
            responseTypesSupported = emptyArray(),
            responseModesSupported = emptyArray(),
            subjectTypesSupported = emptyArray(),
            idTokenSigningAlgValuesSupported = emptyArray(),
            claimsSupported = emptyArray()
        )

        val oidcMetadataInfoWithAttribute = OIDCMetadataInfo(
            issuer = "issuer",
            authorizationEndpoint = "authorizationEndpoint",
            tokenEndpoint = "tokenEndpoint",
            userinfoEndpoint = "userinfoEndpoint",
            jwksUri = "jwksUri",
            registrationEndpoint = "registrationEndpoint",
            responseTypesSupported = emptyArray(),
            responseModesSupported = emptyArray(),
            subjectTypesSupported = emptyArray(),
            idTokenSigningAlgValuesSupported = emptyArray(),
            claimsSupported = emptyArray(),
            displayValuesSupported = emptyArray()
        )

        assertFalse(oidcMetadataInfoOnlyMandatory == oidcMetadataInfoWithAttribute)
        assertFalse(oidcMetadataInfoWithAttribute == oidcMetadataInfoOnlyMandatory)
    }


    @Test
    fun equals_areDifferent_claimsLocalesSupported_shouldReturnFalse() {
        val oidcMetadataInfoEmpty =
            json.decodeFromString<OIDCMetadataInfo>(openidConfigurationEmpty)
        assertFalse(oidcMetadata == oidcMetadataInfoEmpty)

        assertFalse(
            oidcMetadataInfoEmpty == changeAttributeValue(
                oidcMetadataInfoEmpty,
                "claims_locales_supported",
                arrayOf("claims_locales_supported")
            )
        )

        val oidcMetadataInfoOnlyMandatory = OIDCMetadataInfo(
            issuer = "issuer",
            authorizationEndpoint = "authorizationEndpoint",
            tokenEndpoint = "tokenEndpoint",
            userinfoEndpoint = "userinfoEndpoint",
            jwksUri = "jwksUri",
            registrationEndpoint = "registrationEndpoint",
            responseTypesSupported = emptyArray(),
            responseModesSupported = emptyArray(),
            subjectTypesSupported = emptyArray(),
            idTokenSigningAlgValuesSupported = emptyArray(),
            claimsSupported = emptyArray()
        )

        val oidcMetadataInfoWithAttribute = OIDCMetadataInfo(
            issuer = "issuer",
            authorizationEndpoint = "authorizationEndpoint",
            tokenEndpoint = "tokenEndpoint",
            userinfoEndpoint = "userinfoEndpoint",
            jwksUri = "jwksUri",
            registrationEndpoint = "registrationEndpoint",
            responseTypesSupported = emptyArray(),
            responseModesSupported = emptyArray(),
            subjectTypesSupported = emptyArray(),
            idTokenSigningAlgValuesSupported = emptyArray(),
            claimsSupported = emptyArray(),
            claimsLocalesSupported = emptyArray()
        )

        assertFalse(oidcMetadataInfoOnlyMandatory == oidcMetadataInfoWithAttribute)
        assertFalse(oidcMetadataInfoWithAttribute == oidcMetadataInfoOnlyMandatory)
    }


    @Test
    fun equals_areDifferent_uiLocalesSupported_shouldReturnFalse() {
        val oidcMetadataInfoEmpty =
            json.decodeFromString<OIDCMetadataInfo>(openidConfigurationEmpty)
        assertFalse(oidcMetadata == oidcMetadataInfoEmpty)

        assertFalse(
            oidcMetadataInfoEmpty == changeAttributeValue(
                oidcMetadataInfoEmpty,
                "ui_locales_supported",
                arrayOf("ui_locales_supported")
            )
        )

        val oidcMetadataInfoOnlyMandatory = OIDCMetadataInfo(
            issuer = "issuer",
            authorizationEndpoint = "authorizationEndpoint",
            tokenEndpoint = "tokenEndpoint",
            userinfoEndpoint = "userinfoEndpoint",
            jwksUri = "jwksUri",
            registrationEndpoint = "registrationEndpoint",
            responseTypesSupported = emptyArray(),
            responseModesSupported = emptyArray(),
            subjectTypesSupported = emptyArray(),
            idTokenSigningAlgValuesSupported = emptyArray(),
            claimsSupported = emptyArray()
        )

        val oidcMetadataInfoWithAttribute = OIDCMetadataInfo(
            issuer = "issuer",
            authorizationEndpoint = "authorizationEndpoint",
            tokenEndpoint = "tokenEndpoint",
            userinfoEndpoint = "userinfoEndpoint",
            jwksUri = "jwksUri",
            registrationEndpoint = "registrationEndpoint",
            responseTypesSupported = emptyArray(),
            responseModesSupported = emptyArray(),
            subjectTypesSupported = emptyArray(),
            idTokenSigningAlgValuesSupported = emptyArray(),
            claimsSupported = emptyArray(),
            uiLocalesSupported = emptyArray()
        )

        assertFalse(oidcMetadataInfoOnlyMandatory == oidcMetadataInfoWithAttribute)
        assertFalse(oidcMetadataInfoWithAttribute == oidcMetadataInfoOnlyMandatory)
    }


    // from https://sdk.verify.ibm.com/oauth2/.well-known/openid-configuration
    private val openidConfiguration = """
        {
          "request_parameter_supported": true,
          "introspection_endpoint": "https://sdk.verify.ibm.com/oauth2/introspect",
          "claims_parameter_supported": true,
          "scopes_supported": [
            "openid",
            "profile",
            "email",
            "phone"
          ],
          "issuer": "https://sdk.verify.ibm.com/oauth2",
          "id_token_encryption_enc_values_supported": [
            "none",
            "A128GCM",
            "A192GCM",
            "A256GCM"
          ],
          "userinfo_encryption_enc_values_supported": [
            "none"
          ],
          "authorization_endpoint": "https://sdk.verify.ibm.com/oauth2/authorize",
          "request_object_encryption_enc_values_supported": [
            "none"
          ],
          "device_authorization_endpoint": "https://sdk.verify.ibm.com/oauth2/device_authorization",
          "userinfo_signing_alg_values_supported": [
            "none"
          ],
          "claims_supported": [
            "realmName",
            "preferred_username",
            "given_name",
            "uid",
            "upn",
            "groupIds",
            "employee_id",
            "name",
            "tenantId",
            "mobile_number",
            "department",
            "family_name",
            "job_title",
            "email",
            "iss"
          ],
          "claim_types_supported": [
            "normal"
          ],
          "token_endpoint_auth_methods_supported": [
            "client_secret_basic",
            "client_secret_post",
            "client_secret_jwt",
            "private_key_jwt"
          ],
          "response_modes_supported": [
            "query",
            "fragment",
            "form_post"
          ],
          "token_endpoint": "https://sdk.verify.ibm.com/oauth2/token",
          "response_types_supported": [
            "code",
            "none",
            "token",
            "id_token",
            "token id_token",
            "code id_token",
            "code token",
            "code token id_token"
          ],
          "user_authorization_endpoint": "https://sdk.verify.ibm.com/oauth2/user_authorization",
          "request_uri_parameter_supported": false,
          "userinfo_encryption_alg_values_supported": [
            "none"
          ],
          "grant_types_supported": [
            "authorization_code",
            "implicit",
            "client_credentials",
            "password",
            "refresh_token",
            "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "urn:ietf:params:oauth:grant-type:device_code",
            "policyauth"
          ],
          "revocation_endpoint": "https://sdk.verify.ibm.com/oauth2/revoke",
          "userinfo_endpoint": "https://sdk.verify.ibm.com/oauth2/userinfo",
          "id_token_encryption_alg_values_supported": [
            "none",
            "RSA-OAEP",
            "RSA-OAEP-256"
          ],
          "jwks_uri": "https://sdk.verify.ibm.com/oauth2/jwks",
          "subject_types_supported": [
            "public"
          ],
          "id_token_signing_alg_values_supported": [
            "none",
            "HS256",
            "HS384",
            "HS512",
            "RS256",
            "RS384",
            "RS512",
            "PS256",
            "PS384",
            "PS512",
            "ES256",
            "ES384",
            "ES512"
          ],
          "registration_endpoint": "https://sdk.verify.ibm.com/oauth2/client_registration",
          "request_object_signing_alg_values_supported": [
            "none"
          ],
           "request_object_encryption_alg_values_supported": [
              "none"
            ]
        }
    """.trimIndent()

    private val openidConfigurationEmpty = """
        {
          "authorization_endpoint": "",
          "claim_types_supported": [],
          "claims_locales_supported": [],
          "claims_parameter_supported": true,
          "claims_supported": [],
          "device_authorization_endpoint": "",
          "display_values_supported": [],
          "grant_types_supported": [],
          "id_token_encryption_alg_values_supported": [],
          "id_token_encryption_enc_values_supported": [],
          "id_token_signing_alg_values_supported": [],
          "introspection_endpoint": "",
          "issuer": "",
          "jwks_uri": "",
          "op_policy_uri": "",
          "op_tos_uri": "",
          "registration_endpoint": "",
          "request_object_encryption_enc_values_supported": [],
          "request_object_encryption_alg_values_supported": [],
          "request_object_signing_alg_values_supported": [],
          "request_parameter_supported": true,
          "request_uri_parameter_supported": false,
          "response_modes_supported": [],
          "response_types_supported": [],
          "revocation_endpoint": "",
          "service_documentation": "",
          "scopes_supported": [],
          "subject_types_supported": [],
          "token_endpoint": "",
          "token_endpoint_auth_methods_supported": [],
          "token_endpoint_auth_signing_alg_values_supported": [],
          "ui_locales_supported": [],
          "user_authorization_endpoint": "",
          "userinfo_encryption_alg_values_supported": [],
          "userinfo_encryption_enc_values_supported": [],
          "userinfo_endpoint": "",
          "userinfo_signing_alg_values_supported": []
        }
    """.trimIndent()

    private val openidConfigurationMinimal = """
        {
          "authorization_endpoint": "",
          "claim_types_supported": [],
          "claims_parameter_supported": true,
          "claims_supported": [],
          "device_authorization_endpoint": "",
          "id_token_encryption_alg_values_supported": [],
          "id_token_encryption_enc_values_supported": [],
          "id_token_signing_alg_values_supported": [],
          "introspection_endpoint": "",
          "issuer": "",
          "jwks_uri": "",
          "registration_endpoint": "",
          "request_object_encryption_enc_values_supported": [],
          "request_object_encryption_alg_values_supported": [],
          "request_object_signing_alg_values_supported": [],
          "request_parameter_supported": true,
          "request_uri_parameter_supported": false,
          "response_modes_supported": [],
          "response_types_supported": [],
          "revocation_endpoint": "",
          "scopes_supported": [],
          "subject_types_supported": [],
          "token_endpoint": "",
          "token_endpoint_auth_methods_supported": [],
          "user_authorization_endpoint": "",
          "userinfo_endpoint": "",
          "userinfo_signing_alg_values_supported": []
        }
    """.trimIndent()
}
