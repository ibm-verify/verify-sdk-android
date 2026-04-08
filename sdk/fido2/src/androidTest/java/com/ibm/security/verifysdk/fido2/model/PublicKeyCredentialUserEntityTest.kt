package com.ibm.security.verifysdk.fido2.model

import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith
import org.skyscreamer.jsonassert.JSONAssert

private val json = Json {
    encodeDefaults = true
    explicitNulls = false
    ignoreUnknownKeys = true
    isLenient = true
}

@RunWith(AndroidJUnit4::class)
class PublicKeyCredentialUserEntityTest {

    @Test
    fun testSerialization_withAllFields() {
        val userEntity = PublicKeyCredentialUserEntity(
            id = "userId123",
            displayName = "User Display Name",
            name = "User Name",
            icon = "userIcon.png"
        )

        val jsonString = json.encodeToString(PublicKeyCredentialUserEntity.serializer(), userEntity)
        val expectedJson = """{"id":"userId123","displayName":"User Display Name","name":"User Name","icon":"userIcon.png"}"""
        JSONAssert.assertEquals(expectedJson, jsonString, false)
    }

    @Test
    fun testSerialization_withoutIcon() {
        val userEntity = PublicKeyCredentialUserEntity(
            id = "userId123",
            displayName = "User Display Name",
            name = "User Name"
        )

        val jsonString = json.encodeToString(PublicKeyCredentialUserEntity.serializer(), userEntity)
        val expectedJson = """{"id":"userId123","displayName":"User Display Name","name":"User Name"}"""
        JSONAssert.assertEquals(expectedJson, jsonString, false)
    }

    @Test
    fun testDeserialization_withAllFields() {
        val jsonString = """{"id":"userId123","displayName":"User Display Name","name":"User Name","icon":"userIcon.png"}"""
        val userEntity = json.decodeFromString(PublicKeyCredentialUserEntity.serializer(), jsonString)

        assertEquals("userId123", userEntity.id)
        assertEquals("User Display Name", userEntity.displayName)
        assertEquals("User Name", userEntity.name)
        assertEquals("userIcon.png", userEntity.icon)
    }

    @Test
    fun testDeserialization_withoutIcon() {
        val jsonString = """{"id":"userId123","displayName":"User Display Name","name":"User Name"}"""
        val userEntity = json.decodeFromString(PublicKeyCredentialUserEntity.serializer(), jsonString)

        assertEquals("userId123", userEntity.id)
        assertEquals("User Display Name", userEntity.displayName)
        assertEquals("User Name", userEntity.name)
        assertNull(userEntity.icon)
    }

    @Test
    fun testEquality() {
        val userEntity1 = PublicKeyCredentialUserEntity(
            id = "userId123",
            displayName = "User Display Name",
            name = "User Name",
            icon = "userIcon.png"
        )

        val userEntity2 = PublicKeyCredentialUserEntity(
            id = "userId123",
            displayName = "User Display Name",
            name = "User Name",
            icon = "userIcon.png"
        )

        assertEquals(userEntity1, userEntity2)
    }

    @Test
    fun testInequality_differentId() {
        val userEntity1 = PublicKeyCredentialUserEntity(
            id = "userId123",
            displayName = "User Display Name",
            name = "User Name",
            icon = "userIcon.png"
        )

        val userEntity2 = PublicKeyCredentialUserEntity(
            id = "userId456",
            displayName = "User Display Name",
            name = "User Name",
            icon = "userIcon.png"
        )

        assertNotEquals(userEntity1, userEntity2)
    }

    @Test
    fun testInequality_differentDisplayName() {
        val userEntity1 = PublicKeyCredentialUserEntity(
            id = "userId123",
            displayName = "User Display Name",
            name = "User Name",
            icon = "userIcon.png"
        )

        val userEntity2 = PublicKeyCredentialUserEntity(
            id = "userId123",
            displayName = "Different Display Name",
            name = "User Name",
            icon = "userIcon.png"
        )

        assertNotEquals(userEntity1, userEntity2)
    }

    @Test
    fun testInequality_differentName() {
        val userEntity1 = PublicKeyCredentialUserEntity(
            id = "userId123",
            displayName = "User Display Name",
            name = "User Name",
            icon = "userIcon.png"
        )

        val userEntity2 = PublicKeyCredentialUserEntity(
            id = "userId123",
            displayName = "User Display Name",
            name = "Different Name",
            icon = "userIcon.png"
        )

        assertNotEquals(userEntity1, userEntity2)
    }

    @Test
    fun testInequality_differentIcon() {
        val userEntity1 = PublicKeyCredentialUserEntity(
            id = "userId123",
            displayName = "User Display Name",
            name = "User Name",
            icon = "userIcon.png"
        )

        val userEntity2 = PublicKeyCredentialUserEntity(
            id = "userId123",
            displayName = "User Display Name",
            name = "User Name",
            icon = "differentIcon.png"
        )

        assertNotEquals(userEntity1, userEntity2)
    }

}
