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
class PublicKeyCredentialRpEntityTest {

    @Test
    fun testSerialization_withIdAndIcon() {
        val entity = PublicKeyCredentialRpEntity(
            id = "testId",
            name = "testName",
            icon = "testIcon"
        )

        val jsonString = json.encodeToString(PublicKeyCredentialRpEntity.serializer(), entity)
        val expectedJson = """{"id":"testId","name":"testName","icon":"testIcon"}"""
        JSONAssert.assertEquals(expectedJson, jsonString, false)
    }

    @Test
    fun testSerialization_withIdWithoutIcon() {
        val entity = PublicKeyCredentialRpEntity(
            id = "testId",
            name = "testName"
        )

        val jsonString = json.encodeToString(PublicKeyCredentialRpEntity.serializer(), entity)
        val expectedJson = """{"id":"testId","name":"testName"}"""
        assertEquals(expectedJson, jsonString)
    }

    @Test
    fun testSerialization_withNullIdAndWithoutIcon() {
        val entity = PublicKeyCredentialRpEntity(
            id = null,
            name = "testName"
        )

        val jsonString = json.encodeToString(PublicKeyCredentialRpEntity.serializer(), entity)
        val expectedJson = """{"name":"testName"}"""
        assertEquals(expectedJson, jsonString)
    }

    @Test
    fun testDeserialization_withIdAndIcon() {
        val jsonString = """{"id":"testId","name":"testName","icon":"testIcon"}"""
        val entity = json.decodeFromString(PublicKeyCredentialRpEntity.serializer(), jsonString)

        assertEquals("testId", entity.id)
        assertEquals("testName", entity.name)
        assertEquals("testIcon", entity.icon)
    }

    @Test
    fun testDeserialization_withIdWithoutIcon() {
        val jsonString = """{"id":"testId","name":"testName"}"""
        val entity = json.decodeFromString(PublicKeyCredentialRpEntity.serializer(), jsonString)

        assertEquals("testId", entity.id)
        assertEquals("testName", entity.name)
        assertNull(entity.icon)
    }

    @Test
    fun testDeserialization_withNullIdWithoutIcon() {
        val jsonString = """{"name":"testName"}"""
        val entity = json.decodeFromString(PublicKeyCredentialRpEntity.serializer(), jsonString)

        assertNull(entity.id)
        assertEquals("testName", entity.name)
        assertNull(entity.icon)
    }

    @Test
    fun testEquality() {
        val entity1 = PublicKeyCredentialRpEntity(
            id = "testId",
            name = "testName",
            icon = "testIcon"
        )

        val entity2 = PublicKeyCredentialRpEntity(
            id = "testId",
            name = "testName",
            icon = "testIcon"
        )

        assertEquals(entity1, entity2)
    }

    @Test
    fun testInequality_differentId() {
        val entity1 = PublicKeyCredentialRpEntity(
            id = "testId1",
            name = "testName",
            icon = "testIcon"
        )

        val entity2 = PublicKeyCredentialRpEntity(
            id = "testId2",
            name = "testName",
            icon = "testIcon"
        )

        assertNotEquals(entity1, entity2)
    }

    @Test
    fun testInequality_differentName() {
        val entity1 = PublicKeyCredentialRpEntity(
            id = "testId",
            name = "testName1",
            icon = "testIcon"
        )

        val entity2 = PublicKeyCredentialRpEntity(
            id = "testId",
            name = "testName2",
            icon = "testIcon"
        )

        assertNotEquals(entity1, entity2)
    }

    @Test
    fun testInequality_differentIcon() {
        val entity1 = PublicKeyCredentialRpEntity(
            id = "testId",
            name = "testName",
            icon = "testIcon1"
        )

        val entity2 = PublicKeyCredentialRpEntity(
            id = "testId",
            name = "testName",
            icon = "testIcon2"
        )

        assertNotEquals(entity1, entity2)
    }

    @Test
    fun testSetId() {
        val entity = PublicKeyCredentialRpEntity(
            id = "initialId",
            name = "testName"
        )
        entity.id = "updatedId"
        assertEquals("updatedId", entity.id)
    }
}
