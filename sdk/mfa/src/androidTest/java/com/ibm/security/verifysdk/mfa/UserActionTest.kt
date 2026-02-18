/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.mfa

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class UserActionTest {

    @Test
    fun enumValues_shouldContainAllActions() {
        // Given
        val expectedActions = setOf(
            UserAction.DENY,
            UserAction.MARK_AS_FRAUD,
            UserAction.VERIFY,
            UserAction.BIOMETRY_FAILED
        )

        // When
        val actualActions = UserAction.values().toSet()

        // Then
        assertEquals(expectedActions, actualActions)
        assertEquals(4, UserAction.values().size)
    }

    @Test
    fun deny_valueShouldBeUserDenied() {
        // When
        val value = UserAction.DENY.value

        // Then
        assertEquals("USER_DENIED", value)
    }

    @Test
    fun markAsFraud_valueShouldBeUserFraudulent() {
        // When
        val value = UserAction.MARK_AS_FRAUD.value

        // Then
        assertEquals("USER_FRAUDULENT", value)
    }

    @Test
    fun verify_valueShouldBeVerifyAttempt() {
        // When
        val value = UserAction.VERIFY.value

        // Then
        assertEquals("VERIFY_ATTEMPT", value)
    }

    @Test
    fun biometryFailed_valueShouldBeBiometryFailed() {
        // When
        val value = UserAction.BIOMETRY_FAILED.value

        // Then
        assertEquals("BIOMETRY_FAILED", value)
    }

    @Test
    fun allActions_shouldHaveUniqueValues() {
        // Given
        val actions = UserAction.values()

        // When
        val values = actions.map { it.value }.toSet()

        // Then
        assertEquals(actions.size, values.size)
    }

    @Test
    fun name_shouldReturnEnumName() {
        // Then
        assertEquals("DENY", UserAction.DENY.name)
        assertEquals("MARK_AS_FRAUD", UserAction.MARK_AS_FRAUD.name)
        assertEquals("VERIFY", UserAction.VERIFY.name)
        assertEquals("BIOMETRY_FAILED", UserAction.BIOMETRY_FAILED.name)
    }

    @Test
    fun valueOf_withValidName_shouldReturnEnumValue() {
        // Then
        assertEquals(UserAction.DENY, UserAction.valueOf("DENY"))
        assertEquals(UserAction.MARK_AS_FRAUD, UserAction.valueOf("MARK_AS_FRAUD"))
        assertEquals(UserAction.VERIFY, UserAction.valueOf("VERIFY"))
        assertEquals(UserAction.BIOMETRY_FAILED, UserAction.valueOf("BIOMETRY_FAILED"))
    }

    @Test(expected = IllegalArgumentException::class)
    fun valueOf_withInvalidName_shouldThrowException() {
        // When
        UserAction.valueOf("INVALID")
    }

    @Test
    fun ordinal_shouldReturnCorrectOrder() {
        // Then
        assertEquals(0, UserAction.DENY.ordinal)
        assertEquals(1, UserAction.MARK_AS_FRAUD.ordinal)
        assertEquals(2, UserAction.VERIFY.ordinal)
        assertEquals(3, UserAction.BIOMETRY_FAILED.ordinal)
    }

    @Test
    fun compareTo_shouldCompareByOrdinal() {
        // Then
        assert(UserAction.DENY < UserAction.MARK_AS_FRAUD)
        assert(UserAction.MARK_AS_FRAUD < UserAction.VERIFY)
        assert(UserAction.VERIFY < UserAction.BIOMETRY_FAILED)
    }

    @Test
    fun toString_shouldReturnEnumName() {
        // Then
        assertEquals("DENY", UserAction.DENY.toString())
        assertEquals("MARK_AS_FRAUD", UserAction.MARK_AS_FRAUD.toString())
        assertEquals("VERIFY", UserAction.VERIFY.toString())
        assertEquals("BIOMETRY_FAILED", UserAction.BIOMETRY_FAILED.toString())
    }

    @Test
    fun deny_shouldRepresentUserDenial() {
        // Given
        val action = UserAction.DENY

        // Then
        assertEquals("USER_DENIED", action.value)
        assertEquals("DENY", action.name)
    }

    @Test
    fun markAsFraud_shouldRepresentFraudulentAction() {
        // Given
        val action = UserAction.MARK_AS_FRAUD

        // Then
        assertEquals("USER_FRAUDULENT", action.value)
        assertEquals("MARK_AS_FRAUD", action.name)
    }

    @Test
    fun verify_shouldRepresentVerificationAttempt() {
        // Given
        val action = UserAction.VERIFY

        // Then
        assertEquals("VERIFY_ATTEMPT", action.value)
        assertEquals("VERIFY", action.name)
    }

    @Test
    fun biometryFailed_shouldRepresentFailedBiometry() {
        // Given
        val action = UserAction.BIOMETRY_FAILED

        // Then
        assertEquals("BIOMETRY_FAILED", action.value)
        assertEquals("BIOMETRY_FAILED", action.name)
    }

    @Test
    fun allActions_shouldHaveDistinctNames() {
        // Given
        val actions = UserAction.values()

        // When
        val names = actions.map { it.name }.toSet()

        // Then
        assertEquals(actions.size, names.size)
    }

    @Test
    fun allActions_shouldHaveDistinctOrdinals() {
        // Given
        val actions = UserAction.values()

        // When
        val ordinals = actions.map { it.ordinal }.toSet()

        // Then
        assertEquals(actions.size, ordinals.size)
    }

    @Test
    fun valueProperty_shouldBeAccessible() {
        // When/Then
        assertEquals("USER_DENIED", UserAction.DENY.value)
        assertEquals("USER_FRAUDULENT", UserAction.MARK_AS_FRAUD.value)
        assertEquals("VERIFY_ATTEMPT", UserAction.VERIFY.value)
        assertEquals("BIOMETRY_FAILED", UserAction.BIOMETRY_FAILED.value)
    }

    @Test
    fun whenExpression_shouldBeExhaustive() {
        // Given
        val actions = UserAction.values()

        // When/Then - Verify all actions can be handled
        for (action in actions) {
            val result = when (action) {
                UserAction.DENY -> "denied"
                UserAction.MARK_AS_FRAUD -> "fraud"
                UserAction.VERIFY -> "verify"
                UserAction.BIOMETRY_FAILED -> "biometry_failed"
            }
            assert(result.isNotEmpty())
        }
    }

    @Test
    fun equality_shouldWorkCorrectly() {
        // Given
        val action1 = UserAction.VERIFY
        val action2 = UserAction.VERIFY
        val action3 = UserAction.DENY

        // Then
        assertEquals(action1, action2)
        assert(action1 != action3)
    }

    @Test
    fun hashCode_shouldBeConsistent() {
        // Given
        val action1 = UserAction.VERIFY
        val action2 = UserAction.VERIFY

        // Then
        assertEquals(action1.hashCode(), action2.hashCode())
    }
}
