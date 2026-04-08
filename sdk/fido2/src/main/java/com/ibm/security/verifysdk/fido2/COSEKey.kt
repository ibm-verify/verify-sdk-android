/*
 *  Copyright contributors to the IBM Verify FIDO2 SDK for Android project
 */
package com.ibm.security.verifysdk.fido2

import com.fasterxml.jackson.dataformat.cbor.databind.CBORMapper

/**
 * Represents a key in COSE format (CBOR Object Signing and Encryption).
 *
 * This class encapsulates a key with its key type, algorithm,
 * curve, x-coordinate, and y-coordinate.
 *
 * The byte array representation is computed lazily and cached for performance.
 * The CBORMapper is shared across all instances to reduce memory overhead.
 *
 * @param kty The key type identifier.
 * @param alg The algorithm identifier.
 * @param crv The curve identifier.
 * @param x The x-coordinate of the key.
 * @param y The y-coordinate of the key.
 *
 * @property _kty The internal storage for the key type.
 * @property _alg The internal storage for the algorithm.
 * @property _crv The internal storage for the curve.
 * @property _x The internal storage for the x-coordinate.
 * @property _y The internal storage for the y-coordinate.
 * @property toByteArray A property that returns the COSE key as a byte array (cached).
 *
 * @constructor Creates a COSEKey instance with the specified attributes.
 */
class COSEKey(kty: Int, alg: Int, crv: Int, x: ByteArray, y: ByteArray) {

    private val _kty = kty
    private val _alg = alg
    private val _crv = crv
    private val _x = x
    private val _y = y

    /**
     * Converts the COSEKey instance to a byte array representation.
     *
     * This property constructs a CBOR map containing the key attributes,
     * and then converts it to a byte array representation using a shared CBOR mapper.
     * The result is computed once and cached for subsequent accesses.
     *
     * @return The byte array representation of the COSEKey.
     */
    val toByteArray: ByteArray by lazy {
        val map = mapOf(
            1 to _kty,
            3 to _alg,
            -1 to _crv,
            -2 to _x,
            -3 to _y
        )
        cborMapper.writeValueAsBytes(map)
    }

    companion object {
        /**
         * Shared CBORMapper instance used by all COSEKey instances.
         * This reduces memory overhead and improves performance.
         */
        private val cborMapper = CBORMapper()
    }
}