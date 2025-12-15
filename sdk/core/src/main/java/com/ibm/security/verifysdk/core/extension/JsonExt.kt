/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.core.extension

import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.double
import kotlinx.serialization.json.doubleOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import kotlinx.serialization.json.longOrNull

fun Any?.toJsonElement(): JsonElement = when (this) {
    is Array<*> -> this.toJsonArray()
    is Boolean -> JsonPrimitive(this)
    is JsonElement -> this
    is List<*> -> this.toJsonArray()
    is Map<*, *> -> this.toJsonObject()
    is Number -> JsonPrimitive(this)
    is String -> JsonPrimitive(this)
    else -> JsonNull
}

fun Array<*>.toJsonArray() = JsonArray(map { it.toJsonElement() })
fun Iterable<*>.toJsonArray() = JsonArray(map { it.toJsonElement() })
fun Map<*, *>.toJsonObject(): JsonObject =
    JsonObject(mapKeys { it.key.toString() }.mapValues { it.value.toJsonElement() })

fun JsonObject.getJsonArrayOrNull(path: String): List<JsonElement>? {
    return this[path]?.jsonArray?.toList()
}

fun JsonObject.getStringOrNull(path: String): String? {
    return this[path]?.jsonPrimitive?.content
}

fun JsonObject.getStringOrThrow(key: String): String {
    return this[key]?.jsonPrimitive?.content ?: throw SerializationException("Missing $key")
}

fun JsonObject.getStringList(key: String): List<String> {
    return this[key]?.jsonArray?.mapNotNull { it.jsonPrimitive.contentOrNull } ?: emptyList()
}

fun JsonElement.toKotlinType(): Any? {
    return when (this) {
        is JsonNull -> null
        is JsonPrimitive -> when {
            this.isString -> this.content
            this.booleanOrNull != null -> this.boolean
            this.longOrNull != null -> this.long
            this.doubleOrNull != null -> this.double
            else -> this.content
        }
        is JsonObject -> this.mapValues { it.value.toKotlinType() }
        is JsonArray -> this.map { it.toKotlinType() }
    }
}



