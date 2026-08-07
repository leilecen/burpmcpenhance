package net.portswigger.mcp.security

import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.awt.Frame

/**
 * Finds the Burp Suite main frame or the largest available frame as fallback
 */
fun findBurpFrame(): Frame? {
    val burpIdentifiers = listOf("Burp Suite", "Professional", "Community", "burp")

    return Frame.getFrames().find { frame ->
        frame.isVisible && frame.isDisplayable && burpIdentifiers.any { identifier ->
            frame.title.contains(identifier, ignoreCase = true) ||
                    frame.javaClass.name.contains(identifier, ignoreCase = true) ||
                    frame.javaClass.simpleName.contains(identifier, ignoreCase = true)
        }
    } ?: Frame.getFrames()
        .filter { it.isVisible && it.isDisplayable }
        .maxByOrNull { it.width * it.height }
}

private val SENSITIVE_CONFIG_KEYS = setOf(
    "password",
    "certificate_password",
    "hashed_key"
)

private const val REDACTED_CONFIG_VALUE = "*****"

fun filterConfigCredentials(json: String): String {
    return try {
        Json.encodeToString(filterConfigElement(Json.parseToJsonElement(json)))
    } catch (_: SerializationException) {
        """{"error":"failed to parse config json"}"""
    }
}

private fun filterConfigElement(element: JsonElement): JsonElement = when (element) {
    is JsonObject -> JsonObject(element.mapValues { (key, value) -> filterConfigValue(key, value) })
    is JsonArray -> JsonArray(element.map(::filterConfigElement))
    else -> element
}

private fun filterConfigValue(key: String, value: JsonElement): JsonElement =
    if (key.lowercase() in SENSITIVE_CONFIG_KEYS && value is JsonPrimitive && value.isString) {
        JsonPrimitive(REDACTED_CONFIG_VALUE)
    } else {
        filterConfigElement(value)
    }
