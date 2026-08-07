package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.burpsuite.TaskExecutionEngine.TaskExecutionEngineState.PAUSED
import burp.api.montoya.burpsuite.TaskExecutionEngine.TaskExecutionEngineState.RUNNING
import burp.api.montoya.collaborator.InteractionFilter
import burp.api.montoya.core.BurpSuiteEdition
import burp.api.montoya.http.HttpMode
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.requests.HttpRequest
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import net.portswigger.mcp.config.EXPORT_NOISE_MODE_BALANCED
import net.portswigger.mcp.config.EXPORT_NOISE_MODE_OFF
import net.portswigger.mcp.config.EXPORT_NOISE_MODE_RELAXED
import net.portswigger.mcp.config.EXPORT_NOISE_MODE_STRICT
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.config.normalizeExportNoiseMode
import net.portswigger.mcp.db.Database
import net.portswigger.mcp.exporter.Exporter
import net.portswigger.mcp.plugins.BurpPluginImpactDiagnostics
import net.portswigger.mcp.plugins.buildBurpInfoSummary
import net.portswigger.mcp.plugins.collectBurpPluginInventory
import net.portswigger.mcp.queue.FileQueue
import net.portswigger.mcp.queue.MessageQueue
import net.portswigger.mcp.schema.toSerializableForm
import net.portswigger.mcp.security.HistoryAccessSecurity
import net.portswigger.mcp.security.HistoryAccessType
import net.portswigger.mcp.security.HttpRequestSecurity
import net.portswigger.mcp.security.filterConfigCredentials
import java.awt.KeyboardFocusManager
import java.util.regex.Pattern
import javax.swing.JTextArea

internal fun normalizeHttpContent(content: String): String {
    val preludeEnd = findHttpPreludeEnd(content) ?: return normalizeHttpPrelude(content)
    return normalizeHttpPrelude(content.substring(0, preludeEnd)) + content.substring(preludeEnd)
}

private val HTTP_BLANK_LINE_MARKERS = listOf(
    "\r\n\r\n",
    "\n\n",
    "\\r\\n\\r\\n",
    "\\n\\n"
)

private fun findHttpPreludeEnd(content: String): Int? {
    var firstMarkerStart = -1
    var firstMarkerLength = 0
    for (marker in HTTP_BLANK_LINE_MARKERS) {
        val markerStart = content.indexOf(marker)
        if (markerStart >= 0 && (firstMarkerStart < 0 || markerStart < firstMarkerStart)) {
            firstMarkerStart = markerStart
            firstMarkerLength = marker.length
        }
    }
    return if (firstMarkerStart < 0) null else firstMarkerStart + firstMarkerLength
}

private fun normalizeHttpPrelude(prelude: String): String = prelude
    .replace("\\r\\n", "\n")
    .replace("\\n", "\n")
    .replace("\\r", "")
    .replace("\r", "")
    .replace("\n", "\r\n")

private fun buildHttp2HeaderList(
    pseudoHeaders: Map<String, String>,
    headers: Map<String, String>
): List<HttpHeader> {
    val orderedPseudoHeaderNames = listOf(":scheme", ":method", ":path", ":authority")
    val normalizedPseudoHeaders = LinkedHashMap<String, String>().apply {
        orderedPseudoHeaderNames.forEach { name ->
            val value = pseudoHeaders[name.removePrefix(":")] ?: pseudoHeaders[name]
            if (value != null) put(name, value)
        }
        pseudoHeaders.forEach { (key, value) ->
            val normalizedKey = if (key.startsWith(":")) key else ":$key"
            if (!containsKey(normalizedKey)) put(normalizedKey, value)
        }
    }
    return (normalizedPseudoHeaders + headers).map { (name, value) ->
        HttpHeader.httpHeader(name.lowercase(), value)
    }
}

private data class OrganizerLimitedText(val value: String, val truncated: Boolean)

private fun String.limitOrganizerText(maxChars: Int): OrganizerLimitedText {
    if (length <= maxChars) return OrganizerLimitedText(this, false)
    var end = maxChars
    if (end > 0 && Character.isHighSurrogate(this[end - 1])) end--
    return OrganizerLimitedText(substring(0, end), true)
}

private fun omitHttpBody(content: String): String {
    val separators = listOf("\r\n\r\n", "\n\n")
    val match = separators.mapNotNull { separator ->
        content.indexOf(separator).takeIf { it >= 0 }?.let { it to separator.length }
    }.minByOrNull { it.first } ?: return content
    val bodyStart = match.first + match.second
    return if (bodyStart < content.length) {
        content.substring(0, bodyStart) + "<body omitted>"
    } else {
        content
    }
}

private suspend fun checkHistoryPermissionOrDeny(
    accessType: HistoryAccessType, config: McpConfig, api: MontoyaApi, logMessage: String
): Boolean {
    val allowed = HistoryAccessSecurity.checkHistoryAccessPermission(accessType, config)
    if (!allowed) {
        api.logging().logToOutput("MCP $logMessage access denied")
        return false
    }
    api.logging().logToOutput("MCP $logMessage access granted")
    return true
}

private fun truncateIfNeeded(serialized: String): String {
    return if (serialized.length > 5000) {
        serialized.substring(0, 5000) + "... (truncated)"
    } else {
        serialized
    }
}

private const val RAW_HISTORY_DEFAULT_LIMIT = 10
private const val RAW_HISTORY_MAX_LIMIT = 20
private const val RAW_HISTORY_DEFAULT_MAX_BYTES = 50_000
private const val RAW_HISTORY_MAX_BYTES = 100_000

private fun limitedRawHistoryResponse(items: Sequence<String>, offset: Int, requestedLimit: Int?, requestedMaxBytes: Int): String {
    val limit = (requestedLimit ?: RAW_HISTORY_DEFAULT_LIMIT).coerceIn(1, RAW_HISTORY_MAX_LIMIT)
    val maxBytes = requestedMaxBytes.coerceIn(1_000, RAW_HISTORY_MAX_BYTES)
    val page = items.drop(offset.coerceAtLeast(0)).take(limit).toList()
    val joined = joinWithSizeLimit(page, maxSize = maxBytes)
    return when {
        page.isEmpty() -> "Reached end of items"
        joined.contains("response truncated") || requestedLimit == null || (requestedLimit > RAW_HISTORY_MAX_LIMIT) ->
            "$joined\n\n[Raw history limited: limit=$limit maxBytes=$maxBytes. Prefer cached list/detail tools.]"
        else -> joined
    }
}

fun Server.registerTools(
    api: MontoyaApi,
    config: McpConfig,
    messageQueue: MessageQueue? = null,
    fileQueue: FileQueue? = null,
    database: Database? = null,
    exporter: Exporter? = null
) {
    val advancedTools = true
    // Register queue/file tools if infrastructure is available
    if (advancedTools && messageQueue != null && fileQueue != null) {
        registerQueueTools(api, messageQueue, fileQueue)
    }
    // Register exporter/two-tier query tools if infrastructure is available
    if (database != null && exporter != null) {
        registerExporterTools(database, exporter, advancedTools)
        registerDiffTools(database)
    }
    registerScopeTools(api, config, advancedTools) { exporter?.reimport() }
    registerGraphQLTools(api, config)

    mcpTool<SendHttp1Request>("Issues an HTTP/1.1 request and returns the response.") {
        val allowed = runBlocking {
            HttpRequestSecurity.checkHttpRequestPermission(targetHostname, targetPort, config, content, api)
        }
        if (!allowed) {
            api.logging().logToOutput("MCP HTTP request denied: $targetHostname:$targetPort")
            return@mcpTool "Send HTTP request denied by Burp Suite"
        }

        api.logging().logToOutput("MCP HTTP/1.1 request: $targetHostname:$targetPort")

        val fixedContent = normalizeHttpContent(content)

        val request = HttpRequest.httpRequest(toMontoyaService(), fixedContent)
        val response = api.http().sendRequest(request)

        response?.toString() ?: "<no response>"
    }

    mcpTool<CreateRepeaterTab>("Creates a new Repeater tab with the specified HTTP request and optional tab name. Make sure to use carriage returns appropriately.") {
        val request = HttpRequest.httpRequest(toMontoyaService(), normalizeHttpContent(content))
        api.repeater().sendToRepeater(request, tabName)
    }

    mcpTool<CreateRepeaterTabHttp2>(
        "Creates an HTTP/2 Repeater tab with the specified headers, body, and optional tab name."
    ) {
        val request = HttpRequest.http2Request(
            toMontoyaService(),
            buildHttp2HeaderList(pseudoHeaders, headers),
            requestBody
        )
        api.repeater().sendToRepeater(request, tabName)
    }

    if (advancedTools) {
    mcpTool<SendHttp2Request>("Issues an HTTP/2 request and returns the response. Do NOT pass headers to the body parameter.") {
        val http2RequestDisplay = buildString {
            pseudoHeaders.forEach { (key, value) ->
                val headerName = if (key.startsWith(":")) key else ":$key"
                appendLine("$headerName: $value")
            }
            headers.forEach { (key, value) ->
                appendLine("$key: $value")
            }
            if (requestBody.isNotBlank()) {
                appendLine()
                append(requestBody)
            }
        }

        val allowed = runBlocking {
            HttpRequestSecurity.checkHttpRequestPermission(targetHostname, targetPort, config, http2RequestDisplay, api)
        }
        if (!allowed) {
            api.logging().logToOutput("MCP HTTP request denied: $targetHostname:$targetPort")
            return@mcpTool "Send HTTP request denied by Burp Suite"
        }

        api.logging().logToOutput("MCP HTTP/2 request: $targetHostname:$targetPort")

        val request = HttpRequest.http2Request(toMontoyaService(), buildHttp2HeaderList(pseudoHeaders, headers), requestBody)
        val response = api.http().sendRequest(request, HttpMode.HTTP_2)

        response?.toString() ?: "<no response>"
    }

    mcpTool<SendToIntruder>("Sends an HTTP request to Intruder with the specified HTTP request and optional tab name. Make sure to use carriage returns appropriately.") {
        val request = HttpRequest.httpRequest(toMontoyaService(), normalizeHttpContent(content))
        api.intruder().sendToIntruder(request, tabName)
    }

    mcpTool<UrlEncode>("URL encodes the input string") {
        api.utilities().urlUtils().encode(content)
    }

    mcpTool<UrlDecode>("URL decodes the input string") {
        api.utilities().urlUtils().decode(content)
    }

    mcpTool<Base64Encode>("Base64 encodes the input string") {
        api.utilities().base64Utils().encodeToString(content)
    }

    mcpTool<Base64Decode>("Base64 decodes the input string") {
        api.utilities().base64Utils().decode(content).toString()
    }

    mcpTool<GenerateRandomString>("Generates a random string of specified length and character set") {
        api.utilities().randomUtils().randomString(length, characterSet)
    }

    mcpTool(
        "output_project_options",
        "Outputs current project-level configuration in JSON format. You can use this to determine the schema for available config options."
    ) {
        val json = api.burpSuite().exportProjectOptionsAsJson()
        if (config.filterConfigCredentials) filterConfigCredentials(json) else json
    }

    mcpTool(
        "output_user_options",
        "Outputs current user-level configuration in JSON format. You can use this to determine the schema for available config options."
    ) {
        val json = api.burpSuite().exportUserOptionsAsJson()
        if (config.filterConfigCredentials) filterConfigCredentials(json) else json
    }

    val toolingDisabledMessage =
        "User has disabled configuration editing. They can enable it in the MCP tab in Burp by selecting 'Enable tools that can edit your config'"

    mcpTool<SetProjectOptions>("Sets project-level configuration in JSON format. This will be merged with existing configuration. Make sure to export before doing this, so you know what the schema is. Make sure the JSON has a top level 'project_options' object!") {
        if (config.configEditingTooling) {
            api.logging().logToOutput("Setting project-level configuration: $json")
            api.burpSuite().importProjectOptionsFromJson(json)

            "Project configuration has been applied"
        } else {
            toolingDisabledMessage
        }
    }


    mcpTool<SetUserOptions>("Sets user-level configuration in JSON format. This will be merged with existing configuration. Make sure to export before doing this, so you know what the schema is. Make sure the JSON has a top level 'user_options' object!") {
        if (config.configEditingTooling) {
            api.logging().logToOutput("Setting user-level configuration: $json")
            api.burpSuite().importUserOptionsFromJson(json)

            "User configuration has been applied"
        } else {
            toolingDisabledMessage
        }
    }

    if (api.burpSuite().version().edition() == BurpSuiteEdition.PROFESSIONAL) {
        mcpPaginatedTool<GetScannerIssues>("Displays information about issues identified by the scanner. Use count ≤ 20 per request to avoid truncation.") {
            api.siteMap().issues().asSequence().map { Json.encodeToString(it.toSerializableForm()) }
        }

        val collaboratorClient by lazy { api.collaborator().createClient() }

        mcpTool<GenerateCollaboratorPayload>(
            "Generates a Burp Collaborator payload URL for out-of-band (OOB) testing. " +
            "Inject this payload into requests to detect server-side interactions (DNS lookups, HTTP requests, SMTP). " +
            "Use get_collaborator_interactions with the returned payloadId to check for interactions."
        ) {
            api.logging().logToOutput("MCP generating Collaborator payload${customData?.let { " with custom data" } ?: ""}")

            val payload = if (customData != null) {
                collaboratorClient.generatePayload(customData)
            } else {
                collaboratorClient.generatePayload()
            }

            val server = collaboratorClient.server()
            "Payload: $payload\nPayload ID: ${payload.id()}\nCollaborator server: ${server.address()}"
        }

        mcpTool<GetCollaboratorInteractions>(
            "Polls Burp Collaborator for out-of-band interactions (DNS, HTTP, SMTP). " +
            "Optionally filter by payloadId from generate_collaborator_payload. " +
            "Returns interaction details including type, timestamp, client IP, and protocol-specific data."
        ) {
            api.logging().logToOutput("MCP polling Collaborator interactions${payloadId?.let { " for payload: $it" } ?: ""}")

            val interactions = if (payloadId != null) {
                collaboratorClient.getInteractions(InteractionFilter.interactionIdFilter(payloadId))
            } else {
                collaboratorClient.getAllInteractions()
            }

            if (interactions.isEmpty()) {
                "No interactions detected"
            } else {
                interactions.joinToString("\n\n") {
                    Json.encodeToString(it.toSerializableForm())
                }
            }
        }
    }

    mcpTool<GetProxyHttpHistory>(
        "Displays items within the proxy HTTP history. Optionally filter with a Java regex pattern via the 'regex' param. " +
        "Advanced raw history reader. Explicitly pass limit ≤ 20 and maxBytes ≤ 100000; optional startTimeMs/endTimeMs are accepted for client-side time windows when available. Prefer cached list_proxy_http_history/get_proxy_http_detail."
    ) {
        val allowed = runBlocking {
            checkHistoryPermissionOrDeny(HistoryAccessType.HTTP_HISTORY, config, api, "HTTP history")
        }
        if (!allowed) {
            return@mcpTool "HTTP history access denied by Burp Suite"
        }
        val items = if (regex != null) {
            val compiledRegex = Pattern.compile(regex)
            api.proxy().history { it.contains(compiledRegex) }.asSequence()
                .map { truncateIfNeeded(Json.encodeToString(it.toSerializableForm())) }
        } else {
            api.proxy().history().asSequence()
                .map { truncateIfNeeded(Json.encodeToString(it.toSerializableForm())) }
        }
        limitedRawHistoryResponse(items, offset, limit ?: count, maxBytes)
    }

    mcpTool<GetProxyWebsocketHistory>(
        "Displays items within the proxy WebSocket history. Optionally filter with a Java regex pattern via the 'regex' param. " +
        "Advanced raw history reader. Explicitly pass limit ≤ 20 and maxBytes ≤ 100000; optional startTimeMs/endTimeMs are accepted for client-side time windows when available."
    ) {
        val allowed = runBlocking {
            checkHistoryPermissionOrDeny(HistoryAccessType.WEBSOCKET_HISTORY, config, api, "WebSocket history")
        }
        if (!allowed) {
            return@mcpTool "WebSocket history access denied by Burp Suite"
        }
        val items = if (regex != null) {
            val compiledRegex = Pattern.compile(regex)
            api.proxy().webSocketHistory { it.contains(compiledRegex) }.asSequence()
                .map { truncateIfNeeded(Json.encodeToString(it.toSerializableForm())) }
        } else {
            api.proxy().webSocketHistory().asSequence()
                .map { truncateIfNeeded(Json.encodeToString(it.toSerializableForm())) }
        }
        limitedRawHistoryResponse(items, offset, limit ?: count, maxBytes)
    }

    mcpTool<ListOrganizerItems>(
        "Lists lightweight Organizer summaries. Use get_organizer_item_detail with selected IDs for request/response evidence."
    ) {
        val allowed = runBlocking {
            checkHistoryPermissionOrDeny(HistoryAccessType.ORGANIZER, config, api, "Organizer")
        }
        if (!allowed) return@mcpTool "Organizer access denied by Burp Suite"

        val normalizedQuery = query?.trim()?.takeIf { it.isNotEmpty() }
        val summaries = api.organizer().items().asSequence().map { item ->
            val requestText = item.request()?.toString().orEmpty()
            val requestLine = requestText.lineSequence().firstOrNull().orEmpty().limitOrganizerText(512)
            val notes = item.annotations().notes()?.limitOrganizerText(512)
            OrganizerItemSummary(
                id = item.id(),
                status = item.status().displayName(),
                requestLine = requestLine.value,
                hasResponse = item.response() != null,
                notes = notes?.value,
                requestLineTruncated = requestLine.truncated,
                notesTruncated = notes?.truncated == true
            )
        }.filter { summary ->
            normalizedQuery == null || listOf(summary.status, summary.requestLine, summary.notes.orEmpty())
                .any { it.contains(normalizedQuery, ignoreCase = true) }
        }.drop(offset.coerceAtLeast(0)).take(count.coerceIn(1, 50)).toList()
        Json.encodeToString(summaries)
    }

    mcpTool<GetOrganizerItemDetail>(
        "Gets Organizer items by comma-separated IDs. Bodies are omitted by default; set includeBody=true explicitly when needed."
    ) {
        val allowed = runBlocking {
            checkHistoryPermissionOrDeny(HistoryAccessType.ORGANIZER, config, api, "Organizer")
        }
        if (!allowed) return@mcpTool "Organizer access denied by Burp Suite"

        val requestedIds = ids.split(',').mapNotNull { it.trim().toIntOrNull() }.distinct().take(20)
        if (requestedIds.isEmpty()) return@mcpTool "{\"error\":\"no valid organizer ids\"}"
        val itemById = api.organizer().items().associateBy { it.id() }
        val safeMaxChars = maxChars.coerceIn(1_024, 262_144)
        val details = requestedIds.mapNotNull { id ->
            itemById[id]?.let { item ->
                val request = item.request()?.toString().orEmpty()
                val response = item.response()?.toString().orEmpty()
                val limitedRequest = (if (includeBody) request else omitHttpBody(request))
                    .limitOrganizerText(safeMaxChars)
                val limitedResponse = (if (includeBody) response else omitHttpBody(response))
                    .limitOrganizerText(safeMaxChars)
                val limitedNotes = item.annotations().notes()?.limitOrganizerText(safeMaxChars)
                OrganizerItemDetail(
                    id = item.id(),
                    status = item.status().displayName(),
                    request = limitedRequest.value,
                    response = limitedResponse.value,
                    notes = limitedNotes?.value,
                    bodyIncluded = includeBody,
                    requestTruncated = limitedRequest.truncated,
                    responseTruncated = limitedResponse.truncated,
                    notesTruncated = limitedNotes?.truncated == true
                )
            }
        }
        Json.encodeToString(details)
    }

    mcpTool<SetTaskExecutionEngineState>("Sets the state of Burp's task execution engine (paused or unpaused)") {
        api.burpSuite().taskExecutionEngine().state = if (running) RUNNING else PAUSED

        "Task execution engine is now ${if (running) "running" else "paused"}"
    }

    mcpTool<SetProxyInterceptState>("Enables or disables Burp Proxy Intercept") {
        if (intercepting) {
            api.proxy().enableIntercept()
        } else {
            api.proxy().disableIntercept()
        }

        "Intercept has been ${if (intercepting) "enabled" else "disabled"}"
    }

    mcpTool("get_active_editor_contents", "Outputs the contents of the user's active message editor") {
        getActiveEditor(api)?.text ?: "<No active editor>"
    }

    mcpTool<SetActiveEditorContents>("Sets the content of the user's active message editor") {
        val editor = getActiveEditor(api) ?: return@mcpTool "<No active editor>"

        if (!editor.isEditable) {
            return@mcpTool "<Current editor is not editable>"
        }

        editor.text = text

        "Editor text has been set"
    }

    mcpTool<ManageAutoApproveTargets>(
        "Manages the HTTP request auto-approve list. Future requests to approved targets skip user confirmation. " +
        "action: 'add' (target required, e.g. 'example.com' or '*.example.com:8080'), " +
        "'remove' (target required), 'list' (no target needed), 'clear' (no target needed)."
    ) {
        when (action.lowercase()) {
            "add" -> {
                val t = target ?: return@mcpTool "target is required for 'add' action"
                if (config.addAutoApproveTarget(t)) "Target added to auto-approve list: $t"
                else "Failed to add target (invalid or already in list): $t"
            }
            "remove" -> {
                val t = target ?: return@mcpTool "target is required for 'remove' action"
                if (config.removeAutoApproveTarget(t)) "Target removed from auto-approve list: $t"
                else "Target not found in auto-approve list: $t"
            }
            "list" -> {
                val targets = config.getAutoApproveTargetsList()
                if (targets.isEmpty()) "No auto-approve targets configured"
                else targets.joinToString("\n") { "- $it" }
            }
            "clear" -> {
                config.clearAutoApproveTargets()
                "All auto-approve targets have been cleared"
            }
            else -> "Invalid action: $action. Use 'add', 'remove', 'list', or 'clear'."
        }
    }

    mcpTool("get_export_noise_mode",
        "Returns the current proxy history export noise mode used by the Burp MCP cache. " +
        "Modes: 'off', 'relaxed', 'balanced', 'strict'. Also reports whether exporting is restricted to in-scope requests."
    ) {
        buildString {
            appendLine("mode=${config.exportNoiseMode}")
            appendLine("in_scope_only=${config.exportInScopeOnly}")
            append("description=${config.exportNoiseModeDescription()}")
        }
    }

    mcpTool<SetExportNoiseMode>(
        "Sets the proxy history export noise mode for the Burp MCP cache. " +
        "mode must be one of: 'off', 'relaxed', 'balanced', 'strict'. " +
        "Optional inScopeOnly overrides whether only Burp Scope requests are exported."
    ) {
        val normalizedMode = normalizeExportNoiseMode(mode)
        if (mode.lowercase() !in setOf(
                EXPORT_NOISE_MODE_OFF,
                EXPORT_NOISE_MODE_RELAXED,
                EXPORT_NOISE_MODE_BALANCED,
                EXPORT_NOISE_MODE_STRICT
            )
        ) {
            return@mcpTool "Invalid mode: $mode. Use 'off', 'relaxed', 'balanced', or 'strict'."
        }

        config.exportNoiseMode = normalizedMode
        if (inScopeOnly != null) {
            config.exportInScopeOnly = inScopeOnly
        }

        buildString {
            appendLine("Export noise mode updated.")
            appendLine("mode=${config.exportNoiseMode}")
            appendLine("in_scope_only=${config.exportInScopeOnly}")
            append("description=${config.exportNoiseModeDescription()}")
        }
    }
    }

    mcpTool("get_burp_info",
        "Returns Burp Suite edition, version, and a summary of available MCP tool categories. " +
        "Use this first in a session to understand what capabilities are available. " +
        "Pro-only tools (start_active_scan, get_scanner_issues, generate_collaborator_payload, get_collaborator_interactions) " +
        "are listed separately and only present in Burp Suite Professional. " +
        "Also reports third-party plugin visibility when Burp exposes it or when configured in the MCP UI."
    ) {
        val inventory = collectBurpPluginInventory(api, config.getKnownBurpPluginsList())
        val exporterStats = exporter?.stats
        val diagnostics = database?.let {
            BurpPluginImpactDiagnostics(
                dbStats = it.stats(),
                exporterLastCycleDurationMs = exporterStats?.lastCycleDurationMs,
                exporterHistorySeen = exporterStats?.historySeen,
                exporterNewEntriesSeen = exporterStats?.newEntriesSeen
            )
        }
        buildBurpInfoSummary(api, inventory, diagnostics)
    }
}

fun getActiveEditor(api: MontoyaApi): JTextArea? {
    val frame = api.userInterface().swingUtils().suiteFrame()

    val focusManager = KeyboardFocusManager.getCurrentKeyboardFocusManager()
    val permanentFocusOwner = focusManager.permanentFocusOwner

    val isInBurpWindow = generateSequence(permanentFocusOwner) { it.parent }.any { it == frame }

    return if (isInBurpWindow && permanentFocusOwner is JTextArea) {
        permanentFocusOwner
    } else {
        null
    }
}

interface HttpServiceParams {
    val targetHostname: String
    val targetPort: Int
    val usesHttps: Boolean

    fun toMontoyaService(): HttpService = HttpService.httpService(targetHostname, targetPort, usesHttps)
}

@Serializable
data class SendHttp1Request(
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class SendHttp2Request(
    val pseudoHeaders: Map<String, String>,
    val headers: Map<String, String>,
    val requestBody: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class CreateRepeaterTab(
    val tabName: String? = null,
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class CreateRepeaterTabHttp2(
    val pseudoHeaders: Map<String, String>,
    val headers: Map<String, String>,
    val requestBody: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean,
    val tabName: String? = null
) : HttpServiceParams

@Serializable
data class SendToIntruder(
    val tabName: String? = null,
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class UrlEncode(val content: String)

@Serializable
data class UrlDecode(val content: String)

@Serializable
data class Base64Encode(val content: String)

@Serializable
data class Base64Decode(val content: String)

@Serializable
data class GenerateRandomString(val length: Int, val characterSet: String)

@Serializable
data class SetProjectOptions(val json: String)

@Serializable
data class SetUserOptions(val json: String)

@Serializable
data class SetTaskExecutionEngineState(val running: Boolean)

@Serializable
data class SetProxyInterceptState(val intercepting: Boolean)

@Serializable
data class SetActiveEditorContents(val text: String)

@Serializable
data class GetScannerIssues(override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetProxyHttpHistory(
    val regex: String? = null,
    val limit: Int? = null,
    val maxBytes: Int = RAW_HISTORY_DEFAULT_MAX_BYTES,
    val startTimeMs: Long? = null,
    val endTimeMs: Long? = null,
    override val count: Int = RAW_HISTORY_DEFAULT_LIMIT,
    override val offset: Int = 0
) : Paginated

@Serializable
data class GetProxyWebsocketHistory(
    val regex: String? = null,
    val limit: Int? = null,
    val maxBytes: Int = RAW_HISTORY_DEFAULT_MAX_BYTES,
    val startTimeMs: Long? = null,
    val endTimeMs: Long? = null,
    override val count: Int = RAW_HISTORY_DEFAULT_LIMIT,
    override val offset: Int = 0
) : Paginated

@Serializable
data class ListOrganizerItems(
    val count: Int = 20,
    val offset: Int = 0,
    val query: String? = null
)

@Serializable
data class GetOrganizerItemDetail(
    val ids: String,
    val includeBody: Boolean = false,
    val maxChars: Int = 65_536
)

@Serializable
data class OrganizerItemSummary(
    val id: Int,
    val status: String,
    val requestLine: String,
    val hasResponse: Boolean,
    val notes: String?,
    val requestLineTruncated: Boolean,
    val notesTruncated: Boolean
)

@Serializable
data class OrganizerItemDetail(
    val id: Int,
    val status: String,
    val request: String,
    val response: String,
    val notes: String?,
    val bodyIncluded: Boolean,
    val requestTruncated: Boolean,
    val responseTruncated: Boolean,
    val notesTruncated: Boolean
)

@Serializable
data class GenerateCollaboratorPayload(
    val customData: String? = null
)

@Serializable
data class GetCollaboratorInteractions(
    val payloadId: String? = null
)

@Serializable
data class ManageAutoApproveTargets(
    val action: String,
    val target: String? = null
)

@Serializable
data class SetExportNoiseMode(
    val mode: String,
    val inScopeOnly: Boolean? = null
)
