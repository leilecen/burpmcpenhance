package net.portswigger.mcp.providers

import burp.api.montoya.logging.Logging
import io.mockk.every
import io.mockk.mockk
import net.portswigger.mcp.config.McpConfig
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import org.junit.jupiter.api.parallel.ResourceLock
import org.junit.jupiter.api.parallel.Resources
import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.exists
import kotlin.io.path.readText

@ResourceLock(Resources.SYSTEM_PROPERTIES)
class ClaudeDesktopProviderTest {
    @TempDir
    lateinit var tempHome: Path

    @Test
    fun `install should prefer an existing store config over an empty traditional directory`() {
        val originalHome = System.getProperty("user.home")
        val originalOs = System.getProperty("os.name")
        val traditionalDir = tempHome.resolve("AppData/Roaming/Claude")
        val storeDir = tempHome.resolve("AppData/Local/Packages/Claude_test/LocalCache/Roaming/Claude")
        val storeConfig = storeDir.resolve("claude_desktop_config.json")
        Files.createDirectories(traditionalDir)
        Files.createDirectories(storeDir)
        Files.writeString(storeConfig, """{"mcpServers":{"existing":{"command":"keep"}}}""")

        val logging = mockk<Logging>(relaxed = true)
        val proxyJarManager = mockk<ProxyJarManager>()
        val config = mockk<McpConfig>()
        every { proxyJarManager.getProxyJar() } returns tempHome.resolve("mcp-proxy-all.jar")
        every { config.host } returns "127.0.0.1"
        every { config.port } returns 9876

        try {
            System.setProperty("user.home", tempHome.toString())
            System.setProperty("os.name", "Windows 11")

            ClaudeDesktopProvider(logging, proxyJarManager).install(config)

            val updatedStoreConfig = storeConfig.readText()
            assertTrue(updatedStoreConfig.contains("\"existing\""), updatedStoreConfig)
            assertTrue(updatedStoreConfig.contains("\"burp\""), updatedStoreConfig)
            assertFalse(traditionalDir.resolve("claude_desktop_config.json").exists())
        } finally {
            System.setProperty("user.home", originalHome)
            System.setProperty("os.name", originalOs)
        }
    }

    @Test
    fun `install should keep traditional config priority when both configs exist`() {
        val originalHome = System.getProperty("user.home")
        val originalOs = System.getProperty("os.name")
        val traditionalConfig = tempHome.resolve("AppData/Roaming/Claude/claude_desktop_config.json")
        val storeConfig = tempHome.resolve(
            "AppData/Local/Packages/Claude_test/LocalCache/Roaming/Claude/claude_desktop_config.json"
        )
        Files.createDirectories(traditionalConfig.parent)
        Files.createDirectories(storeConfig.parent)
        Files.writeString(traditionalConfig, """{"mcpServers":{"traditional":{"command":"keep"}}}""")
        Files.writeString(storeConfig, """{"mcpServers":{"store":{"command":"keep"}}}""")

        val logging = mockk<Logging>(relaxed = true)
        val proxyJarManager = mockk<ProxyJarManager>()
        val config = mockk<McpConfig>()
        every { proxyJarManager.getProxyJar() } returns tempHome.resolve("mcp-proxy-all.jar")
        every { config.host } returns "127.0.0.1"
        every { config.port } returns 9876

        try {
            System.setProperty("user.home", tempHome.toString())
            System.setProperty("os.name", "Windows 11")

            ClaudeDesktopProvider(logging, proxyJarManager).install(config)

            assertTrue(traditionalConfig.readText().contains("\"burp\""))
            assertFalse(storeConfig.readText().contains("\"burp\""))
        } finally {
            System.setProperty("user.home", originalHome)
            System.setProperty("os.name", originalOs)
        }
    }

    @Test
    fun `install should fail when no Claude config directory exists`() {
        val originalHome = System.getProperty("user.home")
        val originalOs = System.getProperty("os.name")
        val logging = mockk<Logging>(relaxed = true)
        val proxyJarManager = mockk<ProxyJarManager>()
        val config = mockk<McpConfig>()
        every { proxyJarManager.getProxyJar() } returns tempHome.resolve("mcp-proxy-all.jar")

        try {
            System.setProperty("user.home", tempHome.toString())
            System.setProperty("os.name", "Windows 11")

            val error = assertThrows(IllegalStateException::class.java) {
                ClaudeDesktopProvider(logging, proxyJarManager).install(config)
            }
            assertTrue(error.message.orEmpty().contains("Could not find Claude config path"))
        } finally {
            System.setProperty("user.home", originalHome)
            System.setProperty("os.name", originalOs)
        }
    }
}
