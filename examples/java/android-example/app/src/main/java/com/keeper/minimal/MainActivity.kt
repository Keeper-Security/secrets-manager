package com.keeper.minimal

import android.os.Bundle
import android.util.Log
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.keepersecurity.secretsManager.core.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.serialization.ExperimentalSerializationApi
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security

/**
 * MINIMAL WORKING EXAMPLE
 *
 * This is the simplest possible Android app using the KSM Java SDK.
 * It demonstrates that the SDK CAN work on Android as-is with minimal changes.
 *
 * What works:
 * ✅ InMemoryStorage (no file I/O issues)
 * ✅ Background threading (no ANR)
 * ✅ All crypto operations
 * ✅ Network communication
 *
 * What's minimal:
 * - Uses InMemoryStorage (config not persisted)
 * - Uses default HttpsURLConnection (not optimized but works)
 * - Simple UI (no fancy compose)
 * - Minimal error handling
 *
 * This proves: SDK works on Android with proper threading!
 */
@ExperimentalSerializationApi
class MainActivity : AppCompatActivity() {

    private lateinit var tokenInput: EditText
    private lateinit var initButton: Button
    private lateinit var loadButton: Button
    private lateinit var statusText: TextView
    private lateinit var resultsText: TextView

    // Use InMemoryStorage to avoid file I/O issues
    private val storage = InMemoryStorage()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Register BouncyCastle security provider for EC crypto
        // Remove existing BC provider if present, then add ours
        Security.removeProvider("BC")
        Security.insertProviderAt(BouncyCastleProvider(), 1)

        Log.d("KSM_MINIMAL", "BouncyCastle registered. Available providers: ${Security.getProviders().joinToString { it.name }}")

        setContentView(R.layout.activity_main)

        // Find views
        tokenInput = findViewById(R.id.tokenInput)
        initButton = findViewById(R.id.initButton)
        loadButton = findViewById(R.id.loadButton)
        statusText = findViewById(R.id.statusText)
        resultsText = findViewById(R.id.resultsText)

        // Setup click listeners
        initButton.setOnClickListener {
            val token = tokenInput.text.toString()
            if (token.isNotBlank()) {
                initializeKsm(token)
            } else {
                statusText.text = "❌ Please enter a token"
            }
        }

        loadButton.setOnClickListener {
            loadSecrets()
        }

        // Disable load button until initialized
        loadButton.isEnabled = false
    }

    /**
     * Initialize KSM with one-time token.
     * MUST run on background thread to avoid blocking UI.
     */
    private fun initializeKsm(token: String) {
        // Disable buttons during operation
        setButtonsEnabled(false)
        statusText.text = "⏳ Initializing..."
        resultsText.text = ""

        // Use lifecycleScope for coroutine
        lifecycleScope.launch {
            try {
                // Switch to IO dispatcher for network/crypto operations
                withContext(Dispatchers.IO) {
                    // This is the actual SDK call - works as-is!
                    initializeStorage(storage, token)

                    Log.d("KSM_MINIMAL", "Initialization successful")
                }

                // Back on main thread - update UI
                statusText.text = "✅ Initialized successfully!\nNow tap 'Load Secrets'"
                loadButton.isEnabled = true
                initButton.isEnabled = true

            } catch (e: Exception) {
                // Handle errors
                Log.e("KSM_MINIMAL", "Initialization failed", e)
                statusText.text = "❌ Error: ${e.message}"
                initButton.isEnabled = true
            }
        }
    }

    /**
     * Load secrets from Keeper.
     * Also MUST run on background thread.
     */
    private fun loadSecrets() {
        setButtonsEnabled(false)
        statusText.text = "⏳ Loading secrets..."
        resultsText.text = ""

        lifecycleScope.launch {
            try {
                // Switch to IO dispatcher
                val secrets = withContext(Dispatchers.IO) {
                    // Create options with our storage
                    val options = SecretsManagerOptions(storage)

                    // This is the actual SDK call - works as-is!
                    getSecrets(options)
                }

                Log.d("KSM_MINIMAL", "Loaded ${secrets.records.size} secrets")

                // Build results string
                val results = buildString {
                    appendLine("📊 Found ${secrets.records.size} secret(s):")
                    appendLine()

                    secrets.records.forEachIndexed { index, record ->
                        appendLine("${index + 1}. ${record.data.title ?: "Untitled"}")
                        appendLine("   Type: ${record.data.type}")
                        appendLine("   UID: ${record.recordUid}")

                        // Try to get password
                        try {
                            val password = record.getPassword()
                            if (password != null) {
                                appendLine("   Password: ${password.take(3)}***")
                            }
                        } catch (e: Exception) {
                            appendLine("   (no password)")
                        }
                        appendLine()
                    }
                }

                // Update UI on main thread
                statusText.text = "✅ Secrets loaded successfully!"
                resultsText.text = results
                setButtonsEnabled(true)

            } catch (e: Exception) {
                Log.e("KSM_MINIMAL", "Load failed", e)
                statusText.text = "❌ Error: ${e.message}"
                setButtonsEnabled(true)
            }
        }
    }

    private fun setButtonsEnabled(enabled: Boolean) {
        initButton.isEnabled = enabled
        loadButton.isEnabled = enabled && storage.getString("clientId") != null
    }
}
