package org.godotengine.plugin.android.oauth2

import android.util.Log
import androidx.credentials.ClearCredentialStateRequest
import androidx.credentials.CredentialManager
import androidx.credentials.CustomCredential
import androidx.credentials.GetCredentialRequest
import androidx.credentials.GetCredentialResponse
import androidx.credentials.exceptions.GetCredentialCancellationException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.exceptions.NoCredentialException
import com.google.android.libraries.identity.googleid.GetGoogleIdOption
import com.google.android.libraries.identity.googleid.GetSignInWithGoogleOption
import com.google.android.libraries.identity.googleid.GoogleIdTokenCredential
import com.google.android.libraries.identity.googleid.GoogleIdTokenParsingException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import org.godotengine.godot.Godot
import org.godotengine.godot.plugin.GodotPlugin
import org.godotengine.godot.plugin.SignalInfo
import org.godotengine.godot.plugin.UsedByGodot
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64

/**
 * Godot Android OAuth2 Plugin
 *
 * Implements Google Sign-In using Android's Credential Manager API
 * following official Google documentation best practices.
 *
 * @see https://developer.android.com/identity/sign-in/credential-manager-siwg
 */
class GodotAndroidPlugin(godot: Godot): GodotPlugin(godot) {

    companion object {
        private const val TAG = "GodotOAuth2Plugin"
    }

    // Credential Manager instance - initialized lazily with Activity context
    private var credentialManager: CredentialManager? = null

    // Coroutine scope for async operations. SupervisorJob so one failed child
    // doesn't cancel siblings; cancelled in onMainDestroy to avoid leaks across
    // Activity recreation.
    private val coroutineScope = CoroutineScope(SupervisorJob() + Dispatchers.Main)

    // Store the web client ID for fallback retry
    private var currentWebClientId: String? = null

    override fun getPluginName() = BuildConfig.GODOT_PLUGIN_NAME

    override fun onMainDestroy() {
        Log.d(TAG, "onMainDestroy: cancelling coroutine scope")
        super.onMainDestroy()
        coroutineScope.cancel()
        credentialManager = null
    }

    /**
     * Initialize the Credential Manager with proper Activity context.
     * Must be called before any sign-in operations.
     *
     * @return true if initialization successful, false otherwise
     */
    private fun initializeCredentialManager(): Boolean {
        if (credentialManager != null) {
            return true
        }

        val activityContext = activity
        if (activityContext == null) {
            Log.e(TAG, "Activity context is null - cannot initialize CredentialManager")
            return false
        }

        return try {
            // IMPORTANT: Use Activity context, NOT ApplicationContext
            // ApplicationContext can cause issues with the credential dialog
            credentialManager = CredentialManager.create(activityContext)
            Log.d(TAG, "CredentialManager initialized successfully")
            true
        } catch (e: Exception) {
            Log.e(TAG, "Failed to initialize CredentialManager: ${e.localizedMessage}")
            false
        }
    }

    /**
     * Generate a cryptographically secure nonce for token security.
     * The nonce helps prevent replay attacks.
     *
     * @return Base64-encoded SHA-256 hash of random bytes
     */
    private fun generateNonce(): String {
        val randoms = ByteArray(24)
        SecureRandom().nextBytes(randoms)
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(randoms)
        return Base64.getEncoder().encodeToString(hash)
    }

    /**
     * Signs in with Google using the Credential Manager API.
     *
     * This method first attempts to sign in with previously authorized accounts
     * (filterByAuthorizedAccounts=true). If no credentials are found, it
     * automatically falls back to showing all available accounts.
     *
     * Features:
     * - Auto-select enabled for seamless returning user experience
     * - Nonce generation for security
     * - Automatic fallback for new users
     *
     * @param webClientId Your Google OAuth web client ID from Google Cloud Console
     * @return true if sign-in process started successfully, false otherwise
     */
    @UsedByGodot
    fun signInWithGoogle(webClientId: String): Boolean {
        Log.d(TAG, "signInWithGoogle called with client ID: ${webClientId.take(20)}...")

        if (!initializeCredentialManager()) {
            emitSignal("authentication_failed", "Failed to initialize CredentialManager")
            return false
        }

        currentWebClientId = webClientId

        // First attempt: Try with authorized accounts only (for returning users)
        return performGoogleSignIn(
            webClientId = webClientId,
            filterByAuthorizedAccounts = true,
            autoSelectEnabled = true,
            isRetryAttempt = false
        )
    }

    /**
     * Signs in with Google, showing all available accounts (not just authorized ones).
     * Use this for explicit sign-up flows or when you want to always show account picker.
     *
     * @param webClientId Your Google OAuth web client ID
     * @return true if sign-in process started successfully, false otherwise
     */
    @UsedByGodot
    fun signInWithGoogleAllAccounts(webClientId: String): Boolean {
        Log.d(TAG, "signInWithGoogleAllAccounts called")

        if (!initializeCredentialManager()) {
            emitSignal("authentication_failed", "Failed to initialize CredentialManager")
            return false
        }

        currentWebClientId = webClientId

        return performGoogleSignIn(
            webClientId = webClientId,
            filterByAuthorizedAccounts = false,
            autoSelectEnabled = false,
            isRetryAttempt = false
        )
    }

    /**
     * Internal method to perform Google Sign-In with configurable options.
     */
    private fun performGoogleSignIn(
        webClientId: String,
        filterByAuthorizedAccounts: Boolean,
        autoSelectEnabled: Boolean,
        isRetryAttempt: Boolean
    ): Boolean {
        val activityContext = activity
        if (activityContext == null) {
            Log.e(TAG, "Activity context is null")
            emitSignal("authentication_failed", "Activity not available")
            return false
        }

        try {
            // Build Google ID option - no nonce to match original working implementation
            val googleIdOption = GetGoogleIdOption.Builder()
                .setFilterByAuthorizedAccounts(filterByAuthorizedAccounts)
                .setServerClientId(webClientId)
                .setAutoSelectEnabled(autoSelectEnabled)
                .build()

            val request = GetCredentialRequest.Builder()
                .addCredentialOption(googleIdOption)
                .build()

            Log.d(TAG, "Starting credential request (filterByAuthorized=$filterByAuthorizedAccounts, autoSelect=$autoSelectEnabled)")

            coroutineScope.launch {
                try {
                    // Use Activity context (required for auto-select to work)
                    val result = credentialManager!!.getCredential(
                        context = activityContext,
                        request = request
                    )
                    handleSignInResult(result)
                } catch (e: NoCredentialException) {
                    // No credentials found - this is expected for new users
                    Log.d(TAG, "No credentials found: ${e.localizedMessage}")

                    if (!isRetryAttempt && filterByAuthorizedAccounts) {
                        // Fallback: Retry with all accounts for new users
                        Log.d(TAG, "Retrying with all accounts (fallback for new users)")
                        performGoogleSignIn(
                            webClientId = webClientId,
                            filterByAuthorizedAccounts = false,
                            autoSelectEnabled = false,
                            isRetryAttempt = true
                        )
                    } else {
                        emitSignal("authentication_failed", "No Google accounts available. Please add a Google account to your device.")
                    }
                } catch (e: GetCredentialCancellationException) {
                    // User cancelled the sign-in flow
                    Log.d(TAG, "Sign-in cancelled by user")
                    emitSignal("authentication_cancelled", "Sign-in was cancelled")
                } catch (e: GetCredentialException) {
                    // Per Google: only NoCredentialException triggers the
                    // filterByAuthorizedAccounts=false retry. That's caught
                    // above. Any other GetCredentialException subtype (network,
                    // timeout, provider error) must fail straight through —
                    // retrying would re-prompt the user on transient errors.
                    Log.e(TAG, "GetCredentialException: ${e.type} - ${e.localizedMessage}")
                    emitSignal("authentication_failed", e.localizedMessage ?: "Sign-in failed")
                } catch (e: Exception) {
                    Log.e(TAG, "Unexpected error during sign-in: ${e.localizedMessage}")
                    emitSignal("authentication_failed", e.localizedMessage ?: "Unknown error occurred")
                }
            }

            return true
        } catch (e: Exception) {
            Log.e(TAG, "Error setting up sign-in request: ${e.localizedMessage}")
            emitSignal("authentication_failed", e.localizedMessage ?: "Failed to start sign-in")
            return false
        }
    }

    /**
     * Shows the "Sign in with Google" button flow.
     * This provides a more explicit sign-in UI with the Google branding.
     *
     * Note: When using this option, it must be the ONLY credential option in the request.
     *
     * @param webClientId Your Google OAuth web client ID
     * @return true if sign-in process started successfully, false otherwise
     */
    @UsedByGodot
    fun showSignInWithGoogleButton(webClientId: String): Boolean {
        Log.d(TAG, "showSignInWithGoogleButton called")

        if (!initializeCredentialManager()) {
            emitSignal("authentication_failed", "Failed to initialize CredentialManager")
            return false
        }

        val activityContext = activity
        if (activityContext == null) {
            Log.e(TAG, "Activity context is null")
            emitSignal("authentication_failed", "Activity not available")
            return false
        }

        try {
            // GetSignInWithGoogleOption for the branded button flow - no nonce
            val signInWithGoogleOption = GetSignInWithGoogleOption.Builder(webClientId)
                .build()

            // IMPORTANT: This option must be the only one in the request
            val request = GetCredentialRequest.Builder()
                .addCredentialOption(signInWithGoogleOption)
                .build()

            coroutineScope.launch {
                try {
                    val result = credentialManager!!.getCredential(
                        context = activityContext,
                        request = request
                    )
                    handleSignInResult(result)
                } catch (e: GetCredentialCancellationException) {
                    Log.d(TAG, "Sign-in cancelled by user")
                    emitSignal("authentication_cancelled", "Sign-in was cancelled")
                } catch (e: GetCredentialException) {
                    Log.e(TAG, "Sign-in failed: ${e.type} - ${e.localizedMessage}")
                    emitSignal("authentication_failed", e.localizedMessage ?: "Sign-in failed")
                } catch (e: Exception) {
                    Log.e(TAG, "Unexpected error: ${e.localizedMessage}")
                    emitSignal("authentication_failed", e.localizedMessage ?: "Unknown error")
                }
            }

            return true
        } catch (e: Exception) {
            Log.e(TAG, "Error setting up sign-in: ${e.localizedMessage}")
            emitSignal("authentication_failed", e.localizedMessage ?: "Failed to start sign-in")
            return false
        }
    }

    /**
     * Handle the credential response and extract the Google ID token.
     */
    private fun handleSignInResult(result: GetCredentialResponse) {
        val credential = result.credential
        Log.d(TAG, "Received credential of type: ${credential.type}")

        when (credential) {
            is CustomCredential -> {
                if (credential.type == GoogleIdTokenCredential.TYPE_GOOGLE_ID_TOKEN_CREDENTIAL) {
                    try {
                        val googleIdTokenCredential = GoogleIdTokenCredential.createFrom(credential.data)

                        val idToken = googleIdTokenCredential.idToken
                        val displayName = googleIdTokenCredential.displayName ?: ""
                        val email = googleIdTokenCredential.id // This is the email
                        val profilePictureUri = googleIdTokenCredential.profilePictureUri?.toString() ?: ""

                        Log.d(TAG, "Sign-in successful for: $email")
                        Log.d(TAG, "ID Token length: ${idToken.length}")

                        // Emit success with the ID token
                        emitSignal("authentication_completed", idToken)

                        // Also emit detailed user info
                        emitSignal("user_info_received", email, displayName, profilePictureUri)

                    } catch (e: GoogleIdTokenParsingException) {
                        Log.e(TAG, "Failed to parse Google ID token: ${e.localizedMessage}")
                        emitSignal("authentication_failed", "Invalid Google ID token")
                    }
                } else {
                    Log.e(TAG, "Unexpected custom credential type: ${credential.type}")
                    emitSignal("authentication_failed", "Unexpected credential type: ${credential.type}")
                }
            }
            else -> {
                Log.e(TAG, "Unexpected credential class: ${credential.javaClass.simpleName}")
                emitSignal("authentication_failed", "Unsupported credential type")
            }
        }
    }

    /**
     * Signs out the user by clearing the credential state.
     * This notifies credential providers that any stored credential session
     * should be cleared.
     *
     * @return true if sign-out process started successfully
     */
    @UsedByGodot
    fun signOut(): Boolean {
        Log.d(TAG, "signOut called")

        if (!initializeCredentialManager()) {
            emitSignal("sign_out_failed", "CredentialManager not initialized")
            return false
        }

        try {
            coroutineScope.launch {
                try {
                    val clearRequest = ClearCredentialStateRequest()
                    credentialManager!!.clearCredentialState(clearRequest)
                    Log.d(TAG, "Credential state cleared successfully")
                    emitSignal("sign_out_completed")
                } catch (e: Exception) {
                    Log.e(TAG, "Sign-out failed: ${e.localizedMessage}")
                    emitSignal("sign_out_failed", e.localizedMessage ?: "Sign-out failed")
                }
            }
            return true
        } catch (e: Exception) {
            Log.e(TAG, "Error initiating sign-out: ${e.localizedMessage}")
            emitSignal("sign_out_failed", e.localizedMessage ?: "Failed to start sign-out")
            return false
        }
    }

    /**
     * Check if Credential Manager is available on this device.
     *
     * @return true if Credential Manager can be used
     */
    @UsedByGodot
    fun isCredentialManagerAvailable(): Boolean {
        return try {
            initializeCredentialManager()
        } catch (e: Exception) {
            Log.e(TAG, "CredentialManager not available: ${e.localizedMessage}")
            false
        }
    }

    /**
     * Register all signals that this plugin can emit.
     */
    override fun getPluginSignals(): Set<SignalInfo> {
        return setOf(
            // Primary authentication signals
            SignalInfo("authentication_completed", String::class.java),  // idToken
            SignalInfo("authentication_failed", String::class.java),     // errorMessage
            SignalInfo("authentication_cancelled", String::class.java),  // message

            // User info signal (email, displayName, profilePictureUri)
            SignalInfo("user_info_received", String::class.java, String::class.java, String::class.java),

            // Sign-out signals
            SignalInfo("sign_out_completed"),
            SignalInfo("sign_out_failed", String::class.java)  // errorMessage
        )
    }
}
