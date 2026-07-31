package com.gaugewright.gaugedesk.deviceidentity

import android.app.Activity
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import java.nio.charset.StandardCharsets
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import org.json.JSONArray
import org.json.JSONObject

@InvokeArg
class SignChallengeArgs {
    lateinit var challenge: String
}

@InvokeArg
class StoreMachineCredentialArgs {
    lateinit var endpoint: String
    lateinit var machine: String
    lateinit var grantId: String
    lateinit var credential: String
}

@InvokeArg
class RemoveMachineCredentialArgs {
    lateinit var machine: String
}

@InvokeArg
class StoreAccountSessionArgs {
    lateinit var idToken: String
}

@TauriPlugin
class DeviceIdentityPlugin(private val activity: Activity) : Plugin(activity) {
    private val alias = "com.gaugewright.gaugedesk.device-identity.v1"
    private val vaultAlias = "com.gaugewright.gaugedesk.machine-credential.v1"
    private val preferences = "com.gaugewright.gaugedesk.device-identity"
    private val registryIvKey = "machineCredentialsIv"
    private val registryCiphertextKey = "machineCredentials"
    private val legacyIvKey = "machineCredentialIv"
    private val legacyCiphertextKey = "machineCredential"
    private val accountSessionIvKey = "accountSessionIv"
    private val accountSessionCiphertextKey = "accountSession"

    @Synchronized
    private fun keyStore(): KeyStore {
        val store = KeyStore.getInstance("AndroidKeyStore")
        store.load(null)
        if (!store.containsAlias(alias)) {
            val builder = KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
            )
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setUserAuthenticationRequired(false)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                builder.setUnlockedDeviceRequired(true)
            }
            KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC,
                "AndroidKeyStore",
            ).apply {
                initialize(builder.build())
                generateKeyPair()
            }
            store.load(null)
        }
        return store
    }

    private fun base64Url(bytes: ByteArray): String =
        Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)

    private fun fixed32(value: java.math.BigInteger): ByteArray {
        val encoded = value.toByteArray()
        val unsigned = if (encoded.size > 32) encoded.copyOfRange(encoded.size - 32, encoded.size) else encoded
        return ByteArray(32).also {
            System.arraycopy(unsigned, 0, it, 32 - unsigned.size, unsigned.size)
        }
    }

    private fun compressedSec1(key: ECPublicKey): ByteArray {
        val x = fixed32(key.w.affineX)
        val prefix: Byte = if (key.w.affineY.testBit(0)) 0x03 else 0x02
        return byteArrayOf(prefix) + x
    }

    private fun hex(bytes: ByteArray): String =
        bytes.joinToString(separator = "") { "%02x".format(it.toInt() and 0xff) }

    private fun derLength(bytes: ByteArray, offset: IntArray): Int {
        val first = bytes[offset[0]++].toInt() and 0xff
        if ((first and 0x80) == 0) return first
        val count = first and 0x7f
        require(count in 1..2)
        var length = 0
        repeat(count) {
            length = (length shl 8) or (bytes[offset[0]++].toInt() and 0xff)
        }
        return length
    }

    private fun rawEcdsa(der: ByteArray): ByteArray {
        val offset = intArrayOf(0)
        require((der[offset[0]++].toInt() and 0xff) == 0x30)
        val sequenceLength = derLength(der, offset)
        require(offset[0] + sequenceLength == der.size)
        fun integer(): ByteArray {
            require((der[offset[0]++].toInt() and 0xff) == 0x02)
            val length = derLength(der, offset)
            val encoded = der.copyOfRange(offset[0], offset[0] + length)
            offset[0] += length
            val unsigned = encoded.dropWhile { it == 0.toByte() }.toByteArray()
            require(unsigned.size <= 32)
            return ByteArray(32).also {
                System.arraycopy(unsigned, 0, it, 32 - unsigned.size, unsigned.size)
            }
        }
        return integer() + integer()
    }

    private fun decodeCredential(
        encodedIv: String,
        encodedCiphertext: String,
    ): JSONObject {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(
                Cipher.DECRYPT_MODE,
                vaultKey(),
                GCMParameterSpec(
                    128,
                    Base64.decode(
                        encodedIv,
                        Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP,
                    ),
                ),
            )
        }
        val plaintext = cipher.doFinal(
            Base64.decode(
                encodedCiphertext,
                Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP,
            ),
        )
        return JSONObject(String(plaintext, StandardCharsets.UTF_8))
    }

    private fun credentialRegistry(): MutableMap<String, JSONObject> {
        val prefs = activity.getSharedPreferences(preferences, Activity.MODE_PRIVATE)
        val encodedIv = prefs.getString(registryIvKey, null)
        val encodedCiphertext = prefs.getString(registryCiphertextKey, null)
        if (encodedIv != null && encodedCiphertext != null) {
            val root = decodeCredential(encodedIv, encodedCiphertext)
            require(root.optInt("version") == 1) {
                "unsupported Machine credential registry version"
            }
            val credentials = root.optJSONArray("credentials") ?: JSONArray()
            return buildMap {
                for (index in 0 until credentials.length()) {
                    val credential = credentials.getJSONObject(index)
                    put(credential.getString("machine"), credential)
                }
            }.toMutableMap()
        }

        // Additive, idempotent migration from the v1 singleton. The legacy
        // ciphertext is deleted only after the registry has been durably saved.
        val legacyIv = prefs.getString(legacyIvKey, null)
        val legacyCiphertext = prefs.getString(legacyCiphertextKey, null)
        if (legacyIv != null && legacyCiphertext != null) {
            val credential = decodeCredential(legacyIv, legacyCiphertext)
            val migrated = migrateSingletonCredential(
                emptyMap(),
                credential.getString("machine"),
                credential,
            )
            saveCredentialRegistry(migrated)
            prefs.edit()
                .remove(legacyIvKey)
                .remove(legacyCiphertextKey)
                .commit()
            return migrated.toMutableMap()
        }
        return mutableMapOf()
    }

    private fun saveCredentialRegistry(credentials: Map<String, JSONObject>) {
        val prefs = activity.getSharedPreferences(preferences, Activity.MODE_PRIVATE)
        if (credentials.isEmpty()) {
            prefs.edit()
                .remove(registryIvKey)
                .remove(registryCiphertextKey)
                .commit()
            return
        }
        val entries = JSONArray()
        credentials.toSortedMap().values.forEach(entries::put)
        val plaintext = JSONObject()
            .put("version", 1)
            .put("credentials", entries)
            .toString()
            .toByteArray(StandardCharsets.UTF_8)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(Cipher.ENCRYPT_MODE, vaultKey())
        }
        val encrypted = cipher.doFinal(plaintext)
        check(
            prefs.edit()
                .putString(registryIvKey, base64Url(cipher.iv))
                .putString(registryCiphertextKey, base64Url(encrypted))
                .commit(),
        ) { "could not commit the Machine credential registry" }
    }

    private fun credentialObject(args: StoreMachineCredentialArgs): JSONObject =
        JSONObject()
            .put("endpoint", args.endpoint)
            .put("machine", args.machine)
            .put("grantId", args.grantId)
            .put("credential", args.credential)

    private fun saveAccountSession(idToken: String?) {
        val prefs = activity.getSharedPreferences(preferences, Activity.MODE_PRIVATE)
        if (idToken == null) {
            prefs.edit()
                .remove(accountSessionIvKey)
                .remove(accountSessionCiphertextKey)
                .commit()
            return
        }
        require(idToken.isNotBlank()) { "account session token is empty" }
        val plaintext = JSONObject()
            .put("idToken", idToken)
            .toString()
            .toByteArray(StandardCharsets.UTF_8)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(Cipher.ENCRYPT_MODE, vaultKey())
        }
        val encrypted = cipher.doFinal(plaintext)
        check(
            prefs.edit()
                .putString(accountSessionIvKey, base64Url(cipher.iv))
                .putString(accountSessionCiphertextKey, base64Url(encrypted))
                .commit(),
        ) { "could not commit the account session" }
    }

    private fun accountSession(): String? {
        val prefs = activity.getSharedPreferences(preferences, Activity.MODE_PRIVATE)
        val encodedIv = prefs.getString(accountSessionIvKey, null) ?: return null
        val encodedCiphertext =
            prefs.getString(accountSessionCiphertextKey, null) ?: return null
        return decodeCredential(encodedIv, encodedCiphertext).getString("idToken")
    }

    @Synchronized
    private fun vaultKey(): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        if (!store.containsAlias(vaultAlias)) {
            val builder = KeyGenParameterSpec.Builder(
                vaultAlias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setUserAuthenticationRequired(false)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                builder.setUnlockedDeviceRequired(true)
            }
            KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES,
                "AndroidKeyStore",
            ).apply {
                init(builder.build())
                generateKey()
            }
            store.load(null)
        }
        return store.getKey(vaultAlias, null) as SecretKey
    }

    @Command
    fun getIdentity(invoke: Invoke) {
        try {
            val publicKey = compressedSec1(
                keyStore().getCertificate(alias).publicKey as ECPublicKey,
            )
            val fingerprint = MessageDigest.getInstance("SHA-256").digest(publicKey)
            val result = JSObject()
            result.put("id", "device:${base64Url(fingerprint)}")
            result.put("publicKey", hex(publicKey))
            result.put("algorithm", "ES256")
            invoke.resolve(result)
        } catch (error: Exception) {
            invoke.reject("could not open the device identity: ${error.message}")
        }
    }

    @Command
    fun getLaunchUrl(invoke: Invoke) {
        val result = JSObject()
        result.put("url", activity.intent?.dataString ?: JSONObject.NULL)
        invoke.resolve(result)
    }

    @Command
    fun signChallenge(invoke: Invoke) {
        try {
            val args = invoke.parseArgs(SignChallengeArgs::class.java)
            val privateKey = keyStore().getKey(alias, null)
            val signature = Signature.getInstance("SHA256withECDSA").run {
                initSign(privateKey as java.security.PrivateKey)
                update(args.challenge.toByteArray(StandardCharsets.UTF_8))
                rawEcdsa(sign())
            }
            val result = JSObject()
            result.put("algorithm", "ES256")
            result.put("signature", base64Url(signature))
            invoke.resolve(result)
        } catch (error: Exception) {
            invoke.reject("could not sign the device challenge: ${error.message}")
        }
    }

    @Command
    @Synchronized
    fun storeMachineCredential(invoke: Invoke) {
        try {
            val args = invoke.parseArgs(StoreMachineCredentialArgs::class.java)
            val registry = upsertMachineCredential(
                credentialRegistry(),
                args.machine,
                credentialObject(args),
            )
            saveCredentialRegistry(registry)
            invoke.resolve()
        } catch (error: Exception) {
            invoke.reject("could not store the Machine credential: ${error.message}")
        }
    }

    @Command
    @Synchronized
    fun getMachineCredential(invoke: Invoke) {
        try {
            val credential = credentialRegistry().toSortedMap().values.firstOrNull()
            if (credential == null) {
                invoke.resolve(JSObject().apply { put("credential", JSONObject.NULL) })
                return
            }
            invoke.resolve(JSObject().apply { put("credential", credential) })
        } catch (error: Exception) {
            invoke.reject("could not open the Machine credential: ${error.message}")
        }
    }

    @Command
    @Synchronized
    fun clearMachineCredential(invoke: Invoke) {
        try {
            activity.getSharedPreferences(preferences, Activity.MODE_PRIVATE)
                .edit()
                .remove(registryIvKey)
                .remove(registryCiphertextKey)
                .remove(legacyIvKey)
                .remove(legacyCiphertextKey)
                .commit()
            invoke.resolve()
        } catch (error: Exception) {
            invoke.reject("could not clear the Machine credential: ${error.message}")
        }
    }

    @Command
    @Synchronized
    fun listMachineCredentials(invoke: Invoke) {
        try {
            val entries = JSONArray()
            credentialRegistry().toSortedMap().values.forEach(entries::put)
            invoke.resolve(
                JSObject().apply {
                    put("version", 1)
                    put("credentials", entries)
                },
            )
        } catch (error: Exception) {
            invoke.reject("could not list Machine credentials: ${error.message}")
        }
    }

    @Command
    @Synchronized
    fun removeMachineCredential(invoke: Invoke) {
        try {
            val args = invoke.parseArgs(RemoveMachineCredentialArgs::class.java)
            val registry = removeMachineCredential(
                credentialRegistry(),
                args.machine,
            )
            saveCredentialRegistry(registry)
            invoke.resolve()
        } catch (error: Exception) {
            invoke.reject("could not remove the Machine credential: ${error.message}")
        }
    }

    @Command
    @Synchronized
    fun storeAccountSession(invoke: Invoke) {
        try {
            val args = invoke.parseArgs(StoreAccountSessionArgs::class.java)
            saveAccountSession(args.idToken)
            invoke.resolve()
        } catch (error: Exception) {
            invoke.reject("could not store the account session: ${error.message}")
        }
    }

    @Command
    @Synchronized
    fun getAccountSession(invoke: Invoke) {
        try {
            invoke.resolve(
                JSObject().apply {
                    put("idToken", accountSession() ?: JSONObject.NULL)
                },
            )
        } catch (error: Exception) {
            invoke.reject("could not open the account session: ${error.message}")
        }
    }

    @Command
    @Synchronized
    fun clearAccountSession(invoke: Invoke) {
        try {
            saveAccountSession(null)
            invoke.resolve()
        } catch (error: Exception) {
            invoke.reject("could not clear the account session: ${error.message}")
        }
    }
}
