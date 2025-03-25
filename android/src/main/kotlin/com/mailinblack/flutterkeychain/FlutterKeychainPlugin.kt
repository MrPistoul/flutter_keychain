package com.mailinblack.flutterkeychain

import android.annotation.SuppressLint
import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import io.flutter.plugin.common.PluginRegistry.Registrar
import java.math.BigInteger
import java.nio.charset.Charset
import java.security.*
import java.security.spec.AlgorithmParameterSpec
import java.util.*
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import javax.security.auth.x500.X500Principal

interface KeyWrapper {
    @Throws(Exception::class)
    fun wrap(key: Key): ByteArray

    @Throws(Exception::class)
    fun unwrap(wrappedKey: ByteArray, algorithm: String): Key
}

class RsaKeyStoreKeyWrapper(context: Context) : KeyWrapper {

    private val keyAlias: String
    private val context: Context
    private val TYPE_RSA = "RSA"
    private val KEYSTORE_PROVIDER_ANDROID = "AndroidKeyStore"

    init {
        this.keyAlias = context.packageName + ".FlutterKeychain"
        this.context = context
        createRSAKeysIfNeeded()
    }

    @Throws(Exception::class)
    override fun wrap(key: Key): ByteArray {
        val publicKey = getKeyStore().getCertificate(keyAlias)?.publicKey
        val cipher = getRSACipher()
        cipher.init(Cipher.WRAP_MODE, publicKey)
        return cipher.wrap(key)
    }

    @Throws(Exception::class)
    override fun unwrap(wrappedKey: ByteArray, algorithm: String): Key {
        val privateKey = getKeyStore().getKey(keyAlias, null)
        val cipher = getRSACipher()
        cipher.init(Cipher.UNWRAP_MODE, privateKey)

        return cipher.unwrap(wrappedKey, algorithm, Cipher.SECRET_KEY)
    }

    @Throws(Exception::class)
    fun encrypt(input: ByteArray): ByteArray {
        val publicKey = getKeyStore().getCertificate(keyAlias).publicKey
        val cipher = getRSACipher()
        cipher.init(Cipher.ENCRYPT_MODE, publicKey)

        return cipher.doFinal(input)
    }

    @Throws(Exception::class)
    fun decrypt(input: ByteArray): ByteArray {
        val privateKey = getKeyStore().getKey(keyAlias, null)
        val cipher = getRSACipher()
        cipher.init(Cipher.DECRYPT_MODE, privateKey)

        return cipher.doFinal(input)
    }

    @Throws(Exception::class)
    private fun getKeyStore(): KeyStore {
        val ks = KeyStore.getInstance(KEYSTORE_PROVIDER_ANDROID)
        ks.load(null)

        return ks
    }

    @Throws(Exception::class)
    private fun getRSACipher(): Cipher {
        return if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            Cipher.getInstance(
                "RSA/ECB/PKCS1Padding",
                "AndroidOpenSSL"
            ) // error in android 6: InvalidKeyException: Need RSA private or public key
        } else {
            Cipher.getInstance(
                "RSA/ECB/PKCS1Padding",
                "AndroidKeyStoreBCWorkaround"
            ) // error in android 5: NoSuchProviderException: Provider not available: AndroidKeyStoreBCWorkaround
        }
    }

    @Throws(Exception::class)
    private fun createRSAKeysIfNeeded() {
        val ks = KeyStore.getInstance(KEYSTORE_PROVIDER_ANDROID)
        ks.load(null)

        // Added hacks for getting KeyEntry:
        // https://stackoverflow.com/questions/36652675/java-security-unrecoverablekeyexception-failed-to-obtain-information-about-priv
        // https://stackoverflow.com/questions/36488219/android-security-keystoreexception-invalid-key-blob
        var privateKey: PrivateKey? = null
        var publicKey: PublicKey? = null
        for (i in 1..5) {
            try {
                privateKey = ks.getKey(keyAlias, null) as PrivateKey
                publicKey = ks.getCertificate(keyAlias).publicKey
                break
            } catch (ignored: Exception) {
            }
        }

        if (privateKey == null || publicKey == null) {
            createKeys()
            try {
                privateKey = ks.getKey(keyAlias, null) as PrivateKey
                publicKey = ks.getCertificate(keyAlias).publicKey
            } catch (ignored: Exception) {
                ks.deleteEntry(keyAlias)
            }
            if (privateKey == null || publicKey == null) {
                createKeys()
            }
        }
    }

    @SuppressLint("NewApi")
    @Throws(Exception::class)
    private fun createKeys() {
        val start = Calendar.getInstance()
        val end = Calendar.getInstance()
        end.add(Calendar.YEAR, 25)

        val kpGenerator = KeyPairGenerator.getInstance(TYPE_RSA, KEYSTORE_PROVIDER_ANDROID)

        val spec: AlgorithmParameterSpec

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {

            spec = android.security.KeyPairGeneratorSpec.Builder(context)
                .setAlias(keyAlias)
                .setSubject(X500Principal("CN=$keyAlias"))
                .setSerialNumber(BigInteger.valueOf(1))
                .setStartDate(start.time)
                .setEndDate(end.time)
                .build()
        } else {
            spec = KeyGenParameterSpec.Builder(
                keyAlias,
                KeyProperties.PURPOSE_DECRYPT or KeyProperties.PURPOSE_ENCRYPT
            )
                .setCertificateSubject(X500Principal("CN=$keyAlias"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                .setUserAuthenticationRequired(false)
                .setCertificateSerialNumber(BigInteger.valueOf(1))
                .setCertificateNotBefore(start.time)
                .setCertificateNotAfter(end.time)
                .build()
        }
        kpGenerator.initialize(spec)
        kpGenerator.generateKeyPair()
    }

}

interface StringEncryptor {
    @Throws(Exception::class)
    fun encrypt(input: String?): String?

    @Throws(Exception::class)
    fun decrypt(input: String?): String?
}

class AesStringEncryptor
@Throws(Exception::class)
constructor(
    preferences: SharedPreferences,
    keyWrapper: KeyWrapper
) : StringEncryptor {

    // Taille de clé AES (16 bytes = 128 bits)
    private val keySize = 16
    private val KEY_ALGORITHM = "AES"

    // Identifiant de la clé chiffrée (la clé AES) dans SharedPreferences
    private val WRAPPED_AES_KEY_ITEM = "W0n5hlJtrAH0K8mIreDGxtG"

    private val charset: Charset = Charset.forName("UTF-8")
    private val secureRandom: SecureRandom = SecureRandom()

    // -- Paramètres GCM --
    // Taille de l'IV recommandée pour GCM
    private val GCM_IV_SIZE = 12
    // Taille du tag d’authentification (en bits)
    private val GCM_TAG_SIZE = 128

    // La clé AES en clair (mais stockée chiffrée dans le Keystore)
    private var secretKey: Key

    // On instancie le Cipher une seule fois pour AES/GCM/NoPadding
    private val cipher: Cipher = Cipher.getInstance("AES/GCM/NoPadding")

    init {
        val wrappedAesKey = preferences.getString(WRAPPED_AES_KEY_ITEM, null)

        // 1) Si on n’a pas encore de clé AES stockée, on la crée et on l’enregistre dans SharedPreferences (chiffrée avec RSA).
        // 2) Sinon, on la récupère et on la "déchiffre" avec RSA (KeyWrapper).
        if (wrappedAesKey == null) {
            secretKey = createKey(preferences, keyWrapper)
        } else {
            val encryptedAesKeyBytes = Base64.decode(wrappedAesKey, Base64.DEFAULT)
            try {
                secretKey = keyWrapper.unwrap(encryptedAesKeyBytes, KEY_ALGORITHM)
            } catch (ignored: Exception) {
                // En cas d’erreur (clé corrompue ?), on régénère la clé.
                secretKey = createKey(preferences, keyWrapper)
            }
        }
    }

    /**
     * Génère une nouvelle clé AES 128 bits,
     * la chiffre avec RSA et la stocke en base64 dans SharedPreferences.
     */
    private fun createKey(
        preferences: SharedPreferences,
        keyWrapper: KeyWrapper
    ): Key {
        // Génération aléatoire de la clé AES
        val rawKey = ByteArray(keySize)
        secureRandom.nextBytes(rawKey)
        val secretKey = SecretKeySpec(rawKey, KEY_ALGORITHM)

        // Chiffrement de la clé AES via RSA
        val wrappedKey = keyWrapper.wrap(secretKey)
        val wrappedKeyB64 = Base64.encodeToString(wrappedKey, Base64.DEFAULT)

        // Stockage en SharedPreferences
        preferences.edit()
            .putString(WRAPPED_AES_KEY_ITEM, wrappedKeyB64)
            .apply()

        return secretKey
    }

    /**
     * Chiffre la [input] (UTF-8) en AES/GCM.
     * Retourne une chaîne base64 (IV + ciphertext + tag).
     */
    @Throws(Exception::class)
    override fun encrypt(input: String?): String? {
        if (input == null) return null

        // IV de 12 octets recommandé pour GCM
        val iv = ByteArray(GCM_IV_SIZE)
        secureRandom.nextBytes(iv)

        // Configuration de GCM (tag de 128 bits + IV)
        val gcmSpec = GCMParameterSpec(GCM_TAG_SIZE, iv)

        // Initialisation en mode ENCRYPT
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec)

        // On chiffre
        val ciphertextWithTag = cipher.doFinal(input.toByteArray(charset))

        // Concatène IV + ciphertext+tag
        val combined = ByteArray(iv.size + ciphertextWithTag.size)
        System.arraycopy(iv, 0, combined, 0, iv.size)
        System.arraycopy(ciphertextWithTag, 0, combined, iv.size, ciphertextWithTag.size)

        // Encodage final en base64
        return Base64.encodeToString(combined, Base64.DEFAULT)
    }

    /**
     * Déchiffre la [input] base64 (contenant IV + ciphertext + tag) en AES/GCM.
     * Retourne la chaîne UTF-8 déchiffrée.
     */
    @Throws(Exception::class)
    override fun decrypt(input: String?): String? {
        if (input == null) return null

        // Décodage base64
        val allBytes = Base64.decode(input, Base64.DEFAULT)

        if (allBytes.size < GCM_IV_SIZE) {
            // Données invalides
            return null
        }

        // Extraction de l’IV (12 octets)
        val iv = allBytes.copyOfRange(0, GCM_IV_SIZE)

        // Récupération du ciphertext+tag
        val ciphertextWithTag = allBytes.copyOfRange(GCM_IV_SIZE, allBytes.size)

        // Configuration GCM identique à celle utilisée pour encrypt()
        val gcmSpec = GCMParameterSpec(GCM_TAG_SIZE, iv)

        // Initialisation en mode DECRYPT
        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec)

        // Déchiffrement
        val decryptedBytes = cipher.doFinal(ciphertextWithTag)
        return String(decryptedBytes, charset)
    }
}

class FlutterKeychainPlugin : FlutterPlugin, MethodCallHandler {
    private var channel: MethodChannel? = null
    private val WRAPPED_AES_KEY_ITEM = "W0n5hlJtrAH0K8mIreDGxtG"

    companion object {
        private const val channelName = "plugin.appmire.be/flutter_keychain"

        lateinit private var encryptor: StringEncryptor
        lateinit private var preferences: SharedPreferences

        @JvmStatic
        fun registerWith(registrar: Registrar) {

            try {
                preferences = registrar.context()
                    .getSharedPreferences("FlutterKeychain", Context.MODE_PRIVATE)
                encryptor = AesStringEncryptor(
                    preferences = preferences,
                    keyWrapper = RsaKeyStoreKeyWrapper(registrar.context())
                )

                val instance = FlutterKeychainPlugin()
                instance.channel = MethodChannel(registrar.messenger(), channelName)
                instance.channel?.setMethodCallHandler(FlutterKeychainPlugin())
            } catch (e: Exception) {
                Log.e("flutter_keychain", "Could not register plugin", e)
            }
        }
    }

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        preferences =
            binding.applicationContext.getSharedPreferences("FlutterKeychain", Context.MODE_PRIVATE)
        encryptor = AesStringEncryptor(
            preferences = preferences,
            keyWrapper = RsaKeyStoreKeyWrapper(binding.applicationContext)
        )

        channel = MethodChannel(binding.binaryMessenger, channelName)
        channel!!.setMethodCallHandler(this)
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel?.setMethodCallHandler(null)
        channel = null
    }

    fun MethodCall.key(): String? {
        return this.argument("key")
    }

    fun MethodCall.value(): String? {
        return this.argument("value")
    }

    override fun onMethodCall(call: MethodCall, result: Result): Unit {
        try {
            when (call.method) {
                "get" -> {
                    val encryptedValue: String? = preferences.getString(call.key(), null)
                    val value = encryptor.decrypt(encryptedValue)
                    result.success(value)
                }
                "put" -> {
                    val value = encryptor.encrypt(call.value())
                    preferences.edit().putString(call.key(), value).commit()
                    result.success(null)
                }
                "remove" -> {
                    preferences.edit().remove(call.key()).commit()
                    result.success(null)
                }
                "clear" -> {
                    val savedValue: String? = preferences.getString(WRAPPED_AES_KEY_ITEM, null)
                    preferences.edit().clear().commit()
                    preferences.edit().putString(WRAPPED_AES_KEY_ITEM, savedValue).commit()
                    result.success(null)
                }
                else -> result.notImplemented()
            }
        } catch (e: Exception) {
            Log.e("flutter_keychain", e.message ?: e.toString())
            result.error("flutter_keychain", e.message, e)
        }
    }
}
