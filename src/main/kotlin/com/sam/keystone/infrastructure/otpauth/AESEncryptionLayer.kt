package com.sam.keystone.infrastructure.otpauth

import com.sam.keystone.config.models.CodeEncoding
import org.apache.commons.codec.binary.Base32
import org.springframework.stereotype.Component
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.io.encoding.Base64

@Component
class AESEncryptionLayer(private val properties: OTPAuthProperties) {

    private val algorithm = "AES"
    private val transformation = "AES/CBC/PKCS5Padding"

    private val _base32 by lazy { Base32() }

    private val key: SecretKey by lazy {
        val decoded = Base64.decode(properties.aesSecret)
        SecretKeySpec(decoded, 0, decoded.size, algorithm)
    }

    private val iv: IvParameterSpec by lazy {
        val byteArray = ByteArray(16)
        SecureRandom().nextBytes(byteArray)
        IvParameterSpec(byteArray)
    }

    fun encrypt(
        text: String,
        inputEncoding: CodeEncoding = CodeEncoding.BASE_64,
        outputEncoding: CodeEncoding = CodeEncoding.BASE_64,
    ): String {
        val inputBytes = text.toInputBytes(inputEncoding)

        val cipher = Cipher.getInstance(transformation)
        cipher.init(Cipher.ENCRYPT_MODE, key, iv)
        val result = cipher.doFinal(inputBytes)

        return result.toOutputString(outputEncoding)
    }

    fun decrypt(
        text: String,
        inputEncoding: CodeEncoding = CodeEncoding.BASE_64,
        outputEncoding: CodeEncoding = CodeEncoding.BASE_64,
    ): String {
        val inputBytes = text.toInputBytes(inputEncoding)

        val cipher = Cipher.getInstance(transformation)
        cipher.init(Cipher.DECRYPT_MODE, key, iv)
        val result = cipher.doFinal(inputBytes)

        return result.toOutputString(outputEncoding)
    }

    private fun String.toInputBytes(encoding: CodeEncoding): ByteArray {
        return when (encoding) {
            CodeEncoding.BASE_64 -> Base64.decode(this)
            CodeEncoding.BASE_32 -> _base32.decode(this)
            CodeEncoding.HEX_UPPERCASE -> hexToByteArray(HexFormat.UpperCase)
            CodeEncoding.HEX_LOWERCASE -> hexToByteArray(HexFormat.Default)
        }
    }

    private fun ByteArray.toOutputString(encoding: CodeEncoding): String {
        return when (encoding) {
            CodeEncoding.BASE_64 -> Base64.encode(this)
            CodeEncoding.BASE_32 -> _base32.encodeToString(this)
            CodeEncoding.HEX_LOWERCASE -> toHexString(HexFormat.Default)
            CodeEncoding.HEX_UPPERCASE -> toHexString(HexFormat.UpperCase)
        }
    }
}