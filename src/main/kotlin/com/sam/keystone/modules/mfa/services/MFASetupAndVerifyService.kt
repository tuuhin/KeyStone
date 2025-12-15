package com.sam.keystone.modules.mfa.services

import com.sam.keystone.config.RandomTokenGeneratorConfig
import com.sam.keystone.config.models.CodeEncoding
import com.sam.keystone.infrastructure.otpauth.AESEncryptionLayer
import com.sam.keystone.infrastructure.otpauth.EncodedQRCodeBuilder
import com.sam.keystone.infrastructure.otpauth.OTPAuthProperties
import com.sam.keystone.infrastructure.otpauth.TOTPValidator
import com.sam.keystone.infrastructure.redis.MFASecretStore
import com.sam.keystone.modules.mfa.dto.MFACodeRequestDto
import com.sam.keystone.modules.mfa.dto.MFASetupResponseDto
import com.sam.keystone.modules.mfa.dto.MFAVerifyResponseDto
import com.sam.keystone.modules.mfa.entity.TOTPEntity
import com.sam.keystone.modules.mfa.exceptions.MFASetupAlreadyDoneException
import com.sam.keystone.modules.mfa.repository.TOTPRepository
import com.sam.keystone.modules.user.entity.User
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.net.URLEncoder
import kotlin.time.Duration.Companion.minutes

@Service
class MFASetupAndVerifyService(
    private val tokenGenerator: RandomTokenGeneratorConfig,
    private val encryptor: AESEncryptionLayer,
    private val tempSecretStore: MFASecretStore,
    private val properties: OTPAuthProperties,
    private val imageBuilder: EncodedQRCodeBuilder,
    private val totpValidator: TOTPValidator,
    private val repository: TOTPRepository,
) {

    @Transactional
    fun setup2fa(user: User, includeImage: Boolean = false): MFASetupResponseDto {

        // check if 2fa auth is already setup
        if (user.totpState?.isEnabled == true) throw MFASetupAlreadyDoneException()
        val inputEncoding = CodeEncoding.BASE_32
        // generate the token
        val secret = tokenGenerator.generateRandomToken(16, inputEncoding)

        // save the encrypted secret as base64
        val encryptedSecret = encryptor.encrypt(secret, inputEncoding, CodeEncoding.BASE_64)
        tempSecretStore.saveTempSetupSecret(encryptedSecret, user.id, 2.minutes)

        val encodedIssuer = URLEncoder.encode(properties.issuer, Charsets.UTF_8)
        val encodedUserName = URLEncoder.encode(user.username, Charsets.UTF_8)
        // now build the uri
        val queryParams = buildMap {
            put("secret", secret)
            put("issuer", encodedIssuer)
            put("digits", "6")
            put("period", "30")
        }

        val otpAuthURL = buildString {
            append("otpauth://totp/")
            append(encodedIssuer)
            append(":")
            append(encodedUserName)
            append("?")
            queryParams.toList().forEachIndexed { index, (key, value) ->
                append("$key=$value")
                if (index + 1 != queryParams.size) append("&")
            }
        }
        // build the qr code
        val qr = if (includeImage) imageBuilder.base64EncodedImage(otpAuthURL) else null

        return MFASetupResponseDto(secret = secret, otpAuthUrl = otpAuthURL, encodedCode = qr)
    }

    @Transactional
    fun verify2FACode(request: MFACodeRequestDto, user: User): MFAVerifyResponseDto {

        // check if 2fa auth is already setup
        if (user.totpState?.isEnabled == true) throw MFASetupAlreadyDoneException()

        val encryptedSecret = tempSecretStore.getTempSetupSecret(user.id)
            ?: return MFAVerifyResponseDto(isVerified = false, message = "Cannot validate secret code")

        val base32DecryptedSecret = encryptor.decrypt(
            text = encryptedSecret,
            inputEncoding = CodeEncoding.BASE_64,
            outputEncoding = CodeEncoding.BASE_32
        )

        val isValid = totpValidator.validateTOTP(request.code, base32DecryptedSecret)
        if (!isValid) return MFAVerifyResponseDto(isVerified = false, message = "Cannot validate code")

        // reencrypt it into base32
        val base32EncryptedSecret = encryptor.encrypt(
            text = base32DecryptedSecret,
            inputEncoding = CodeEncoding.BASE_32,
            outputEncoding = CodeEncoding.BASE_32
        )

        return try {
            // update the secret
            val entity = repository.findTOTPEntityByUser(user) ?: TOTPEntity(user = user)
            entity.totpSecret = base32EncryptedSecret
            repository.save(entity)

            // so the code is valid
            MFAVerifyResponseDto(isVerified = true, message = "Code validated")
        } finally {
            tempSecretStore.deleteTempSetupSecret(user.id)
        }
    }

}