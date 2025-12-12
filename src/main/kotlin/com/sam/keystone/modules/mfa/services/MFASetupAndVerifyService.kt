package com.sam.keystone.modules.mfa.services

import com.sam.keystone.config.RandomTokenGeneratorConfig
import com.sam.keystone.config.models.CodeEncoding
import com.sam.keystone.infrastructure.otpauth.AESEncryptionLayer
import com.sam.keystone.infrastructure.otpauth.EncodedQRCodeBuilder
import com.sam.keystone.infrastructure.otpauth.OTPAuthProperties
import com.sam.keystone.infrastructure.otpauth.TOTPValidator
import com.sam.keystone.infrastructure.redis.MFATempSecretStore
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
    private val tempSecretStore: MFATempSecretStore,
    private val properties: OTPAuthProperties,
    private val imageBuilder: EncodedQRCodeBuilder,
    private val totpValidator: TOTPValidator,
    private val repository: TOTPRepository,
) {

    fun setup2fa(user: User, includeImage: Boolean = false): MFASetupResponseDto {

        // check if 2fa auth is already setup
        if (user.totpState?.isEnabled == true) throw MFASetupAlreadyDoneException()

        // generate the token
        val secret = tokenGenerator.generateRandomToken(16, CodeEncoding.BASE_32)

        // save the encrypted secret
        val encryptedSecret = encryptor.encrypt(secret, CodeEncoding.BASE_32, CodeEncoding.BASE_64)
        tempSecretStore.saveTempSecret(encryptedSecret, user.id, 2.minutes)

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

        val encryptedSecret = tempSecretStore.getTempSecret(user.id)
            ?: return MFAVerifyResponseDto(isVerified = false, message = "Cannot validate code")

        val base32DecryptedSecret = encryptor.decrypt(
            text = encryptedSecret,
            inputEncoding = CodeEncoding.BASE_64,
            outputEncoding = CodeEncoding.BASE_32
        )

        val isValid = totpValidator.validateTOTP(request.code, base32DecryptedSecret)
        if (!isValid) return MFAVerifyResponseDto(isVerified = false, message = "Cannot validate code")

        // update the secret
        val entity = repository.findTOTPEntityByUser(user) ?: TOTPEntity(user = user)
        entity.totpSecret = base32DecryptedSecret
        repository.save(entity)

        // so the code is valid
        return MFAVerifyResponseDto(isVerified = true, message = "Code validated")
    }

}