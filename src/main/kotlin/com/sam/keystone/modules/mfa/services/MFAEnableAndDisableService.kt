package com.sam.keystone.modules.mfa.services

import com.sam.keystone.config.RandomTokenGeneratorConfig
import com.sam.keystone.config.models.CodeEncoding
import com.sam.keystone.infrastructure.otpauth.AESEncryptionLayer
import com.sam.keystone.infrastructure.otpauth.BackupCodeGenerator
import com.sam.keystone.infrastructure.otpauth.TOTPValidator
import com.sam.keystone.modules.mfa.dto.MFADisableRequestDto
import com.sam.keystone.modules.mfa.dto.MFADisableResponseDto
import com.sam.keystone.modules.mfa.dto.MFAEnableResponseDto
import com.sam.keystone.modules.mfa.entity.TOTPBackupCodesEntity
import com.sam.keystone.modules.mfa.exceptions.MFAAlreadyEnabledException
import com.sam.keystone.modules.mfa.exceptions.MFANotEnabledException
import com.sam.keystone.modules.mfa.exceptions.MFASetupIncompleteException
import com.sam.keystone.modules.mfa.exceptions.TOTPCodeInvalidException
import com.sam.keystone.modules.mfa.repository.TOTPBackupCodeRepository
import com.sam.keystone.modules.mfa.repository.TOTPRepository
import com.sam.keystone.modules.user.entity.User
import com.sam.keystone.modules.user.exceptions.UserAuthException
import com.sam.keystone.modules.user.repository.UserRepository
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional

@Service
class MFAEnableAndDisableService(
    private val tokenGenerator: RandomTokenGeneratorConfig,
    private val encryptor: AESEncryptionLayer,
    private val backupCodeGenerator: BackupCodeGenerator,
    private val totpValidator: TOTPValidator,
    private val passwordEncoder: PasswordEncoder,
    private val repository: TOTPRepository,
    private val backupCodeRepository: TOTPBackupCodeRepository,
    private val userRepository: UserRepository,
) {

    @Transactional
    fun enable2FA(user: User): MFAEnableResponseDto {
        // check the pre-conditions
        if (user.totpState?.isEnabled == true) throw MFAAlreadyEnabledException()
        if (user.totpState?.totpSecret == null) throw MFASetupIncompleteException()

        val totp = repository.findTOTPEntityByUser(user) ?: throw MFANotEnabledException()

        // generate the back-up codes
        val backupCodes = List(10) { backupCodeGenerator.generateBackUpCode() }

        // update the fields
        val backupCodesEntities = backupCodes.map {
            TOTPBackupCodesEntity(backUpCode = tokenGenerator.hashToken(it), totp = totp)
        }
        totp.isEnabled = true

        // save the repos
        repository.save(totp)
        backupCodeRepository.saveAll(backupCodesEntities)

        return MFAEnableResponseDto(enabled = true, backupCodes = backupCodes)
    }

    @Transactional
    fun regenerateBackUpCodes(user: User): MFAEnableResponseDto {
        // check the pre-conditions
        if (user.totpState?.isEnabled == false) throw MFANotEnabledException()

        val tOTPEntity = repository.findTOTPEntityByUser(user) ?: throw MFANotEnabledException()

        // re-generate the back-up codes
        val backupCodes = List(10) { backupCodeGenerator.generateBackUpCode() }

        // save the backup codes
        val backupCodesEntities = backupCodes.map {
            val hashedCode = tokenGenerator.hashToken(it, CodeEncoding.HEX_LOWERCASE)
            TOTPBackupCodesEntity(backUpCode = hashedCode, totp = tOTPEntity)
        }

        // delete old back up codes and save the new ones
        val entries = backupCodeRepository.findTOTPBackupCodesEntitiesByTotp(tOTPEntity)
        backupCodeRepository.deleteAll(entries)
        backupCodeRepository.saveAll(backupCodesEntities)

        // mark it as enabled
        tOTPEntity.isEnabled = true
        repository.save(tOTPEntity)

        return MFAEnableResponseDto(enabled = true, backupCodes = backupCodes)
    }

    @Transactional
    fun validateDisableRequest(request: MFADisableRequestDto, user: User): MFADisableResponseDto {
        // match the password
        val passwordSame = passwordEncoder.matches(request.password, user.pWordHash)
        if (!passwordSame) throw UserAuthException("Invalid password")

        // validate incoming code
        val entity = repository.findTOTPEntityByUser(user) ?: throw MFANotEnabledException()

        val base32DecryptedSecret = encryptor.decrypt(
            text = entity.totpSecret,
            inputEncoding = CodeEncoding.BASE_32,
            outputEncoding = CodeEncoding.BASE_32
        )

        // check if it's a totp code otherwise check if this is a back-up code
        val isValid = totpValidator.validateTOTP(request.code, base32DecryptedSecret)
        val requestValidated = if (isValid) true
        else {
            val hash = tokenGenerator.hashToken(request.code, CodeEncoding.HEX_LOWERCASE)
            val foundCode = backupCodeRepository.findTOTPBackupCodesEntityByBackUpCodeAndTotp(hash, entity)
            val isUsedCode = (foundCode?.isUsed) ?: true
            if (foundCode != null && !isUsedCode) {
                // update is used to true
                foundCode.isUsed = true
                backupCodeRepository.save(foundCode)
            }
            foundCode != null && !isUsedCode
        }
        if (!requestValidated) throw TOTPCodeInvalidException()
        // if this is valid delete the entity
        repository.delete(entity)
        return MFADisableResponseDto(isDisabled = true)
    }


    @Transactional
    fun updateTokenVersion(user: User) {
        // cannot modify the user its read only from parameters so we read the user again
        val currentUser = userRepository.findUserById(user.id) ?: throw UserAuthException("User not found")
        currentUser.tokenVersion += 1
        userRepository.save(currentUser)
    }
}