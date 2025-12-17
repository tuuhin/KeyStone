package com.sam.keystone.modules.user.service

import com.sam.keystone.config.RandomTokenGeneratorConfig
import com.sam.keystone.config.models.CodeEncoding
import com.sam.keystone.infrastructure.email.EmailSenderService
import com.sam.keystone.infrastructure.redis.UserEmailUpdateTokenStore
import com.sam.keystone.infrastructure.redis.models.EmailUpdateData
import com.sam.keystone.modules.user.dto.request.UpdateEmailRequest
import com.sam.keystone.modules.user.entity.User
import com.sam.keystone.modules.user.exceptions.UserAuthException
import com.sam.keystone.modules.user.exceptions.UserValidationException
import com.sam.keystone.modules.user.repository.UserRepository
import com.sam.keystone.modules.user.repository.UserVerificationRepository
import com.sam.keystone.security.exception.TooManyRequestException
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.time.Instant
import kotlin.time.Duration
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.minutes
import kotlin.time.toJavaDuration

@Service
class UserUpdateEmailService(
    private val tokenGenerator: RandomTokenGeneratorConfig,
    private val userRepository: UserRepository,
    private val userVerifyRepo: UserVerificationRepository,
    private val pWordEncoder: PasswordEncoder,
    private val emailSenderService: EmailSenderService,
    private val tokenManager: UserEmailUpdateTokenStore,
) {

    @Transactional
    fun updateEmailAddressAndVerify(request: UpdateEmailRequest, user: User, expiry: Duration = 6.hours) {
        // validate user
        val isSame = pWordEncoder.matches(request.password, user.pWordHash)
        if (!isSame) throw UserAuthException("Invalid credentials cannot continue")

        // add the pending email and
        val verifyInfo = userVerifyRepo.findUserVerifyInfoByUser(user)
            ?: throw UserAuthException("Invalid verification state")

        // check if the current email and pending email are similar and there is no pending email set earlier
        if (user.email == request.email) throw UserValidationException("Using the same email cannot do anything")
        val pendingExpiry = user.verifyState?.pendingEmailExpiry
        if (pendingExpiry != null && pendingExpiry.isAfter(Instant.now()))
            throw UserValidationException("Cannot create a new request pending email is not validated yet")

        verifyInfo.pendingEmail = request.email
        verifyInfo.pendingEmailExpiry = Instant.now().plus(expiry.toJavaDuration())
        // update the verify info
        userVerifyRepo.save(verifyInfo)

        // generate token and save it
        val token = tokenGenerator.generateRandomToken(32)
        val tokenHash = tokenGenerator.hashToken(token, CodeEncoding.HEX_LOWERCASE)

        val normalizedEmail = request.email.trim().lowercase()
        // save the token
        val saveData = EmailUpdateData(userId = user.id, tokenGenerator.hashToken(normalizedEmail))
        tokenManager.saveToken(tokenHash, saveData, expiry = expiry)

        // send the email update mail
        emailSenderService.sendUserEmailChangeMail(user, request.email, tokenHash)
    }


    @Transactional
    fun verifyUpdateEmailRequest(token: String) {

        val tokenData =
            tokenManager.getEmailUpdateData(token, true)
                ?: throw UserValidationException("Cannot validate the given token")

        val user = userRepository.findUserById(tokenData.userId)
            ?: throw UserValidationException("Cannot validate the given token")

        val verifyInfo = userVerifyRepo.findUserVerifyInfoByUser(user)
            ?: throw UserAuthException("Invalid State")

        val pendingEmailExpiry =
            verifyInfo.pendingEmailExpiry ?: throw UserValidationException("No update email request was made")
        val pendingEmail = verifyInfo.pendingEmail ?: throw UserValidationException("No update email request was made")

        val normalizedEmail = pendingEmail.trim().lowercase()
        if (tokenGenerator.hashToken(normalizedEmail) != tokenData.meta) throw UserValidationException("Cannot validate the associated token")

        if (pendingEmailExpiry.isBefore(Instant.now())) {
            // cleaning the pending email column
            cleanUpPendingEmail(user)
            throw UserValidationException("Cannot update the email any more, request too late")
        }

        // set pending email to current email
        user.email = verifyInfo.pendingEmail ?: user.email
        user.tokenVersion++
        userRepository.save(user)

        // clear fields in verify info
        cleanUpPendingEmail(user)
    }

    fun cancelEmailUpdateRequest(user: User) {
        val verifyInfo = user.verifyState ?: return

        if (verifyInfo.pendingEmail == null)
            throw UserValidationException("No email change request were made earlier")

        // cleaning the pending email column
        verifyInfo.pendingEmail = null
        verifyInfo.pendingEmailExpiry = null
        userVerifyRepo.save(verifyInfo)

        tokenManager.deleteSaveDataViaUserId(user.id)
    }

    private fun cleanUpPendingEmail(user: User) {
        val verifyInfo = user.verifyState ?: return
        verifyInfo.pendingEmail = null
        verifyInfo.pendingEmailExpiry = null
        userVerifyRepo.save(verifyInfo)
    }

    fun resendEmailVerificationRequest(user: User, expiry: Duration = 5.minutes, maximumRequestPerDay: Int = 3) {

        val verifyInfo = user.verifyState ?: return
        val pendingEmail = verifyInfo.pendingEmail
            ?: throw UserValidationException("No email change request were made earlier")

        val isValid = tokenManager.updateSendCount(user.id, maximumRequestPerDay)
        if (!isValid) throw TooManyRequestException("Cannot send more than $maximumRequestPerDay in a day")

        // generate token and save it
        val token = tokenGenerator.generateRandomToken(32)
        val tokenHash = tokenGenerator.hashToken(token, CodeEncoding.HEX_LOWERCASE)

        val normalizedEmail = pendingEmail.trim().lowercase()
        // save the token
        val saveData = EmailUpdateData(userId = user.id, tokenGenerator.hashToken(normalizedEmail))
        tokenManager.saveToken(tokenHash, saveData, expiry = expiry)

        // send the email update mail
        emailSenderService.sendUserEmailChangeMail(user, pendingEmail, tokenHash)
    }
}