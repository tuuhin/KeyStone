package com.sam.keystone.modules.user.service

import com.sam.keystone.config.RandomTokenGeneratorConfig
import com.sam.keystone.config.models.CodeEncoding
import com.sam.keystone.infrastructure.email.EmailSenderService
import com.sam.keystone.infrastructure.redis.UserPWordResetStore
import com.sam.keystone.modules.user.dto.request.ChangePasswordRequest
import com.sam.keystone.modules.user.dto.request.ResetPasswordRequest
import com.sam.keystone.modules.user.entity.User
import com.sam.keystone.modules.user.exceptions.UserAuthException
import com.sam.keystone.modules.user.exceptions.UserValidationException
import com.sam.keystone.modules.user.repository.UserRepository
import com.sam.keystone.modules.user.utils.validator.PasswordValidator
import com.sam.keystone.security.exception.TooManyRequestException
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.time.Instant
import kotlin.time.Duration
import kotlin.time.Duration.Companion.hours

@Service
class UserPasswordManagementService(
    private val tokenGenerator: RandomTokenGeneratorConfig,
    private val pWordEncoder: PasswordEncoder,
    private val userRepository: UserRepository,
    private val emailSenderService: EmailSenderService,
    private val tokenStore: UserPWordResetStore,
    private val pWordValidator: PasswordValidator,
) {

    fun changeCurrentUserPassword(request: ChangePasswordRequest, user: User, validateStrength: Boolean = false) {
        // validate old password
        val isSame = pWordEncoder.matches(request.oldPassword, user.pWordHash)
        if (!isSame) throw UserAuthException("Invalid credentials cannot continue")

        if (validateStrength) pWordValidator.validate(request.newPassword)

        // update the new hashed password
        val newHashedPWord = pWordEncoder.encode(request.newPassword)
        user.pWordHash = newHashedPWord
        user.pWordUpdateAt = Instant.now()
        user.tokenVersion++
        userRepository.save(user)
    }

    @Transactional
    fun sendPasswordResetRequest(request: ResetPasswordRequest, expiry: Duration = 2.hours, maxRequest: Int = 5) {

        // find the associated user
        val userId = userRepository.findUserIDByEmailAndUsername(request.email, request.userName)
            ?: return

        // check the request count
        val canRequest = tokenStore.requestCount(request.userName, maxRequest)
        if (!canRequest) throw TooManyRequestException("Cannot request more than $maxRequest in a day")

        // generate token and save it
        val token = tokenGenerator.generateRandomToken(32, CodeEncoding.HEX_LOWERCASE)
        val tokenHash = tokenGenerator.hashToken(token)

        // save the token
        tokenStore.saveToken(tokenHash, userId = userId, expiry = expiry)
        // send the email update mail
        emailSenderService.sendResetPasswordEmail(request.email, token)
    }


    @Transactional
    fun confirmPasswordChange(token: String, newPassword: String, validateStrength: Boolean = false) {

        val tokenHash = tokenGenerator.hashToken(token)
        val userId = tokenStore.getResetTokenData(tokenHash = tokenHash, deleteWhenDone = true)
            ?: throw UserValidationException("Cannot validate the given token")

        val user = userRepository.findUserById(userId)
            ?: throw UserValidationException("Cannot validate the given token")

        if (validateStrength) pWordValidator.validate(newPassword)

        val newHashedPWord = pWordEncoder.encode(newPassword)
        user.pWordHash = newHashedPWord
        user.pWordUpdateAt = Instant.now()
        user.tokenVersion++
        userRepository.save(user)
    }
}