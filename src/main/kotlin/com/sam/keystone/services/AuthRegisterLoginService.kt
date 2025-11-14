package com.sam.keystone.services

import com.sam.keystone.components.EmailManager
import com.sam.keystone.components.JWTTokenManager
import com.sam.keystone.components.TokenGenerator
import com.sam.keystone.components.UsersTokenManager
import com.sam.keystone.dto.request.LoginUserRequest
import com.sam.keystone.dto.request.RegisterUserRequest
import com.sam.keystone.dto.response.RegisterUserResponseDto
import com.sam.keystone.dto.response.TokenResponseDto
import com.sam.keystone.entity.User
import com.sam.keystone.entity.UserProfile
import com.sam.keystone.entity.UserVerifyInfo
import com.sam.keystone.exceptions.UserAuthException
import com.sam.keystone.exceptions.UserValidationException
import com.sam.keystone.exceptions.UserVerificationException
import com.sam.keystone.repository.UserRepository
import com.sam.keystone.utils.mappers.toReposeDTO
import jakarta.transaction.Transactional
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Service

@Service
class AuthRegisterLoginService(
    private val userRepository: UserRepository,
    private val passwordEncoder: PasswordEncoder,
    private val jwtTokenManager: JWTTokenManager,
    private val usersTokenManager: UsersTokenManager,
    private val emailManager: EmailManager,
    private val tokenGenerator: TokenGenerator,
) {

    @Transactional
    fun createNewUser(request: RegisterUserRequest): RegisterUserResponseDto {
        val probableUser = userRepository.findUserByUserName(request.userName)

        if (probableUser != null) throw UserValidationException("User name is already taken")

        val hash = passwordEncoder.encode(request.password)

        // create a new token
        val randomToken = tokenGenerator.generateRandomToken()
        val tokenHash = tokenGenerator.hashToken(randomToken)

        val newUser = User(
            email = request.email,
            pWordHash = hash,
            userName = request.userName,
        ).apply {
            profile = UserProfile(user = this)
            verifyState = UserVerifyInfo(user = this, isVerified = false, resendKey = tokenHash, isKeyValid = true)
        }

        val user = userRepository.save(newUser)
        // user created
        val verificationToken = usersTokenManager.createVerificationToken(user.id)
        emailManager.sendVerificationEmailHtml(user, verificationToken, "/auth/verify")
        return RegisterUserResponseDto(user = user.toReposeDTO(), resendToken = randomToken)
    }


    @Transactional
    fun loginUser(request: LoginUserRequest): TokenResponseDto {

        val user = userRepository.findUserByUserName(request.userName)
        val foundUser = user ?: throw UserAuthException("Cannot find the given user")

        val passwordSame = passwordEncoder.matches(request.password, foundUser.pWordHash)
        if (!passwordSame) throw UserAuthException("Invalid password")

        // user is not verified
        if (user.verifyState?.isVerified == false)
            throw UserVerificationException("User not verified")

        // so the user exists
        return jwtTokenManager.generateTokenPairs(foundUser)
    }

    @Transactional
    fun deleteUser(userId: Long) {
        val user = userRepository.findUserById(userId) ?: throw UserAuthException("User cannot be deleted")
        userRepository.delete(user)
    }

}