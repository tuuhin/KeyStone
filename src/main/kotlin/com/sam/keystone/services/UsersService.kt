package com.sam.keystone.services

import com.sam.keystone.components.EmailManager
import com.sam.keystone.components.JWTTokenManager
import com.sam.keystone.components.TokenBlackListManager
import com.sam.keystone.components.UsersTokenManager
import com.sam.keystone.dto.request.LoginUserRequest
import com.sam.keystone.dto.request.RefreshTokenRequest
import com.sam.keystone.dto.request.RegisterUserRequest
import com.sam.keystone.dto.response.TokenResponseDto
import com.sam.keystone.entity.User
import com.sam.keystone.entity.UserProfile
import com.sam.keystone.exceptions.TooManyRequestException
import com.sam.keystone.exceptions.UserAuthException
import com.sam.keystone.exceptions.UserValidationException
import com.sam.keystone.exceptions.UserVerificationException
import com.sam.keystone.models.JWTTokenType
import com.sam.keystone.repository.UserRepository
import jakarta.transaction.Transactional
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Service

@Service
class UsersService(
    private val repository: UserRepository,
    private val passwordEncoder: PasswordEncoder,
    private val tokenManager: JWTTokenManager,
    private val blackListManager: TokenBlackListManager,
    private val usersTokenManager: UsersTokenManager,
    private val emailManager: EmailManager,
) {

    @Transactional
    fun createNewUser(request: RegisterUserRequest): User {
        val probableUser = repository.findUserByUserName(request.userName)

        if (probableUser != null) throw UserValidationException("User name is already taken")

        val hash = passwordEncoder.encode(request.password)

        val newUser = User(
            email = request.email,
            pWordHash = hash,
            userName = request.userName,
            isVerified = false
        ).apply {
            profile = UserProfile(user = this)
        }

        val user = repository.save(newUser)
        // user created
        val verificationToken = usersTokenManager.createVerificationToken(user.id)
        emailManager.sendVerificationEmailHtml(user, verificationToken)

        return user
    }


    @Transactional
    fun loginUser(request: LoginUserRequest): TokenResponseDto {

        val user = repository.findUserByUserName(request.userName)
        val foundUser = user ?: throw UserAuthException("Cannot find the given user")

        val passwordSame = passwordEncoder.matches(request.password, foundUser.pWordHash)
        if (!passwordSame) throw UserAuthException("Invalid password")

        if (!user.isVerified) throw UserVerificationException("User not verified")

        // so the user exists
        return tokenManager.generateTokenPairs(foundUser)
    }

    @Transactional
    fun verifyRegisterToken(token: String): User {
        val userId = usersTokenManager.validateVerificationToken(token, deleteWhenDone = true)
            ?: throw UserValidationException("Cannot verify the given token")

        val user = repository.findUserById(userId)
            ?: throw UserValidationException("Cannot find the associated user")

        val updatedUser = user.apply { isVerified = true }
        return repository.save(updatedUser)
    }

    @Transactional
    fun resendEmail(request: LoginUserRequest) {
        val user = repository.findUserByUserName(request.userName) ?: return

        val passwordSame = passwordEncoder.matches(request.password, user.pWordHash)
        if (!passwordSame) return

        // so this is the correct user
        if (user.isVerified) throw UserVerificationException("User is already verified")

        if (usersTokenManager.isVerificationEmailLimitActive(user.id))
            throw TooManyRequestException("Cannot resend email this soon try later")
        // delete the earlier tokens
        usersTokenManager.deleteUserTokens(user.id)

        val verificationToken = usersTokenManager.createVerificationToken(user.id, setRateLimit = true)
        emailManager.sendVerificationEmailHtml(user, verificationToken)
    }


    fun generateNewTokenPairs(request: RefreshTokenRequest, currentUser: User): TokenResponseDto {
        val (userId, expireAfter) = tokenManager.validateToken(request.token, type = JWTTokenType.REFRESH_TOKEN)
            ?: throw UserAuthException("Refresh Token expired or invalid")

        if (userId != currentUser.id) throw UserAuthException("Invalid account access request")

        if (blackListManager.isBlackListed(request.token))
            throw UserAuthException("Refresh token blacklisted")

        // add the item to the blacklist so it cannot be used anymore
        blackListManager.addToBlackList(request.token, expireAfter)

        // create a new token pair
        val user = repository.findUserById(userId) ?: throw UserAuthException("Cannot find user")
        return tokenManager.generateTokenPairs(user)
    }

    fun blackListToken(request: RefreshTokenRequest) {
        val (_, expireAfter) = tokenManager.validateToken(request.token, type = JWTTokenType.REFRESH_TOKEN)
            ?: throw UserAuthException("Refresh Token expired or invalid")

        // add the item to the blacklist so it cannot be used anymore
        if (blackListManager.isBlackListed(request.token)) return
        blackListManager.addToBlackList(request.token, expireAfter)
    }
}