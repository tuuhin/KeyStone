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
import com.sam.keystone.exceptions.UserAuthException
import com.sam.keystone.exceptions.UserValidationException
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

        // now we can create a user
        val encoded = passwordEncoder.encode(request.password)

        val newUser = User(email = request.email, pWordHash = encoded, userName = request.userName)
        val newProfile = UserProfile(user = newUser)
        val userWithProfile = newUser.apply { profile = newProfile }

        val user = repository.save(userWithProfile)
        // user created
        val createToken = usersTokenManager.prepareTokenForUser(user.id)
        emailManager.sendVerificationEmailHtml(user, createToken)
        return user
    }


    @Transactional
    fun loginUser(request: LoginUserRequest): TokenResponseDto {
        val user = repository.findUserByUserName(request.userName)

        val foundUser = user ?: throw UserAuthException("Cannot find the given user")

        if (!foundUser.isVerified) throw UserAuthException("User not verified, required verification before use")

        val passwordSame = passwordEncoder.matches(request.password, foundUser.pWordHash)
        if (!passwordSame) throw UserAuthException("Invalid password")
        // so the user exists
        return tokenManager.generateTokenPairs(foundUser)
    }

    @Transactional
    fun verifyRegisterToken(token: String): User {
        val userId = usersTokenManager.validateToken(token)
            ?: throw UserValidationException("Cannot verify the given token")

        val user = repository.findUserById(userId)
            ?: throw UserValidationException("Cannot find the associated user")

        // delete the tokens
        usersTokenManager.removeTokens(user.id)

        val updatedUser = user.apply { isVerified = true }
        return repository.save(updatedUser)
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