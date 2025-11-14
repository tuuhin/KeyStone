package com.sam.keystone.services

import com.sam.keystone.components.JWTTokenManager
import com.sam.keystone.components.TokenBlackListManager
import com.sam.keystone.dto.request.RefreshTokenRequest
import com.sam.keystone.dto.response.TokenResponseDto
import com.sam.keystone.entity.User
import com.sam.keystone.exceptions.UserAuthException
import com.sam.keystone.models.JWTTokenType
import com.sam.keystone.repository.UserRepository
import org.springframework.stereotype.Service

@Service
class AuthTokenManagementService(
    private val userRepository: UserRepository,
    private val jwtTokenManager: JWTTokenManager,
    private val blackListManager: TokenBlackListManager,
) {

    fun handleRefreshTokenRequest(request: RefreshTokenRequest, currentUser: User): TokenResponseDto {
        val (userId, expireAfter) = jwtTokenManager.validateToken(request.token, type = JWTTokenType.REFRESH_TOKEN)
            ?: throw UserAuthException("Refresh Token expired or invalid")

        if (userId != currentUser.id) throw UserAuthException("Invalid account access request")

        if (blackListManager.isBlackListed(request.token))
            throw UserAuthException("Refresh token blacklisted")

        // add the item to the blacklist so it cannot be used anymore
        blackListManager.addToBlackList(request.token, expireAfter)

        // create a new token pair
        val user = userRepository.findUserById(userId) ?: throw UserAuthException("Cannot find user")
        return jwtTokenManager.generateTokenPairs(user)
    }


    fun blackListToken(request: RefreshTokenRequest) {
        val (_, expireAfter) = jwtTokenManager.validateToken(request.token, type = JWTTokenType.REFRESH_TOKEN)
            ?: throw UserAuthException("Refresh Token expired or invalid")

        // add the item to the blacklist so it cannot be used anymore
        if (blackListManager.isBlackListed(request.token)) return
        blackListManager.addToBlackList(request.token, expireAfter)
    }
}