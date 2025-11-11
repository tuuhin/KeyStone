package com.sam.keystone.services

import com.sam.keystone.components.JWTTokenManager
import com.sam.keystone.dto.request.LoginUserRequest
import com.sam.keystone.dto.request.RegisterUserRequest
import com.sam.keystone.dto.response.TokenResponseDto
import com.sam.keystone.entity.User
import com.sam.keystone.entity.UserProfile
import com.sam.keystone.repository.UserRepository
import jakarta.transaction.Transactional
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Service

@Service
class UsersService(
    private val repository: UserRepository,
    private val passwordEncoder: PasswordEncoder,
    private val tokenManger: JWTTokenManager,
) {

    @Transactional
    fun createNewUser(request: RegisterUserRequest): TokenResponseDto {
        // check for errors
        if (repository.findUserByEmail(request.email) != null)
            throw IllegalArgumentException("Email Id is already taken")

        if (repository.findUserByUserName(request.userName) != null)
            throw IllegalArgumentException("User name is already taken")

        // now we can create a user
        val encoded = passwordEncoder.encode(request.password)
            ?: throw Exception("Unable to read the password")

        val newUser = User(email = request.email, pWordHash = encoded, userName = request.userName)
        val newProfile = UserProfile(user = newUser)
        val userWithProfile = newUser.apply { profile = newProfile }

        val user = repository.save<User>(userWithProfile)
        // so the user exists
        return tokenManger.generateTokenPairs(user)
    }


    @Transactional
    fun loginUser(request: LoginUserRequest): TokenResponseDto {

        if (request.email == null && request.userName == null)
            throw IllegalArgumentException("Both username and email cannot be null")

        val user = if (request.email != null) repository.findUserByEmail(request.email)
        else repository.findUserByUserName(request.userName!!)

        val foundUser = user ?: throw IllegalArgumentException("Cannot find the given user")

        val passwordSame = passwordEncoder.matches(request.password, foundUser.pWordHash)
        if (!passwordSame) throw IllegalArgumentException("Password cannot be verified")
        // so the user exists
        return tokenManger.generateTokenPairs(user)
    }
}