package com.sam.keystone.modules.user.repository

import com.sam.keystone.modules.user.entity.User
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.stereotype.Repository

@Repository
interface UserRepository : JpaRepository<User, Long> {

    fun findUserByEmail(email: String): User?

    fun findUserByUserName(userName: String): User?

    fun findUserById(id: Long): User?
}