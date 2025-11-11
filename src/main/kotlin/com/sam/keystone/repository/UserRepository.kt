package com.sam.keystone.repository

import com.sam.keystone.entity.User
import org.springframework.data.jpa.repository.JpaRepository

interface UserRepository : JpaRepository<User, Long> {

    fun findUserByEmail(email: String): User?

    fun findUserByUserName(userName: String): User?

    fun findUserById(id: Long): User?
}