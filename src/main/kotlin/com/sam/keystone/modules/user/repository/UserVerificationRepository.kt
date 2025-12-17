package com.sam.keystone.modules.user.repository

import com.sam.keystone.modules.user.entity.User
import com.sam.keystone.modules.user.entity.UserVerifyInfo
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.stereotype.Repository

@Repository
interface UserVerificationRepository : JpaRepository<UserVerifyInfo, Long> {

    fun findUserVerifyInfoByUser(user: User): UserVerifyInfo?

    fun findUserVerifyInfoByResendKeyIs(keyHash: String): UserVerifyInfo?
}