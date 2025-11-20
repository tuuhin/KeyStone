package com.sam.keystone.modules.user.repository

import com.sam.keystone.modules.user.entity.UserVerifyInfo
import org.springframework.data.jpa.repository.JpaRepository

interface UserVerificationRepository : JpaRepository<UserVerifyInfo, Long> {

    fun findUserVerifyInfoByResendKeyIs(keyHash: String): UserVerifyInfo?
}