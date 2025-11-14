package com.sam.keystone.repository

import com.sam.keystone.entity.UserVerifyInfo
import org.springframework.data.jpa.repository.JpaRepository

interface UserVerificationRepository : JpaRepository<UserVerifyInfo, Long> {

    fun findUserVerifyInfoByResendKeyIs(keyHash: String): UserVerifyInfo?
}