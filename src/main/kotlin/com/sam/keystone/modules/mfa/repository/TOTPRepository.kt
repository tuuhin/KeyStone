package com.sam.keystone.modules.mfa.repository

import com.sam.keystone.modules.mfa.entity.TOTPEntity
import com.sam.keystone.modules.user.entity.User
import org.springframework.data.jpa.repository.JpaRepository

interface TOTPRepository : JpaRepository<TOTPEntity, Long> {

    fun findTOTPEntityByUser(user: User): TOTPEntity?
}