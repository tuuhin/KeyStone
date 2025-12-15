package com.sam.keystone.modules.user.repository

import com.sam.keystone.modules.user.entity.User
import com.sam.keystone.modules.user.entity.UserProfile
import org.springframework.data.jpa.repository.JpaRepository

interface UserProfileRepository : JpaRepository<UserProfile, Long> {

    fun findUserProfileByUser(user: User): UserProfile?
}