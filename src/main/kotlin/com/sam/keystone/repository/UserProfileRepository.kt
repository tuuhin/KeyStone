package com.sam.keystone.repository

import com.sam.keystone.entity.UserProfile
import org.springframework.data.jpa.repository.JpaRepository

interface UserProfileRepository : JpaRepository<UserProfile, Long>