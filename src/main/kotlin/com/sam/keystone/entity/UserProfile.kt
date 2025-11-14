package com.sam.keystone.entity

import jakarta.persistence.*

@Entity
@Table(name = "users_profile")
class UserProfile(

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "profile_id", columnDefinition = "INTEGER")
    var id: Long? = null,

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false, unique = true)
    val user: User? = null,

    @Column(name = "bio", length = 512, nullable = true)
    var bio: String? = null,

    @Column(name = "full_name", nullable = true)
    var fullName: String? = null,

    @Column(name = "avatar_url", nullable = true)
    var avatarUrl: String? = null,
)