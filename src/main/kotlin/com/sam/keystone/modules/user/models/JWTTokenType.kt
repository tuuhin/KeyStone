package com.sam.keystone.modules.user.models

enum class JWTTokenType(val simpleName: String) {
    ACCESS_TOKEN("access_token"),
    REFRESH_TOKEN("refresh_token")
}