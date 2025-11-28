package com.sam.keystone.modules.oauth2.exceptions

class ClientAuthFailedException : RuntimeException("Client authentication failed") {

    val error: String
        get() = "invalid_client"
}