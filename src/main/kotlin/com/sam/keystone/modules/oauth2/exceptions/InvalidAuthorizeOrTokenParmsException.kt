package com.sam.keystone.modules.oauth2.exceptions

class InvalidAuthorizeOrTokenParmsException(override val message: String) : RuntimeException(message) {

    constructor(clientId: Long) : this(
        "Invalid authorization or token parameters for provided by for the given client :$clientId"
    )
}