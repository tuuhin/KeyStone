package com.sam.keystone.modules.oauth2.exceptions

import com.sam.keystone.modules.user.models.JWTTokenType

class OAuth2TokenInvalidException(val token: JWTTokenType) : RuntimeException("Cannot validate the ${token.simpleName}")