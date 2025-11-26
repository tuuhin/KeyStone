package com.sam.keystone.modules.oauth2.exceptions

class InvalidAuthorizeOrTokenParmsException(clientId: String) :
    RuntimeException("Invalid authorization or token parameters for provided by for the given client :$clientId")