package com.sam.keystone.modules.oauth2.exceptions

class OAuth2InvalidResponseTypeException : RuntimeException("Response type other than code is not allowed meanwhile")