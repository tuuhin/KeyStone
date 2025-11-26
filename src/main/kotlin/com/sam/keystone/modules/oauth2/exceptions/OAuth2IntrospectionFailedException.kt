package com.sam.keystone.modules.oauth2.exceptions

class OAuth2IntrospectionFailedException :
    RuntimeException("Introspection failed: some of the required claims are missing ")