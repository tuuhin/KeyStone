package com.sam.keystone.infrastructure.jwt

class JWTIntrospectionMissingClaims :
    RuntimeException("Introspection failed: some of the required claims are missing ")