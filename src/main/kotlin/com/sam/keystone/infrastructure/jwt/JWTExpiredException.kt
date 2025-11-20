package com.sam.keystone.infrastructure.jwt

class JWTExpiredException : RuntimeException("Verified jwt has a expired token")