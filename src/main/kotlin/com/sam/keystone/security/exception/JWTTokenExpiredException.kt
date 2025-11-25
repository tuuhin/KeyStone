package com.sam.keystone.security.exception

class JWTTokenExpiredException : RuntimeException("Token is expired cannot work with this any more")