package com.sam.keystone.modules.oauth2.exceptions

class PKCEInvalidException : RuntimeException("Invalid PKCE challege or verifier cannot validete the user")