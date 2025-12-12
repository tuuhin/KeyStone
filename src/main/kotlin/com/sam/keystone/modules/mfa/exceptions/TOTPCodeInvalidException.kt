package com.sam.keystone.modules.mfa.exceptions

class TOTPCodeInvalidException(isBackUpCode: Boolean = false) :
    RuntimeException("Cannot validate the give ${if (isBackUpCode) "backup code" else "totp code"}") {
}