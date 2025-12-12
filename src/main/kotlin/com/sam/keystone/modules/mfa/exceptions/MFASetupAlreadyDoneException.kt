package com.sam.keystone.modules.mfa.exceptions

class MFASetupAlreadyDoneException :
    RuntimeException("2FA setup is already done and is enabled to re-enable it disable it first")