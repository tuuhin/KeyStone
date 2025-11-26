package com.sam.keystone.modules.oauth2.exceptions

class ClientNotFoundException(clientId: String) : RuntimeException("Cannot find with the given client id :$clientId")