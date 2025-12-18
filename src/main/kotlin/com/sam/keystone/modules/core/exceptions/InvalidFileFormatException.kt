package com.sam.keystone.modules.core.exceptions

class InvalidFileFormatException(requestedFormat: String, foundFormat: String) :
    RuntimeException("File cannot be used REQUIRED :$requestedFormat FOUND:$foundFormat")