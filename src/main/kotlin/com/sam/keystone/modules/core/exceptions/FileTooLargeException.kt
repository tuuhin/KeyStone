package com.sam.keystone.modules.core.exceptions

class FileTooLargeException(size: Long) : RuntimeException("File cannot be used its too large :$size bytes")