package com.keepersecurity.secretsManager.core

internal open class SecretsManagerException(message: String): Exception(message)

internal class SecureRandomException(message: String): SecretsManagerException(message)
internal class SecureRandomSlowGenerationException(message: String): SecretsManagerException(message)
