class ConfigKeyDoesNotExistError(Exception):
    pass


class ConfigValidationError(Exception):
    pass


class VaultInvalidUsernameOrPasswordError(Exception):
    pass


class VaultUnavailableError(Exception):
    pass


class VaultUndecryptableError(Exception):
    pass
