class ClientAlreadyExists(Exception):
    pass

class ClientDoesNotExist(Exception):
    pass

class CannotSetSecretAndHashedSecretForClient(Exception):
    pass