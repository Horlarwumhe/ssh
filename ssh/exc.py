class AuthenticationError(Exception):
    def __init__(self, message: str, auth_methods: list[str]):
        super().__init__(message)
        self.auth_methods = auth_methods

class ServerDisconnected(Exception):
    pass

class AuthError(Exception):
    def __init__(self, message: str, auth_methods: list[str]):
        super().__init__(message)
        self.auth_methods = auth_methods