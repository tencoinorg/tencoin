class RPCError(Exception):
    """Base RPC error"""
    pass

class ConnectionError(RPCError):
    """Network connection error"""
    pass

class AuthenticationError(RPCError):
    """Authentication failed"""
    pass

class TimeoutError(RPCError):
    """Request timeout"""
    pass

class ResponseError(RPCError):
    """Invalid response from server"""
    pass

class InvalidMethodError(RPCError):
    """Invalid RPC method"""
    pass


class PublicKeyNotFoundError(RPCError, LookupError):
    """The address has never been used as a spending input, so its public key is not on-chain."""
    def __init__(self, address: str = "", message: str = ""):
        self.address = address
        super().__init__(
            message or "No public key found for this address "
                       "(it has never been used as a spending input)."
        )

class PublicKeyVerificationError(RPCError):
    """The node returned a public key that does not match the requested address."""
    pass
