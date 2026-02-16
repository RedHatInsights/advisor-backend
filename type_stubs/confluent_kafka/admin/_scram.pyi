from .. import cimpl as cimpl
from _typeshed import Incomplete
from enum import Enum

class ScramMechanism(Enum):
    UNKNOWN = ...
    SCRAM_SHA_256 = ...
    SCRAM_SHA_512 = ...
    def __lt__(self, other): ...

class ScramCredentialInfo:
    mechanism: Incomplete
    iterations: Incomplete
    def __init__(self, mechanism, iterations) -> None: ...

class UserScramCredentialsDescription:
    user: Incomplete
    scram_credential_infos: Incomplete
    def __init__(self, user, scram_credential_infos) -> None: ...

class UserScramCredentialAlteration:
    user: Incomplete
    def __init__(self, user: str) -> None: ...

class UserScramCredentialUpsertion(UserScramCredentialAlteration):
    scram_credential_info: Incomplete
    password: Incomplete
    salt: Incomplete
    def __init__(self, user, scram_credential_info, password, salt=None) -> None: ...

class UserScramCredentialDeletion(UserScramCredentialAlteration):
    mechanism: Incomplete
    def __init__(self, user, mechanism) -> None: ...
