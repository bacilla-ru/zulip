import secrets
import string

TOKEN_LENGTH = 40
_ALPHABET1 = set(string.ascii_letters + string.digits)
_ALPHABET2 = _ALPHABET1.union("-_")


def generate() -> str:
    alphabet1 = list(_ALPHABET1)
    alphabet2 = list(_ALPHABET2)
    return (
        secrets.choice(alphabet1) +
        ''.join(secrets.choice(alphabet2) for _ in range(TOKEN_LENGTH - 2)) +
        secrets.choice(alphabet1)
    )


def has_valid_format(s: str) -> bool:
    return (
        len(s) == TOKEN_LENGTH and
        s[0] in _ALPHABET1 and
        s[-1] in _ALPHABET1 and
        set(s[1:-1]).issubset(_ALPHABET2)
    )
