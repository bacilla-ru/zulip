from typing import Optional, Sequence

from zerver.lib.cache import cache_delete


def auth_token_cache_key(auth_token: str) -> str:
    return f"auth_token:{auth_token}"


def flush_auth_token(
    *,
    instance: "AuthToken",
    update_fields: Optional[Sequence[str]] = None,
    **kwargs: object,
) -> None:
    if update_fields is None or not {"issued", "token"}.isdisjoint(set(update_fields)):
        cache_delete(auth_token_cache_key(instance.token))
