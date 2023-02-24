import secrets
import string
from datetime import datetime
from typing import List, NamedTuple, Optional, Tuple

from dateutil.relativedelta import relativedelta
from django.conf import settings
from django.contrib.postgres.fields import ArrayField
from django.core.validators import (
    MaxLengthValidator, MinLengthValidator, RegexValidator)
from django.db import models
from django.db.models import CASCADE
from django.db.models.signals import post_delete, post_save
from django.utils import timezone

from zerver.lib.cache import cache_delete, cache_with_key
from zerver.models import (
    UserGroup, UserGroupMembership, UserProfile, get_user_profile_by_id)

from .lib.cache import auth_token_cache_key, flush_auth_token


class AuthToken(models.Model):
    TOKEN_LENGTH = 40
    TOKEN_LIFETIME = (
        relativedelta(minutes=settings.MOD_AUTH_TOKEN_LIFETIME_MINUTES)
        if settings.MOD_AUTH_TOKEN_LIFETIME_MINUTES > 0
        else None
    )

    fcm_token = models.TextField(null=True)
    issued = models.DateTimeField()
    name = models.TextField()
    token = models.CharField(
        max_length=TOKEN_LENGTH,
        unique=True,
        validators=[MinLengthValidator(TOKEN_LENGTH)]
    )
    user_profile = models.ForeignKey(UserProfile, on_delete=CASCADE, related_name="+")

    class Meta:
        unique_together = (("user_profile", "name"),)

    def save(self, update_fields=None, **kwargs):
        if not self.token and (update_fields is None or "token" in update_fields):
            self.issued = timezone.now().replace(microsecond=0)
            alphabet1 = string.ascii_letters + string.digits
            alphabet2 = alphabet1 + "-_"
            self.token = (
                secrets.choice(alphabet1) +
                ''.join(secrets.choice(alphabet2) for _ in range(self.TOKEN_LENGTH - 2)) +
                secrets.choice(alphabet1)
            )
            if update_fields is not None and "issued" not in update_fields:
                update_fields = {*update_fields, "issued"}
        return super().save(update_fields=update_fields, **kwargs)

    @property
    def expires(self) -> int:
        if self.TOKEN_LIFETIME:
            return int((self.issued + self.TOKEN_LIFETIME).timestamp())
        return 0x7FFF_FFFF

    def expired(self, current_time=timezone.now) -> bool:
        if self.TOKEN_LIFETIME:
            return not(current_time() < self.issued + self.TOKEN_LIFETIME)
        return False

    def refresh(self):
        cache_delete(auth_token_cache_key(self.token))
        self.token = None
        self.save(update_fields={"issued", "token"})

    def set_fcm_token(self, fcm_token: Optional[str]):
        self.fcm_token = fcm_token
        self.save(update_fields={"fcm_token"})

    def __str__(self):
        return self.token


post_save.connect(flush_auth_token, sender=AuthToken)
post_delete.connect(flush_auth_token, sender=AuthToken)


class AuthTokenCacheItem(NamedTuple):
    issued: int
    user_profile_id: int

    def expired(self, current_time=timezone.now) -> bool:
        if AuthToken.TOKEN_LIFETIME:
            t = current_time()
            return not(t < datetime.fromtimestamp(self.issued, t.tzinfo) + AuthToken.TOKEN_LIFETIME)
        return False


@cache_with_key(auth_token_cache_key, timeout=3600 * 24 * 7)
def get_auth_token_cache_item(auth_token: str) -> Optional[AuthTokenCacheItem]:
    issued: datetime
    user_profile_id: int
    try:
        issued, user_profile_id = (
            AuthToken.objects.values_list("issued", "user_profile_id").get(token=auth_token)
        )
    except AuthToken.DoesNotExist:
        return None
    return AuthTokenCacheItem(int(issued.timestamp()), user_profile_id)


def get_user_profile_by_auth_token(auth_token: str) -> UserProfile:
    cache_item = get_auth_token_cache_item(auth_token)
    if cache_item and not cache_item.expired():
        return get_user_profile_by_id(cache_item.user_profile_id)
    raise UserProfile.DoesNotExist


class UserGroupMembershipStatus(models.Model):
    membership = models.OneToOneField(
        UserGroupMembership,
        on_delete=CASCADE,
        related_name="membership_status",
        primary_key=True
    )
    status = models.TextField()

    def set_status(self, status: str):
        self.status = status
        self.save(update_fields={"status"})


def get_direct_membership(
    user_profile: UserProfile,
    skip_system_groups: bool = True
) -> List[Tuple[UserGroup, UserGroupMembership, Optional[UserGroupMembershipStatus]]]:
    queryset = (
        UserGroupMembership.objects.select_related("user_group", "membership_status")
        .filter(user_profile=user_profile)
        .order_by("user_group__name")
    )
    if skip_system_groups:
        queryset = queryset.exclude(user_group__is_system_group=True)
    return [
        (m.user_group, m, m.membership_status if hasattr(m, "membership_status") else None)
        for m in queryset
    ]


def _max_avatar_length():
    return settings.MAX_AVATAR_FILE_SIZE_MIB * 1024 * 1024


def _default_permissions():
    return ["messaging/*"]


class UserProfileExt(models.Model):
    EXTERNAL = "external"
    INTERNAL = "internal"
    ACCOUNT_TYPES = (
        (EXTERNAL, "External account"),
        (INTERNAL, "Internal account")
    )

    id = models.IntegerField(primary_key=True)
    account_type = models.TextField(default=INTERNAL, choices=ACCOUNT_TYPES)
    avatar = models.BinaryField(
        blank=True,
        null=True,
        editable=True,
        validators=[MaxLengthValidator(_max_avatar_length)]
    )
    name = models.CharField(
        max_length=UserProfile.MAX_NAME_LENGTH - 2,
        validators=[RegexValidator(r"^\S+$")]
    )
    patronymic = models.CharField(
        max_length=UserProfile.MAX_NAME_LENGTH - 4,
        blank=True,
        default="",
        validators=[RegexValidator(r"^\S*$")]
    )
    permissions = ArrayField(models.TextField(), default=_default_permissions)
    phone = models.CharField(
        max_length=10,
        unique=True,
        validators=[MinLengthValidator(10), RegexValidator(r"^\d{10}$")]
    )
    surname = models.CharField(
        max_length=UserProfile.MAX_NAME_LENGTH - 2,
        validators=[RegexValidator(r"^\S+$")]
    )
    user_profile = models.OneToOneField(UserProfile, on_delete=CASCADE, related_name="+")

    @property
    def full_name(self):
        if self.patronymic == "":
            return "{} {}".format(self.surname, self.name)
        else:
            return "{} {} {}".format(self.surname, self.name, self.patronymic)
