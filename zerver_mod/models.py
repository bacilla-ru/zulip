import secrets
import string
from typing import Any, Dict, List, Optional, Tuple

from dateutil.relativedelta import relativedelta
from django.conf import settings
from django.contrib.postgres.fields import ArrayField
from django.core.validators import MaxLengthValidator, MinLengthValidator, RegexValidator
from django.db import models
from django.db.models import CASCADE
from django.utils import timezone
from zerver.models import UserGroup, UserGroupMembership, UserProfile


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
                ''.join(secrets.choice(alphabet2) for _ in range(38)) +
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

    def __str__(self):
        return self.token


class UserGroupMembershipStatus(models.Model):
    membership = models.OneToOneField(
        UserGroupMembership,
        on_delete=CASCADE,
        related_name="membership_status",
        primary_key=True
    )
    status = models.TextField()


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
    avatar = models.BinaryField(blank=True, null=True, editable=True, validators=[MaxLengthValidator(_max_avatar_length)])
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
