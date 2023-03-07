import base64
import binascii
from io import BytesIO
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

import orjson
from django.core import validators
from django.core.exceptions import BadRequest, ValidationError
from django.db import models, transaction
from django.db.utils import IntegrityError
from django.http import HttpRequest, HttpResponse, HttpResponseNotAllowed
from django.urls.resolvers import URLPattern
from django.utils.functional import empty
from django.utils.timezone import now as timezone_now
from sqlalchemy.dialects.postgresql import array_agg
from sqlalchemy.sql import any_, column, not_, select, table
from sqlalchemy.sql.selectable import SelectBase
from sqlalchemy.types import VARCHAR, Boolean, Integer

from zerver.actions import (
    create_user as create_user_actions, user_settings as user_settings_actions,
    users as users_actions)
from zerver.actions.user_groups import (
    bulk_add_members_to_user_group, remove_members_from_user_group)
from zerver.decorator import require_realm_admin
from zerver.lib.email_validation import (
    email_allowed_for_realm as lib_email_allowed_for_realm)
from zerver.lib.exceptions import (
    InvalidAPIKeyError, JsonableError, MissingAuthenticationError,
    OrganizationAdministratorRequiredError, UnauthorizedError)
from zerver.lib.push_notifications import (
    add_push_device_token as lib_add_push_device_token,
    clear_push_device_tokens as lib_clear_push_device_tokens,
    remove_push_device_token as lib_remove_push_device_token)
from zerver.lib.rest import rest_dispatch as lib_rest_dispatch
from zerver.lib.sqlalchemy_utils import get_sqlalchemy_connection
from zerver.lib.upload import (
    BadImageError, upload_avatar_image as lib_upload_avatar_image)
from zerver.lib.users import check_full_name as lib_check_full_name
from zerver.models import (
    DisposableEmailError, DomainNotAllowedForRealmError,
    EmailContainsPlusError, PushDeviceToken, Realm, RealmAuditLog, UserGroup,
    UserGroupMembership, UserProfile)

from ..lib.avatar import gen_avatar
from ..models import (
    AuthToken, UserGroupMembershipStatus, UserProfileExt,
    get_direct_membership)

__all__ = [
    "get_user_backend",
    "create_user_backend",
    "update_user_backend",
    "partial_update_user_backend",
    "deactivate_user_backend",
    "get_auth_tokens_backend",
    "get_or_create_auth_token_backend",
    "refresh_or_create_auth_token_backend",
    "delete_auth_token_backend",
    "update_fcm_token_backend",
    "delete_fcm_token_backend",
    "rest_path",
]


def get_user_backend(request, admin: UserProfile, user_id=None) -> HttpResponse:  # GET
    try:
        user_profile_ext: UserProfileExt = (
            UserProfileExt.objects
            .select_related("user_profile")
            .get(id=user_id, user_profile__realm=admin.realm)
        )
    except UserProfileExt.DoesNotExist:
        return not_found_response()
    user_profile: UserProfile = user_profile_ext.user_profile
    return success_response(
        account_type=user_profile_ext.account_type,
        avatar=bytes_to_json(user_profile_ext.avatar),
        email=user_profile.delivery_email,
        groups=[
            {"name": user_group.name, "status": "" if membership_status is None else membership_status.status}
            for user_group, _, membership_status
            in get_direct_membership(user_profile)
        ],
        is_active=user_profile.is_active,
        name=user_profile_ext.name,
        patronymic=user_profile_ext.patronymic,
        permissions=user_profile_ext.permissions,
        phone=user_profile_ext.phone,
        surname=user_profile_ext.surname
    )


def create_user_backend(request, admin: UserProfile, user_id=None) -> HttpResponse:  # POST
    if not admin.can_create_users:
        return forbidden_response()
    u, groups = validate_request_body(request, default_groups={})
    email = validate_email(u.pop("email", empty))
    tokens = validate_tokens(u.pop("tokens", []))
    created_tokens: Optional[List[AuthToken]] = None
    with transaction.atomic():
        realm = admin.realm
        user_profile_ext: Optional[UserProfileExt] = (
            UserProfileExt.objects
            .select_related("user_profile")
            .select_for_update()
            .filter(id=user_id, user_profile__realm=realm)
            .first()
        )
        if user_profile_ext is None:
            user_profile_ext = UserProfileExt(id=user_id)
            apply_dict_values(user_profile_ext, u)
            validate_user_profile_ext(user_profile_ext, exclude=["id", "user_profile"])
            full_name = check_full_name(user_profile_ext.full_name)
            check_email(email, realm)
            check_user_group_names(list(groups), realm)
            try:
                user_profile = create_user_actions.do_create_user(
                    email=email,
                    password=None,
                    realm=realm,
                    full_name=full_name,
                    avatar_source=UserProfile.AVATAR_FROM_USER,
                    acting_user=admin,
                    enable_marketing_emails=False
                )
            except IntegrityError:
                raise Failure("email_already_in_use")
            user_profile_ext.user_profile = user_profile
            save_user_profile_ext(user_profile_ext, force_insert=True)
            upload_avatar_image(user_profile_ext, acting_user=admin)
            result = created_response
        else:
            user_profile: UserProfile = user_profile_ext.user_profile
            if user_profile.is_active:
                raise Failure("user_already_exists")
            if email.upper() != user_profile.delivery_email.upper():
                raise Failure("email_can_not_be_changed")
            current_avatar: Optional[bytes] = user_profile_ext.avatar
            apply_dict_values(user_profile_ext, u)
            validate_user_profile_ext(user_profile_ext)
            full_name = check_full_name(user_profile_ext.full_name)
            check_user_group_names(list(groups), realm)
            if full_name != user_profile.full_name:
                do_change_full_name(user_profile, full_name, acting_user=admin)
            save_user_profile_ext(user_profile_ext)
            if (
                user_profile_ext.avatar != current_avatar or
                user_profile.avatar_source != UserProfile.AVATAR_FROM_USER
            ):
                upload_avatar_image(user_profile_ext, acting_user=admin)
                user_settings_actions.do_change_avatar_fields(
                    user_profile,
                    UserProfile.AVATAR_FROM_USER,
                    skip_notify=True,
                    acting_user=user_profile
                )
            create_user_actions.do_reactivate_user(user_profile, acting_user=admin)
            result = success_response
        create_user_group_membership(user_profile, groups, realm)
        if tokens:
            created_tokens = []
            for name, fcm_token in tokens.items():
                created_tokens.append(
                    AuthToken.objects.create(
                        user_profile=user_profile,
                        name=name,
                        fcm_token=fcm_token if fcm_token else None
                    )
                )
                if fcm_token:
                    add_push_device_token(user_profile, fcm_token)
    if created_tokens:
        return result(tokens=[
            dict(
                expires=token.expires,
                name=token.name,
                token=token.token
            )
            for token in created_tokens
        ])
    return result()


def update_user_backend(request, admin: UserProfile, user_id=None):  # PUT
    u, groups = validate_request_body(request, default_groups={})
    with transaction.atomic():
        try:
            user_profile_ext: UserProfileExt = (
                UserProfileExt.objects
                .select_related("user_profile")
                .select_for_update()
                .get(id=user_id, user_profile__realm=admin.realm)
            )
        except UserProfileExt.DoesNotExist:
            return not_found_response()
        user_profile: UserProfile = user_profile_ext.user_profile
        current_avatar: Optional[bytes] = user_profile_ext.avatar
        apply_dict_values(user_profile_ext, u)
        validate_user_profile_ext(user_profile_ext)
        full_name = check_full_name(user_profile_ext.full_name)
        if user_profile.is_active:
            check_user_group_names(list(groups), admin.realm)
        if full_name != user_profile.full_name:
            do_change_full_name(
                user_profile,
                full_name,
                skip_notify=not user_profile.is_active,
                acting_user=admin
            )
        save_user_profile_ext(user_profile_ext)
        if (
            user_profile_ext.avatar != current_avatar or
            user_profile.avatar_source != UserProfile.AVATAR_FROM_USER
        ):
            upload_avatar_image(user_profile_ext, acting_user=admin)
            user_settings_actions.do_change_avatar_fields(
                user_profile,
                UserProfile.AVATAR_FROM_USER,
                skip_notify=not user_profile.is_active,
                acting_user=user_profile
            )
        if user_profile.is_active:
            update_user_group_membership(user_profile, groups, admin.realm)
    return success_response()


def partial_update_user_backend(request, admin: UserProfile, user_id=None):  # PATCH
    u, groups = validate_request_body(request)
    with transaction.atomic():
        try:
            user_profile_ext: UserProfileExt = (
                UserProfileExt.objects
                .select_related("user_profile")
                .select_for_update()
                .get(id=user_id, user_profile__realm=admin.realm)
            )
        except UserProfileExt.DoesNotExist:
            return not_found_response()
        user_profile: UserProfile = user_profile_ext.user_profile
        current_avatar: Optional[bytes] = user_profile_ext.avatar
        current_name: str = user_profile_ext.name
        current_patronymic: str = user_profile_ext.patronymic
        current_surname: str = user_profile_ext.surname
        apply_dict_values(user_profile_ext, u, use_defaults=False)
        validate_user_profile_ext(user_profile_ext)
        full_name_changed = (
            user_profile_ext.name != current_name or
            user_profile_ext.patronymic != current_patronymic or
            user_profile_ext.surname != current_surname
        )
        if full_name_changed:
            full_name = check_full_name(user_profile_ext.full_name)
        if user_profile.is_active and groups is not None:
            check_user_group_names(list(groups), admin.realm)
        if full_name_changed and full_name != user_profile.full_name:
            do_change_full_name(
                user_profile,
                full_name,
                skip_notify=not user_profile.is_active,
                acting_user=admin
            )
        save_user_profile_ext(user_profile_ext)
        if user_profile_ext.avatar != current_avatar:
            upload_avatar_image(user_profile_ext, acting_user=admin)
            user_settings_actions.do_change_avatar_fields(
                user_profile,
                UserProfile.AVATAR_FROM_USER,
                skip_notify=not user_profile.is_active,
                acting_user=user_profile
            )
        if user_profile.is_active and groups is not None:
            update_user_group_membership(user_profile, groups, admin.realm)
    return success_response()


def deactivate_user_backend(request, admin: UserProfile, user_id=None):  # DELETE
    with transaction.atomic():
        try:
            user_profile_ext: UserProfileExt = (
                UserProfileExt.objects
                .select_related("user_profile")
                .select_for_update()
                .get(id=user_id, user_profile__realm=admin.realm)
            )
        except UserProfileExt.DoesNotExist:
            return not_found_response()
        user_profile: UserProfile = user_profile_ext.user_profile
        if user_profile.is_active:
            users_actions.do_deactivate_user(user_profile, acting_user=admin)
            UserGroupMembership.objects.filter(
                user_profile=user_profile,
                user_group__is_system_group=False
            ).delete()
            AuthToken.objects.filter(user_profile=user_profile).delete()
            lib_clear_push_device_tokens(user_profile.id)
    return success_response()


def get_auth_tokens_backend(request, admin: UserProfile, user_id=None) -> HttpResponse:
    try:
        user_profile_ext: UserProfileExt = (
            UserProfileExt.objects.only("user_profile_id").get(id=user_id, user_profile__realm=admin.realm)
        )
    except UserProfileExt.DoesNotExist:
        return not_found_response()
    auth_tokens: List[AuthToken] = list(
        AuthToken.objects.filter(user_profile_id=user_profile_ext.user_profile_id)
                         .order_by("name")
    )
    return success_response(
        tokens=[
            dict(
                expires=auth_token.expires,
                name=auth_token.name,
                token=auth_token.token
            ) for auth_token in auth_tokens
        ]
    )


def get_or_create_auth_token_backend(request, admin: UserProfile, user_id=None, name=None) -> HttpResponse:
    try:
        user_profile_ext: UserProfileExt = (
            UserProfileExt.objects.only("user_profile_id").get(id=user_id, user_profile__realm=admin.realm)
        )
    except UserProfileExt.DoesNotExist:
        return not_found_response()
    with transaction.atomic():
        auth_token: AuthToken
        created: bool
        auth_token, created = AuthToken.objects.select_for_update().get_or_create(
            user_profile_id=user_profile_ext.user_profile_id,
            name=name
        )
    ret = dict(
        expires=auth_token.expires,
        name=auth_token.name,
        token=auth_token.token
    )
    if created:
        return created_response(ret)
    return success_response(ret)


def refresh_or_create_auth_token_backend(request, admin: UserProfile, user_id=None, name=None) -> HttpResponse:
    try:
        user_profile_ext: UserProfileExt = (
            UserProfileExt.objects.only("user_profile_id")
            .get(id=user_id, user_profile__realm=admin.realm)
        )
    except UserProfileExt.DoesNotExist:
        return not_found_response()
    auth_token: AuthToken
    created: bool
    with transaction.atomic():
        auth_token, created = AuthToken.objects.select_for_update().get_or_create(
            user_profile_id=user_profile_ext.user_profile_id,
            name=name
        )
        if not created:
            auth_token.refresh()
    ret = dict(
        expires=auth_token.expires,
        name=auth_token.name,
        token=auth_token.token
    )
    if created:
        return created_response(ret)
    return success_response(ret)


def delete_auth_token_backend(request, admin: UserProfile, user_id=None, name=None) -> HttpResponse:
    try:
        user_profile_ext: UserProfileExt = (
            UserProfileExt.objects
            .select_related("user_profile")
            .get(id=user_id, user_profile__realm=admin.realm)
        )
    except UserProfileExt.DoesNotExist:
        return not_found_response()
    user_profile: UserProfile = user_profile_ext.user_profile
    with transaction.atomic():
        try:
            auth_token = AuthToken.objects.select_for_update().get(user_profile=user_profile, name=name)
        except AuthToken.DoesNotExist:
            return success_response()
        auth_token.delete()
        if auth_token.fcm_token:
            remove_push_device_token(user_profile, auth_token.fcm_token)
    return success_response()


def update_fcm_token_backend(request, admin: UserProfile, user_id=None, name=None) -> HttpResponse:
    if request.content_type != "text/plain":
        return failure_response()
    try:
        fcm_token = request.body.decode(request.encoding or "iso-8859-1")
    except UnicodeError:
        return failure_response()
    if len(fcm_token) < 1:
        return failure_response()
    try:
        user_profile_ext: UserProfileExt = (
            UserProfileExt.objects
            .select_related("user_profile")
            .get(id=user_id, user_profile__realm=admin.realm)
        )
    except UserProfileExt.DoesNotExist:
        return not_found_response()
    user_profile: UserProfile = user_profile_ext.user_profile
    auth_token: AuthToken
    created: bool
    token_was_null: bool
    with transaction.atomic():
        auth_token, created = AuthToken.objects.select_for_update().get_or_create(
            user_profile=user_profile,
            name=name,
            defaults=dict(fcm_token=fcm_token)
        )
        if not created:
            token_was_null = auth_token.fcm_token is None
            if not token_was_null:
                remove_push_device_token(user_profile, auth_token.fcm_token)
            auth_token.set_fcm_token(fcm_token)
        add_push_device_token(user_profile, fcm_token)
    if created:
        return created_response(
            expires=auth_token.expires,
            name=auth_token.name,
            token=auth_token.token
        )
    if token_was_null:
        return created_response()
    return success_response()


def delete_fcm_token_backend(request, admin: UserProfile, user_id=None, name=None) -> HttpResponse:
    try:
        user_profile_ext: UserProfileExt = (
            UserProfileExt.objects
            .select_related("user_profile")
            .get(id=user_id, user_profile__realm=admin.realm)
        )
    except UserProfileExt.DoesNotExist:
        return not_found_response()
    user_profile: UserProfile = user_profile_ext.user_profile
    auth_token: AuthToken
    with transaction.atomic():
        try:
            auth_token = AuthToken.objects.select_for_update().get(user_profile=user_profile, name=name)
        except AuthToken.DoesNotExist:
            return success_response()
        fcm_token: Optional[str] = auth_token.fcm_token
        if fcm_token is None:
            return success_response()
        auth_token.set_fcm_token(None)
        remove_push_device_token(user_profile, fcm_token)
    return success_response()


# Serialization helpers -----------------------------------


def bytes_to_json(val: Optional[bytes]) -> Optional[str]:
    if val is None:
        return None
    return base64.standard_b64encode(val).decode()


# Deserialization helpers ---------------------------------


def validate_request_body(request, default_groups=None) -> Tuple[Dict[str, Any], Optional[Dict[str, str]]]:
    if request.content_type != "application/json":
        raise BadRequest
    if request.encoding is not None and request.encoding.lower() != "utf-8":
        raise BadRequest
    try:
        u = orjson.loads(request.body)
    except orjson.JSONDecodeError:
        raise BadRequest
    if not isinstance(u, dict):
        raise BadRequest
    try:
        u_groups = u.pop("groups")
    except KeyError:
        return u, default_groups
    if not isinstance(u_groups, list):
        raise BadRequest
    groups: Dict[str, str] = dict()
    for u_group in u_groups:
        if not isinstance(u_group, dict):
            raise BadRequest
        name, status = u_group.get("name"), u_group.get("status", "")
        if not isinstance(name, str) or name in groups:
            raise BadRequest
        groups[name] = status
    return u, groups


def validate_tokens(raw_tokens) -> Dict[str, str]:
    if not isinstance(raw_tokens, list):
        raise BadRequest
    tokens: Dict[str, str] = dict()
    for raw_token in raw_tokens:
        if not isinstance(raw_token, dict):
            raise BadRequest
        name, fcm_token = raw_token.get("name"), raw_token.get("fcm_token")
        if not isinstance(name, str) or name == "" or name in tokens:
            raise BadRequest
        if fcm_token is not None and (not isinstance(fcm_token, str) or fcm_token == ""):
            raise BadRequest
        tokens[name] = fcm_token
    return tokens


def apply_dict_values(user_profile_ext: UserProfileExt, values: Dict[str, Any], use_defaults=True):
    # noinspection PyProtectedMember
    for field in UserProfileExt._meta.get_fields():
        if field.is_relation or field.primary_key:
            continue
        try:
            val = values[field.name]
        except KeyError:
            if not use_defaults:
                continue
            if field.has_default():
                val = field.get_default()
            elif field.null:
                val = None
            else:
                raise BadRequest
        if isinstance(field, models.BinaryField) and isinstance(val, str):
            try:
                val = bytes_from_json(val)
            except ValueError:
                raise BadRequest
        field.save_form_data(user_profile_ext, val)


def bytes_from_json(val: Optional[str]) -> Optional[bytes]:
    if val is None:
        return None
    try:
        return base64.standard_b64decode(val)
    except binascii.Error:
        raise ValueError


# Validators ----------------------------------------------


def validate_user_profile_ext(user_profile_ext: UserProfileExt, exclude=None):
    try:
        user_profile_ext.full_clean(exclude=exclude)
    except ValidationError as e:
        phone_errors = e.error_dict.get("phone")
        if phone_errors and any(error.code == "unique" for error in phone_errors):
            raise Failure("phone_already_in_use")
        raise BadRequest


def check_full_name(raw_full_name: str) -> str:
    try:
        return lib_check_full_name(raw_full_name)
    except JsonableError:
        raise BadRequest


def validate_email(raw_email) -> str:
    if not isinstance(raw_email, str):
        raise BadRequest
    email = raw_email.strip()
    if email == "":
        raise BadRequest
    try:
        validators.validate_email(email)
    except ValidationError:
        raise BadRequest
    return email


def check_email(email: str, realm: Realm):
    try:
        lib_email_allowed_for_realm(email, realm)
    except (DisposableEmailError, DomainNotAllowedForRealmError, EmailContainsPlusError):
        raise BadRequest
    if UserProfile.objects.filter(delivery_email__iexact=email, realm=realm).exists():
        raise Failure("email_already_in_use")


def check_user_group_names(user_group_names: List[str], realm: Realm):
    if user_group_names and not check_all_user_groups_exists(user_group_names, realm):
        raise Failure("group_not_found")


def check_all_user_groups_exists(user_group_names: List[str], realm: Realm) -> bool:
    query: SelectBase = (
        select(
            array_agg(column("name", VARCHAR)).contains(user_group_names)
        )
        .where(
            column("realm_id", Integer) == realm.id,
            not_(column("is_system_group", Boolean)),
            column("name", VARCHAR) == any_(user_group_names),
        )
        .select_from(
            table("zerver_usergroup")
        )
    )
    with get_sqlalchemy_connection() as sa_conn:
        return sa_conn.execute(query).scalar()


# Services ------------------------------------------------


def save_user_profile_ext(user_profile_ext: UserProfileExt, force_insert=False):
    try:
        user_profile_ext.save(force_insert=force_insert)
    except IntegrityError:
        # only `phone` field has a unique constraint
        raise Failure("phone_already_in_use")


def do_change_full_name(
    user_profile: UserProfile, full_name: str, skip_notify: bool = False, *, acting_user: Optional[UserProfile]
) -> None:
    """Same as :func:`zerver.actions.user_settings.do_change_full_name`,
    but without sending any event if `skip_notify` is set to True."""
    if not skip_notify:
        return user_settings_actions.do_change_full_name(user_profile, full_name, acting_user)
    old_name = user_profile.full_name
    user_profile.full_name = full_name
    user_profile.save(update_fields=["full_name"])
    event_time = timezone_now()
    RealmAuditLog.objects.create(
        realm=user_profile.realm,
        acting_user=acting_user,
        modified_user=user_profile,
        event_type=RealmAuditLog.USER_FULL_NAME_CHANGED,
        event_time=event_time,
        extra_data=old_name,
    )


def upload_avatar_image(
    user_profile_ext: UserProfileExt,
    acting_user: UserProfile
):
    avatar_bytes: Optional[bytes] = user_profile_ext.avatar
    user_profile: UserProfile = user_profile_ext.user_profile
    if avatar_bytes is None:
        lib_upload_avatar_image(
            gen_avatar(
                user_profile.full_name,
                f"{user_profile_ext.surname[0].upper()}{user_profile_ext.name[0].upper()}"
            ),
            acting_user,
            user_profile,
            "image/png"
        )
    else:
        try:
            lib_upload_avatar_image(
                BytesIO(avatar_bytes),
                acting_user,
                user_profile
            )
        except BadImageError:
            raise BadRequest


def create_user_group_membership(
    user_profile: UserProfile,
    groups: Dict[str, str],
    realm: Realm
):
    if not groups:
        return
    user_profile_ids = [user_profile.id]
    status_by_user_group_id: Dict[int, str] = {}
    for user_group in (
        UserGroup.objects.filter(
            name__in=list(groups),
            realm=realm,
            is_system_group=False
        )
    ):  # add user to group
        bulk_add_members_to_user_group(user_group, user_profile_ids)
        status = groups[user_group.name]
        if status:
            status_by_user_group_id[user_group.id] = status
    if status_by_user_group_id:
        UserGroupMembershipStatus.objects.bulk_create([
            UserGroupMembershipStatus(
                membership=membership,
                status=status_by_user_group_id[membership.user_group_id]
            )
            for membership in (
                UserGroupMembership.objects.filter(
                    user_group_id__in=list(status_by_user_group_id),
                    user_profile=user_profile
                )
            )
        ])


def update_user_group_membership(
    user_profile: UserProfile,
    groups: Dict[str, str],
    realm: Realm
):
    user_profile_ids: List[int] = [user_profile.id]
    current: Dict[str, Tuple[UserGroup, UserGroupMembership, Optional[UserGroupMembershipStatus]]] = {
        t[0].name: t
        for t in get_direct_membership(user_profile)
    }
    current_set: Set[str] = set(current)
    groups_set: Set[str] = set(groups)
    update_set: Set[str] = current_set.intersection(groups_set)
    for group_name in update_set:  # create/update membership status if needed
        status: str = groups[group_name]
        user_group, membership, membership_status = current[group_name]
        if membership_status is None and status != "":
            UserGroupMembershipStatus.objects.create(membership=membership, status=status)
        elif membership_status is not None:
            if status == "":
                membership_status.delete()
            elif membership_status.status != status:
                membership_status.set_status(status)
                # membership_status.status = status
                # membership_status.save(update_fields=["status"])
    for group_name in current_set.difference(update_set):  # remove user from groups
        user_group, _, _ = current[group_name]
        remove_members_from_user_group(user_group, user_profile_ids)
    create_set: Set[str] = groups_set.difference(update_set)
    if create_set:
        create_user_group_membership(
            user_profile,
            {group_name: groups[group_name] for group_name in create_set},
            realm
        )


def add_push_device_token(user_profile: UserProfile, token_str: str) -> PushDeviceToken:
    return lib_add_push_device_token(user_profile, token_str, PushDeviceToken.GCM)


def remove_push_device_token(user_profile: UserProfile, token_str: str):
    try:
        lib_remove_push_device_token(user_profile, token_str, PushDeviceToken.GCM)
    except JsonableError:
        pass


# Response helpers ----------------------------------------


def to_json(*dicts: dict, **kwargs) -> bytes:
    accum = dict()
    for d in dicts:
        accum.update(d)
    if kwargs:
        accum.update(kwargs)
    return orjson.dumps(accum, option=orjson.OPT_APPEND_NEWLINE)


FAILURE_DICT = dict(ok=False)
FAILURE: bytes = to_json(FAILURE_DICT)
SUCCESS_DICT = dict(ok=True)
SUCCESS: bytes = to_json(SUCCESS_DICT)
BAD_REQUEST: bytes = to_json(FAILURE_DICT, errors=["bad_request"])
UNAUTHORIZED: bytes = to_json(FAILURE_DICT, errors=["unauthorized"])
FORBIDDEN: bytes = to_json(FAILURE_DICT, errors=["forbidden"])
NOT_FOUND: bytes = to_json(FAILURE_DICT, errors=["not_found"])
METHOD_NOT_ALLOWED: bytes = to_json(FAILURE_DICT, errors=["method_not_allowed"])


class Failure(Exception):
    pass


def response(content: bytes, status: int = 200) -> HttpResponse:
    return HttpResponse(
        content=content,
        content_type="application/json",
        status=status,
    )


def bad_request_response() -> HttpResponse:
    return response(BAD_REQUEST, 400)


def unauthorized_response() -> HttpResponse:
    return response(UNAUTHORIZED, 401)


def forbidden_response() -> HttpResponse:
    return response(FORBIDDEN, 403)


def not_found_response() -> HttpResponse:
    return response(NOT_FOUND, 404)


def failure_response(*errors: str) -> HttpResponse:
    if errors:
        return response(to_json(FAILURE_DICT, errors=errors))
    return response(FAILURE)


def success_response(*dicts: dict, **kwargs) -> HttpResponse:
    if dicts or kwargs:
        return response(to_json(SUCCESS_DICT, *dicts, **kwargs))
    return response(SUCCESS)


def created_response(*dicts: dict, **kwargs) -> HttpResponse:
    if dicts or kwargs:
        return response(to_json(SUCCESS_DICT, *dicts, **kwargs), 201)
    return response(SUCCESS, 201)


# Dispatch ------------------------------------------------


def dispatch(request: HttpRequest, /, **kwargs: object) -> HttpResponse:
    try:
        resp: HttpResponse = lib_rest_dispatch(request, **kwargs)
    except (InvalidAPIKeyError, MissingAuthenticationError, UnauthorizedError):
        return unauthorized_response()
    except OrganizationAdministratorRequiredError:
        return forbidden_response()
    except BadRequest:
        return bad_request_response()
    except Failure as e:
        return failure_response(*e.args)
    except JsonableError:
        return failure_response()
    if isinstance(resp, HttpResponseNotAllowed):
        resp.content = METHOD_NOT_ALLOWED
    return resp


def rest_path(
    route: str,
    **handlers: Callable[..., HttpResponse],
) -> URLPattern:
    from django.urls import path

    return path(
        route,
        dispatch,
        {
            http_method: (require_realm_admin(handler), {"override_api_url_scheme"})
            for http_method, handler in handlers.items()
        }
    )
