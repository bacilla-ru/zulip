import base64
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, Dict, Set, Union
from unittest import mock

import orjson
from django.db import transaction
from django.forms.models import model_to_dict
from django.http import HttpRequest, HttpResponse
from django.test import override_settings
from django.utils.crypto import get_random_string
from django.utils.timezone import now as timezone_now

from zerver.actions.user_groups import (
    bulk_add_members_to_user_group, remove_members_from_user_group)
from zerver.actions.user_settings import (
    do_change_avatar_fields, do_change_full_name)
from zerver.actions.users import (
    do_change_can_create_users, do_change_user_role, do_deactivate_user)
from zerver.lib.test_classes import ZulipTestCase
from zerver.lib.test_helpers import avatar_disk_path
from zerver.lib.user_groups import create_user_group
from zerver.models import (
    UserGroup, UserGroupMembership, UserProfile, get_realm,
    get_user_by_delivery_email)

from ..lib.avatar import gen_avatar
from ..models import AuthToken, UserGroupMembershipStatus, UserProfileExt


class BaseTestCase(ZulipTestCase):
    def assert_json_success(
        self,
        result: Union["TestHttpResponse", HttpResponse],
        status_code: int = 200
    ) -> Dict[str, Any]:
        try:
            json = orjson.loads(result.content)
        except orjson.JSONDecodeError:  # nocoverage
            self.fail("Error parsing JSON in response")
        self.assertEqual(result.status_code, status_code)
        self.assertEqual(json.pop("ok"), True)
        return json

    def assert_json_error(
        self,
        result: "TestHttpResponse",
        status_code: int = 400,
        errors: Union[str, Set[str]] = set({"bad_request"})
    ) -> None:
        try:
            json = orjson.loads(result.content)
        except orjson.JSONDecodeError:  # nocoverage
            self.fail("Error parsing JSON in response")
        self.assertEqual(result.status_code, status_code)
        self.assertEqual(json.get("ok"), False)
        self.assertSetEqual(set(json.get("errors")), errors if isinstance(errors, set) else {errors})


class GetUserTest(BaseTestCase):

    def test_get_user(self):
        hamlet = self.example_user("hamlet")

        url = f"/iparty-internal/v1/user/1"

        result = self.client_get(url)
        self.assert_json_error(result, 401, "unauthorized")

        self.login("cordelia")
        result = self.client_get(url)
        self.assert_json_error(result, 403, "forbidden")

        self.login("iago")
        result = self.client_get(url)
        self.assert_json_error(result, 404, "not_found")

        UserProfileExt.objects.create(
            id=1,
            name="Hamlet",
            phone="9991234567",
            surname="King",
            user_profile=hamlet
        )
        result = self.client_get(url)
        result_json = self.assert_json_success(result)
        self.assertEqual(
            result_json,
            dict(
                account_type="internal",
                avatar=None,
                email="hamlet@zulip.com",
                groups=[dict(name="hamletcharacters", status="")],
                is_active=True,
                name="Hamlet",
                patronymic="",
                permissions=["messaging/*"],
                phone="9991234567",
                surname="King"
            )
        )


class CreateUserTest(BaseTestCase):
    def test_create_user(self):
        realm = get_realm("zulip")
        hamlet = self.example_user("hamlet")

        create_user_group("Verona", [], realm)

        self.assertFalse(
            UserProfileExt.objects.filter(pk=1).exists()
        )

        avatar = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQIW2NgmPb/PwAExAKVyQg5/QAAAABJRU5ErkJggg=="
        url = "/iparty-internal/v1/user/1"
        params = dict(
            account_type="internal",
            avatar=avatar,
            email="romeo@er.ru",
            groups=[dict(name="Verona", status="Idealistic lover")],
            name="Romeo",
            patronymic="X",
            permissions=["messaging/*"],
            phone="9991234567",
            surname="Montague"
        )

        result = self.client_post(url, params, content_type="application/json")
        self.assert_json_error(result, 401, "unauthorized")

        admin = self.example_user("cordelia")
        self.login_user(admin)
        self.assertEqual(admin.can_create_users, False)
        result = self.client_post(url, params, content_type="application/json")
        self.assert_json_error(result, 403, "forbidden")

        do_change_can_create_users(admin, True)
        result = self.client_post(url, params, content_type="application/json")
        self.assert_json_error(result, 403, "forbidden")

        do_change_can_create_users(admin, False)
        do_change_user_role(admin, UserProfile.ROLE_REALM_ADMINISTRATOR, acting_user=None)
        result = self.client_post(url, params, content_type="application/json")
        self.assert_json_error(result, 403, "forbidden")

        do_change_can_create_users(admin, True)

        result = self.client_post(url, dict(params, email=self.example_email("hamlet")), content_type="application/json")
        self.assert_json_error(result, 200, errors="email_already_in_use")

        self.assertFalse(
            UserGroup.objects.filter(name="Nonexistent", realm=realm).exists()
        )
        result = self.client_post(url, dict(params, groups=[dict(name="Nonexistent")]), content_type="application/json")
        self.assert_json_error(result, 200, errors="group_not_found")

        hamlet_ext = UserProfileExt.objects.create(
            id=2,
            name="Hamlet",
            phone="9991234567",
            surname="King",
            user_profile=hamlet
        )
        result = self.client_post(url, params, content_type="application/json")
        self.assert_json_error(result, 200, errors="phone_already_in_use")
        hamlet_ext.delete()

        hamlet_ext = UserProfileExt.objects.create(
            id=1,
            name="Hamlet",
            phone="9991234567",
            surname="King",
            user_profile=hamlet
        )
        self.assertTrue(hamlet.is_active)
        result = self.client_post(url, params, content_type="application/json")
        self.assert_json_error(result, 200, errors="user_already_exists")
        hamlet_ext.delete()

        result = self.client_post(url, params, content_type="application/json")
        result_json = self.assert_json_success(result, 201)
        self.assertEqual(result_json, {})
        new_user = get_user_by_delivery_email("romeo@er.ru", realm)
        self.assertEqual(new_user.full_name, "Montague Romeo X")
        self.assertEqual(new_user.avatar_source, UserProfile.AVATAR_FROM_USER)
        self.assertEqual(new_user.role, UserProfile.ROLE_MEMBER)
        new_user_ext = UserProfileExt.objects.get(pk=1)
        self.assertEqual(new_user_ext.account_type, "internal")
        self.assertEqual(new_user_ext.avatar.tobytes(), base64.b64decode(avatar))
        self.assertEqual(new_user_ext.name, "Romeo")
        self.assertEqual(new_user_ext.patronymic, "X")
        self.assertEqual(new_user_ext.permissions, ["messaging/*"])
        self.assertEqual(new_user_ext.phone, "9991234567")
        self.assertEqual(new_user_ext.surname, "Montague")
        self.assertEqual(new_user_ext.user_profile_id, new_user.id)
        self.assertTrue(
            new_user.direct_groups
            .filter(name="Verona", realm=realm)
            .exists()
        )
        self.assertEqual(
            UserGroupMembershipStatus.objects
            .filter(
                membership__user_group__name="Verona",
                membership__user_group__realm=realm,
                membership__user_profile=new_user
            )
            .first()
            .status,
            "Idealistic lover"
        )
        with open(avatar_disk_path(new_user, original=True), "rb") as fp:
            avatar_contents = fp.read()
        self.assertEqual(avatar_contents, base64.b64decode(avatar))

    def test_create_user_using_defaults(self):
        realm = get_realm("zulip")
        admin = self.example_user("iago")
        do_change_can_create_users(admin, True)
        self.login_user(admin)

        create_user_group("Verona", [], realm)

        url = "/iparty-internal/v1/user/1"
        params = dict(
            email="romeo@er.ru",
            name="Romeo",
            phone="9991234567",
            surname="Montague"
        )

        result = self.client_post(url, params, content_type="application/json")
        result_json = self.assert_json_success(result, 201)
        self.assertEqual(result_json, {})
        new_user = get_user_by_delivery_email("romeo@er.ru", realm)
        self.assertEqual(new_user.full_name, "Montague Romeo")
        self.assertEqual(new_user.avatar_source, UserProfile.AVATAR_FROM_USER)
        self.assertEqual(new_user.role, UserProfile.ROLE_MEMBER)
        new_user_ext = UserProfileExt.objects.get(pk=1)
        self.assertEqual(new_user_ext.account_type, "internal")
        self.assertIsNone(new_user_ext.avatar)
        self.assertEqual(new_user_ext.name, "Romeo")
        self.assertEqual(new_user_ext.patronymic, "")
        self.assertEqual(new_user_ext.permissions, ["messaging/*"])
        self.assertEqual(new_user_ext.phone, "9991234567")
        self.assertEqual(new_user_ext.surname, "Montague")
        self.assertEqual(new_user_ext.user_profile_id, new_user.id)
        self.assertFalse(
            new_user.direct_groups.select_related()
            .filter(is_system_group=False, realm=realm)
            .exists()
        )
        self.assertFalse(
            UserGroupMembershipStatus.objects
            .filter(
                membership__user_group__is_system_group=False,
                membership__user_group__realm=realm,
                membership__user_profile=new_user
            )
            .exists()
        )
        with open(avatar_disk_path(new_user, original=True), "rb") as fp:
            avatar_contents = fp.read()
        self.assertEqual(avatar_contents, gen_avatar("Montague Romeo", "MR").read())

    def test_create_user_with_tokens(self):
        admin = self.example_user("iago")
        do_change_can_create_users(admin, True)
        self.login_user(admin)

        url = "/iparty-internal/v1/user/1"
        params = dict(
            email="romeo@er.ru",
            name="Romeo",
            phone="9991234567",
            surname="Montague"
        )

        params["tokens"] = [dict(name="")]
        result = self.client_post(url, params, content_type="application/json")
        self.assert_json_error(result)

        params["tokens"] = [dict(name="default", fcm_token="")]
        result = self.client_post(url, params, content_type="application/json")
        self.assert_json_error(result)

        params["tokens"] = [dict(name="default")] * 2
        result = self.client_post(url, params, content_type="application/json")
        self.assert_json_error(result)

        random_fcm_token_1 = get_random_string(40)
        params["tokens"] = [
            dict(name="default"),
            dict(name="iPhone 13", fcm_token=None),
            dict(name="Pixel 7 Pro", fcm_token=random_fcm_token_1),
        ]
        unix_time = timezone_now().timestamp()
        result = self.client_post(url, params, content_type="application/json")
        result_json = self.assert_json_success(result, 201)
        new_user_ext: UserProfileExt = UserProfileExt.objects.select_related("user_profile").get(pk=1)
        new_user: UserProfile = new_user_ext.user_profile
        tokens: List[Dict[str, Any]] = result_json["tokens"]
        self.assertEqual(
            {token["name"] for token in tokens},
            {token["name"] for token in params["tokens"]}
        )
        for token in tokens:
            self.assertGreater(token["expires"], unix_time)
            self.assert_length(token["token"], 40)
            kwargs = dict(name=token["name"], token__iregex=r"^[\w-]{40}\Z", user_profile=new_user)
            if token["name"] == "Pixel 7 Pro":
                kwargs["fcm_token"] = random_fcm_token_1
            self.assertTrue(AuthToken.objects.filter(**kwargs).exists())

    def test_reactivate_user(self):
        realm = get_realm("zulip")
        create_user_group("Verona", [], realm)
        hamlet = self.example_user("hamlet")
        UserProfileExt.objects.create(
            id=1,
            avatar=b"",
            name="Hamlet",
            phone="9997654321",
            surname="King",
            user_profile=hamlet
        )

        admin = self.example_user("iago")
        do_change_can_create_users(admin, True)
        self.login_user(admin)

        url = "/iparty-internal/v1/user/1"
        params = dict(
            email="HAMLET@zulip.com",
            groups=[dict(name="Verona", status="Idealistic lover")],
            name="Romeo",
            phone="9991234567",
            surname="Montague"
        )

        result = self.client_post(url, params, content_type="application/json")
        self.assert_json_error(result, 200, "user_already_exists")

        do_deactivate_user(hamlet, acting_user=None)
        result = self.client_post(url, {**params, "email": "romeo@er.ru"}, content_type="application/json")
        self.assert_json_error(result, 200, "email_can_not_be_changed")

        result = self.client_post(url, params, content_type="application/json")
        result_json = self.assert_json_success(result)
        self.assertEqual(result_json, {})
        new_user = self.example_user("hamlet")
        self.assertTrue(new_user.is_active)
        self.assertEqual(new_user.full_name, "Montague Romeo")
        self.assertEqual(new_user.avatar_source, UserProfile.AVATAR_FROM_USER)
        self.assertEqual(new_user.role, UserProfile.ROLE_MEMBER)
        new_user_ext = UserProfileExt.objects.get(pk=1)
        self.assertEqual(new_user_ext.account_type, "internal")
        self.assertIsNone(new_user_ext.avatar)
        self.assertEqual(new_user_ext.name, "Romeo")
        self.assertEqual(new_user_ext.patronymic, "")
        self.assertEqual(new_user_ext.permissions, ["messaging/*"])
        self.assertEqual(new_user_ext.phone, "9991234567")
        self.assertEqual(new_user_ext.surname, "Montague")
        self.assertEqual(new_user_ext.user_profile_id, new_user.id)
        self.assertTrue(
            new_user.direct_groups
            .filter(name="Verona", realm=realm)
            .exists()
        )
        self.assertEqual(
            UserGroupMembershipStatus.objects
            .filter(
                membership__user_group__name="Verona",
                membership__user_group__realm=realm,
                membership__user_profile=new_user
            )
            .first()
            .status,
            "Idealistic lover"
        )


class UpdateUserTest(BaseTestCase):

    def test_update_user(self):
        realm = get_realm("zulip")
        create_user_group("Verona", [], realm)
        hamlet = self.example_user("hamlet")
        do_change_avatar_fields(hamlet, UserProfile.AVATAR_FROM_GRAVATAR, skip_notify=True, acting_user=None)

        UserProfileExt.objects.create(
            id=1,
            account_type="external",
            avatar=b"",
            name="Hamlet",
            # patronymic="",
            permissions=["messaging/bellow"],
            phone="9997654321",
            surname="King",
            user_profile=hamlet
        )

        avatar = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQIW2NgmPb/PwAExAKVyQg5/QAAAABJRU5ErkJggg=="
        url = "/iparty-internal/v1/user/1"
        params = dict(
            account_type="internal",
            avatar=avatar,
            email="romeo@er.ru",
            groups=[dict(name="Verona", status="Idealistic lover")],
            name="Romeo",
            patronymic="X",
            permissions=["messaging/*"],
            phone="9991234567",
            surname="Montague"
        )

        result = self.json_put(url, params)
        self.assert_json_error(result, 401, "unauthorized")

        self.login("cordelia")
        result = self.json_put(url, params)
        self.assert_json_error(result, 403, "forbidden")

        self.login("iago")
        result = self.json_put(url[:-1] + "2", params)
        self.assert_json_error(result, 404, "not_found")

        # TODO: check various bad inputs
        # - group_not_found
        # - phone_already_in_use

        result = self.json_put(url, params)
        result_json = self.assert_json_success(result)
        self.assertEqual(result_json, {})
        upd_user = self.example_user("hamlet")
        self.assertEqual(upd_user.full_name, "Montague Romeo X")
        self.assertEqual(upd_user.delivery_email, "hamlet@zulip.com")
        self.assertEqual(upd_user.avatar_source, UserProfile.AVATAR_FROM_USER)
        self.assertEqual(upd_user.role, UserProfile.ROLE_MEMBER)
        upd_user_ext = UserProfileExt.objects.get(pk=1)
        self.assertEqual(upd_user_ext.account_type, "internal")
        self.assertEqual(upd_user_ext.avatar.tobytes(), base64.b64decode(avatar))
        self.assertEqual(upd_user_ext.name, "Romeo")
        self.assertEqual(upd_user_ext.patronymic, "X")
        self.assertEqual(upd_user_ext.permissions, ["messaging/*"])
        self.assertEqual(upd_user_ext.phone, "9991234567")
        self.assertEqual(upd_user_ext.surname, "Montague")
        self.assertEqual(upd_user_ext.user_profile_id, upd_user.id)
        self.assertTrue(
            upd_user.direct_groups
            .filter(name="Verona", realm=realm)
            .exists()
        )
        self.assertEqual(
            UserGroupMembershipStatus.objects
            .filter(
                membership__user_group__name="Verona",
                membership__user_group__realm=realm,
                membership__user_profile=upd_user
            )
            .first()
            .status,
            "Idealistic lover"
        )
        with open(avatar_disk_path(upd_user, original=True), "rb") as fp:
            avatar_contents = fp.read()
        self.assertEqual(avatar_contents, base64.b64decode(avatar))

    def test_update_user_using_defaults(self):
        realm = get_realm("zulip")
        hamlet = self.example_user("hamlet")
        membership = UserGroupMembership.objects.get(
            user_group=create_user_group("Denmark", [hamlet], realm),
            user_profile=hamlet
        )
        UserGroupMembershipStatus.objects.create(membership=membership, status="Prince of Denmark")
        do_change_avatar_fields(hamlet, UserProfile.AVATAR_FROM_GRAVATAR, skip_notify=True, acting_user=None)
        UserProfileExt.objects.create(
            id=1,
            account_type="external",
            avatar=b"",
            name="Hamlet",
            patronymic="X",
            permissions=["messaging/bellow"],
            phone="9997654321",
            surname="King",
            user_profile=hamlet
        )

        url = "/iparty-internal/v1/user/1"
        params = dict(
            name="Romeo",
            phone="9991234567",
            surname="Montague"
        )

        self.login("iago")
        result = self.json_put(url, params)
        result_json = self.assert_json_success(result)
        self.assertEqual(result_json, {})
        upd_user = self.example_user("hamlet")
        self.assertEqual(upd_user.full_name, "Montague Romeo")
        self.assertEqual(upd_user.delivery_email, "hamlet@zulip.com")
        self.assertEqual(upd_user.avatar_source, UserProfile.AVATAR_FROM_USER)
        self.assertEqual(upd_user.role, UserProfile.ROLE_MEMBER)
        upd_user_ext = UserProfileExt.objects.get(pk=1)
        self.assertEqual(upd_user_ext.account_type, "internal")
        self.assertIsNone(upd_user_ext.avatar)
        self.assertEqual(upd_user_ext.name, "Romeo")
        self.assertEqual(upd_user_ext.patronymic, "")
        self.assertEqual(upd_user_ext.permissions, ["messaging/*"])
        self.assertEqual(upd_user_ext.phone, "9991234567")
        self.assertEqual(upd_user_ext.surname, "Montague")
        self.assertEqual(upd_user_ext.user_profile_id, upd_user.id)
        self.assertFalse(
            upd_user.direct_groups
            .filter(name="Denmark", realm=realm)
            .exists()
        )
        with open(avatar_disk_path(upd_user, original=True), "rb") as fp:
            avatar_contents = fp.read()
        self.assertEqual(avatar_contents, gen_avatar("Montague Romeo", "MR").read())

    def test_update_deactivated_user(self):
        # test user group membership is not changed
        pass

    def test_partial_update_user(self):
        realm = get_realm("zulip")
        hamlet = self.example_user("hamlet")
        membership = UserGroupMembership.objects.get(
            user_group=create_user_group("Denmark", [hamlet], realm),
            user_profile=hamlet
        )
        UserGroupMembershipStatus.objects.create(membership=membership, status="King of Denmark")
        do_change_avatar_fields(hamlet, UserProfile.AVATAR_FROM_GRAVATAR, skip_notify=True, acting_user=None)
        create_user_group("Fathers", [], realm)

        url = "/iparty-internal/v1/user/1"

        result = self.json_patch(url, {})
        self.assert_json_error(result, 401, "unauthorized")

        admin = self.example_user("cordelia")
        self.login_user(admin)

        result = self.json_patch(url, {})
        self.assert_json_error(result, 403, "forbidden")

        do_change_user_role(admin, UserProfile.ROLE_REALM_ADMINISTRATOR, acting_user=None)

        result = self.json_patch(url[:-1] + "2", {})
        self.assert_json_error(result, 404, "not_found")

        # TODO: check various bad inputs
        # - group_not_found
        # - phone_already_in_use

        def assert_equal(user_ext1: UserProfileExt, user_ext2: UserProfileExt, exclude=None):
            for f in UserProfileExt._meta.get_fields():
                if exclude and f.name in exclude:
                    continue
                val1, val2 = f.value_from_object(user_ext1), f.value_from_object(user_ext2)
                self.assertEqual(val1, val2)

        # noinspection PyShadowingNames
        @contextmanager
        def test_patch(**kwargs):
            with transaction.atomic():
                try:
                    UserProfileExt.objects.create(
                        id=1,
                        account_type="external",
                        avatar=b"SAMPLE",
                        name="Hamlet",
                        permissions=["messaging/bellow"],
                        phone="9997654321",
                        surname="King",
                        user_profile=hamlet
                    )
                    original_user_ext = UserProfileExt.objects.get(pk=1)
                    result = self.json_patch(url, kwargs)
                    result_json = self.assert_json_success(result)
                    self.assertEqual(result_json, {})
                    upd_user_ext = UserProfileExt.objects.get(pk=1)
                    assert_equal(upd_user_ext, original_user_ext, set(kwargs))
                    yield self.example_user("hamlet"), upd_user_ext, original_user_ext
                finally:
                    transaction.set_rollback(True)

        with test_patch():
            pass

        with test_patch(email="romeo@er.ru") as (upd_user, upd_user_ext, original_user_ext):
            self.assertEqual(upd_user.delivery_email, "hamlet@zulip.com")

        with test_patch(account_type="internal") as (_, upd_user_ext, _):
            self.assertEqual(upd_user_ext.account_type, "internal")

        avatar = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQIW2NgmPb/PwAExAKVyQg5/QAAAABJRU5ErkJggg=="
        with test_patch(avatar=avatar) as (upd_user, upd_user_ext, _):
            self.assertEqual(upd_user_ext.avatar.tobytes(), base64.b64decode(avatar))
            self.assertEqual(upd_user.avatar_source, UserProfile.AVATAR_FROM_USER)
            with open(avatar_disk_path(upd_user, original=True), "rb") as fp:
                avatar_contents = fp.read()
            self.assertEqual(avatar_contents, base64.b64decode(avatar))

        with test_patch(name="Romeo") as (upd_user, upd_user_ext, _):
            self.assertEqual(upd_user_ext.name, "Romeo")
            self.assertEqual(upd_user.full_name, "King Romeo")

        with test_patch(surname="Montague") as (upd_user, upd_user_ext, _):
            self.assertEqual(upd_user_ext.surname, "Montague")
            self.assertEqual(upd_user.full_name, "Montague Hamlet")

        with test_patch(name="Romeo", surname="Montague") as (upd_user, upd_user_ext, _):
            self.assertEqual(upd_user_ext.name, "Romeo")
            self.assertEqual(upd_user_ext.surname, "Montague")
            self.assertEqual(upd_user.full_name, "Montague Romeo")

        with test_patch(patronymic="ofDenmark") as (upd_user, upd_user_ext, _):
            self.assertEqual(upd_user_ext.patronymic, "ofDenmark")
            self.assertEqual(upd_user.full_name, "King Hamlet ofDenmark")

        with test_patch(permissions=["messaging/*"]) as (_, upd_user_ext, _):
            self.assertEqual(upd_user_ext.permissions, ["messaging/*"])

        with test_patch(phone="9991234567") as (_, upd_user_ext, _):
            self.assertEqual(upd_user_ext.phone, "9991234567")

        with test_patch(groups=[dict(name="Fathers", status="Father of Prince Hamlet")]) as (upd_user, _, _):
            self.assertTrue(
                upd_user.direct_groups
                .filter(name="Fathers", realm=realm)
                .exists()
            )
            self.assertFalse(
                upd_user.direct_groups
                .filter(name="Kings", realm=realm)
                .exists()
            )
            self.assertEqual(
                UserGroupMembershipStatus.objects
                .filter(
                    membership__user_group__name="Fathers",
                    membership__user_group__realm=realm,
                    membership__user_profile=upd_user
                )
                .first()
                .status,
                "Father of Prince Hamlet"
            )

    def test_deactivate_user(self):
        realm = get_realm("zulip")
        hamlet = self.example_user("hamlet")
        user_group = create_user_group("Denmark", [hamlet], realm)
        membership = UserGroupMembership.objects.get(
            user_group=user_group,
            user_profile=hamlet
        )
        UserGroupMembershipStatus.objects.create(membership=membership, status="Prince of Denmark")
        UserProfileExt.objects.create(
            id=1,
            name="Hamlet",
            phone="9997654321",
            surname="King",
            user_profile=hamlet
        )
        AuthToken.objects.create(name="default", user_profile=hamlet)

        url = "/iparty-internal/v1/user/1"

        result = self.client_delete(url)
        self.assert_json_error(result, 401, "unauthorized")

        admin = self.example_user("cordelia")
        self.login_user(admin)

        result = self.client_delete(url)
        self.assert_json_error(result, 403, "forbidden")

        do_change_user_role(admin, UserProfile.ROLE_REALM_ADMINISTRATOR, acting_user=None)

        result = self.client_delete(url[:-1] + "2")
        self.assert_json_error(result, 404, "not_found")

        result = self.client_delete(url)
        result_json = self.assert_json_success(result)
        self.assertEqual(result_json, {})
        hamlet = self.example_user("hamlet")
        self.assertFalse(hamlet.is_active)
        self.assertFalse(
            UserGroupMembership.objects
            .filter(user_group__is_system_group=False, user_profile=hamlet)
            .exists()
        )
        self.assertFalse(
            AuthToken.objects.filter(user_profile=hamlet).exists()
        )


class AuthTokenTest(BaseTestCase):

    def client_put_plain_text(
        self,
        url: str,
        info: str = "",
        skip_user_agent: bool = False,
        follow: bool = False,
        secure: bool = False,
        **extra: str,
    ) -> "TestHttpResponse":
        extra["content_type"] = "text/plain"
        django_client = self.client  # see WRAPPER_COMMENT
        self.set_http_headers(extra, skip_user_agent)
        return django_client.put(url, info, follow=follow, secure=secure, **extra)

    def create_hamlet_user_profile_ext(self) -> UserProfile:
        hamlet = self.example_user("hamlet")
        UserProfileExt.objects.create(
            id=1,
            name="Hamlet",
            phone="9991234567",
            surname="King",
            user_profile=hamlet
        )
        return hamlet

    def test_get_tokens(self):
        hamlet = self.create_hamlet_user_profile_ext()
        existing_tokens: Dict[str, AuthToken] = {
            name: AuthToken.objects.create(name=name, user_profile=hamlet)
            for name in ["default", "iPhone 13", "Pixel 7 Pro"]
        }

        url = f"/iparty-internal/v1/user/1/tokens"

        result = self.client_get(url)
        self.assert_json_error(result, 401, "unauthorized")

        self.login("cordelia")
        result = self.client_get(url)
        self.assert_json_error(result, 403, "forbidden")

        self.login("iago")
        result = self.client_get(url.replace("r/1/t", "r/2/t"))
        self.assert_json_error(result, 404, "not_found")

        result = self.client_get(url)
        result_json = self.assert_json_success(result)
        tokens: List[Dict[str, Any]] = result_json["tokens"]
        self.assertEqual({token["name"] for token in tokens}, {"default", "iPhone 13", "Pixel 7 Pro"})
        for token in tokens:
            self.assertEqual(token["expires"], existing_tokens[token["name"]].expires)
            self.assert_length(token["token"], 40)
            self.assertEqual(token["token"], existing_tokens[token["name"]].token)

    def test_get_existing_token(self):
        hamlet = self.create_hamlet_user_profile_ext()
        existing_token = AuthToken.objects.create(name="default", user_profile=hamlet)

        url = f"/iparty-internal/v1/user/1/tokens/default"

        result = self.client_get(url)
        self.assert_json_error(result, 401, "unauthorized")

        self.login("cordelia")
        result = self.client_get(url)
        self.assert_json_error(result, 403, "forbidden")

        self.login("iago")
        result = self.client_get(url.replace("r/1/t", "r/2/t"))
        self.assert_json_error(result, 404, "not_found")

        result = self.client_get(url)
        result_json = self.assert_json_success(result)
        self.assertEqual(result_json, dict(
            expires=existing_token.expires,
            name=existing_token.name,
            token=existing_token.token
        ))

    def test_get_non_existent_token(self):
        hamlet = self.create_hamlet_user_profile_ext()
        self.assertFalse(
            AuthToken.objects.filter(name="default", user_profile=hamlet).exists()
        )
        url = f"/iparty-internal/v1/user/1/tokens/default"
        self.login("iago")
        result = self.client_get(url)
        result_json = self.assert_json_success(result, 201)
        token = AuthToken.objects.get(name="default", user_profile=hamlet)
        self.assertEqual(result_json, dict(
            expires=token.expires,
            name=token.name,
            token=token.token
        ))

    def test_refresh_existing_token(self):
        hamlet = self.create_hamlet_user_profile_ext()
        AuthToken.objects.create(name="default", user_profile=hamlet)
        AuthToken.objects.filter(name="default", user_profile=hamlet).update(
            issued=(timezone_now() - timedelta(hours=1)).replace(microsecond=0)
        )
        existing_token = AuthToken.objects.get(name="default", user_profile=hamlet)

        url = f"/iparty-internal/v1/user/1/tokens/default"

        result = self.json_put(url)
        self.assert_json_error(result, 401, "unauthorized")

        self.login("cordelia")
        result = self.json_put(url)
        self.assert_json_error(result, 403, "forbidden")

        self.login("iago")
        result = self.json_put(url.replace("r/1/t", "r/2/t"))
        self.assert_json_error(result, 404, "not_found")

        result = self.json_put(url)
        result_json = self.assert_json_success(result)
        refreshed_token = AuthToken.objects.get(name="default", user_profile=hamlet)
        self.assertEqual(result_json, dict(
            expires=refreshed_token.expires,
            name=refreshed_token.name,
            token=refreshed_token.token
        ))
        self.assertNotEqual(refreshed_token.token, existing_token.token)
        self.assertNotEqual(refreshed_token.issued, existing_token.issued)

    def test_refresh_non_existent_token(self):
        hamlet = self.create_hamlet_user_profile_ext()
        self.assertFalse(
            AuthToken.objects.filter(name="default", user_profile=hamlet).exists()
        )
        url = f"/iparty-internal/v1/user/1/tokens/default"
        self.login("iago")
        result = self.json_put(url)
        result_json = self.assert_json_success(result, 201)
        token = AuthToken.objects.get(name="default", user_profile=hamlet)
        self.assertEqual(result_json, dict(
            expires=token.expires,
            name=token.name,
            token=token.token
        ))

    def test_delete_token(self):
        hamlet = self.create_hamlet_user_profile_ext()
        for name in ["default", "iPhone 13", "Pixel 7 Pro"]:
            AuthToken.objects.create(name=name, user_profile=hamlet)

        url = f"/iparty-internal/v1/user/1/tokens/Pixel 7 Pro"

        result = self.client_delete(url)
        self.assert_json_error(result, 401, "unauthorized")

        self.login("cordelia")
        result = self.client_delete(url)
        self.assert_json_error(result, 403, "forbidden")

        self.login("iago")
        result = self.client_delete(url.replace("r/1/t", "r/2/t"))
        self.assert_json_error(result, 404, "not_found")

        result = self.client_delete(url)
        result_json = self.assert_json_success(result)
        self.assertEqual(result_json, {})
        for name in ["default", "iPhone 13"]:
            self.assertTrue(
                AuthToken.objects.filter(name=name, user_profile=hamlet).exists()
            )
        self.assertFalse(
            AuthToken.objects.filter(name="Pixel 7 Pro", user_profile=hamlet).exists()
        )

    def test_delete_non_existent_token(self):
        hamlet = self.create_hamlet_user_profile_ext()
        self.assertFalse(
            AuthToken.objects.filter(name="default", user_profile=hamlet).exists()
        )
        url = f"/iparty-internal/v1/user/1/tokens/default"
        self.login("iago")
        result = self.client_delete(url)
        self.assert_json_success(result)

    def test_create_fcm_token_in_existing_auth_token(self):
        hamlet = self.create_hamlet_user_profile_ext()
        existing_token = AuthToken.objects.create(name="default", user_profile=hamlet)
        self.assertIsNone(existing_token.fcm_token)

        url = f"/iparty-internal/v1/user/1/tokens/default/fcm-token"
        fcm_token = get_random_string(60)

        result = self.client_put_plain_text(url, fcm_token)
        self.assert_json_error(result, 401, "unauthorized")

        self.login("cordelia")
        result = self.client_put_plain_text(url, fcm_token)
        self.assert_json_error(result, 403, "forbidden")

        self.login("iago")
        result = self.client_put_plain_text(url.replace("r/1/t", "r/2/t"), fcm_token)
        self.assert_json_error(result, 404, "not_found")

        result = self.client_put_plain_text(url, fcm_token)
        result_json = self.assert_json_success(result, 201)
        self.assertEqual(result_json, {})
        updated_token = AuthToken.objects.get(name="default", user_profile=hamlet)
        self.assertEqual(updated_token.fcm_token, fcm_token)
        self.assertEqual(updated_token.token, existing_token.token)
        self.assertEqual(updated_token.expires, existing_token.expires)
        self.assertEqual(updated_token.issued, existing_token.issued)

    def test_update_fcm_token_in_existing_auth_token(self):
        hamlet = self.create_hamlet_user_profile_ext()
        existing_token = AuthToken.objects.create(name="default", user_profile=hamlet, fcm_token="OLD")

        url = f"/iparty-internal/v1/user/1/tokens/default/fcm-token"
        fcm_token = get_random_string(60)

        self.login("iago")
        result = self.client_put_plain_text(url, fcm_token)
        result_json = self.assert_json_success(result)
        self.assertEqual(result_json, {})
        updated_token = AuthToken.objects.get(name="default", user_profile=hamlet)
        self.assertEqual(updated_token.fcm_token, fcm_token)
        self.assertEqual(updated_token.token, existing_token.token)
        self.assertEqual(updated_token.expires, existing_token.expires)
        self.assertEqual(updated_token.issued, existing_token.issued)

    def test_create_fcm_token_creates_auth_token(self):
        hamlet = self.create_hamlet_user_profile_ext()
        self.assertFalse(
            AuthToken.objects.filter(name="default", user_profile=hamlet).exists()
        )

        url = f"/iparty-internal/v1/user/1/tokens/default/fcm-token"
        fcm_token = get_random_string(60)

        self.login("iago")
        result = self.client_put_plain_text(url, fcm_token)
        result_json = self.assert_json_success(result, 201)
        created_token = AuthToken.objects.get(name="default", user_profile=hamlet)
        self.assertEqual(result_json, dict(
            expires=created_token.expires,
            name=created_token.name,
            token=created_token.token
        ))
        self.assertEqual(created_token.fcm_token, fcm_token)

    def test_delete_existing_fcm_token(self):
        hamlet = self.create_hamlet_user_profile_ext()
        existing_token = AuthToken.objects.create(
            name="default",
            user_profile=hamlet,
            fcm_token=get_random_string(60)
        )

        url = f"/iparty-internal/v1/user/1/tokens/default/fcm-token"

        result = self.client_delete(url)
        self.assert_json_error(result, 401, "unauthorized")

        self.login("cordelia")
        result = self.client_delete(url)
        self.assert_json_error(result, 403, "forbidden")

        self.login("iago")
        result = self.client_delete(url.replace("r/1/t", "r/2/t"))
        self.assert_json_error(result, 404, "not_found")

        result = self.client_delete(url)
        result_json = self.assert_json_success(result)
        self.assertEqual(result_json, {})
        updated_token = AuthToken.objects.get(name="default", user_profile=hamlet)
        self.assertIsNone(updated_token.fcm_token)
        self.assertEqual(updated_token.token, existing_token.token)
        self.assertEqual(updated_token.expires, existing_token.expires)
        self.assertEqual(updated_token.issued, existing_token.issued)

    def test_delete_non_existent_fcm_token(self):
        hamlet = self.create_hamlet_user_profile_ext()
        existing_token = AuthToken.objects.create(name="default", user_profile=hamlet)
        self.assertIsNone(existing_token.fcm_token)
        url = f"/iparty-internal/v1/user/1/tokens/default/fcm-token"
        self.login("iago")
        result = self.client_delete(url)
        result_json = self.assert_json_success(result)
        self.assertEqual(result_json, {})
        updated_token = AuthToken.objects.get(name="default", user_profile=hamlet)
        self.assertIsNone(updated_token.fcm_token)
        updated_token.delete()
        self.assertFalse(
            AuthToken.objects.filter(name="default", user_profile=hamlet).exists()
        )
        result = self.client_delete(url)
        result_json = self.assert_json_success(result)
        self.assertEqual(result_json, {})
