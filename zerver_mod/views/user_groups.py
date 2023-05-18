from typing import Any, Dict, List

from django.db.models.functions import Lower
from django.http import HttpRequest, HttpResponse

from zerver.decorator import require_member_or_admin
from zerver.lib.cache import realm_user_dict_fields
from zerver.lib.exceptions import JsonableError
from zerver.lib.request import REQ, has_request_variables
from zerver.lib.response import json_success
from zerver.lib.user_groups import (
    access_user_group_by_id, get_user_group_direct_members)
from zerver.lib.users import format_user_row
from zerver.lib.validator import check_bool, check_int, check_list
from zerver.models import UserGroup, UserProfile

from ..lib.user_groups import (
    get_membership_statuses, get_recursive_groups_with_accessible_members)
from ..models import UserGroupMembershipStatus


@require_member_or_admin
@has_request_variables
def get_user_groups_with_accessible_members_tree(request: HttpRequest, user_profile: UserProfile) -> HttpResponse:
    subgroups_by_level_and_supergroup: Dict[int, Dict[int, List[UserGroup]]] = dict()  # { <level>: { <group-id>: [<subgroups>], ... }, ... }
    top_level_groups: List[UserGroup] = []
    for group in get_recursive_groups_with_accessible_members(user_profile=user_profile):
        if group.supergroup_id is None:
            top_level_groups.append(group)
        else:
            subgroups_by_level_and_supergroup.setdefault(group.level - 1, {}).setdefault(group.supergroup_id, []).append(group)

    def serialize(groups: List[UserGroup]) -> List[dict]:
        result: List[dict] = []
        for group in groups:
            try:
                subgroups: List[UserGroup] = subgroups_by_level_and_supergroup[group.level][group.id]
            except KeyError:
                subgroups = []
            result.append({
                "description": group.description,
                "id": group.id,
                "name": group.name,
                "subgroups": serialize(subgroups),
                "total_direct_members": group.total_direct_members
            })
        return result

    return json_success(request, data=dict(user_groups_tree=serialize(top_level_groups)))


@require_member_or_admin
@has_request_variables
def get_user_group_direct_member_users(
    request: HttpRequest,
    user_profile: UserProfile,
    user_group_id: int = REQ(json_validator=check_int, path_only=True),
) -> HttpResponse:
    user_group: UserGroup = access_user_group_by_id(user_group_id, user_profile, for_read=True)
    user_dicts: List[Dict[str, Any]] = list(
        get_user_group_direct_members(user_group)
        .filter(is_active=True)
        .exclude(id=user_profile.id)
        .order_by(Lower("full_name"), "delivery_email")
        .values(*realm_user_dict_fields)
    )
    membership_statuses = get_membership_statuses(user_group, [x["id"] for x in user_dicts])
    result: List[Dict[str, Any]] = []
    for row in user_dicts:
        user = format_user_row(
            user_profile.realm,
            acting_user=user_profile,
            row=row,
            client_gravatar=True,
            user_avatar_url_field_optional=False
        )
        user["membership_status"] = membership_statuses.get(row["id"], "")
        result.append(user)
    return json_success(request, data=dict(members=result))
