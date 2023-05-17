from typing import Dict, List

from django.http import HttpRequest, HttpResponse

from zerver.decorator import require_member_or_admin
from zerver.lib.exceptions import JsonableError
from zerver.lib.request import REQ, has_request_variables
from zerver.lib.response import json_success
from zerver.lib.validator import check_bool, check_int, check_list
from zerver.models import UserGroup, UserProfile

from ..lib.user_groups import get_recursive_groups_with_accessible_members


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

    ret = dict(
        user_groups_tree=serialize(top_level_groups),
        result="success",
        msg="",
    )
    return json_success(request, data=ret)
