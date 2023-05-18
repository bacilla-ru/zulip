from typing import Dict, List

from django.db.models import BooleanField, Count, F, IntegerField, Q, QuerySet, Value
from django.db.models.functions import Cast
from django_cte import With

from zerver.models import UserGroup, UserProfile

from ..models import UserGroupMembershipStatus


def get_recursive_groups_with_accessible_members(user_profile: UserProfile) -> QuerySet[UserGroup]:
    groups_cte = With.recursive(
        lambda cte:
        user_profile.direct_groups
        .exclude(is_system_group=True)
        .values("id", level=Value(1), supergroup_id=Cast(None, output_field=IntegerField()))
        .union(
            cte.join(UserGroup, direct_supergroups=cte.col.id)
            .filter(is_system_group=False)
            .values("id", level=cte.col.level + Value(1), supergroup_id=F("direct_supergroups__id")),
            all=True
        ),
        name="w1"
    )
    links_groups_cte = With(
        groups_cte.join(UserGroup, direct_subgroups=groups_cte.col.id)
        .filter(name__startswith="@link:")
        .values("id", level=groups_cte.col.level, supergroup_id=groups_cte.col.supergroup_id),
        name="w2"
    )
    linked_groups_cte = With(
        links_groups_cte.join(UserGroup, direct_supergroups=links_groups_cte.col.id)
        .exclude(id__in=groups_cte.queryset().values("id"))
        .values("id", level=links_groups_cte.col.level, supergroup_id=links_groups_cte.col.supergroup_id),
        name="w3"
    )
    groups_and_linked_groups_cte = With(
        groups_cte.queryset().values("id", "level", "supergroup_id")
        .union(
            linked_groups_cte.queryset().values("id", "level", "supergroup_id"),
            all=True
        ),
        name="w4"
    )
    return (
        groups_and_linked_groups_cte.join(UserGroup, id=groups_and_linked_groups_cte.col.id)
        .with_cte(groups_cte)
        .with_cte(links_groups_cte)
        .with_cte(linked_groups_cte)
        .with_cte(groups_and_linked_groups_cte)
        .annotate(
            level=groups_and_linked_groups_cte.col.level,
            supergroup_id=groups_and_linked_groups_cte.col.supergroup_id,
            total_direct_members=Count(
                Q(direct_members__is_active=True) | Value(None, output_field=BooleanField())
            )
        )
        .order_by("name")
    )


def get_membership_statuses(user_group: UserGroup, user_profile_ids: List[int]) -> Dict[int, str]:
    return {
        x["user_profile_id"]: x["status"] for x in 
        UserGroupMembershipStatus.objects.filter(
            membership__user_group=user_group, membership__user_profile__id__in=user_profile_ids
        ).values("status", user_profile_id=F("membership__user_profile__id"))
    }
