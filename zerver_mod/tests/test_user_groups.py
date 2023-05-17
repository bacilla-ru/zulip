from typing import List, Optional

from zerver.lib.test_classes import ZulipTestCase
from zerver.models import (
    GroupGroupMembership,
    UserGroup,
    UserGroupMembership,
    get_realm,
)

from zerver_mod.lib.user_groups import get_recursive_groups_with_accessible_members


class UserGroupTestCase(ZulipTestCase):
    def test_get_recursive_groups_with_accessible_members(self) -> None:
        realm = get_realm("zulip")

        desdemona = self.example_user("desdemona")
        shiva = self.example_user("shiva")

        def create(name: str, supergroup: Optional[UserGroup] = None) -> UserGroup:
            result: UserGroup = UserGroup.objects.create(realm=realm, name=name)
            if supergroup:
                GroupGroupMembership.objects.create(supergroup=supergroup, subgroup=result)
            return result

        def create_link(name: str, first_group: UserGroup, second_group: UserGroup) -> UserGroup:
            result: UserGroup = UserGroup.objects.create(realm=realm, name="@link:" + name)
            GroupGroupMembership.objects.create(supergroup=result, subgroup=first_group)
            GroupGroupMembership.objects.create(supergroup=result, subgroup=second_group)
            return result

        federals_group = create(name="Federals")
        region_1_group = create(name="Region 1", supergroup=federals_group)
        region_2_group = create(name="Region 2", supergroup=federals_group)
        reg_office_1_1_group = create(name="Reg Office 1-1", supergroup=region_1_group)
        reg_office_1_2_group = create(name="Reg Office 1-2", supergroup=region_1_group)
        reg_office_2_1_group = create(name="Reg Office 2-1", supergroup=region_2_group)
        reg_office_2_2_group = create(name="Reg Office 2-2", supergroup=region_2_group)
        loc_office_1_1_1_group = create(name="Loc Office 1-1-1", supergroup=reg_office_1_1_group)
        loc_office_1_1_2_group = create(name="Loc Office 1-1-2", supergroup=reg_office_1_1_group)
        loc_office_1_2_1_group = create(name="Loc Office 1-2-1", supergroup=reg_office_1_2_group)
        loc_office_1_2_2_group = create(name="Loc Office 1-2-2", supergroup=reg_office_1_2_group)
        loc_office_2_1_1_group = create(name="Loc Office 2-1-1", supergroup=reg_office_2_1_group)
        loc_office_2_1_2_group = create(name="Loc Office 2-1-2", supergroup=reg_office_2_1_group)
        loc_office_2_2_1_group = create(name="Loc Office 2-2-1", supergroup=reg_office_2_2_group)
        loc_office_2_2_2_group = create(name="Loc Office 2-2-2", supergroup=reg_office_2_2_group)
        unit1_group = create(name="Unit 1")
        link_1_group = create_link("Reg Office 1-1 <-> Reg Office 2-2", reg_office_1_1_group, reg_office_2_2_group)
        link_2_group = create_link("Loc Office 2-2-1 <-> Unit 1", loc_office_2_2_1_group, unit1_group)

        UserGroupMembership.objects.create(user_profile=desdemona, user_group=reg_office_2_2_group)
        UserGroupMembership.objects.create(user_profile=shiva, user_group=federals_group)

        desdemona_groups_names = {x.name for x in get_recursive_groups_with_accessible_members(desdemona)}
        self.assertSetEqual(desdemona_groups_names, {
            "Reg Office 2-2",
            "Reg Office 1-1",
            "Loc Office 2-2-1",
            "Loc Office 2-2-2",
            "Unit 1"
        })

        for group in get_recursive_groups_with_accessible_members(desdemona):
            if group.name == "Reg Office 2-2":
                self.assertIsNone(group.supergroup_id)
                self.assertEqual(group.level, 1)
            elif group.name == "Reg Office 1-1":
                self.assertIsNone(group.supergroup_id)
                self.assertEqual(group.level, 1)
                # self.assertEqual(group.supergroup_id, reg_office_2_2_group.id)
                # self.assertEqual(group.level, 2)
            elif group.name == "Loc Office 2-2-1":
                self.assertEqual(group.supergroup_id, reg_office_2_2_group.id)
                self.assertEqual(group.level, 2)
            elif group.name == "Loc Office 2-2-2":
                self.assertEqual(group.supergroup_id, reg_office_2_2_group.id)
                self.assertEqual(group.level, 2)
            elif group.name == "Unit 1":
                self.assertEqual(group.supergroup_id, reg_office_2_2_group.id)
                self.assertEqual(group.level, 2)

        shiva_groups_names = {x.name for x in get_recursive_groups_with_accessible_members(shiva)}
        self.assertSetEqual(shiva_groups_names, {
            "Federals", "Region 1", "Region 2",
            "Reg Office 1-1", "Reg Office 1-2", "Reg Office 2-1", "Reg Office 2-2",
            "Loc Office 1-1-1", "Loc Office 1-1-2", "Loc Office 1-2-1", "Loc Office 1-2-2",
            "Loc Office 2-1-1", "Loc Office 2-1-2", "Loc Office 2-2-1", "Loc Office 2-2-2",
            "Unit 1"
        })

        for group in get_recursive_groups_with_accessible_members(shiva):
            if group.name == "Federals":
                self.assertIsNone(group.supergroup_id)
                self.assertEqual(group.level, 1)
            elif group.name == "Region 1" or group.name == "Region 2":
                self.assertEqual(group.supergroup_id, federals_group.id)
                self.assertEqual(group.level, 2)
            elif group.name == "Reg Office 1-1" or group.name == "Reg Office 1-2":
                self.assertEqual(group.supergroup_id, region_1_group.id)
                self.assertEqual(group.level, 3)
            elif group.name == "Reg Office 2-1" or group.name == "Reg Office 2-2":
                self.assertEqual(group.supergroup_id, region_2_group.id)
                self.assertEqual(group.level, 3)
            elif group.name == "Loc Office 1-1-1" or group.name == "Loc Office 1-1-2":
                self.assertEqual(group.supergroup_id, reg_office_1_1_group.id)
                self.assertEqual(group.level, 4)
            elif group.name == "Loc Office 1-2-1" or group.name == "Loc Office 1-2-2":
                self.assertEqual(group.supergroup_id, reg_office_1_2_group.id)
                self.assertEqual(group.level, 4)
            elif group.name == "Loc Office 2-1-1" or group.name == "Loc Office 2-1-2":
                self.assertEqual(group.supergroup_id, reg_office_2_1_group.id)
                self.assertEqual(group.level, 4)
            elif group.name == "Loc Office 2-2-1" or group.name == "Loc Office 2-2-2":
                self.assertEqual(group.supergroup_id, reg_office_2_2_group.id)
                self.assertEqual(group.level, 4)
            elif group.name == "Unit 1":
                self.assertEqual(group.supergroup_id, reg_office_2_2_group.id)
                self.assertEqual(group.level, 4)


class UserGroupAPITestCase(UserGroupTestCase):
    def test_user_groups_tree_get(self) -> None:
        realm = get_realm("zulip")

        desdemona = self.example_user("desdemona")
        shiva = self.example_user("shiva")

        def create(name: str, supergroup: Optional[UserGroup] = None) -> UserGroup:
            result: UserGroup = UserGroup.objects.create(realm=realm, name=name)
            if supergroup:
                GroupGroupMembership.objects.create(supergroup=supergroup, subgroup=result)
            return result

        def create_link(name: str, first_group: UserGroup, second_group: UserGroup) -> UserGroup:
            result: UserGroup = UserGroup.objects.create(realm=realm, name="@link:" + name)
            GroupGroupMembership.objects.create(supergroup=result, subgroup=first_group)
            GroupGroupMembership.objects.create(supergroup=result, subgroup=second_group)
            return result

        def assert_items(items: List[dict]):
            for x in items:
                self.assertIsInstance(x["description"], str)
                self.assertIsInstance(x["id"], int)
                self.assertIsInstance(x["name"], str)
                self.assertIsInstance(x["subgroups"], list)
                self.assertIsInstance(x["total_direct_members"], int)
                assert_items(x["subgroups"])

        federals_group = create(name="Federals")
        region_1_group = create(name="Region 1", supergroup=federals_group)
        region_2_group = create(name="Region 2", supergroup=federals_group)
        reg_office_1_1_group = create(name="Reg Office 1-1", supergroup=region_1_group)
        reg_office_1_2_group = create(name="Reg Office 1-2", supergroup=region_1_group)
        reg_office_2_1_group = create(name="Reg Office 2-1", supergroup=region_2_group)
        reg_office_2_2_group = create(name="Reg Office 2-2", supergroup=region_2_group)
        loc_office_1_1_1_group = create(name="Loc Office 1-1-1", supergroup=reg_office_1_1_group)
        loc_office_1_1_2_group = create(name="Loc Office 1-1-2", supergroup=reg_office_1_1_group)
        loc_office_1_2_1_group = create(name="Loc Office 1-2-1", supergroup=reg_office_1_2_group)
        loc_office_1_2_2_group = create(name="Loc Office 1-2-2", supergroup=reg_office_1_2_group)
        loc_office_2_1_1_group = create(name="Loc Office 2-1-1", supergroup=reg_office_2_1_group)
        loc_office_2_1_2_group = create(name="Loc Office 2-1-2", supergroup=reg_office_2_1_group)
        loc_office_2_2_1_group = create(name="Loc Office 2-2-1", supergroup=reg_office_2_2_group)
        loc_office_2_2_2_group = create(name="Loc Office 2-2-2", supergroup=reg_office_2_2_group)
        unit1_group = create(name="Unit 1")
        link_1_group = create_link("Reg Office 1-1 <-> Reg Office 2-2", reg_office_1_1_group, reg_office_2_2_group)
        link_2_group = create_link("Loc Office 2-2-1 <-> Unit 1", loc_office_2_2_1_group, unit1_group)

        UserGroupMembership.objects.create(user_profile=desdemona, user_group=reg_office_2_2_group)
        UserGroupMembership.objects.create(user_profile=shiva, user_group=federals_group)

        self.login_user(desdemona)
        result = self.client_get("/json/user_groups/tree")
        response_dict = self.assert_json_success(result)
        tree = response_dict["user_groups_tree"]
        self.assert_length(tree, 2)
        self.assertSetEqual({x["name"] for x in tree}, {"Reg Office 2-2", "Reg Office 1-1"})
        assert_items(tree)
        # from pprint import pprint
        # pprint(response_dict)

        self.login_user(shiva)
        result = self.client_get("/json/user_groups/tree")
        response_dict = self.assert_json_success(result)
        tree = response_dict["user_groups_tree"]
        self.assert_length(tree, 1)
        self.assertSetEqual({x["name"] for x in tree}, {"Federals"})
        assert_items(tree)
        # pprint(response_dict)
