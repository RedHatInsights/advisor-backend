# Copyright 2016-2024 the Advisor Backend team at Red Hat.
# This file is part of the Insights Advisor project.

# Insights Advisor is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option)
# any later version.

# Insights Advisor is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
# more details.

# You should have received a copy of the GNU General Public License along
# with Insights Advisor. If not, see <https://www.gnu.org/licenses/>.

from datetime import timedelta

from kessel.inventory.v1beta2 import check_request_pb2

from django.utils import timezone

from api import kessel
from api.models import InventoryHost
from api.permissions import identity_to_subject, auth_header_for_testing


class constants(object):
    """
    Gather all the commonly-used string constants into the methods of a class
    so they're easy to access, while also providing a single point of
    definition.  It's good to reduce the number of string constants used :-)

    The basic rule is: if you use the same constant in different test modules,
    or more than about five times, put it in here.
    """
    standard_acct = '1234567'
    # See the 'owner_id' in basic_test_data
    standard_acct_satellite = '55df28a7-d7ef-48c5-bc57-8967025399b1'
    self_owned_system = '4f34fdbf-dae6-46fc-a85d-bdd4872587e9'
    alternate_acct = '1122334'
    host_tag_acct = '1000000'

    standard_org = '9876543'
    alternate_org = '9988776'
    host_tag_org = '1000000'
    test_username = 'testing'
    test_user_id = '16777216'
    test_service_user_id = '33554432'

    service_account = {
        'client_id': '10203040-5060-7080-90a0-b0c0d0e0f000',
        # username longer than the old 40 character limits for some usernames
        'username': 'service_account_10203040-5060-7080-90a0-b0c0d0e0f000',
        'user_id': test_service_user_id
    }

    # Rule IDs and details
    active_rule = 'test|Active_rule'
    active_title = 'Active rule'
    inactive_rule = 'test|Inactive_rule'
    inactive_title = 'Inactive rule'
    acked_rule = 'test|Acked_rule'
    acked_title = 'Acked rule'
    deleted_rule = 'test|Deleted_rule'
    deleted_title = 'Deleted rule'
    second_rule = 'test|Second_rule'
    second_title = 'Second rule, which has no node_id'
    high_sev_rule = 'test|High_severity_rule'
    notyetactive_rule = 'test|Rule_not_yet_activated'

    # System IDs and details:  (inid = 'Insights' ID client assigns itself)
    host_01_name = 'system01.example.com'
    host_01_uuid = '00112233-4455-6677-8899-012345678901'
    host_01_inid = 'ffeeddcc-bbaa-9988-7766-554433221101'
    host_01_said = 'aabbccdd-eeff-ffee-ddcc-aabbccddee01'
    host_03_name = 'system03.example.com'
    host_03_uuid = '00112233-4455-6677-8899-012345678903'
    host_03_inid = 'ffeeddcc-bbaa-9988-7766-554433221103'
    host_03_said = 'aabbccdd-eeff-ffee-ddcc-aabbccddee03'
    # Host 3 pretends to be the Satellite for this account.
    host_03_system_data = {
        'cn': standard_acct_satellite, 'cert_type': 'satellite',
    }
    host_04_name = 'system04.example.com'
    host_04_uuid = '00112233-4455-6677-8899-012345678904'
    host_04_inid = 'ffeeddcc-bbaa-9988-7766-554433221104'
    host_04_said = 'aabbccdd-eeff-ffee-ddcc-aabbccddee04'
    host_04_system_data = {
        'cn': self_owned_system, 'cert_type': 'system',
    }
    # Host 04 is not owned by the Satellite - it's self-owned
    host_05_name = 'system05.example.com'
    host_05_uuid = '00112233-4455-6677-8899-012345678905'
    host_05_inid = 'ffeeddcc-bbaa-9988-7766-554433221105'
    host_05_said = 'aabbccdd-eeff-ffee-ddcc-aabbccddee05'
    host_06_name = 'stale-warn.example.com'
    host_06_uuid = '00112233-4455-6677-8899-012345678906'
    host_06_inid = 'ffeeddcc-bbaa-9988-7766-554433221106'
    # Host 06 is not owned by the Satellite
    host_08_name = 'stale-hide.example.com'
    host_08_uuid = '00112233-4455-6677-8899-012345678908'
    host_08_inid = 'ffeeddcc-bbaa-9988-7766-554433221108'
    # Host 08 is not owned by the Satellite
    host_09_name = 'system09.example.com'
    host_09_uuid = '00112233-4455-6677-8899-012345678909'
    host_09_inid = 'ffeeddcc-bbaa-9988-7766-554433221109'
    host_09_said = 'aabbccdd-eeff-ffee-ddcc-aabbccddee09'
    host_0A_name = 'stale-hide-2.example.com'
    host_0A_uuid = '00112233-4455-6677-8899-01234567890A'
    host_0a_uuid = '00112233-4455-6677-8899-01234567890a'
    host_0a_inid = 'ffeeddcc-bbaa-9988-7766-55443322110a'
    host_e1_uuid = '00112233-4455-6677-8899-0123456789e1'
    host_e1_name = 'edge01.example.com'
    host_e1_inid = 'ffeeddcc-bbaa-9988-7766-5544332211e1'
    host_e1_said = 'aabbccdd-eeff-ffee-ddcc-aabbccddeee1'

    host_02_name = 'system02.example.org'
    host_02_uuid = '02468135-7902-4681-3579-024681357902'
    host_02_inid = 'ffeeddcc-bbaa-9988-7766-554433221102'
    host_07_name = 'system07.example.org'
    host_07_uuid = '02468135-7902-4681-3579-024681357907'
    host_07_inid = 'ffeeddcc-bbaa-9988-7766-554433221107'
    host_11_name = 'system11.example.com'
    host_11_uuid = '00112233-4455-6677-8899-012345678911'
    host_11_inid = 'ffeeddcc-bbaa-9988-7766-554433221101'
    host_ht_01_name = 'system01.example.biz'
    host_ht_01_uuid = '00102030-4050-6070-8090-000000000001'
    host_ht_02_name = 'system02.example.biz'
    host_ht_02_uuid = '00102030-4050-6070-8090-000000000002'
    host_ht_03_name = 'system03.example.biz'
    host_ht_03_uuid = '00102030-4050-6070-8090-000000000003'
    host_ht_04_name = 'system04.example.biz'
    host_ht_04_uuid = '00102030-4050-6070-8090-000000000004'

    remote_branch_uc = 'AABBCCDD-EEFF-FFEE-DDCC-001122334455'
    remote_branch_lc = 'aabbccdd-eeff-ffee-ddcc-001122334455'
    missing_branch = 'AABBCCDD-EEFF-FFEE-DDCC-554433221100'
    subset_working = 'foreman__32ad2ec89a7c20c4cd75394aaf393182ee1cb4b6'
    subset_missing = 'foreman__42cfd4137cc112f5459554c9b927e4ffbc137a04'

    host_group_1_id = '11111111-1111-1111-1111-111111111111'
    host_group_1_name = 'group_1'
    host_group_2_id = '11111111-1111-1111-1111-222222222222'

    # pathway data
    first_pathway = {
        "slug": "test-component-1",
        "name": "test component 1",
        "description": "Testing Component 1",
        "component": "test1",
        "resolution_risk": {
            "name": "Adjust Service Status",
            "risk": 1
        },
        "publish_date": "2018-05-23 15:38:55+00:00",
        "has_incident": False,
        "incident_count": 0,
        "impacted_systems_count": 4,
        "critical_risk_count": 0,
        "high_risk_count": 0,
        "medium_risk_count": 0,
        "low_risk_count": 6,
        "recommendation_level": 62
    }

    second_pathway = {
        "slug": "test-component-2",
        "name": "test component 2",
        "description": "Testing Component 2",
        "component": "test2",
        "resolution_risk": {
            "name": "Adjust Service Status",
            "risk": 1
        },
        "publish_date": "2018-05-23 15:38:55+00:00",
        "has_incident": False,
        "incident_count": 0,
        "impacted_systems_count": 1,
        "critical_risk_count": 0,
        "high_risk_count": 0,
        "medium_risk_count": 1,
        "low_risk_count": 0,
        "recommendation_level": 66
    }

    third_pathway = {
        "slug": "update-grub-kernel-boot-options",
        "name": "Update GRUB Kernel Boot Options",
        "description": "Stay on top of system boot failures, kernel panics, kdump failures and other issues by updating your kernel boot options.",
        "component": "grub",
        "resolution_risk": {
            "name": "Update Kernel Boot Options",
            "risk": 3
        },
        "publish_date": "2021-07-28T15:38:55Z",
        "has_incident": False,
        "incident_count": 0,
        "impacted_systems_count": 2,
        "critical_risk_count": 2,
        "high_risk_count": 0,
        "medium_risk_count": 0,
        "low_risk_count": 0,
        "recommendation_level": 94
    }

    fourth_pathway = {
        "slug": "update-networkmanager-package",
        "name": "Update NetworkManager Package",
        "description": "Prevent drops in network performance and network connectivity losses by updating the NetworkManager package.",
        "component": "NetworkManager",
        "resolution_risk": {
            "name": "Update Package",
            "risk": 1
        },
        "publish_date": "2021-07-28T15:38:55Z",
        "has_incident": False,
        "incident_count": 0,
        "impacted_systems_count": 1,
        "critical_risk_count": 0,
        "high_risk_count": 1,
        "medium_risk_count": 0,
        "low_risk_count": 0,
        "recommendation_level": 78
    }

    fifth_pathway = {
        "slug": "upgrade-kernel",
        "name": "Upgrade Kernel",
        "description": "Upgrade your kernel to avoid problems with boot failures, kernel panic situations, or system performance degradations.",
        "component": "kernel",
        "resolution_risk": {
            "name": "Upgrade Kernel",
            "risk": 3
        },
        "publish_date": "2021-07-28T15:38:55Z",
        "has_incident": False,
        "incident_count": 0,
        "impacted_systems_count": 1,
        "critical_risk_count": 0,
        "high_risk_count": 0,
        "medium_risk_count": 1,
        "low_risk_count": 0,
        "recommendation_level": 66
    }

    incident_pathway = {
        'name': 'Pathway with an incident'
    }

    no_incident_pathway = {
        'name': 'Pathway without an incident'
    }

    reboot_required_pathway = {
        'name': 'Pathway requiring a reboot'
    }

    no_reboot_required_pathway = {
        'name': 'Pathway no reboot'
    }
    pathway_rule_1 = {
        'rule_id': 'test|pathway_rule_1'
    }

    availability_category = {'id': 1, 'name': 'Availability'}
    security_category = {'id': 2, 'name': 'Security'}
    stability_category = {'id': 3, 'name': 'Stability'}
    performance_category = {'id': 4, 'name': 'Performance'}

    # Miscellaneous constants
    json_mime = 'application/json'
    csv_mime = 'text/csv'
    rhel_release = 'Red Hat Enterprise Linux Server'
    read_timeout_errmsg = "ERROR:advisor-log:Error: Timed out reached for middleware: 'Read timed out'"
    default_from_email = 'Red Hat Hybrid Cloud Console <noreply@redhat.com>'

    # Auto sub exclusion constants
    first_exclusion = {
        'org_id': '10042355',
        'account': '5812269'
    }
    last_exclusion = {
        'org_id': '916453',
        'account': '636204'
    }
    delete_exclusion = {
        'org_id': '13155542'
    }

    # KESSELWORKSPACE1
    kessel_std_workspace_id = '4f574c45-5353-454b-3145-434150534b52'

    # Kessel RBAC permission constants
    kessel_std_org_obj = kessel.Workspace(kessel_std_workspace_id).to_ref().as_pb2()
    kessel_std_user_identity_dict = auth_header_for_testing(
        user_id=test_user_id, unencoded=True
    )['identity']
    kessel_std_service_identity_dict = auth_header_for_testing(
        service_account={'user_id': test_service_user_id}, unencoded=True
    )['identity']
    kessel_std_user_obj = identity_to_subject(kessel_std_user_identity_dict).as_pb2()
    kessel_std_svc_user_obj = identity_to_subject(kessel_std_service_identity_dict).as_pb2()
    kessel_host_01_obj = kessel.Host(host_01_uuid).to_ref().as_pb2()

    # Kessel individual requests
    kessel_cpr_disable_recom_write = check_request_pb2.CheckRequest(
        object=kessel_std_org_obj,
        relation="advisor_disable_recommendations_edit",
        subject=kessel_std_user_obj,
    )
    kessel_cpr_disable_recom_read = check_request_pb2.CheckRequest(
        object=kessel_std_org_obj,
        relation="advisor_disable_recommendations_view",
        subject=kessel_std_user_obj,
    )
    kessel_cpr_read_recom_write = check_request_pb2.CheckRequest(
        object=kessel_std_org_obj,
        relation="advisor_recommendation_results_edit",
        subject=kessel_std_user_obj,
    )
    kessel_cpr_read_recom_read = check_request_pb2.CheckRequest(
        object=kessel_std_org_obj,
        relation="advisor_recommendation_results_view",
        subject=kessel_std_user_obj,
    )
    kessel_cpr_read_recom_svc_write = check_request_pb2.CheckRequest(
        object=kessel_std_org_obj,
        relation="advisor_recommendation_results_edit",
        subject=kessel_std_svc_user_obj,
    )
    kessel_cpr_read_recom_svc_read = check_request_pb2.CheckRequest(
        object=kessel_std_org_obj,
        relation="advisor_recommendation_results_view",
        subject=kessel_std_svc_user_obj,
    )
    kessel_cpr_host_01_recom_read = check_request_pb2.CheckRequest(
        object=kessel_host_01_obj,
        relation="advisor_recommendation_results_view",
        subject=kessel_std_user_obj,
    )

    # Kessel full permissions grants

    kessel_allow_disable_recom_rw = [(
        kessel_cpr_disable_recom_write, kessel.ALLOWED
    ), (
        kessel_cpr_disable_recom_read, kessel.ALLOWED
    )]
    kessel_allow_disable_recom_ro = [(
        kessel_cpr_disable_recom_write, kessel.DENIED
    ), (
        kessel_cpr_disable_recom_read, kessel.ALLOWED
    )]
    kessel_allow_recom_read_ro = [(
        kessel_cpr_read_recom_write, kessel.DENIED
    ), (
        kessel_cpr_read_recom_read, kessel.ALLOWED
    )]
    kessel_allow_recom_read_svc_ro = [(
        kessel_cpr_read_recom_svc_read, kessel.ALLOWED
    )]
    kessel_allow_host_01_read = [(
        kessel_cpr_host_01_recom_read, kessel.ALLOWED
    )]
    # Kessel allow standard user access to host group 1
    kessel_svc_user_in_workspace_host_group_1 = [(
        kessel_std_svc_user_obj,
        [host_group_1_id]
    )]
    kessel_user_in_workspace_host_group_1 = [(
        kessel_std_user_obj,
        [host_group_1_id]
    )]
    # Note - because these are lists you can use + to join them together to
    # make more complex examples.


def update_stale_dates(valid_days: float = 3.0):
    """
    Updates all the *host* data so it's not stale, except for:
    * systems that start with the word 'stale-warn', which have the
      stale-warn date set to before now, or
    * systems that start with the word 'stale-hide', which have the
      stale-hide (and stale-warn) dates set to before now.
    Note that this _does_not_ update the uploads attached to that host.  On
    the one hand, that host may have had a more recent message from Inventory
    giving newer stale times than the host's last upload.  On the other hand,
    there's nothing else in the code that enforces a relationship between
    the host's staleness dates and its uploads' dates.
    """
    now = timezone.now()
    full_valid = now + timedelta(days=valid_days)
    all_valid = now + timedelta(days=1)
    somewhat_stale = now - timedelta(days=1)
    really_stale = now - timedelta(days=3)

    for inventory_host in InventoryHost.objects.all():
        if inventory_host.display_name.startswith('stale-warn'):
            check_in = somewhat_stale
            stale_timestamp = somewhat_stale
            stale_warning_timestamp = all_valid
            culled_timestamp = full_valid
        elif inventory_host.display_name.startswith('stale-hide'):
            check_in = really_stale
            stale_timestamp = really_stale
            stale_warning_timestamp = somewhat_stale
            culled_timestamp = all_valid
        elif inventory_host.display_name.startswith('culled'):
            check_in = really_stale
            stale_timestamp = really_stale
            stale_warning_timestamp = really_stale
            culled_timestamp = somewhat_stale
        else:
            check_in = now
            stale_timestamp = all_valid
            stale_warning_timestamp = full_valid
            culled_timestamp = full_valid

        # We now DO NOT update the old (stale,stale_warning,culled)_timestamp
        # fields, because we now ONLY rely on the per-reporter staleness.
        # The deliberately out-of-date values in the overall fields are left
        # as tripwires.
        inventory_host.per_reporter_staleness = {
            "puptoo": {
                "stale_timestamp": str(stale_timestamp),
                "stale_warning_timestamp": str(stale_warning_timestamp),
                "culled_timestamp": str(culled_timestamp),
                "last_check_in": str(check_in),
                "check_in_succeeded": True
            }
        }
        inventory_host.save()


def rbac_data(permissions='advisor:*:*', raw=None, groups=None):
    """
    Return a dict that can be put into the `json` parameter of `responses.add`
    when testing RBAC.

    If 'raw' is supplied, simply return that.  That allows us to make up
    mangled RBAC data for code coverage tests.

    If `groups` is supplied, an extra `inventory:hosts:read` permissions
    object is added, with a resource definition with an 'inventory.groups'
    filter attribute with that value.  This must be a list in order for the
    query construction to work right.
    """
    if raw:
        return raw
    rbac_data = {'data': []}  # {'data': [{'permission': permissions}]}
    if groups:
        rbac_data['data'].append({
            'permission': 'inventory:hosts:read',
            'resourceDefinitions': [{'attributeFilter': {
                'key': 'group.id',
                'value': groups,
                'operation': 'in'
            }}]
        })
        rbac_data['data'].append({
            'permission': permissions,
            'resourceDefinitions': [{'attributeFilter': {
                'key': 'group.id',
                'value': groups,
                'operation': 'in'
            }}]
        })
    else:
        rbac_data = {'data': [{'permission': permissions}]}
    return rbac_data
