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

import json
import os
import sys
import subprocess
import time
import uuid
import datetime
import copy
from os.path import dirname, abspath

import pytest
from confluent_kafka import KafkaError
from django.db import OperationalError
from django.utils import timezone

# Setup the Service Environment so we can import shared models
# and other logic
PARENT = dirname(dirname(abspath(__file__)))
sys.path.append(PARENT)
service_file = "service/service.py" if os.path.exists("service/service.py") else "../service.py"

import reports
from service import db as models  # avoid clash with 'db' fixture from pytest-django
from settings import AUTOACK


class FailOnce(object):
    """
    Call a function, but fail it on the first call with an exception.

    The second time the function is called, the exception is not raised, and the
    result of the functional call will be returned.

    Patch your function with this class, which is a callable.
    """

    def __init__(self, func, exc):
        self.failed_once = False
        self.called = 0
        self.exc = exc
        self.func = func

    def __call__(self, *args, **kwargs):
        self.called += 1
        if not self.failed_once:
            self.failed_once = True
            raise self.exc("I FAILED")
        return self.func(*args, **kwargs)


def _check_host_integrity(sample_report_data, service):
    # host will be different depending on third party rule hits vs ingress
    # this is third party (RHV, AIOPS)
    if sample_report_data.get('source'):
        inventory_id = sample_report_data.get('inventory_id')
        account = sample_report_data.get('account')
        org_id = sample_report_data.get('org_id')
    # this is the normal ingress upload pipeline
    else:
        host_data = sample_report_data.get('input').get('host')
        account = host_data.get('account')
        platform_metadata = sample_report_data.get('input').get('platform_metadata')
        org_id = platform_metadata.get('org_id')
        inventory_id = host_data.get('id')

    assert models.Host.objects.filter(inventory_id=inventory_id, account=account, org_id=org_id).exists()


def _check_reports(sample_report_data, service):
    # Currently, the reports will still be inserted into the DB even if updating inventory fails..
    report_list_rule_ids = [x['rule_id'] for x in sample_report_data['results']['reports']]
    if service.settings.FILTER_OUT_NON_RHEL:
        if service.settings.FILTER_OUT_NON_RHEL_RULE_ID in report_list_rule_ids:
            filtered_report_data = list()
            for report in sample_report_data['results']['reports']:
                if report['rule_id'] == service.settings.FILTER_OUT_NON_RHEL_RULE_ID:
                    filtered_report_data.append(report)
            sample_report_data['reports'] = filtered_report_data

    for report in sample_report_data['results']["reports"]:
        # Check that the DB report was created with the expected system ID and report details
        # for each report in our sample data
        reports = models.CurrentReport.objects.filter(
            host=sample_report_data['input']['host']['id'],
            rule__rule_id=report["rule_id"]
        )
        assert reports, (
            f"Report for rule hit '{report['rule_id']}' missing in DB"
        )


def _check_rule_hits(sample_rule_hits):
    system_id = sample_rule_hits["inventory_id"]
    for report in sample_rule_hits["hits"]:
        # Check that the DB report was created with the expected system ID and report details
        # for each report in our sample data
        reports = models.CurrentReport.objects.filter(
            host=system_id, details__error_key=report["details"]["error_key"]
        )
        assert reports, (
            f"Report for rule hit '{report['rule_id']} missing in DB"
        )


@pytest.mark.django_db(transaction=True)
def test_similar_uploads(db, service, sample_engine_results, mock_request_post_return_200):
    # Push 2 uploads to compare their upload ids and upload times
    service.handle_engine_results(sample_engine_results)
    uuid = sample_engine_results['input']['host']['id']
    error_key = sample_engine_results['results']['reports'][0]['details']['error_key']
    first_report = models.CurrentReport.objects.filter(
        host=uuid,
        details__error_key=error_key
    ).first()
    first_upload = first_report.upload

    # Push another upload for the same system with the same rule hits, get the upload
    service.handle_engine_results(sample_engine_results)
    second_report = models.CurrentReport.objects.filter(
        host=uuid,
        details__error_key=error_key
    ).first()
    second_upload = second_report.upload

    # Test the upload ids are the same but the upload times are different
    assert first_upload.id == second_upload.id, "New upload should have same id as previous upload"
    assert first_upload.checked_on != second_upload.checked_on, "New upload time should be different to previous upload time"
    # Test the report ids and impacted dates are the same (the impacted date didn't change with the second upload)
    assert first_report.id == second_report.id, "Report IDs should be the same"
    assert first_report.impacted_date == second_report.impacted_date, "Report impacted_dates should be the same"
    # The second upload should be the current one (well, its the same as the first upload anyway)
    assert second_upload.current
    assert second_report.details != {}, "Details on new report shouldn't be empty"


@pytest.mark.django_db(transaction=True)
def test_impacted_date(db, service, sample_engine_results, mock_request_post_return_200):
    account = '477931'
    org_id = '5882103'
    host_id = '57c4c38b-a8c6-4289-9897-223681fd804d'
    other_linux_system_rule = models.Rule.objects.get(rule_id='other_linux_system|OTHER_LINUX_SYSTEM')

    # 'Upload' an archive for host_id with a match for the other_linux_system rule
    service.handle_engine_results(sample_engine_results)

    # Confirm a report has been generated for the particular account, host and other_linux_system rule
    cr = models.CurrentReport.objects.filter(
        rule=other_linux_system_rule, account=account, org_id=org_id, host_id=host_id)
    assert cr.exists() is True
    # Check its impacted date isn't Null and that its now() ... well, almost now - within the last minute of now
    first_impacted_date = cr[0].impacted_date
    assert first_impacted_date is not None
    assert first_impacted_date > timezone.now() - timezone.timedelta(minutes=1)

    # 'Upload' another archive for host_id with a match for the other_linux_system rule
    service.handle_engine_results(sample_engine_results)
    cr = models.CurrentReport.objects.filter(
        rule=other_linux_system_rule, account=account, org_id=org_id, host_id=host_id)
    # Confirm that the impacted date is still the same as before
    assert first_impacted_date == cr[0].impacted_date

    # Now have the host be impacted by a different rule, which will delete the other_linux_system report
    different_engine_results = json.loads(
            json.dumps(sample_engine_results)
                .replace('other_linux_system', 'hardening_gpg_pubkey')
                .replace('OTHER_LINUX_SYSTEM', 'REDHAT_GPGKEY_NOT_INSTALLED')
        )
    service.handle_engine_results(different_engine_results)
    # Confirm there isn't a report anymore for the account, host and other_linux_system rule
    assert models.CurrentReport.objects.filter(
        rule=other_linux_system_rule, account=account, org_id=org_id, host_id=host_id
    ).exists() is False

    # 'Upload' another archive for host_id but matching the other_linux_system rule again
    service.handle_engine_results(sample_engine_results)
    cr = models.CurrentReport.objects.filter(rule=other_linux_system_rule, account=account, host_id=host_id)
    # Confirm that the new impacted date is greater (later) than the impacted date from before
    second_impacted_date = cr[0].impacted_date
    assert second_impacted_date > first_impacted_date
    assert second_impacted_date > timezone.now() - timezone.timedelta(minutes=1)


@pytest.mark.django_db(transaction=True)
def test_autoacks_for_new_account(db, service, sample_engine_results, mock_request_post_return_200):
    # Add ack for other_linux_system
    account = '477931'
    org_id = '5882103'
    other_linux_system = models.Rule.objects.get(rule_id='other_linux_system|OTHER_LINUX_SYSTEM')
    autoack = models.Tag.objects.get(name=AUTOACK['TAG'])
    other_linux_system.tags.add(autoack)

    # Nothing up our sleeves ...
    # Confirm account 477931, org_id 5882103 doesn't exist - no existing uploads, hosts or acks
    assert models.Upload.objects.filter(account=account, org_id=org_id).exists() is False
    assert models.Host.objects.filter(account=account, org_id=org_id).exists() is False
    assert models.Ack.objects.filter(account=account, org_id=org_id).exists() is False
    # But we must have both InventoryHost objects...
    assert models.InventoryHost.objects.filter(account=account).count() == 2

    # Push an upload for new account 477931 org_id 5882103 that hits other_linux_system
    # Expect an autoack to be created
    service.handle_engine_results(sample_engine_results)
    assert models.Ack.objects.filter(rule=other_linux_system, account=account, org_id=org_id).exists() is True
    assert models.Ack.objects.get(
        rule=other_linux_system, account=account, org_id=org_id).created_by == AUTOACK['CREATED_BY']

    # Simulate removing the ack for other_linux_system and re-uploading
    # Expect no autoack created for existing account org_id 5882103
    models.Ack.objects.filter(rule=other_linux_system, account=account, org_id=org_id).delete()
    service.handle_engine_results(sample_engine_results)
    assert models.Ack.objects.filter(rule=other_linux_system, account=account, org_id=org_id).exists() is False

    # Simulate uploading 2 archives for a new account - just one autoack should be created
    models.Ack.objects.filter(rule=other_linux_system, account=account, org_id=org_id).delete()
    models.Host.objects.filter(account=account, org_id=org_id).delete()
    assert models.Ack.objects.filter(rule=other_linux_system, account=account, org_id=org_id).exists() is False
    another_system = json.loads(
        json.dumps(sample_engine_results)
            .replace('RHIQE.d60db782-8462-410e-b0fc-f4ee97d985cb.test', 'another-system')
            .replace('57c4c38b-a8c6-4289-9897-223681fd804d', '12345678-a8c6-4289-9897-223681fd804d')
    )
    service.handle_engine_results(another_system)
    service.handle_engine_results(sample_engine_results)
    assert models.Ack.objects.filter(rule=other_linux_system, account=account, org_id=org_id).count() == 1

    assert models.Host.objects.filter(account=account, org_id=org_id).count() == 2
    assert models.Host.objects.filter(
        inventory_id='57c4c38b-a8c6-4289-9897-223681fd804d').exists() is True
    assert models.Host.objects.filter(
        inventory_id='12345678-a8c6-4289-9897-223681fd804d').exists() is True
    # Simulate removing autoack and uploading report for new host that also hits other_linux_system
    # Expect that no new autoack is created for the new system because the account already existed
    models.Ack.objects.filter(rule=other_linux_system, account=account, org_id=org_id).delete()
    # delete the host and re-upload its report
    models.Host.objects.filter(
        inventory_id='57c4c38b-a8c6-4289-9897-223681fd804d'
    ).delete()
    # No uploads or host objects for the deleted host
    assert models.Host.objects.filter(
        inventory_id='57c4c38b-a8c6-4289-9897-223681fd804d').exists() is False
    assert models.Upload.objects.filter(
        host_id='57c4c38b-a8c6-4289-9897-223681fd804d').exists() is False
    # but an upload and host for the remaining host
    assert models.Host.objects.filter(
        inventory_id='12345678-a8c6-4289-9897-223681fd804d').exists() is True
    assert models.Upload.objects.filter(
        host_id='12345678-a8c6-4289-9897-223681fd804d').exists() is True
    # Now run an upload for the (deleted) host
    service.handle_engine_results(sample_engine_results)
    # And no auto-acks should be created
    assert models.Ack.objects.filter(rule=other_linux_system, account=account, org_id=org_id).exists() is False

    # Simulate having an existing manual ack for other_linux_system
    # Expect manual ack isn't replaced by autoack
    models.Host.objects.filter(account=account, org_id=org_id).delete()
    models.Ack.objects.filter(rule=other_linux_system, account=account, org_id=org_id).delete()
    models.Ack(
        rule=other_linux_system, account=account, org_id=org_id, created_by="User", justification="Coz"
    ).save()
    service.handle_engine_results(sample_engine_results)
    assert models.Ack.objects.get(
        rule=other_linux_system, account=account, org_id=org_id
    ).created_by != AUTOACK['CREATED_BY']


@pytest.mark.django_db(transaction=True)
def test_handle_engine_results(db, service, sample_engine_results, mock_request_post_return_200):
    service.handle_engine_results(sample_engine_results)
    _check_host_integrity(sample_engine_results, service)
    _check_reports(sample_engine_results, service)
    # No satellite IDs - Host should not have branch_id or satellite_id
    host = models.Host.objects.get(inventory_id="57c4c38b-a8c6-4289-9897-223681fd804d")
    assert host.satellite_id is None
    assert host.branch_id is None


@pytest.mark.django_db(transaction=True)
def test_handle_engine_results_two_sources(db, service, sample_engine_results, sample_rule_hits, mock_request_post_return_200):
    # We should be able to handle an upload on the same system from different
    # sources.  The engine results always has the source 'insights-client',
    # the rule hits sample is set to source 'aiops'.  So we need to make sure
    # that the aiops sample is on the same system as the insights-client sample.
    service.handle_engine_results(sample_engine_results)
    sample_rule_hits['inventory_id'] = sample_engine_results['input']['host']['id']
    service.handle_rule_hits(sample_rule_hits)

    _check_host_integrity(sample_engine_results, service)
    _check_reports(sample_engine_results, service)
    # No satellite IDs - Host should not have branch_id or satellite_id
    host = models.Host.objects.get(inventory_id=sample_rule_hits['inventory_id'])
    assert host.satellite_id is None
    assert host.branch_id is None
    # We should have two upload objects - one for each source.
    client_upload = models.Upload.objects.get(source__name='insights-client', host_id=sample_rule_hits['inventory_id'])
    assert client_upload.current
    assert client_upload.currentreport_set.count(), 4
    aiops_upload = models.Upload.objects.get(source__name='aiops', host_id=sample_rule_hits['inventory_id'])
    assert aiops_upload.current
    assert aiops_upload.currentreport_set.count(), 1


@pytest.mark.django_db(transaction=True)
def test_satellite_handle_engine_results(
    db, service, sample_satellite_engine_results, mock_request_post_return_200
):
    service.handle_engine_results(sample_satellite_engine_results)
    _check_host_integrity(sample_satellite_engine_results, service)
    _check_reports(sample_satellite_engine_results, service)
    # Satellite system - Host should have branch_id and satellite_id
    host = models.Host.objects.get(inventory_id="c38b57c4-c6a8-4928-9789-2804d23681fd")
    assert host.satellite_id == uuid.UUID("e80e58d1-d5ec-4a5a-bd37-3df104954125")
    assert host.branch_id == uuid.UUID("bd1ddcc7-24a3-4591-bbad-30e9eae6d6ba")


@pytest.mark.django_db(transaction=True)
def test_handle_engine_results_bad_keys(db, service, sample_engine_results,
                                        mock_request_post_return_200):
    bad_input = copy.deepcopy(sample_engine_results)
    bad_input['input'] = None
    assert not service.handle_engine_results(bad_input)

    bad_host = copy.deepcopy(sample_engine_results)
    bad_host['input']['host'] = None
    assert not service.handle_engine_results(bad_host)

    bad_inventory = copy.deepcopy(sample_engine_results)
    bad_inventory['input']['host']['id'] = None
    assert not service.handle_engine_results(bad_inventory)

    bad_org_id = copy.deepcopy(sample_engine_results)
    bad_org_id['input']['platform_metadata']['org_id'] = None
    assert not service.handle_engine_results(bad_org_id)

    bad_engine_results = copy.deepcopy(sample_engine_results)
    bad_engine_results['results'] = None
    assert not service.handle_engine_results(bad_engine_results)

    bad_engine_reports = copy.deepcopy(sample_engine_results)
    bad_engine_reports['results']['reports'] = None
    assert not service.handle_engine_results(bad_engine_reports)

    bad_system_data = copy.deepcopy(sample_engine_results)
    bad_system_data['results']['system'] = None
    assert not service.handle_engine_results(bad_system_data)

    bad_platform_data = copy.deepcopy(sample_engine_results)
    bad_platform_data['input']['platform_metadata'] = None
    assert not service.handle_engine_results(bad_platform_data)


@pytest.mark.django_db(transaction=True)
def test_generate_webhook_msgs_new_report(db, mocker, service, sample_report_data):
    mocked_webhook_func = mocker.patch.object(service.report_hooks, "send_webhook_event")
    mocked_remediations_func = mocker.patch.object(service.report_hooks, "send_remediations_event")

    inventory_uuid = "00112233-4455-6677-8899-012345678901"

    new_report_rule_ids = ['test|Active_rule', 'test|Second_rule', 'test|Inactive_rule', 'test|Acked_rule']
    new_report_rules = models.Rule.objects.filter(rule_id__in=new_report_rule_ids).values(
                'id', 'rule_id', 'active', 'total_risk', 'description',
                'publish_date', 'reboot_required'
            ).annotate(
                has_incident=models.Exists(models.Rule.objects.filter(id=models.OuterRef('id'), tags__name='incident'))
            )

    report_models = models.CurrentReport.objects.filter(rule__rule_id='test|Second_rule').values('id', 'rule_id',
            'rule__total_risk', 'rule__description', 'rule__publish_date',
            'rule__rule_id', 'rule__active', 'rule__reboot_required', 'rule__id').annotate(
                has_incident=models.Exists(models.Rule.objects.filter(id=models.OuterRef('rule'), tags__name='incident'))
            )
    cur_reports = [report_models.first()]
    host_obj = models.InventoryHost.objects.get(id=inventory_uuid)

    service.report_hooks.trigger_report_hooks(host_obj, new_report_rules, cur_reports)

    new = 0
    resolved = 0
    remediations = 0
    for args, _ in mocked_webhook_func.call_args_list:
        msg_obj = args[0]
        if 'event_type' in msg_obj:
            if msg_obj['event_type'] == service.report_hooks.NEW_REPORT_EVENT:
                # Should be only one message here, so test its properties
                new += 1
                assert 'account_id' in msg_obj
                assert msg_obj['account_id'] == '1234567'
                assert 'org_id' in msg_obj
                assert msg_obj['org_id'] == '9876543'
                assert 'context' in msg_obj
                # Kafka values can only be strings, so decode context and
                # events into dicts
                context = json.loads(msg_obj['context'])
                assert isinstance(context, dict)
                assert 'tags' in context
                assert context['tags'] == []
                assert 'events' in msg_obj
                assert isinstance(msg_obj['events'], list)
                assert isinstance(msg_obj['events'][0], dict)
                assert 'payload' in msg_obj['events'][0]
                payload = json.loads(msg_obj['events'][0]['payload'])
                assert isinstance(payload, dict)
                assert 'rule_id' in payload
                assert 'reboot_required' in payload
                assert 'has_incident' in payload
            elif msg_obj['event_type'] == service.report_hooks.RESOLVED_REPORT_EVENT:
                resolved += 1
    for args, _ in mocked_remediations_func.call_args_list:
        if (args[0] == inventory_uuid) and len(args[1]['issues']) > 0:
            remediations += 1
    assert new == 1
    assert resolved == 0
    assert remediations == 1


@pytest.mark.django_db(transaction=True)
def test_generate_webhook_msgs_resolved_report(db, mocker, service, sample_report_data):
    mocked_webhook_func = mocker.patch.object(service.report_hooks, "send_webhook_event")
    mocked_remediations_func = mocker.patch.object(service.report_hooks, "send_remediations_event")

    inventory_uuid = "00112233-4455-6677-8899-012345678901"

    active_rule = models.Rule.objects.filter(rule_id="test|Active_rule").annotate(
        has_incident=models.Exists(models.Rule.objects.filter(id=models.OuterRef('id'), tags__name='incident'))).first()
    inactive_rule = models.Rule.objects.filter(rule_id="test|Inactive_rule").annotate(
        has_incident=models.Exists(models.Rule.objects.filter(id=models.OuterRef('id'), tags__name='incident'))).first()
    acked_rule = models.Rule.objects.filter(rule_id="test|Acked_rule").annotate(
        has_incident=models.Exists(models.Rule.objects.filter(id=models.OuterRef('id'), tags__name='incident'))).first()

    new_rule_objs = [  # No active rule, must have been resolved.
    ]
    cur_reports = [  # Can contain currentreport objects that aren't saved.
        models.CurrentReport.objects.filter(rule=active_rule).values('id', 'rule_id',
            'rule__total_risk', 'rule__description', 'rule__publish_date',
            'rule__rule_id', 'rule__active', 'rule__reboot_required', 'rule__id', 'rule__tags')
        .annotate(
            has_incident=models.Exists(models.Rule.objects.filter(id=models.OuterRef('rule'), tags__name='incident')))
        .first(),
        # We can't use an unsaved CurrentReport object to generate the
        # values, but we can make up the dict struct that values() creates
        {
            'rule_id': inactive_rule.id,
            'rule__total_risk': inactive_rule.total_risk,
            'rule__description': inactive_rule.description,
            'rule__publish_date': inactive_rule.publish_date,
            'rule__rule_id': inactive_rule.rule_id,
            'rule__active': inactive_rule.active,
            'rule__reboot_required': inactive_rule.reboot_required,
            'rule__tags': inactive_rule.tags,
            'has_incident': inactive_rule.has_incident,
        },
        {
            'rule_id': acked_rule.id,
            'rule__total_risk': acked_rule.total_risk,
            'rule__description': acked_rule.description,
            'rule__publish_date': acked_rule.publish_date,
            'rule__rule_id': acked_rule.rule_id,
            'rule__active': acked_rule.active,
            'rule__reboot_required': acked_rule.reboot_required,
            'rule__tags': acked_rule.tags,
            'has_incident': acked_rule.has_incident,
        },
    ]
    host_obj = models.InventoryHost.objects.get(id=inventory_uuid)

    service.report_hooks.trigger_report_hooks(host_obj, new_rule_objs, cur_reports)

    new = 0
    resolved = 0
    remediations = 0
    for args, _ in mocked_webhook_func.call_args_list:
        msg_obj = args[0]
        if 'event_type' in msg_obj:
            if msg_obj['event_type'] == service.report_hooks.NEW_REPORT_EVENT:
                new += 1
            elif msg_obj['event_type'] == service.report_hooks.RESOLVED_REPORT_EVENT:
                resolved += 1
                assert 'account_id' in msg_obj
                assert msg_obj['account_id'] == '1234567'
                assert 'org_id' in msg_obj
                assert msg_obj['org_id'] == '9876543'
                assert 'context' in msg_obj
                # Kafka values can only be strings, so decode context and
                # events into dicts
                context = json.loads(msg_obj['context'])
                assert isinstance(context, dict)
                assert 'tags' in context
                assert context['tags'] == []
                assert 'events' in msg_obj
                assert isinstance(msg_obj['events'], list)
                assert isinstance(msg_obj['events'][0], dict)
                assert 'payload' in msg_obj['events'][0]
                payload = json.loads(msg_obj['events'][0]['payload'])
                assert isinstance(payload, dict)
                assert 'rule_id' in payload
                assert 'reboot_required' in payload
                assert 'has_incident' in payload
    for args, _ in mocked_remediations_func.call_args_list:
        if (args[0] == inventory_uuid) and len(args[1]['issues']) > 0:
            remediations += 1
    assert new == 0
    assert resolved == 1
    assert remediations == 0


@pytest.mark.django_db(transaction=True)
def test_db_one_failure(
    db, monkeypatch, service, sample_engine_results, mock_request_post_return_200
):
    patched_filter_func = FailOnce(models.SystemType.objects.filter, OperationalError)
    monkeypatch.setattr(models.SystemType.objects, "filter", patched_filter_func)

    service.handle_engine_results(sample_engine_results)
    assert patched_filter_func.called == 2
    _check_host_integrity(sample_engine_results, service)
    _check_reports(sample_engine_results, service)


@pytest.mark.django_db(transaction=True)
def test_db_repeated_failure(
    db, mocker, service, sample_engine_results, mock_request_post_return_200
):
    def _raise_error(*args, **kwargs):
        raise OperationalError

    patched_filter_func = mocker.patch.object(
        models.SystemType.objects, "filter", side_effect=_raise_error
    )

    with pytest.raises(OperationalError):
        service.handle_engine_results(sample_engine_results)
    assert patched_filter_func.call_count == 2


def test_executor_unhandled_exception(mocker, service, monkeypatch, env, sample_engine_results):

    class MockMsg(object):
        def error(self):
            return None

        def topic(self):
            return env.get("ENGINE_RESULTS_TOPIC")

        def value(self):
            return json.dumps(sample_engine_results).encode('utf-8')

    def mock_poll(timeout):
        monkeypatch.setattr(service, "_sigterm_received", True)
        return MockMsg()

    monkeypatch.setattr(service.c, "poll", mock_poll)

    def _raise_error(*args):
        raise Exception("AHHHH SOME UNHANDLED EXCEPTION OCCURRED!")

    mocker.patch.object(service, "handle_engine_results", side_effect=_raise_error)
    service.start()


def test_consume_upload(mocker, service, sample_engine_results, monkeypatch, env):

    class MockMsg(object):
        def error(self):
            return None

        def topic(self):
            return env.get("ENGINE_RESULTS_TOPIC")

        def value(self):
            return json.dumps(sample_engine_results).encode('utf-8')

    def mock_poll(timeout):
        monkeypatch.setattr(service, "_sigterm_received", True)
        return MockMsg()

    monkeypatch.setattr(service.c, "poll", mock_poll)
    handle_engine_results = mocker.patch.object(service, "handle_engine_results")
    service.start()
    handle_engine_results.assert_called_once_with(sample_engine_results)


def test_consume_exception_in_process_archive(mocker, service, sample_engine_results,
                                              monkeypatch, env):

    class MockMsg(object):
        def error(self):
            return None

        def topic(self):
            return env.get("ENGINE_RESULTS_TOPIC")

        def value(self):
            return json.dumps(sample_engine_results).encode('utf-8')

    def mock_poll(timeout):
        monkeypatch.setattr(service, "_sigterm_received", True)
        return MockMsg()

    def _raise_error(*args, **kwargs):
        raise Exception("FLASH BOOM BANG!  Oops worker died.")

    monkeypatch.setattr(service.c, "poll", mock_poll)
    request_engine = mocker.patch.object(service, "handle_engine_results", side_effect=_raise_error)
    service.start()
    request_engine.assert_called_once_with(sample_engine_results)


def test_consume_error(mocker, service, monkeypatch):
    class MockError(object):
        def msg(self):
            return "AN ERROR, OH NOES!"

        @staticmethod
        def code():
            return None

    class MockMsg(object):
        def error(self):
            return MockError

    def mock_poll(timeout):
        monkeypatch.setattr(service, "_sigterm_received", True)
        return MockMsg()

    monkeypatch.setattr(service.c, "poll", mock_poll)
    handle_engine_results = mocker.patch.object(service, "handle_engine_results")
    service.start()
    assert handle_engine_results.call_count == 0


def test_consume_partition_eof_error(mocker, service, monkeypatch):
    class MockError(object):
        def msg(self):
            return "AN ERROR, OH NOES!"

        @staticmethod
        def code():
            return KafkaError._PARTITION_EOF

    class MockMsg(object):
        def error(self):
            return MockError

    def mock_poll(timeout):
        monkeypatch.setattr(service, "_sigterm_received", True)
        return MockMsg()

    monkeypatch.setattr(service.c, "poll", mock_poll)
    handle_engine_results = mocker.patch.object(service, "handle_engine_results")
    service.start()
    assert handle_engine_results.call_count == 0


def test_subscribe_and_teardown(mocker, service, monkeypatch, env):
    def mock_poll(timeout):
        monkeypatch.setattr(service, "_sigterm_received", True)
        return None

    monkeypatch.setattr(service.c, "poll", mock_poll)
    subscribe = mocker.patch.object(service.c, "subscribe")
    close = mocker.patch.object(service.c, "close")
    on_assign_fn = service.print_assignment
    service.start()
    subscribe.assert_called_once_with([env.get("ENGINE_RESULTS_TOPIC"),
            env.get("INVENTORY_EVENTS_TOPIC"), env.get("RULE_HITS_TOPIC")], on_assign=on_assign_fn)
    close.assert_called_once_with()


def test_sigterm_shutdown(env):
    env = {**os.environ.copy(), **env}
    proc = subprocess.Popen(("python", service_file), env=env)
    time.sleep(5)
    proc.send_signal(15)
    proc.wait()
    assert proc.poll() == 0


def test_sigterm_shutdown_failed_cloudwatch_setup(env):
    aws_env_vars = {
        "AWS_ACCESS_KEY_ID": "bogus",
        "AWS_SECRET_ACCESS_KEY": "bogus",
        "AWS_REGION_NAME": "bogus"
    }

    env = {**os.environ.copy(), **env, **aws_env_vars}
    proc = subprocess.Popen(("python", service_file), env=env)
    time.sleep(30)  # Sleep long enough for boto timeout
    proc.send_signal(15)
    proc.wait()
    assert proc.poll() == 0


def test_our_log_formatter(env):
    # Use prod env var to trigger an AdvisorHandler to get created
    extra_env_vars = {
        "ADVISOR_ENV": "prod"
    }

    # Not sure how to assert anything about the logging is correct at the moment
    # but at least we'll hit the code by starting the app in 'prod' mode
    env = {**os.environ.copy(), **env, **extra_env_vars}
    proc = subprocess.Popen(("python", "service/service.py"), env=env)
    time.sleep(3)
    proc.send_signal(15)
    proc.wait()


def test_handle_rule_hits_path(mocker, service, monkeypatch, env):
    payload = {
        "id": "123",
        "request_id": "123",
        "service": "advisor",
        "account": "123",
        "org_id": "123",
        "source": "aiops"
    }

    class MockMsg(object):
        def error(self):
            return None

        def topic(self):
            return env.get("RULE_HITS_TOPIC")

        def value(self):
            return json.dumps(payload).encode("utf-8")

    def mock_poll(timeout):
        monkeypatch.setattr(service, "_sigterm_received", True)
        return MockMsg()

    monkeypatch.setattr(service.c, "poll", mock_poll)
    request_rule_hits = mocker.patch.object(service, "handle_rule_hits")
    service.start()
    request_rule_hits.assert_called_once_with(payload)


@pytest.mark.django_db(transaction=True)
def test_handle_rule_hits(db, service, sample_rule_hits, mock_request_post_return_200):
    service.handle_rule_hits(sample_rule_hits)
    service.report_hooks.p.poll.assert_called_with(0)
    assert service.report_hooks.p.produce.call_count == 2
    # One to send_webhooks_event, one to send_remediations_event

    first_call, second_call = service.report_hooks.p.produce.call_args_list
    (msg_type, message_body) = first_call.args
    callback = first_call.kwargs['callback']
    message_json = json.loads(message_body.decode())
    assert isinstance(message_json, dict)
    assert message_json['bundle'] == 'rhel'
    assert message_json['application'] == 'advisor'
    assert message_json['event_type'] == service.report_hooks.NEW_REPORT_EVENT
    # ignore timestamp
    assert message_json['account_id'] == '123456'
    assert message_json['org_id'] == '9876543'
    # Why are we listing JSON objects as strings inside JSON objects?...
    assert message_json['context'] == (
        '{"inventory_id": "2db7adeb-e3e8-4d40-bf68-bd00064e252b"'
        ', "hostname": "unknown", "display_name": "unknown", '
        '"rhel_version": "Unknown system version", '
        '"tags": []}'
    )
    assert message_json['events'] == [
        {
            'metadata': {}, 'payload': '{"rule_id": "aiops_rule_1", '
                '"rule_description": "Active rule", "total_risk": "1", '
                '"publish_date": "2018-05-23T15:38:55+00:00", "rule_url": '
                '"https://console.redhat.com/insights/advisor/recommendations/'
                'aiops_rule_1/", "reboot_required": false, "has_incident": false}'
        }, {
            'metadata': {}, 'payload': '{"rule_id": "aiops_rule_2", '
                '"rule_description": "Active rule", "total_risk": "1", '
                '"publish_date": "2018-05-23T15:38:55+00:00", "rule_url": '
                '"https://console.redhat.com/insights/advisor/recommendations/'
                'aiops_rule_2/", "reboot_required": false, "has_incident": false}'
        }
    ]
    msg_type = second_call.args[0]
    assert second_call.kwargs['key'] == '2db7adeb-e3e8-4d40-bf68-bd00064e252b'
    message_body = second_call.kwargs['value']
    callback = second_call.kwargs['callback']
    message_json = json.loads(message_body.decode())
    assert isinstance(message_json, dict)
    assert message_json['host_id'] == '2db7adeb-e3e8-4d40-bf68-bd00064e252b'
    assert message_json['issues'] == [
        'advisor:aiops_rule_1', 'advisor:aiops_rule_2'
    ]

    assert callback == reports.report_delivery_callback

    service.report_hooks.p.flush.assert_called_with()
    _check_host_integrity(sample_rule_hits, service)
    _check_rule_hits(sample_rule_hits)

    # Now that we've got hits in the database, resolve those issues and see
    # if we send the right resolved messages.
    sample_rule_hits['hits'] = []
    service.report_hooks.p.reset_mock()
    service.handle_rule_hits(sample_rule_hits)
    service.report_hooks.p.poll.assert_called_with(0)
    assert service.report_hooks.p.produce.call_count == 1
    # One to send_webhooks_event for the resolved issue.

    first_call = service.report_hooks.p.produce.call_args_list[0]
    (msg_type, message_body) = first_call.args
    callback = first_call.kwargs['callback']
    message_json = json.loads(message_body.decode())
    assert isinstance(message_json, dict)
    assert message_json['bundle'] == 'rhel'
    assert message_json['application'] == 'advisor'
    assert message_json['event_type'] == service.report_hooks.RESOLVED_REPORT_EVENT
    # ignore timestamp
    assert message_json['account_id'] == '123456'
    assert message_json['org_id'] == '9876543'
    # Why are we listing JSON objects as strings inside JSON objects?...
    assert message_json['context'] == (
        '{"inventory_id": "2db7adeb-e3e8-4d40-bf68-bd00064e252b"'
        ', "hostname": "unknown", "display_name": "unknown", '
        '"rhel_version": "Unknown system version", '
        '"tags": []}'
    )
    assert message_json['events'] == [
        {
            'metadata': {}, 'payload': '{"rule_id": "aiops_rule_1", '
                '"rule_description": "Active rule", "total_risk": "1", '
                '"publish_date": "2018-05-23T15:38:55+00:00", "rule_url": '
                '"https://console.redhat.com/insights/advisor/recommendations/'
                'aiops_rule_1/", "reboot_required": false, "has_incident": false}',
        }, {
            'metadata': {}, 'payload': '{"rule_id": "aiops_rule_2", '
                '"rule_description": "Active rule", "total_risk": "1", '
                '"publish_date": "2018-05-23T15:38:55+00:00", "rule_url": '
                '"https://console.redhat.com/insights/advisor/recommendations/'
                'aiops_rule_2/", "reboot_required": false, "has_incident": false}',
        }
    ]
    assert callback == reports.report_delivery_callback

    service.report_hooks.p.flush.assert_called_with()
    _check_host_integrity(sample_rule_hits, service)
    _check_rule_hits(sample_rule_hits)


def test_handle_rule_hits_missing_keys(service):
    bad_json = {"some": "json"}
    assert not service.handle_rule_hits(bad_json)


@pytest.mark.django_db(transaction=True)
def test_db_reports_bad_upload(service, mocker):
    def _raise_exception(*args, **kwargs):
        raise Exception("AAAHHHHHHH")

    def _return_good_source(*args, **kwargs):
        return 'test', None

    mocker.patch.object(
        models.UploadSource.objects, "get_or_create", _return_good_source
    )

    mocker.patch.object(
        models.Upload.objects, "filter", _raise_exception
    )

    assert not service.create_db_reports(
        [], '57c4c38b-a8c6-4289-9897-223681fd804d', '477931', '1234567', 105, 'blah'
    )


@pytest.mark.django_db(transaction=True)
def test_db_reports_bad_upload_source(service, mocker):
    def _return_bad_source(*args, **kwargs):
        return None, None

    mocker.patch.object(
        models.UploadSource.objects, "get_or_create", _return_bad_source
    )

    assert not service.create_db_reports(
        [], '57c4c38b-a8c6-4289-9897-223681fd804d', '477931', '1234567', 105, 'blah'
    )


@pytest.mark.django_db(transaction=True)
def test_db_reports_upload_source_exception(service, mocker):
    def _raise_exception(*args, **kwargs):
        raise Exception("AAAHHHHHHH")

    mocker.patch.object(
        models.UploadSource.objects, "get_or_create", _raise_exception
    )

    assert not service.create_db_reports(
        [], '57c4c38b-a8c6-4289-9897-223681fd804d', '477931', '1234567', 105, 'blah'
    )


def test_prometheus(service, mocker, env, sample_engine_results, monkeypatch):

    class MockMsg(object):
        def error(self):
            return None

        def topic(self):
            return env.get("ENGINE_RESULTS_TOPIC")

        def value(self):
            return sample_engine_results

    def mock_poll(timeout):
        monkeypatch.setattr(service, "_sigterm_received", True)
        return MockMsg()

    monkeypatch.setattr(service.settings, "DISABLE_PROMETHEUS", False)
    start_prometheus = mocker.patch.object(service.prometheus, "start_prometheus")
    monkeypatch.setattr(service.c, "poll", mock_poll)

    service.start()
    start_prometheus.assert_called_once_with()


def test_handle_inventory_event_path(mocker, service, monkeypatch, env):
    mock_json = {"id": "123", "request_id": "123",
                 "account": "123", "type": "delete", "timestamp": "123"}

    class MockMsg(object):
        def error(self):
            return None

        def topic(self):
            return env.get("INVENTORY_EVENTS_TOPIC")

        def value(self):
            mock_msg = json.dumps(mock_json)
            return mock_msg.encode("utf-8")

    def mock_poll(timeout):
        monkeypatch.setattr(service, "_sigterm_received", True)
        return MockMsg()

    monkeypatch.setattr(service.c, "poll", mock_poll)
    request_inventory_event = mocker.patch.object(service, "handle_inventory_event")
    service.start()
    request_inventory_event.assert_called_once_with(mock_json)


def test_handle_inventory_event_missing_type(service):
    bad_json = {"some": "json"}
    with pytest.raises(ValueError):
        service.handle_inventory_event(bad_json)


def test_handle_inventory_event_missing_delete_keys(service):
    bad_json = {"type": "delete"}
    with pytest.raises(ValueError):
        service.handle_inventory_event(bad_json)


@pytest.mark.django_db(transaction=True)
def test_handle_inventory_delete_event(db, service, monkeypatch):
    inventory_event_json = {
        "id": str(uuid.uuid4()),
        "account": "123",
        "org_id": "123",
        "request_id": "123",
        "timestamp": datetime.datetime.now().isoformat(),
        "type": "delete"
    }
    assert service.handle_inventory_event(inventory_event_json) is None


@pytest.mark.django_db(transaction=True)
def test_bad_db_inventory_upload_delete(
    db, mocker, service, mock_request_post_return_200, monkeypatch
):
    inventory_event_json = {"id": str(uuid.uuid4()),
                            "account": "123",
                            "org_id": "123",
                            "request_id": "123",
                            "timestamp": "123",
                            "type": "delete"}

    def mock_filter_upload(*args, **kwargs):
        class mock_upload(object):
            def values(self, *args, **kwargs):
                return []

            def delete(self, *args, **kwargs):
                raise OperationalError
        return mock_upload()

    patched_filter_func_upload = mocker.patch.object(
        models.Upload.objects, "filter", side_effect=mock_filter_upload
    )

    with pytest.raises(OperationalError):
        service.handle_inventory_event(inventory_event_json)
    assert patched_filter_func_upload.call_count == 3


@pytest.mark.django_db(transaction=True)
def test_bad_db_inventory_current_report_delete(
    db, mocker, service, mock_request_post_return_200, monkeypatch
):
    inventory_event_json = {"id": str(uuid.uuid4()),
                            "request_id": "123",
                            "account": "123",
                            "org_id": "123",
                            "timestamp": "123",
                            "type": "delete"}

    def mock_filter_delete(*args, **kwargs):
        class mock_delete(object):
            def delete(self, *args, **kwargs):
                return True
        return mock_delete()

    def mock_current_report(*args, **kwargs):
        class mock_current_report(object):
            def values(self, *args, **kwargs):
                return []

            def delete(self, *args, **kwargs):
                raise OperationalError
        return mock_current_report()

    mocker.patch.object(
        models.Host.objects, "filter", mock_filter_delete
    )

    mocker.patch.object(
        models.Upload.objects, "filter", mock_filter_delete
    )

    patched_filter_func_current_report = mocker.patch.object(
        models.CurrentReport.objects, "filter", side_effect=mock_current_report
    )

    with pytest.raises(OperationalError):
        service.handle_inventory_event(inventory_event_json)
    assert patched_filter_func_current_report.call_count == 3


@pytest.mark.django_db(transaction=True)
def test_bad_db_inventory_hostack_delete(
    db, mocker, service, mock_request_post_return_200, monkeypatch
):
    inventory_event_json = {"id": "123",
                            "account": "123",
                            "org_id": "123",
                            "request_id": "123",
                            "timestamp": "123",
                            "type": "delete"}

    def mock_filter_delete(*args, **kwargs):
        class mock_delete(object):
            def delete(self, *args, **kwargs):
                return True
        return mock_delete()

    def mock_hostack(*args, **kwargs):
        class mock_hostack(object):
            def values(self, *args, **kwargs):
                return []

            def delete(self, *args, **kwargs):
                raise OperationalError
        return mock_hostack()

    mocker.patch.object(
        models.Host.objects, "filter", mock_filter_delete
    )

    mocker.patch.object(
        models.Upload.objects, "filter", mock_filter_delete
    )

    mocker.patch.object(
        models.CurrentReport.objects, "filter", mock_filter_delete
    )

    patched_filter_func_hostack = mocker.patch.object(
        models.HostAck.objects, "filter", side_effect=mock_hostack
    )

    with pytest.raises(OperationalError):
        service.handle_inventory_event(inventory_event_json)
    assert patched_filter_func_hostack.call_count == 3


@pytest.mark.django_db(transaction=True)
def test_non_rhel_system_filtering(db, service, mocker, sample_engine_results):
    mocker.patch.object(service.settings, "FILTER_OUT_NON_RHEL", False)
    mocker.patch.object(service.settings,
        "FILTER_OUT_NON_RHEL_RULE_ID", "other_linux_system|OTHER_LINUX_SYSTEM")
    service.handle_engine_results(sample_engine_results)
    _check_host_integrity(sample_engine_results, service)
    _check_reports(sample_engine_results, service)


@pytest.mark.django_db(transaction=True)
def test_rhel6_system_filtering(db, service, mocker, sample_rhel6_engine_results):
    # Assert there are 2 rule matches in the sample_rhel6_engine_results archive
    matched_rule_ids = [x['rule_id'] for x in sample_rhel6_engine_results['results']['reports']]
    assert len(matched_rule_ids) == 2
    assert "rhel6_upgrade|RHEL6_HAS_TO_UPGRADE_WARN_V1" in matched_rule_ids
    assert "hardening_gpg_pubkey|REDHAT_GPGKEY_NOT_INSTALLED" in matched_rule_ids

    # Don't filter RHEL6 rules initially
    mocker.patch.object(service.settings, "FILTER_OUT_RHEL6", False)
    assert not service.settings.FILTER_OUT_RHEL6
    service.handle_engine_results(sample_rhel6_engine_results)
    _check_host_integrity(sample_rhel6_engine_results, service)

    # Both rules will be saved in the DB for the currentreport for this host
    reports = models.CurrentReport.objects.filter(
        host=sample_rhel6_engine_results['input']['host']['id'],
    )
    assert reports.count() == 2
    assert reports.filter(rule__rule_id="rhel6_upgrade|RHEL6_HAS_TO_UPGRADE_WARN_V1").exists()
    assert reports.filter(rule__rule_id="hardening_gpg_pubkey|REDHAT_GPGKEY_NOT_INSTALLED").exists()

    # Now filter the matched rules for RHEL6 rules only
    mocker.patch.object(service.settings, "FILTER_OUT_RHEL6", True)
    assert service.settings.FILTER_OUT_RHEL6
    service.handle_engine_results(sample_rhel6_engine_results)
    _check_host_integrity(sample_rhel6_engine_results, service)

    # Now only the RHEL6 rule is saved in the DB for the currentreport for this host
    reports = models.CurrentReport.objects.filter(
        host=sample_rhel6_engine_results['input']['host']['id'],
    )
    assert reports.count() == 1
    assert reports.filter(rule__rule_id="rhel6_upgrade|RHEL6_HAS_TO_UPGRADE_WARN_V1").exists()
    assert not reports.filter(rule__rule_id="hardening_gpg_pubkey|REDHAT_GPGKEY_NOT_INSTALLED").exists()
