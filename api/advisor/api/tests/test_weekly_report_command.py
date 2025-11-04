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

import base64
from copy import deepcopy
from io import StringIO
import json
import responses

# Can't import outbox directly, it only exists during the tests.
from django.core import mail
from django.core.management import call_command
from django.test import TestCase
from django.utils import timezone, dateformat

from api.management.commands.weekly_report_emails import get_rhdisabled_rules_systems
from project_settings import settings
from api.models import WeeklyReportSubscription, Rule, Tag, InventoryHost, Ack
from api.permissions import has_rbac_permission, http_auth_header_key, make_rbac_url
from api.tests import constants, update_stale_dates

test_middleware_url = 'https://middleware.svc/'

TEST_RBAC_URL = 'http://rbac.svc/'  # the setting
# Because we handle the RBAC response with a callback, we accept all
# parameters and work out how to respond from there.
TEST_RBAC_V1_ACCESS = make_rbac_url("access/", rbac_base=TEST_RBAC_URL)


user_details_table = {
    'test-user': {
        'id': 123456701, 'username': 'test-user',
        'email': 'test-user@example.com', 'first_name': 'Test',
        'last_name': 'User', 'account_number': '1234567', 'org_id': '9876543',
        'is_active': True, 'address_string': '"Test User" test-user@example.com'
    },
    'first-acct-user': {
        'id': 123456702, 'username': 'first-acct-user',
        'email': 'admin@example.net', 'first_name': 'First',
        'last_name': 'User', 'account_number': '2000001', 'org_id': '2000001',
        'is_active': True,
    },
    'secnd-acct-user': {
        'id': 123456703, 'username': 'secnd-acct-user',
        'email': 'sysadmin@example.org', 'first_name': 'Second',
        'last_name': 'User', 'account_number': '2000002', 'org_id': '2000002',
        'is_active': True,
    },
    'denied-user': {
        'id': 123456704, 'username': 'denied-user',
        'email': 'denied@example.com', 'first_name': 'Denied',
        'last_name': 'User', 'account_number': '1234567', 'org_id': '9876543',
        'is_active': True,
    },
    'test-deleted-user': {
        'id': 123456705, 'username': 'test-deleted-user',
        'email': 'deleted@example.com', 'first_name': 'Deleted',
        'last_name': 'User', 'account_number': '1234567', 'org_id': '9876543',
        'is_active': False,
    },
    'test-user-no-systems': {
        'id': 112233445, 'username': 'test-user-no-systems',
        'email': 'nosystems@example.com', 'first_name': 'No',
        'last_name': 'Systems', 'account_number': '1928374', 'org_id': '1928374',
        'is_active': True
    }
}

user_permissions_table = {
    'test-user': {"data": [{"permission": "advisor:*:*"}]},
    'first-acct-user': {"data": [{"permission": "advisor:*:*"}]},
    'secnd-acct-user': {"data": [{"permission": "advisor:*:*"}]},
    'denied-user': {"data": [{"permission": "advisor:recommendation-results:read"}]},
    'test-user-no-systems': {"data": [{"permission": "advisor:*:*"}]},
}


def lookup_user_details(request):
    data = json.loads(request.body)
    assert 'users' in data
    assert isinstance(data['users'], list)
    if any(username in user_details_table for username in data['users']):
        rtn = (200, {}, json.dumps([
            user_details_table[username]
            for username in data['users']
            if username in user_details_table
        ]))
    else:
        rtn = (404, {}, json.dumps('No users found'))
    return rtn


def count_posted_emails(request):
    data = json.loads(request.body)
    assert 'emails' in data
    assert isinstance(data['emails'], list)
    mail.outbox.extend(data['emails'])
    return (200, {}, json.dumps({'message': "The emails were sent"}))


def reset_last_email_at():
    """
    Each time the weekly report command is run, it sets the last_email_at
    timestamp on the subscription record.  Within the test run that prevents
    the user from getting a further email.  So to run the command more than
    once, we then need to reset the timestamps - easiest way is to set them
    to null.
    """
    WeeklyReportSubscription.objects.all().update(last_email_at=None)


def lookup_rbac_permissions(request):
    if (identity_hdr := request.headers.get(http_auth_header_key)) is not None:
        identity = json.loads(base64.b64decode(identity_hdr))
        username = identity['identity']['user']['username']
        # logger.info("RBAC faked for username %s via identity", username)
    elif ('username' in request.params):
        username = request.params['username']
        # logger.info("RBAC faked for username %s via parameter", username)

    return 200, {}, json.dumps(user_permissions_table[username])


class WeeklyReportEmailTest(TestCase):
    fixtures = [
        'rulesets', 'system_types', 'rule_categories', 'upload_sources',
        'basic_test_data', 'weekly_report_test_data',
    ]

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        update_stale_dates()

    @responses.activate
    def test_weekly_report_emails_command(self):
        # Set up our fake user account lookup
        responses.add_callback(
            responses.POST, test_middleware_url + '/users',
            callback=lookup_user_details, content_type=constants.json_mime,
        )
        # and our fake mail sender
        responses.add_callback(
            responses.POST, test_middleware_url + '/sendEmails',
            callback=count_posted_emails, content_type=constants.json_mime,
        )
        # And our fake RBAC
        responses.add_callback(
            responses.GET, TEST_RBAC_V1_ACCESS, callback=lookup_rbac_permissions
        )

        with self.settings(
            RBAC_URL=TEST_RBAC_URL, RBAC_ENABLED=True,
            MIDDLEWARE_HOST_URL=test_middleware_url
        ):
            out = StringIO()
            call_command('weekly_report_emails', stdout=out)

            # We should now have received an email for each subscription
            self.assertEqual(len(mail.outbox), 1, [m['recipients'] for m in mail.outbox])
            self.assertEqual(mail.outbox[0]['subject'], 'Weekly Red Hat Lightspeed summary report')
            self.assertEqual(mail.outbox[0]['recipients'], ['"Test User" test-user@example.com'])
            body = mail.outbox[0]['body']
            self.assertIn('Hi Test,', body)
            self.assertIn(f'Red Hat Enterprise Linux - Advisor Weekly Report - {dateformat.format(timezone.now(), "j F Y")}</h1>', body)
            # No incidents
            self.assertNotIn('incident=true"', body)
            self.assertIn('<img src="https://console.redhat.com/apps/frontend-assets/email-assets/lightning-bolt.png"', body)  # for no incidents
            # 7 systems
            self.assertIn("""<span class="rh-metric__count" style="-ms-text-size-adjust: 100%; font-size: 28px; font-weight: 500; font-family: 'Red Hat Display', Helvetica, Arial sans-serif; line-height: 1.5;">7</span>""", body)
            # 3 stale systems
            self.assertIn('<a href="https://console.redhat.com/insights/inventory/?status=stale&status=stale_warning&source=puptoo" style="-ms-text-size-adjust: 100%; -webkit-text-size-adjust: 100%; text-decoration: none !important; color: #0066cc;">Check for stale systems</a>', body)
            # Only low severity rule recommendations
            self.assertIn('Prioritized recommendations</h2>', body)
            self.assertIn('<img src="https://console.redhat.com/apps/frontend-assets/email-assets/img_low.png" alt="Low severity" width="55">', body)
            self.assertIn('https://console.redhat.com/insights/advisor/recommendations?total_risk=1', body)
            # No critical rules
            self.assertNotIn('recommendations?total_risk=4', body)
            # No Red Hat disabled recommendations affecting any systems so no message about it in the email
            self.assertNotIn('Red Hat disabled recommendations applicable to your systems', body)
            self.assertNotIn('rule_status=rhdisabled', body)
            # Button points to Advisor and not general Insights or other outdated links
            self.assertIn('Go to Red Hat Lightspeed Advisor', body)
            self.assertNotIn('"https://https://console.redhat.com/"', body)
            self.assertNotIn('https://console.redhat.com/insights/rules', body)
            # No links to github artifacts
            self.assertNotIn('github', body)
            # No references to cloud.redhat.com
            self.assertNotIn('cloud.redhat.com', body)
            # more tests of content?

            # If we re-run the command, all emails should have now been sent and
            # no more should be generated.
            mail.outbox = []
            call_command('weekly_report_emails', stdout=out)
            self.assertEqual(len(mail.outbox), 0)

            # Some simple tests of org_id and range options.  Easiest to clear
            # the outbox each time to have a sensible number of emails in it
            # after each pass.  We also have to reset the last_email_at date
            # before each run to make sure emails go out.
            mail.outbox = []
            reset_last_email_at()
            # Several different accounts, including one with no subscriptions
            call_command('weekly_report_emails', org_id=['9876543', '9988776', '2000001'])
            self.assertEqual(len(mail.outbox), 1)
            mail.outbox = []
            reset_last_email_at()
            call_command('weekly_report_emails', org_id_from='2000002')
            self.assertEqual(len(mail.outbox), 1)
            mail.outbox = []
            reset_last_email_at()
            call_command('weekly_report_emails', org_id_to='2000001')
            self.assertEqual(len(mail.outbox), 0)
            mail.outbox = []
            reset_last_email_at()
            call_command('weekly_report_emails', org_id_from='2000000', org_id_to='2000001')
            self.assertEqual(len(mail.outbox), 0)
            mail.outbox = []
            reset_last_email_at()
            call_command('weekly_report_emails', org_id=['9876543'], org_id_from='2000002')
            self.assertEqual(len(mail.outbox), 1)

            # Tag Active_rule as an incident so Incidents section is populated
            incident_tag = Tag.objects.get(name='incident')
            Rule.objects.get(rule_id='test|Active_rule').tags.add(incident_tag)
            mail.outbox = []
            reset_last_email_at()
            call_command('weekly_report_emails', org_id=['9876543'])
            self.assertEqual(len(mail.outbox), 1)
            self.assertEqual(mail.outbox[0]['recipients'], ['"Test User" test-user@example.com'])
            body = mail.outbox[0]['body']
            self.assertIn('<a href="https://console.redhat.com/insights/advisor/recommendations?impacting=true&rule_status=enabled&reports_shown=true&incident=true" style="-ms-text-size-adjust: 100%; -webkit-text-size-adjust: 100%; text-decoration: none !important; color: #ffffff;">1</a>', body)
            # Just one incident, so Configuration isn't pluralized
            self.assertIn('Configuration affecting your systems</a>', body)

            # Tag Second_rule as an incident as well so we have 2 incidents now
            Rule.objects.get(rule_id='test|Second_rule').tags.add(incident_tag)
            mail.outbox = []
            reset_last_email_at()
            call_command('weekly_report_emails', org_id=['9876543'])
            self.assertEqual(len(mail.outbox), 1)
            body = mail.outbox[0]['body']
            self.assertIn('<a href="https://console.redhat.com/insights/advisor/recommendations?impacting=true&rule_status=enabled&reports_shown=true&incident=true" style="-ms-text-size-adjust: 100%; -webkit-text-size-adjust: 100%; text-decoration: none !important; color: #ffffff;">2</a>', body)  # 2 incidents
            # And Configuration is pluralized
            self.assertIn('Configurations affecting your systems</a>', body)

            # Delete the stale-hide* hosts so there is only 1 stale system
            InventoryHost.objects.filter(display_name__startswith="stale-hide").delete()
            mail.outbox = []
            reset_last_email_at()
            call_command('weekly_report_emails', org_id=['9876543'])
            body = mail.outbox[0]['body']
            # Only 5 systems now
            self.assertIn("""<span class="rh-metric__count" style="-ms-text-size-adjust: 100%; font-size: 28px; font-weight: 500; font-family: 'Red Hat Display', Helvetica, Arial sans-serif; line-height: 1.5;">5</span>""", body)
            # Only 1 stale system now
            self.assertIn('<a href="https://console.redhat.com/insights/inventory/?status=stale&status=stale_warning&source=puptoo" style="-ms-text-size-adjust: 100%; -webkit-text-size-adjust: 100%; text-decoration: none !important; color: #0066cc;">Check for stale systems</a>', body)

            # Delete the stale-warn host so there are no stale systems
            InventoryHost.objects.filter(display_name__startswith="stale-warn").delete()
            mail.outbox = []
            reset_last_email_at()
            call_command('weekly_report_emails', org_id=['9876543'])
            body = mail.outbox[0]['body']
            # Only 4 systems now
            self.assertIn("""<span class="rh-metric__count" style="-ms-text-size-adjust: 100%; font-size: 28px; font-weight: 500; font-family: 'Red Hat Display', Helvetica, Arial sans-serif; line-height: 1.5;">4</span>""", body)
            # No stale systems now
            self.assertNotIn('https://console.redhat.com/insights/inventory/?status=stale', body)
            self.assertNotIn('stale system', body)

            # Get the number of Red Hat disabled recommendations affecting systems for org_id 9876543
            # Should be none initially
            rhdisabled = get_rhdisabled_rules_systems('9876543')
            self.assertEqual(rhdisabled['rule_count'], 0)
            self.assertEqual(rhdisabled['system_count'], 0)

            # Change the acks for org_id 9876543 to AUTOACKs and there should be 1 system affected
            Ack.objects.filter(org_id='9876543').update(created_by=settings.AUTOACK['CREATED_BY'])
            rhdisabled = get_rhdisabled_rules_systems('9876543')
            self.assertEqual(rhdisabled['rule_count'], 1)
            self.assertEqual(rhdisabled['system_count'], 1)
            mail.outbox = []
            reset_last_email_at()
            call_command('weekly_report_emails', org_id=['9876543'])
            body = mail.outbox[0]['body']
            self.assertIn('Red Hat disabled recommendations applicable to your systems', body)
            self.assertIn('https://console.redhat.com/insights/advisor/recommendations?impacting=false&rule_status=rhdisabled', body)
            self.assertIn('https://console.redhat.com/apps/frontend-assets/email-assets/img_redhat_disabled.png', body)

            # Now AUTOACK the Second_rule and there should be 2 rules affecting 3 distinct systems (system1 is affected by both)
            Ack(account='1234567', org_id='9876543', rule=Rule.objects.get(rule_id='test|Second_rule'), created_by=settings.AUTOACK['CREATED_BY']).save()
            rhdisabled = get_rhdisabled_rules_systems('9876543')
            self.assertEqual(rhdisabled['rule_count'], 2)
            self.assertEqual(rhdisabled['system_count'], 3)
            mail.outbox = []
            reset_last_email_at()
            call_command('weekly_report_emails', org_id=['9876543'])
            body = mail.outbox[0]['body']
            self.assertIn('Red Hat disabled recommendations applicable to your systems', body)
            self.assertIn('https://console.redhat.com/insights/advisor/recommendations?impacting=false&rule_status=rhdisabled', body)
            self.assertIn('https://console.redhat.com/apps/frontend-assets/email-assets/img_redhat_disabled.png', body)

    @responses.activate
    def test_user_account_details_middleware_users_not_in_response(self):
        # Response not a 200 response code
        response_json = [{'username': 'some other username', 'data': 'junk'}]
        responses.add(
            responses.POST, test_middleware_url + '/users', status=200,
            json=response_json
        )
        mail.outbox = []
        reset_last_email_at()
        with self.settings(MIDDLEWARE_HOST_URL=test_middleware_url):
            call_command('weekly_report_emails')
            self.assertEqual(len(mail.outbox), 0)

    @responses.activate
    def test_weekly_report_emails_command_with_rbac(self):
        # Set up our fake user account lookup, fake mail sender and fake rbac service
        responses.add_callback(responses.POST, test_middleware_url + '/users', callback=lookup_user_details)
        responses.add_callback(responses.POST, test_middleware_url + '/sendEmails', callback=count_posted_emails)
        responses.add_callback(responses.GET, TEST_RBAC_V1_ACCESS, callback=lookup_rbac_permissions)
        # responses.add_callback(responses.GET, 'http://rbac.svc?app=insights', callback=lookup_rbac_permissions)
        out = StringIO

        # Initially the users have permissions - expect emails to be sent
        # Test using identity headers
        mail.outbox = []
        reset_last_email_at()
        with self.settings(
            RBAC_URL=TEST_RBAC_URL, RBAC_ENABLED=True,
            MIDDLEWARE_HOST_URL=test_middleware_url
        ):
            call_command('weekly_report_emails', stdout=out)
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0]['recipients'], ['"Test User" test-user@example.com'])

        # Repeat test using Advisor PSK
        mail.outbox = []
        reset_last_email_at()
        with self.settings(
            RBAC_ENABLED=True, RBAC_URL=TEST_RBAC_URL,
            RBAC_PSK="007", MIDDLEWARE_HOST_URL=test_middleware_url
        ):
            call_command('weekly_report_emails', stdout=out)
        self.assertEqual(len(mail.outbox), 1)

        # Change permissions so no users have permissions on Insights - expect no emails sent
        # Test using identity headers
        global user_permissions_table
        former_user_permissions_table = deepcopy(user_permissions_table)
        for key in user_permissions_table.keys():
            user_permissions_table[key]['data'] = []
        mail.outbox = []
        reset_last_email_at()
        with self.settings(
            RBAC_URL=TEST_RBAC_URL, RBAC_ENABLED=True,
            MIDDLEWARE_HOST_URL=test_middleware_url
        ):
            call_command('weekly_report_emails', stdout=out)
        self.assertEqual(len(mail.outbox), 0)

        mail.outbox = []
        reset_last_email_at()
        # Repeat test using Advisor PSK
        with self.settings(
            RBAC_URL=TEST_RBAC_URL, RBAC_PSK="007",
            RBAC_ENABLED=True, MIDDLEWARE_HOST_URL=test_middleware_url
        ):
            call_command('weekly_report_emails', stdout=out)
        self.assertEqual(len(mail.outbox), 0)
        user_permissions_table = former_user_permissions_table

        # Testing RBAC_ENABLED is set but RBAC_URL isn't - expect an exception
        with self.settings(RBAC_ENABLED=True, MIDDLEWARE_HOST_URL=test_middleware_url):
            self.assertRaisesMessage(Exception, "RBAC enabled but no URL specified.",
                                     has_rbac_permission, 'user', 'acct123')

    @responses.activate
    def test_weekly_report_emails_command_with_rbac_delete_expired(self):
        # Set up our fake user account lookup, fake mail sender and fake rbac service
        responses.add_callback(responses.POST, test_middleware_url + '/users', callback=lookup_user_details)
        responses.add_callback(responses.POST, test_middleware_url + '/sendEmails', callback=count_posted_emails)
        responses.add_callback(responses.GET, TEST_RBAC_V1_ACCESS, callback=lookup_rbac_permissions)
        out = StringIO

        self.assertEqual(WeeklyReportSubscription.objects.count(), 6)
        # Initially the users have permissions - expect emails to be sent
        # Test using identity headers
        with self.settings(
            RBAC_URL=TEST_RBAC_URL, RBAC_ENABLED=True,
            MIDDLEWARE_HOST_URL=test_middleware_url
        ):
            call_command('weekly_report_emails', '--delete-expired', stdout=out)
        # Normal emails sent out
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0]['recipients'], ['"Test User" test-user@example.com'])
        # But the unknown and invalid users have been deleted
        self.assertEqual(WeeklyReportSubscription.objects.count(), 4)

    @responses.activate
    def test_weekly_report_emails_command_with_rbac_unknown_user(self):
        # Set up our fake user account lookup, fake mail sender and fake rbac service
        responses.add_callback(responses.POST, test_middleware_url + '/users', callback=lookup_user_details)
        responses.add_callback(responses.POST, test_middleware_url + '/sendEmails', callback=count_posted_emails)
        responses.add_callback(responses.GET, TEST_RBAC_V1_ACCESS, callback=lookup_rbac_permissions)
        out = StringIO

        # Create a new subscription with an unknown username
        sub = WeeklyReportSubscription(username='not found', account='7654321', org_id='1234567')
        sub.save()
        # Trigger the email sending
        mail.outbox = []
        with self.settings(
            RBAC_URL=TEST_RBAC_URL, RBAC_ENABLED=True,
            MIDDLEWARE_HOST_URL=test_middleware_url
        ):
            call_command('weekly_report_emails', '--org-id=7654321', stdout=out)
        self.assertEqual(len(mail.outbox), 0)

    @responses.activate
    def test_weekly_report_emails_command_with_rbac_no_weekly_report(self):
        # Set up our fake user account lookup, fake mail sender and fake rbac service
        responses.add_callback(responses.POST, test_middleware_url + '/users', callback=lookup_user_details)
        responses.add_callback(responses.POST, test_middleware_url + '/sendEmails', callback=count_posted_emails)
        responses.add_callback(responses.GET, TEST_RBAC_V1_ACCESS, callback=lookup_rbac_permissions)
        out = StringIO

        # Trigger the email sending
        mail.outbox = []
        with self.settings(
            RBAC_URL=TEST_RBAC_URL, RBAC_ENABLED=True,
            MIDDLEWARE_HOST_URL=test_middleware_url
        ):
            call_command('weekly_report_emails', '--org-id=1234567', stdout=out)
        self.assertEqual(len(mail.outbox), 0)
