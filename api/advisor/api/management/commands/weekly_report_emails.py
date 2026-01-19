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
import requests
from os import environ
from time import sleep

from django.conf import settings
from django.core.management.base import BaseCommand
from django.http import Http404
from django.db.models import Q, Count, Exists, OuterRef
from django.template.loader import render_to_string
from django.utils import timezone

from api.models import (
    CurrentReport, InventoryHost, WeeklyReportSubscription, stale_systems_q, Ack
)
from api.permissions import (
    RHIdentityAuthentication, has_rbac_permission, request_object_for_testing
)
from api.utils import user_account_details
from api.views.stats import get_reports_stats, get_rules_stats
from advisor_logging import logger


"""
The process here is:

1) Work out which org_ids we want to send emails for - either taken from the
   command line or 'all of them'.
2) `handle_emails()` - send emails:
  a) `get_account_orgs()` - get the list of account and org_ids to send emails to
    1) only users that have not received a report before, or have received one
       more than MAIL_MINIMUM_HOURS hours ago, will receive an email.
  b) step through all the org_ids one at a time:
    1) `get_users_to_email()` - get the users in this org_id to email - if no
      users in this org_id, go to next org_id
       a) `utils.user_account_details()` - get the account details for all the
          users in this org_id
       b) Filter out users that don't have account details
       c) Filter out users that don't have the RBAC WEEKLY_REPORT_RBAC_PERMISSION
          set
       d) Filter out users that don't have an email address
       filtered users are 'rejected' - see later
    2) `get_reports()` - get the reports for this account
    3) `send_emails()` - for each user in this org_id receiving reports:
      a) Try sending the formatted HTML report to this user
      b) Try up to MAIL_RETRY_ATTEMPTS times with exponential backoff
      c) If successful, update the subscription's last email report date
      d) If the --delete-rejected-users flag is set, delete users rejected by
         the filters in step 2.b.1
3) Report the number of failed and successful emails sent (per person).
"""

delete_expired_users_help = '''
If set, users that will not receive an email will be deleted.  This
includes users that have been deleted in the portal, inactive users,
users without RBAC permissions, and users without an email address.
'''

default_subject = environ.get('MAIL_SUBJECT', 'Weekly Red Hat Lightspeed summary report')
default_html_template = environ.get('MAIL_HTML_TEMPLATE', 'weekly_report.html')
MAIL_RETRY_ATTEMPTS = int(environ.get('MAIL_RETRY_ATTEMPTS', 3))
MAIL_MINIMUM_HOURS = int(environ.get('MAIL_MINIMUM_HOURS', 24))
WEEKLY_REPORT_RBAC_PERMISSION = environ.get('WEEKLY_REPORT_RBAC_PERMISSION', 'advisor:*:*')

USE_PROMETHEUS = True if environ.get('USE_PROMETHEUS', '').lower() == 'true' else False
if USE_PROMETHEUS:
    from prometheus_client import push_to_gateway, CollectorRegistry, Gauge
    PROMETHEUS_PUSHGATEWAY = environ.get('PROMETHEUS_PUSHGATEWAY', 'localhost:9091')
    REGISTRY = CollectorRegistry()
    PROMETHEUS_JOB = "weekly_report_emails"
    WEEKLY_EMAILS_STATUS = Gauge(
        'advisor_weekly_report_emails_status',
        'Did the weekly report emails send successfully (1) or not (0)?',
        ['status_message'], registry=REGISTRY)


def send_to_prometheus(email_status, status_message=""):
    if USE_PROMETHEUS:
        logger.info(
            "Sending email status '%d', message '%s', to prometheus pushgateway '%s'",
            email_status, status_message, PROMETHEUS_PUSHGATEWAY
        )
        WEEKLY_EMAILS_STATUS.labels(status_message=status_message).set(email_status)
        try:
            push_to_gateway(PROMETHEUS_PUSHGATEWAY, job=PROMETHEUS_JOB, registry=REGISTRY)
        except Exception as e:
            logger.error("Error sending data to prometheus pushgateway: %s", str(e))


class MiddlewareClient:
    def __init__(self):
        # Just define the session settings here.  The Middleware URL may be
        # set on the fly in testing, so only test that when we want to send
        # an email.
        self.session = requests.Session()
        self.session.verify = settings.MIDDLEWARE_CERT_FILE
        self.session.headers = {
            'x-rh-apitoken': settings.MIDDLEWARE_API_TOKEN,
            'x-rh-clientid': settings.MIDDLEWARE_CLIENT_ID,
        }

    def send_email(self, subject, from_email, recipient, body):
        if not settings.MIDDLEWARE_HOST_URL:
            logger.debug("emails disabled because MIDDLEWARE_HOST_URL not set")
            return
        response = self.session.post(
            settings.MIDDLEWARE_HOST_URL + '/sendEmails',
            json={
                'emails': [
                    {
                        'subject': subject,
                        'body': body,
                        'recipients': [recipient],
                        'bodyType': "html",
                    }
                ]
            },
        )
        if response.status_code == 200:
            logger.debug("email sent successfully to %s", recipient)
        else:
            logger.error(
                "email request failed for %s: HTTP %s -- %s",
                recipient,
                response.status_code,
                response.content.decode()
            )
            response.raise_for_status()


def get_account_orgs(org_filter, latest_email_time):
    return WeeklyReportSubscription.objects.filter(
        org_filter,
        Q(last_email_at__isnull=True) | Q(last_email_at__lt=latest_email_time),
    ).values(
        'account', 'org_id'
    ).order_by('org_id').distinct('org_id')


def get_rhdisabled_rules_systems(org_id):
    return CurrentReport.objects.filter(
        stale_systems_q(org_id=org_id),
        Exists(Ack.objects.filter(
            rule_id=OuterRef('rule_id'),
            org_id=org_id,
            created_by=settings.AUTOACK['CREATED_BY']
        )),
        org_id=org_id,
        rule__active=True
    ).aggregate(
        rule_count=Count('rule', distinct=True),
        system_count=Count('host', distinct=True)
    )


def get_inventory_hosts_stats(org_id):
    # Used in new email template to get the total number of registered & stale hosts
    hosts_qs = InventoryHost.objects.filter(org_id=org_id, host__isnull=False)
    return {
        'total': hosts_qs.count(),
        'stale': hosts_qs.filter(per_reporter_staleness__puptoo__stale_timestamp__lt=str(timezone.now())).count()
    }


def get_reports(org_id):
    return {
        'rules': get_rules_stats(org_id),
        'reports': get_reports_stats(org_id),
        'systems': get_inventory_hosts_stats(org_id),
        'rhdisabled': get_rhdisabled_rules_systems(org_id),
        'date': timezone.now(),
        'news': None  # None or some object containing a 'content' property that
        # lists news in HTML format.
    }


def get_users_to_email(org_id, account, latest_email_time):
    subscription_for = {
        wrs.username: wrs
        for wrs in WeeklyReportSubscription.objects.filter(
            Q(last_email_at__isnull=True) | Q(last_email_at__lt=latest_email_time),
            org_id=org_id,
        )
    }

    # Thanks to use of get_accounts we always have at least one subscription
    try:
        account_details_for = {
            data['username']: data
            for data in user_account_details(sorted(subscription_for.keys()))
        }
    except Http404:
        # Error already logged, go with no account details.
        account_details_for = {}
    users_to_email = []
    expired_users = []

    for username in subscription_for:
        # Ensure we have account details for this user
        if username not in account_details_for:
            logger.debug("no account details found for user '%s'", username)
            expired_users.append(username)
            continue
        subscription_data = subscription_for[username]
        account_data = account_details_for[username]
        if not ('is_active' in account_data and account_data['is_active']):
            expired_users.append(username)
            continue
        org_id = subscription_data.org_id
        request = request_object_for_testing(
            auth_by=RHIdentityAuthentication, org_id=org_id, username=username
        )
        result, _ = has_rbac_permission(request, WEEKLY_REPORT_RBAC_PERMISSION)
        # Don't need the elapsed time here.
        if not result:
            logger.debug("User '%s' in account '%s' org_id '%s' doesn't have permission to receive the report email", username, account, org_id)
            expired_users.append(username)
            continue
        user_to_email = account_data
        user_to_email['subscription_object'] = subscription_data
        user_to_email['address'] = user_to_email.get('address_string') or user_to_email.get('email')
        if user_to_email['address']:
            users_to_email.append(user_to_email)
        else:
            expired_users.append(username)

    return (users_to_email, expired_users)


def send_emails(org_id, account, reports, users_to_email, subject, html_template, client):
    users_success = []
    logger.info(
        "Sending weekly report emails for account %s org_id %s to %d %s",
        account, org_id, len(users_to_email),
        "address" if len(users_to_email) == 1 else "addresses",
    )

    for user in list(users_to_email):
        reports['user'] = user
        for attempt in range(1, MAIL_RETRY_ATTEMPTS + 1):
            logger.debug("Attempt #%d sending email to username: '%s', email: '%s'",
                         attempt, user['username'], user['address'])
            try:
                client.send_email(
                    subject=subject,
                    from_email='Red Hat Lightspeed <noreply@redhat.com>',
                    recipient=user['address'],
                    body=render_to_string(html_template, context=reports),
                )
            except Exception:
                # Send failed for some reason, retry after a short delay
                if attempt < MAIL_RETRY_ATTEMPTS:
                    sleep_time = 0.1 if settings.ENVIRONMENT == 'dev' else 3
                    logger.exception("Problem sending weekly report email to %s.  Retrying in %d seconds ...",
                                     user['address'], sleep_time)
                    sleep(sleep_time)
                else:
                    logger.error("Failed all %d attempts at sending email to %s.  Giving up.",
                                 MAIL_RETRY_ATTEMPTS, user)
            else:
                # Send was successful, take this user out of the 'users_to_email' list so we don't
                # keep retrying it if others fail
                users_to_email.remove(user)
                # Update user's last_email_at time
                user['subscription_object'].last_email_at = timezone.now()
                user['subscription_object'].save(update_fields=['last_email_at'])
                users_success.append(user)
                # Send was successful for this user, break out of retry loop
                break

    # return successful users, failed users
    return users_success, users_to_email


def handle_emails(
    org_id_filter, latest_email_time, subject, html_template,
    delete_expired_users=False
):
    total_users_failed = 0
    total_users_success = 0

    account_orgs = get_account_orgs(org_id_filter, latest_email_time)
    if not account_orgs:
        logger.info(
            "Found no orgs subscribed for weekly emails, or all have emails sent "
            "within last %dhrs", MAIL_MINIMUM_HOURS
        )
        return 0, 0

    client = MiddlewareClient()
    for account_org in account_orgs:
        (users_to_email, expired_users) = get_users_to_email(
            account_org['org_id'], account_org['account'], latest_email_time
        )
        if not users_to_email:
            logger.error(
                f"No users have valid email addresses in account {account_org['account']} org_id {account_org['org_id']}, or we"
                " could not find the users in our WeeklyReportSubscription table"
            )
            continue

        reports = get_reports(account_org['org_id'])

        # Accounts that do not have systems should not receive the email
        if 'systems' in reports and reports['systems']['total'] == 0:
            logger.info("No systems found for org_id %s. Not sending email",
                        account_org['org_id'])
            continue

        users_success, users_failed = send_emails(
            account_org['org_id'], account_org['account'],
            reports, users_to_email, subject, html_template, client
        )
        total_users_failed += len(users_failed)
        total_users_success += len(users_success)

        if expired_users and delete_expired_users:
            delete_stats = WeeklyReportSubscription.objects.filter(
                org_id=account_org['org_id'],
                username__in=expired_users
            ).delete()
            logger.info(
                "Deleted %d expired users from org_id %s",
                delete_stats[0], account_org['org_id']
            )

    return total_users_success, total_users_failed


class Command(BaseCommand):
    help = 'Sends weekly reports'

    def add_arguments(self, parser):
        parser.add_argument(
            '--subject', type=str, default=default_subject,
            help='subject line for email',
        )
        parser.add_argument(
            '--html-template', type=str, default=default_html_template,
            help='Django HTML template for rendering email',
        )
        parser.add_argument(
            '--org-id', type=str, action='append',
            help='An account org_id number to specifically send emails to'
        )
        parser.add_argument(
            '--org-id-from', type=str, action='store',
            help='Start sending emails from this account org_id number (inclusive)'
        )
        parser.add_argument(
            '--org-id-to', type=str, action='store',
            help='End sending emails at this account org_id number (inclusive)'
        )
        parser.add_argument(
            '--delete-expired-users', action='store_true',
            default=False, help=delete_expired_users_help
        )
        parser.epilog = '''
            Can list multiple individual accounts to send emails to.
            This will be combined with the from and to range; addresses in
            any account matching one or more of these criteria will receive
            emails. Only one range can be specified at one time.
        '''

    def handle(self, *args, **options):
        # Parse options and determine org_id filter
        subject = options['subject']
        html_template = options['html_template']
        org_id_filter = Q()
        latest_email_time = timezone.now() - timedelta(hours=MAIL_MINIMUM_HOURS)
        # One or more listed accounts:
        # Argument options are added but are None if not supplied, so test
        # for truthiness rather than existence in dictionary.
        if options['org_id']:
            org_id_filter |= Q(org_id__in=options['org_id'])
        # Or account in range:
        if options['org_id_from'] and options['org_id_to']:
            # Odd - dates can be between a range but not char fields?
            org_id_filter |= Q(
                Q(org_id__gte=options['org_id_from']) & Q(org_id__lte=options['org_id_to'])
            )
        elif options['org_id_from']:
            org_id_filter |= Q(org_id__gte=options['org_id_from'])
        elif options['org_id_to']:
            org_id_filter |= Q(org_id__lte=options['org_id_to'])

        try:
            total_users_success, total_users_failed = handle_emails(
                org_id_filter, latest_email_time, subject, html_template,
                options['delete_expired_users']
            )
        except Exception as e:
            # Catch any unhandled exceptions and report a failure to prometheus
            logger.exception("Failed to send weekly report emails")
            send_to_prometheus(0, str(e))
            raise

        if total_users_failed > 0:
            send_to_prometheus(0, f"Sending emails failed for {total_users_failed} user(s)")
        elif total_users_success == 0:
            send_to_prometheus(0, "No emails were sent to any users!")
        else:
            send_to_prometheus(1, f"Emails sent successfully for {total_users_success} user(s)")
