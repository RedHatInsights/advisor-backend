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

from os import environ

from django.conf import settings
from django.template.loader import render_to_string

from api.models import WeeklyReportSubscription
from api.management.commands.weekly_report_emails import MiddlewareClient
from api.permissions import (
    RHIdentityAuthentication, has_rbac_permission, request_object_for_testing
)


default_subject = environ.get(
    'WELCOME_MAIL_SUBJECT',
    'Subscription Confirmation - Red Hat Lightspeed Advisor Weekly Report'
)
default_html_template = environ.get(
    'WELCOME_MAIL_HTML_TEMPLATE', 'subscription_confirmation.html')


def send_confirmation_email(username):
    """
    Send a confirmation email to this user.

    Permission check has been done in update_wrs (as the only caller).
    """
    client = MiddlewareClient()
    # Ignore errors if sending the email fails...
    try:
        return client.send_email(
            subject=default_subject,
            from_email='Red Hat Lightspeed <noreply@redhat.com>',
            recipient=username,
            body=render_to_string(default_html_template, context={}),
        )
    except Exception:
        # Error already logged in MiddlewareClient.
        pass


def update_wrs(username, account, sub_desired=True, org_id=None, auto_subscribed=False):
    """
    Subscribe and/or Auto-Subscribe a user for a WeeklyReportSubscription.

    Only available if the user has permission to update their weekly report
    settings (and RBAC enabled, of course).
    """
    if settings.RBAC_ENABLED:
        request = request_object_for_testing(
            auth_by=RHIdentityAuthentication, org_id=org_id, username=username
        )
        success, elapsed = has_rbac_permission(request, 'advisor:weekly-report:write')
        if not success:
            return

    sub_qs = WeeklyReportSubscription.objects.filter(
        username=username, org_id=org_id,
    )
    currently_subbed = sub_qs.exists()
    if currently_subbed and not sub_desired:
        # Delete the entry if currently subscribed
        sub_qs.delete()
    elif not currently_subbed and (sub_desired or auto_subscribed):
        # Add an entry if not currently subscribed
        WeeklyReportSubscription.objects.update_or_create(
            username=username, account=account, org_id=org_id, last_email_at=None, autosub=auto_subscribed
        )
        send_confirmation_email(username)
