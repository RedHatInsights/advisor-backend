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

import argparse
import csv
import gzip
import sys

from django.core.management.base import BaseCommand

from api.models import InventoryHost, Rule
from django.db import connection, transaction
from sat_compat.models import SatMaintenance, SatMaintenanceAction


def parse_value(value):
    # Do any data conversions we need here.
    if value == 'NULL':
        return None
    else:
        return value


def read_dump_file_to_struct(gz_file):
    fh = gzip.GzipFile(fileobj=gz_file, mode='rb')
    csv_data = csv.reader((s.decode() for s in fh), delimiter='\t')
    # Have to use that as an iterator
    header = None
    data = []
    for row in csv_data:
        if not header:
            header = row
            if 'maintenance_id' not in row:
                sys.stdout.write("ERROR: Header missing 'maintenance_id' field.")
                exit
            continue
        data.append({
            header_field: parse_value(row_field)
            for header_field, row_field in zip(header, row)
        })
    fh.close()
    return data


def merge_plan_and_action_data(plan_data, action_data):
    """
    Merge the two flat tables into a structure similar to the one we get from
    requests to the Classic /r/insights/v3/maintenance endpoint, because
    that's what we're going to iterate over.  This changes the plan_data
    structure, but it returns it as well.
    """
    # Make up a temporary dict listing the actions for each plan
    actions_for_plan = dict()
    for action in action_data:
        plan_id = action['maintenance_id']
        if plan_id not in actions_for_plan:
            actions_for_plan[plan_id] = []
        # Now mangle the action into the Classic structure - just need the
        # rule and system IDs to be in the right place, and the 'done' flag.
        actions_for_plan[plan_id].append({
            'id': action['id'],
            'done': False,
            'system': {'system_id': action['system_id']},
            'rule': {'id': action['rule_id']},
        })
    # And then assign that list of actions to each plan in the list; each
    # plan needs a list of actions even if it's empty.
    for plan in plan_data:
        # Put actions list into plan data
        plan['actions'] = (
            actions_for_plan[plan['maintenance_id']]
            if plan['maintenance_id'] in actions_for_plan
            else []
        )
        # Add times to timezones
        if plan['start'] is not None:
            plan['start'] += '+00:00'
        if plan['end'] is not None:
            plan['end'] += '+00:00'
        # Fix plan remote branch if it's too large, based on the possibly
        # rash assumption from eyeballing the data that the remote branch
        # UUID is the first 36 characters.
        if plan['remote_branch'] is None:
            pass
        elif plan['remote_branch'] == 'NULL':
            plan['remote_branch'] = None
        elif len(plan['remote_branch']) > 36:
            plan['remote_branch'] = plan['remote_branch'][0:36]
    return plan_data


class Command(BaseCommand):
    help = 'Import maintenance plans from Insights Classic'

    def add_arguments(self, parser):
        parser.add_argument(
            '-pf', '--plan-file', '--plan-dump-file', type=argparse.FileType('rb'),
            help='Dump of all plan data to load plans from (as gzipped TSV)'
        )
        parser.add_argument(
            '-af', '--action-file', '--action-dump-file', type=argparse.FileType('rb'),
            help='Dump of all action data to load plans from (as gzipped TSV)'
        )

    def handle(self, *args, **options):
        # Check options
        verbose = options.get('verbosity', 0)
        # Converted to underscores, yay?
        if options['plan_file'] and options['action_file']:
            plan_data = read_dump_file_to_struct(options['plan_file'])
            action_data = read_dump_file_to_struct(options['action_file'])
            classic_plans = merge_plan_and_action_data(plan_data, action_data)
        else:
            # But not both: argument error; this takes precedence over --file
            self.stdout.write("Error: need both --plan-file and --action-file options")
            return

        # Cache all active rules from rule_id to Rule object
        rule_object_for = {
            rule['rule_id']: rule['id']
            for rule in Rule.objects.filter(active=True).values('id', 'rule_id')
        }

        classic_plans_by_account = {}
        for cp in classic_plans:
            classic_plans_by_account.setdefault(cp['account_number'], []).append(cp)

        # Note that we can't preserve the identifier numbers of the Classic
        # plans and actions without doing away with the AutoFields.  However,
        # users shouldn't be looking up their plans and actions by ID, so we
        # don't really care.
        for account in classic_plans_by_account:
            # Cache insights_id to id for current account
            host_object_for = {
                str(ih['insights_id']): ih['id']
                for ih in InventoryHost.objects.filter(
                     account=account
                ).values('id', 'insights_id')
            }

            for classic_plan in classic_plans_by_account[account]:
                if verbose > 1:
                    self.stdout.write(f"Checking plan {classic_plan['maintenance_id']}... ")
                if 'remote_branch' not in classic_plan or not classic_plan['remote_branch']:
                    if verbose > 1:
                        self.stdout.write("... ignoring due to no valid branch ID")
                        self.stdout.write(f"... {classic_plan=}")
                    continue
                # Create Plan and its actions in a transaction
                with transaction.atomic():
                    adv_plan, created = SatMaintenance.objects.update_or_create(
                        pk=classic_plan['maintenance_id'],
                        defaults={
                            'account': account, 'name': classic_plan['name'],
                            'branch_id': classic_plan['remote_branch'],
                            'description': classic_plan['description'],
                            'start': classic_plan['start'],
                            'end': classic_plan['end'],
                            'created_by': classic_plan['created_by'],
                            'silenced': classic_plan['silenced'],
                            'hidden': classic_plan['hidden'],
                            'suggestion': classic_plan['suggestion'],
                            'allow_reboot': classic_plan['allow_reboot'],
                        }
                    )
                    if verbose > 1:
                        self.stdout.write('... created.' if created else '... updated.')

                    # Throughout this we can assume that Classic and Advisor have the
                    # same set of rules.  But we can't assume that they have the same
                    # hosts.
                    if created:
                        if verbose > 1:
                            self.stdout.write(f"Bulk creating {len(classic_plan['actions'])} (or fewer) actions")
                        SatMaintenanceAction.objects.bulk_create([
                            SatMaintenanceAction(
                                pk=action['id'],
                                plan=adv_plan,
                                rule_id=rule_object_for[action['rule']['id']],
                                host_id=host_object_for[action['system']['system_id']],
                                done=action['done'],
                            )
                            for action in classic_plan['actions']
                            if action['rule']['id'] in rule_object_for and action['system']['system_id'] in host_object_for
                        ])

        # Update auto increment id sequences so new inserts do not collide
        with connection.cursor() as cursor:
            cursor.execute("SELECT setval('sat_compat_satmaintenance_id_seq', (SELECT MAX(id) FROM sat_compat_satmaintenance) + 1);")
            cursor.execute("SELECT setval('sat_compat_satmaintenanceaction_id_seq', (SELECT MAX(id) FROM sat_compat_satmaintenanceaction) + 1);")
