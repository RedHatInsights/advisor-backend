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

import datetime
from dateutil import tz
import functools
from os import remove, rename, stat
from os.path import exists, join
import pytz
import random
import re
import responses
from shutil import copyfile, copystat
from typing import Any, Dict
import yaml
import zlib

from django.conf import settings
from django.core.management import call_command
from django.test import TestCase

from api.models import (
    Ack, Host, Playbook, Resolution, Rule,
    RuleCategory, RuleImpact, RuleSet, Tag,
)
from api.tests import constants
from api.utils import resolve_path


PATH_TO_TEST_CONTENT_REPO = resolve_path('api/test_content')
ACTIVE_RULE_METADATA_FILE = join(
    PATH_TO_TEST_CONTENT_REPO,
    'content/fixture_data/test/Active_rule/metadata.yaml'
)
ACTIVE_RULE_MORE_INFO_FILE = join(
    PATH_TO_TEST_CONTENT_REPO,
    'content/fixture_data/test/Active_rule/more_info.md'
)
ACKED_RULE_RESOLUTION_FILE = join(
    PATH_TO_TEST_CONTENT_REPO,
    'content/fixture_data/test/Acked_rule/resolution.md'
)


def temp_file(name, len):
    random_chars = 'QWERTYUIOPASDFGHJKLZXCVBNM1234567890qwertyuiopasdfghjklzxcvbnm'
    return name + '.temp.' + ''.join(random.sample(random_chars, len))


# A cache for the file content, so we can modify the same file multiple times
# and not have to re-read its content explicitly.
file_content_cache = dict()


class FileDeleter(object):
    """
    A context manager that will make sure that a given set of files are
    deleted after the code block is done.
    """
    def __init__(self, *paths):
        self.paths = paths
        # print(f"Remembering {paths} to remove...")

    def __enter__(self):
        # Nothing to do here...
        pass

    def __exit__(self, exc_type, exc_val, exc_tb):
        for path in self.paths:
            # print(f"Removing {path}")
            if exists(path):
                remove(path)
        # Context manager raises exceptions if we don't suppress:
        return False


class FileMisplacer(object):
    """
    This provides a context manager that will move a given file or directory
    'out of the way' while doing a test.  In other words, inside the context
    the file or directory given will be 'misplaced' to a temporary name
    inside the same directory; when the context ends it will be back in
    place.  If the path name does not exist, nothing happens.
    """

    def __init__(self, *names):
        """
        Given a list of names, prepare a temporary name for each.
        """
        self.names = names
        self.temp_name_of = {
            name: temp_file(name, 6)
            for name in names
        }

    def __enter__(self):
        for name in self.names:
            rename(name, self.temp_name_of[name])

    def __exit__(self, exc_type, exc_val, exc_tb):
        for name in self.names:
            rename(self.temp_name_of[name], name)
        # Context manager raises exceptions if we don't suppress:
        return False


class FileModifier(object):
    """
    This provides a context manager to use both in decorating test methods,
    but also within the test method itself.  We'll see which turns out to be
    the more useful...

    Each modification links a file to a pipeline which modifies its content.

    If the `leave_originals` flag is left at False, then the original file
    is moved out of the way to a temporary name, and the modified content is
    written in its place.  This is normally used when you want to pretend that
    the modified file is as found on the file system.  When leaving the
    context, the modified files are removed and the original files renamed
    back into place.

    If the `leave_originals` flag is set to True, then the original file is
    left as is and the modified content is written to the temporary file name.
    When leaving the context, the modified file is removed.  This allows
    content to be modified and the modifications removed afterward.  In this
    case you will want to capture the dictionary of temporary names returned
    by the context, e.g.:

    with FileModifier((('this_file.txt', modifier_fn),), leave_originals=True) as temp_filename_for:
        with open(temp_filename_for['this_file.txt'], 'r') as fh:
            fh.read()
    """
    def __init__(self, *modifier_tuples, leave_originals=False):
        """
        Given a list of tuples of (file to modify, modifier function),
        prepare a temporary name for the given file.
        """
        self.modifier_tuples = modifier_tuples
        self.leave_originals = leave_originals
        # Precalculate the temp file paths
        self.temp_file_paths = {
            file_path: temp_file(file_path, 6)
            for file_path, _ in modifier_tuples
        }

    def __enter__(self):
        # Go through each modifier, read the file, rename the file out of the
        # way, and write its modified content into place.
        for file_path, pipeline in self.modifier_tuples:
            # Rough hack for zipped file reading and writing.
            read_mode, write_mode = (
                ('rb', 'wb') if file_path.endswith('.gz')
                else ('r', 'w')
            )
            temp_file_path = self.temp_file_paths[file_path]
            # Read the original content, possibly from our cache
            if file_path not in file_content_cache:
                with open(file_path, read_mode) as fh:
                    file_content_cache[file_path] = fh.read()
            content = file_content_cache[file_path]
            if self.leave_originals:
                # Write the modified content - in text mode.
                with open(temp_file_path, write_mode) as fh:
                    new_content = pipeline(content)
                    fh.write(new_content)
            else:
                # Rename the original file out of the way (leaves dates intact)
                rename(file_path, temp_file_path)
                # Write the modified content - in text mode.
                with open(file_path, write_mode) as fh:
                    new_content = pipeline(content)
                    fh.write(new_content)
        # The context returns the temporary file paths
        return self.temp_file_paths

    def __exit__(self, exc_type, exc_val, exc_tb):
        for file_path, _ in self.modifier_tuples:
            temp_file_path = self.temp_file_paths[file_path]
            if self.leave_originals:
                remove(temp_file_path)
            else:
                remove(file_path)
                rename(temp_file_path, file_path)

        # Context manager raises exceptions if we don't suppress:
        return False


def modifies_file(file_path, pipeline):
    """
    A decorator applied to a test method, which takes an absolute file path
    and some 'modifier' function(s) (see below) that acts on the content of
    that file.  The contents of the file are read, and the modified contents
    are written back.
    """
    def modifies_decorator(fn):
        @functools.wraps(fn)
        def fn_to_modify(*args, **kwargs):
            with FileModifier((file_path, pipeline)):
                return fn(*args, **kwargs)

        return fn_to_modify

    return modifies_decorator


# YAML modifier

def modify_yaml(**kwargs):
    """
    Returns a function that interprets text as YAML, treats it as a dictionary,
    modifies keys in it according to the keyword arguments, and returns it as
    text.
    """
    def modify_yaml_text(text):
        in_dict = yaml.load(text, yaml.Loader)
        return yaml.dump({**in_dict, **kwargs})

    return modify_yaml_text


# Text modifiers

def re_sub(pattern, repl):
    """
    Return a function that can be given a line and will apply this regular
    expression substitution of pattern -> repl to it.
    """
    com_pattern = re.compile(pattern)

    def apply_to_line(line):
        return com_pattern.sub(repl, line)

    return apply_to_line


def replace(match, repl):
    """
    Return a function that can be given a line and will return it with
    the given match string replaced with the repl string.
    """
    def apply_to_line(line):
        return line.replace(match, repl)

    return apply_to_line


def modify_text(*modifiers):
    """
    Modify the text using a series of modifiers that act on lines in the text.

    Matchers are constructed using the above re_sub() and replace() functions,
    and are applied in the order given.
    """

    def modify_text_def(in_text):
        # splitlines seems to absorb a trailing newline...
        trailing_newline = in_text.endswith('\n')

        def modify_line(line):
            for modifier in modifiers:
                line = modifier(line)
            return line

        return '\n'.join(
            modify_line(line)
            for line in in_text.splitlines()
        ) + ('\n' if trailing_newline else '')

    return modify_text_def


def modify_compressed(modifier):
    """
    Modify a compressed text file by taking bytes, decompressing them,
    modifying them with the given modifier function, and re-compressing them
    on the fly.
    """
    def encabulator(in_bytes):
        decompressed_bytes = zlib.decompress(in_bytes, wbits=25)
        changed_bytes = modifier(decompressed_bytes.decode('utf-8')).encode('utf-8')
        return zlib.compress(changed_bytes, level=9, wbits=25)

    return encabulator


def parse_modified_datetime(modified_str: str) -> datetime:
    """
    For reasons beyond mortal comprehension, datetime.strptime does NOT normally
    recognise the '%Z' part like 'UTC' in the time string.  So we do our best
    to recognise it here and return a timezone-aware datetime.

    Examples:

    'Wed, 25 Jun 2025 00:58:45 UTC'
    """
    # The string without timezone is 25 characters long.
    assert len(modified_str) >= 25
    std_format = '%a, %d %b %Y %H:%M:%S'
    naive_dt = datetime.datetime.strptime(modified_str[:25], std_format)
    # Then try and guess the timezone
    timezone = (
        modified_str[26:]
        if len(modified_str) > 26
        else 'UTC'
    )
    if timezone not in pytz.common_timezones:
        timezone = 'UTC'
    return naive_dt.astimezone(pytz.timezone(timezone))


def modified_since_callback(request, file_path: str):
    """
    The callback partial for checking whether the request's 'If-Modified-Since'
    date is NO LATER than the given date.  If so, it returns a 304 status with
    no content; if not it returns a 200 with the content.  You don't need to
    set the 'Last-Modified' header in the response.  Use this as:

    callback=functools.partial(
        modified_since_callback, file_path=config_file_path
    )
    """
    # Remember, this is from the perspective of the server, so the file_date
    # is the file we're going to serve and the request_date is the date of
    # the file on the client.

    # We have to have a file to serve, so get its date
    assert exists(file_path)
    file_date = datetime.datetime.fromtimestamp(
        stat(file_path).st_mtime, tz=tz.tzlocal()
    )
    file_header = {
        'Last-Modified': file_date.strftime('%a, %d %b %Y %H:%M:%S %Z')
    }
    # Get request's 'If-Modified-Since' date, or epoch if not present.
    req_date = (
        parse_modified_datetime(request.headers['If-Modified-Since'])
        if 'If-Modified-Since' in request.headers
        else datetime.datetime(1970, 1, 1, 0, 0, 0).astimezone(tz.tzlocal())
    )
    # Compare and give the appropriate response (status, headers, body):
    if file_date < req_date:
        return (304, file_header, b'')  # No body
    else:
        with open(file_path, 'rb') as fh:
            file_content = fh.read()
        return (200, file_header, file_content)


# The actual tests

class ImportContentTestCase(TestCase):
    """
    Test that the content import command works with existing data.
    """
    # NOTE: if you get lots of weird errors about resolutions not being
    # present, and rules that are supposed to be active not being active,
    # then check that the test content directory does not have the
    # rule_content.yaml and playbook_content.yaml files created in the
    # `test_content_dump_load` test...
    fixtures = [
        'basic_test_ruleset', 'system_types', 'rule_categories',
        'upload_sources', 'basic_test_data'
    ]

    def test_basic_import_rule_config(self):
        # First we should just make sure that the content repo path has the
        # basic things we expect...
        self.assertTrue(exists(PATH_TO_TEST_CONTENT_REPO))
        self.assertTrue(exists(join(PATH_TO_TEST_CONTENT_REPO, 'content/')))
        self.assertTrue(exists(join(PATH_TO_TEST_CONTENT_REPO, 'playbooks/')))

        call_command('import_content', '-c', PATH_TO_TEST_CONTENT_REPO)

        # Basic stuff that we should see
        self.assertGreater(RuleCategory.objects.count(), 0)
        self.assertGreater(RuleSet.objects.count(), 0)
        self.assertGreater(RuleImpact.objects.count(), 0)
        self.assertGreater(Tag.objects.count(), 0)

    def test_basic_import_rule_content(self):
        call_command('import_content', '-c', PATH_TO_TEST_CONTENT_REPO)

        # Compare the complete properties of one rule to the standard test data
        active_rule = Rule.objects.get(rule_id=constants.active_rule)
        # Note - compare foreign key fields, not IDs, especially for NoDataImportContentTestcase
        self.assertEqual(active_rule.description, constants.active_title)
        self.assertEqual(active_rule.total_risk, 1)
        self.assertEqual(active_rule.active, True)
        self.assertEqual(active_rule.reboot_required, False)
        self.assertEqual(active_rule.impact.name, 'Invalid Configuration')
        self.assertEqual(active_rule.likelihood, 1)
        self.assertEqual(active_rule.publish_date, datetime.datetime(2018, 5, 23, 15, 38, 55, tzinfo=datetime.timezone.utc))
        self.assertEqual(active_rule.category.name, 'Availability')
        self.assertEqual(active_rule.node_id, "1048576")
        # The summary field in the associated content repository is different
        # from the generic, but the standard rule content remains the same.
        # This tests that the content overrides the rule fixtures.
        self.assertEqual(active_rule.summary, "This content can be different to the `generic.md` file, but can still contain\n**MarkDown** markup.\n")
        self.assertEqual(active_rule.generic, "markdown can include:\n\n* bullet lists\n* block quotations:\n\n    Shall I compare thee to a summer's day?\n\n* *italic* and **bold** markup.\n\n~~~\n10 PRINT 'FENCED CODE'\n20 GOTO 10\n~~~\n")
        self.assertEqual(active_rule.reason, "This rule has\n DoT syntax object {{=pydata.active}} still *embedded* in HTML")
        self.assertEqual(active_rule.more_info, "DoT {{=pydata.active}} active and **mark-up**\n\n* list 1\n  ~~~\n  Code block inside indent\n  ~~~\n* list 2\n")
        active_resolution = active_rule.resolution_set.all()[0]
        self.assertEqual(active_resolution.resolution, 'In order to fix this problem, {{=pydata.active}} must equal **bar**')
        self.assertEqual(active_resolution.resolution_risk.name, 'Adjust Service Status')
        self.assertEqual(active_resolution.system_type_id, 105)
        self.assertEqual(set(t.name for t in active_rule.tags.all()), {'active', 'testing', 'kernel'})
        self.assertEqual(active_rule.pathway.name, 'test component 2')  # Is this changing?
        self.assertEqual(
            active_rule.playbooks()[0].description,
            'Fix for Active_rule on rhel/host'
        )

        # Then test the differences
        acked_rule = Rule.objects.get(rule_id=constants.acked_rule)
        self.assertEqual(acked_rule.description, constants.acked_title)
        second_rule = Rule.objects.get(rule_id=constants.second_rule)
        self.assertEqual(second_rule.description, constants.second_title)
        self.assertEqual(second_rule.node_id, '')
        second_resolution = second_rule.resolution_set.all()[0]
        self.assertEqual(second_resolution.resolution, 'Secondary rule resolution content with {{=pydata.second}} engaged')
        self.assertEqual(second_resolution.system_type_id, 89)
        notyetactive_rule = Rule.objects.get(rule_id=constants.notyetactive_rule)
        self.assertFalse(notyetactive_rule.active)

    def test_autoack_import(self):
        standard_ack_ids = set(Ack.objects.values_list('id', flat=True))
        # Tests won't work if there are no hosts, ergo no org_ids, to create acks for
        if Host.objects.count() == 0:
            return

        with FileModifier(
            (ACTIVE_RULE_METADATA_FILE, modify_yaml(
                tags=['active', 'kernel', 'testing', 'autoack']
            ))
        ):
            call_command('import_content', '-c', PATH_TO_TEST_CONTENT_REPO)

            active_rule = Rule.objects.get(rule_id=constants.active_rule)
            # Firstly, does the rule have the new tag?
            self.assertEqual(
                set(t.name for t in active_rule.tags.all()),
                {'active', 'testing', 'kernel', 'autoack'}
            )

            # And have new Acks been created?
            self.assertGreater(
                Ack.objects.exclude(id__in=standard_ack_ids).count(), 0
            )
            self.assertGreater(
                Ack.objects.filter(created_by=settings.AUTOACK['CREATED_BY']).count(),
                0
            )

        # And now, with the file content back to normal, these should be returned to normal
        call_command('import_content', '-c', PATH_TO_TEST_CONTENT_REPO)
        self.assertEqual(
            Ack.objects.exclude(id__in=standard_ack_ids).count(), 0
        )
        self.assertEqual(
            Ack.objects.filter(created_by=settings.AUTOACK['CREATED_BY']).count(),
            0
        )

    def test_content_update(self):
        """
        Test updates to content.
        """
        call_command('import_content', '-c', PATH_TO_TEST_CONTENT_REPO)
        active_rule = Rule.objects.get(rule_id=constants.active_rule)
        self.assertTrue(active_rule.active)
        self.assertEqual(active_rule.node_id, '1048576')
        self.assertEqual(
            active_rule.more_info,
            "DoT {{=pydata.active}} active and **mark-up**\n\n* list 1\n"
            "  ~~~\n  Code block inside indent\n  ~~~\n* list 2\n"
        )
        acked_rule = Rule.objects.get(rule_id=constants.acked_rule)
        self.assertIn(
            'must equal',
            acked_rule.resolution_set.get(system_type_id=105).resolution,
        )
        # Problem we noticed in Stage - a resolution that's changed its
        # system type and now has two resolutions.  The content import needs
        # to delete the old ones.
        other_res = Resolution(
            rule=acked_rule, system_type_id=99,  # rhev/hypervisor
            resolution="Foo must never be set to 'bar'",
            resolution_risk_id=1
        )
        other_res.save()  # this is the 'old' resolution that should be removed.

        with FileModifier(
            (ACTIVE_RULE_METADATA_FILE, modify_yaml(
                node_id='2097152',
                status='inactive'
            )),
            (ACTIVE_RULE_MORE_INFO_FILE, modify_text(
                replace('list 1', 'item 1')
            )),
            (ACKED_RULE_RESOLUTION_FILE, modify_text(
                replace('must equal', 'must not equal')
            )),
        ):
            call_command('import_content', '-c', PATH_TO_TEST_CONTENT_REPO)

            # Get database updates
            active_rule.refresh_from_db()
            # Status is now inactive:
            self.assertFalse(active_rule.active)
            # Node ID has changed:
            self.assertEqual(active_rule.node_id, '2097152')
            # More info has changed
            self.assertEqual(
                active_rule.more_info,
                "DoT {{=pydata.active}} active and **mark-up**\n\n* item 1\n"
                "  ~~~\n  Code block inside indent\n  ~~~\n* list 2\n"
            )
            acked_rule.refresh_from_db()
            self.assertIn(
                'must not equal',
                acked_rule.resolution_set.get(system_type_id=105).resolution
            )
            # The other resolution should be removed.
            self.assertEqual(
                acked_rule.resolution_set.filter(system_type_id=99).count(), 0
            )

        # And now with those changes reverted the rule should be put back
        call_command('import_content', '-c', PATH_TO_TEST_CONTENT_REPO)
        # Get database updates again
        active_rule.refresh_from_db()
        self.assertTrue(active_rule.active)
        self.assertEqual(active_rule.node_id, '1048576')
        self.assertEqual(
            active_rule.more_info,
            "DoT {{=pydata.active}} active and **mark-up**\n\n* list 1\n"
            "  ~~~\n  Code block inside indent\n  ~~~\n* list 2\n"
        )
        acked_rule.refresh_from_db()
        self.assertIn(
            'must equal',
            acked_rule.resolution_set.get(system_type_id=105).resolution,
        )
        # The other resolution should stay removed.
        self.assertEqual(
            acked_rule.resolution_set.filter(system_type_id=99).count(), 0
        )

    def test_content_dump_load(self):
        content_yaml_file = join(PATH_TO_TEST_CONTENT_REPO, 'rule_content.yaml')
        playbook_yaml_file = join(PATH_TO_TEST_CONTENT_REPO, 'playbook_content.yaml')
        new_config_file = join(PATH_TO_TEST_CONTENT_REPO, 'config.yaml')
        # None of these should exist beforehand
        self.assertFalse(exists(content_yaml_file))
        self.assertFalse(exists(playbook_yaml_file))
        self.assertFalse(exists(new_config_file))

        # We need this context so that if any test fails, we still remove
        # the files we create.  Otherwise other tests see content they
        # probably shouldn't.
        with FileDeleter(
            content_yaml_file, playbook_yaml_file, new_config_file
        ):
            call_command(
                'import_content', '-c', PATH_TO_TEST_CONTENT_REPO,
                '--dump'
            )

            # We should now have the entire content written out in a yaml file.
            self.assertTrue(exists(content_yaml_file))
            # with open(content_yaml_file, 'r') as fh:
            #     print(f"Content from {content_yaml_file=}: {fh.read()}")
            # Because this directory contains playbooks as well...
            self.assertTrue(exists(playbook_yaml_file))

            # Now we have to be tricky.  We want to get the 'content' directory
            # out of the way, but we need its 'config.yaml'.
            orig_content_dir = join(PATH_TO_TEST_CONTENT_REPO, 'content')
            orig_config_file = join(orig_content_dir, 'config.yaml')
            copyfile(orig_config_file, new_config_file)
            with FileMisplacer(orig_content_dir):
                self.assertFalse(exists(orig_content_dir))
                # Delete stuff to check that read works...
                Playbook.objects.all().delete()  # delete before rules
                Rule.objects.all().delete()  # surprisingly this works...
                # Should be now able to read the content and config from the
                # base path.
                call_command(
                    'import_content', '-c', PATH_TO_TEST_CONTENT_REPO,
                )
                # NoData tests have zero rules before, but we should have
                # loaded some now...
                self.assertGreater(Rule.objects.count(), 0)
                self.assertGreater(Playbook.objects.count(), 0)

        # Neither of these should exist afterward either
        self.assertFalse(exists(content_yaml_file))
        self.assertFalse(exists(playbook_yaml_file))

    def test_content_dump_load_compressed(self):
        content_yaml_file = join(PATH_TO_TEST_CONTENT_REPO, 'rule_content.yaml.gz')
        playbook_yaml_file = join(PATH_TO_TEST_CONTENT_REPO, 'playbook_content.yaml.gz')
        new_config_file = join(PATH_TO_TEST_CONTENT_REPO, 'config.yaml')
        # None of these should exist beforehand
        self.assertFalse(exists(content_yaml_file))
        self.assertFalse(exists(playbook_yaml_file))
        self.assertFalse(exists(new_config_file))

        # We need this context so that if any test fails, we still remove
        # the files we create.  Otherwise other tests see content they
        # probably shouldn't.
        with FileDeleter(
            content_yaml_file, playbook_yaml_file, new_config_file
        ):
            call_command(
                'import_content', '-c', PATH_TO_TEST_CONTENT_REPO,
                '--dump', '--compress'
            )

            # We should now have the entire content written out in a yaml file.
            self.assertTrue(exists(content_yaml_file))
            # Because this directory contains playbooks as well...
            self.assertTrue(exists(playbook_yaml_file))

            # Now we have to be tricky.  We want to get the 'content' directory
            # out of the way, but we need its 'config.yaml'.
            orig_content_dir = join(PATH_TO_TEST_CONTENT_REPO, 'content')
            orig_config_file = join(orig_content_dir, 'config.yaml')
            copyfile(orig_config_file, new_config_file)
            with FileMisplacer(orig_content_dir):
                self.assertFalse(exists(orig_content_dir))
                # Delete stuff to check that read works...
                Playbook.objects.all().delete()  # delete before rules
                Rule.objects.all().delete()  # surprisingly this works...
                # Should be now able to read the content and config from the
                # base path.
                call_command(
                    'import_content', '-c', PATH_TO_TEST_CONTENT_REPO,
                )
                # NoData tests have zero rules before, but we should have
                # loaded some now...
                self.assertGreater(Rule.objects.count(), 0)
                self.assertGreater(Playbook.objects.count(), 0)

        # Neither of these should exist afterward either
        self.assertFalse(exists(content_yaml_file))
        self.assertFalse(exists(playbook_yaml_file))

    @responses.activate()
    def test_content_load_from_remote(self):
        """
        We want to test that when the import content command reads from a
        remote URL, it gets updated content.  This should override the
        (compressed or uncompressed) content files it expects to see, if they
        exist.  So the test matrix is:

        source files in content directory | remote files            | tested
        ----------------------------------+-------------------------+-------
        don't exist                       | uncompressed            | test 1
        don't exist                       | compressed
        uncompressed                      | uncompressed, not later
        uncompressed                      | uncompressed, later
        uncompressed                      | compressed, not later
        uncompressed                      | compressed, later
        compressed                        | uncompressed, not later
        compressed                        | uncompressed, later
        compressed                        | compressed, not later
        compressed                        | compressed, later

        Ideally we also care that the content is actually loaded.  Maybe this
        should be better checked with no data, but ideally when we modify the
        content file this should change the file date, which in turn should
        modify the header's 'Last-Modified' date.
        """
        # Note: a fair number of the asserts in here are to make sure that
        # the test environment doesn't have file artefacts from its own
        # tests left lying around.  Use of FileDeleter and FileModifier
        # context managers needs to be pretty strict.

        def response_lookup() -> Dict[str | None, Any]:
            # Translate the list of requests and responses into a dict
            return {
                call.request.url: call.response
                for call in responses.calls
                if call.request.url
            }

        CONTENT_SERVER_BASE_URL = 'http://localhost/content/advisor/'
        rules_url_path = CONTENT_SERVER_BASE_URL + 'rule_content.yaml'
        playbook_url_path = CONTENT_SERVER_BASE_URL + 'playbook_content.yaml'
        config_url_path = CONTENT_SERVER_BASE_URL + 'config.yaml'

        # Generate and dump the content to files
        content_yaml_file = join(PATH_TO_TEST_CONTENT_REPO, 'rule_content.yaml')
        playbook_yaml_file = join(PATH_TO_TEST_CONTENT_REPO, 'playbook_content.yaml')
        config_file = join(PATH_TO_TEST_CONTENT_REPO, 'content/config.yaml')
        base_config_file = join(PATH_TO_TEST_CONTENT_REPO, 'config.yaml')

        with FileDeleter(
            content_yaml_file, playbook_yaml_file
        ):
            self.assertFalse(exists(content_yaml_file))
            self.assertFalse(exists(playbook_yaml_file))
            # The config file is a property of the repository itself...
            self.assertTrue(exists(config_file))
            call_command(
                'import_content', '-c', PATH_TO_TEST_CONTENT_REPO,
                '--dump',
            )
            self.assertTrue(exists(content_yaml_file))
            self.assertTrue(exists(playbook_yaml_file))

            # Now set up our responses server:
            responses.add_callback(
                responses.GET, url=rules_url_path,
                callback=functools.partial(
                    modified_since_callback, file_path=content_yaml_file
                )
            )
            responses.add_callback(
                responses.GET, url=playbook_url_path,
                callback=functools.partial(
                    modified_since_callback, file_path=playbook_yaml_file
                )
            )
            responses.add_callback(
                responses.GET, url=config_url_path,
                callback=functools.partial(
                    modified_since_callback, file_path=config_file
                )
            )
            # Because it will try to search for compressed content we need
            # to return 404s on that explicitly
            responses.get(rules_url_path + '.gz', status=404)
            responses.get(playbook_url_path + '.gz', status=404)

            # Uncompressed content files, no repository dump available
            # Delete stuff to check that read works...
            Playbook.objects.all().delete()  # delete before rules
            Rule.objects.all().delete()  # surprisingly this works...
            # Because we use '-c /tmp' here, files are put into /tmp, so we
            # need to make sure they're removed later.
            with FileDeleter('/tmp/config.yaml', '/tmp/rule_content.yaml', '/tmp/playbook_content.yaml'):
                self.assertFalse(exists('/tmp/config.yaml'))
                self.assertFalse(exists('/tmp/rule_content.yaml'))
                self.assertFalse(exists('/tmp/playbook_content.yaml'))
                # Now try to import content, with a base directory that does not
                # contain any content or playbook repositories.
                call_command(
                    'import_content', '-c', '/tmp',
                    '--remote', CONTENT_SERVER_BASE_URL
                )
            # Basic content checks
            self.assertGreater(Rule.objects.count(), 0)
            self.assertGreater(Playbook.objects.count(), 0)
            # Of course we can't check the requests object directly here, but
            # Responses should have responded to those requests.
            response_for_url = response_lookup()
            self.assertIn(rules_url_path, response_for_url)
            self.assertEqual(response_for_url[rules_url_path].status_code, 200)
            self.assertIn(playbook_url_path, response_for_url)
            self.assertEqual(response_for_url[playbook_url_path].status_code, 200)
            self.assertIn(config_url_path, response_for_url)
            self.assertEqual(response_for_url[config_url_path].status_code, 200)
            # The compressed files were requested first but not found
            self.assertIn(rules_url_path + '.gz', response_for_url)
            self.assertEqual(response_for_url[rules_url_path + '.gz'].status_code, 404)
            self.assertIn(playbook_url_path + '.gz', response_for_url)
            self.assertEqual(response_for_url[playbook_url_path + '.gz'].status_code, 404)

            responses.reset()

            # Uncompressed content, already existing files, no modification.
            # Unfortunately the responses library is not clever enough to
            # respond to the 'If-Modified-Since' header even if
            responses.add_callback(
                responses.GET, url=rules_url_path,
                callback=functools.partial(
                    modified_since_callback, file_path=content_yaml_file
                )
            )
            responses.add_callback(
                responses.GET, url=playbook_url_path,
                callback=functools.partial(
                    modified_since_callback, file_path=playbook_yaml_file
                )
            )
            responses.add_callback(
                responses.GET, url=config_url_path,
                callback=functools.partial(
                    modified_since_callback, file_path=config_file
                )
            )
            # Because it will try to search for compressed content we need
            # to return 404s on that explicitly
            responses.get(rules_url_path + '.gz', status=404)
            responses.get(playbook_url_path + '.gz', status=404)

            # Delete stuff to check that read works...
            Playbook.objects.all().delete()  # delete before rules
            Rule.objects.all().delete()  # surprisingly this works...
            # Note that import_content will check the -c path for config.yaml
            # before content/config.yaml, so we should copy that into the
            # test content repo directory
            with FileDeleter(base_config_file):
                # Copy config including access and modification times
                copyfile(config_file, base_config_file)
                copystat(config_file, base_config_file)
                call_command(
                    'import_content', '-c', PATH_TO_TEST_CONTENT_REPO,
                    '--remote', CONTENT_SERVER_BASE_URL
                )
            # Here we don't expect the content
            # Responses should have responded to those requests.
            response_for_url = response_lookup()
            self.assertIn(rules_url_path, response_for_url)
            self.assertEqual(response_for_url[rules_url_path].status_code, 304)
            self.assertIn(playbook_url_path, response_for_url)
            self.assertEqual(response_for_url[playbook_url_path].status_code, 304)
            self.assertIn(config_url_path, response_for_url)
            self.assertEqual(response_for_url[config_url_path].status_code, 304)
            # The compressed files were requested first but not found
            self.assertIn(rules_url_path + '.gz', response_for_url)
            self.assertEqual(response_for_url[rules_url_path + '.gz'].status_code, 404)
            self.assertIn(playbook_url_path + '.gz', response_for_url)
            self.assertEqual(response_for_url[playbook_url_path + '.gz'].status_code, 404)

            # with FileModifier(
            #     ((content_file, modifiers), (playbook_file, modifiers)),
            #     leave_originals=True
            # ) as temp_file_names:
            #     call_command(
            #         'import_content', '-c', PATH_TO_TEST_CONTENT_REPO,
            #         '--remote', CONTENT_SERVER_BASE_URL
            #     )


class NoDataImportContentTestCase(ImportContentTestCase):
    """
    Test that the content import command works with NO existing data.
    """
    fixtures = ['basic_test_ruleset', 'system_types', 'rule_categories', 'pathways']

    # All the tests of ImportContentTestCase should also work when we do not
    # have the basic_test_data already loaded...
