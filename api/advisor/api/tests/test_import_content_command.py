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
from os import remove, rename
from os.path import basename, exists, join
import random
import re
import responses
from shutil import copyfile
import yaml

from django.conf import settings
from django.core.management import call_command
from django.test import TestCase

from api.models import (
    Ack, Host, Playbook, Resolution, Rule,
    RuleCategory, RuleImpact, RuleSet, Tag,
)
from api.tests import constants
from api.utils import resolve_path

# Mainly for coverage tests
from api.management.commands.import_content import (
    update_model_from_config, load_config_from_file
)


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
CONTENT_URL_BASE = 'http://example.com/advisor_content/'


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
    """
    def __init__(self, *modifier_tuples):
        """
        Given a list of tuples of (file to modify, modifier function),
        prepare a temporary name for the given file.
        """
        self.modifier_tuples = modifier_tuples
        # Precalculate the temp file paths
        self.temp_file_paths = {
            file_path: temp_file(file_path, 6)
            for file_path, _ in modifier_tuples
        }

    def __enter__(self):
        # Go through each modifier, read the file, rename the file out of the
        # way, and write its modified content into place.
        for file_path, pipeline in self.modifier_tuples:
            temp_file_path = self.temp_file_paths[file_path]
            # Read the original content, possibly from our cache
            if file_path not in file_content_cache:
                with open(file_path, 'r') as fh:
                    file_content_cache[file_path] = fh.read()
            content = file_content_cache[file_path]
            # Rename the original file out of the way (leaves dates intact)
            rename(file_path, temp_file_path)
            # Write the modified content - in text mode.
            with open(file_path, 'w') as fh:
                new_content = pipeline(content)
                fh.write(new_content)

    def __exit__(self, exc_type, exc_val, exc_tb):
        for file_path, _ in self.modifier_tuples:
            temp_file_path = self.temp_file_paths[file_path]
            remove(file_path)
            rename(temp_file_path, file_path)

        # Context manager raises exceptions if we don't suppress:
        return False


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

        # There is a 'summary.md' file in the main plugin.yaml directory, but
        # all rules should override it with their own summary content.  This
        # is here mainly for coverage testing.
        self.assertEqual(
            Rule.objects.filter(summary='Summary not appearing in any rule').count(),
            0
        )

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

    @responses.activate
    def test_content_dump_load_from_url(self):
        content_yaml_file = join(PATH_TO_TEST_CONTENT_REPO, 'rule_content.yaml')
        playbook_yaml_file = join(PATH_TO_TEST_CONTENT_REPO, 'playbook_content.yaml')
        config_yaml_file = join(PATH_TO_TEST_CONTENT_REPO, 'content/config.yaml')
        # None of these should exist beforehand
        self.assertFalse(exists(content_yaml_file))
        self.assertFalse(exists(playbook_yaml_file))
        self.assertTrue(exists(config_yaml_file))

        # We need this context so that if any test fails, we still remove
        # the files we create.  Otherwise other tests see content they
        # probably shouldn't.
        with FileDeleter(
            content_yaml_file, playbook_yaml_file
        ):
            call_command(
                'import_content', '-c', PATH_TO_TEST_CONTENT_REPO,
                '--dump'
            )

            # We should now have the entire content written out in a yaml file.
            self.assertTrue(exists(content_yaml_file))
            self.assertTrue(exists(playbook_yaml_file))

            # Serve content from those files.  Because reading from the URL
            # takes precedence over reading local files, we can leave the dump
            # file in place.
            responses.add(
                responses.GET, CONTENT_URL_BASE + 'config.yaml',
                body=open(config_yaml_file, 'r').read(), status=200
            )
            responses.add(
                responses.GET, CONTENT_URL_BASE + 'rule_content.yaml',
                body=open(content_yaml_file, 'r').read(), status=200
            )
            responses.add(
                responses.GET, CONTENT_URL_BASE + 'playbook_content.yaml',
                body=open(playbook_yaml_file, 'r').read(), status=200
            )
            # Because the remote-url import searches for the content.yaml file
            # in compressed format, we need to at least answer this query.
            responses.add(
                responses.GET, CONTENT_URL_BASE + 'rule_content.yaml.gz',
                status=404
            )
            responses.add(
                responses.GET, CONTENT_URL_BASE + 'playbook_content.yaml.gz',
                status=404
            )

            # Delete stuff to check that read works...
            Playbook.objects.all().delete()  # delete before rules
            Rule.objects.all().delete()  # surprisingly this works...
            # Should be now able to read the content and config from the
            # base path.
            call_command(
                'import_content', '-u', CONTENT_URL_BASE,
            )
            # NoData tests have zero rules before, but we should have
            # loaded some now...
            self.assertGreater(Rule.objects.count(), 0)
            self.assertGreater(Playbook.objects.count(), 0)

        # Neither of these should exist afterward either
        self.assertFalse(exists(content_yaml_file))
        self.assertFalse(exists(playbook_yaml_file))

    @responses.activate
    def test_content_dump_load_compressed_from_url(self):
        content_yaml_gz_file = join(PATH_TO_TEST_CONTENT_REPO, 'rule_content.yaml.gz')
        playbook_yaml_gz_file = join(PATH_TO_TEST_CONTENT_REPO, 'playbook_content.yaml.gz')
        config_yaml_file = join(PATH_TO_TEST_CONTENT_REPO, 'content/config.yaml')
        # None of these should exist beforehand
        self.assertFalse(exists(content_yaml_gz_file))
        self.assertFalse(exists(playbook_yaml_gz_file))
        self.assertTrue(exists(config_yaml_file))

        # We need this context so that if any test fails, we still remove
        # the files we create.  Otherwise other tests see content they
        # probably shouldn't.
        with FileDeleter(
            content_yaml_gz_file, playbook_yaml_gz_file
        ):
            call_command(
                'import_content', '-c', PATH_TO_TEST_CONTENT_REPO,
                '--dump', '--compress'
            )

            # We should now have the entire content written out in a yaml file.
            self.assertTrue(exists(content_yaml_gz_file))
            self.assertTrue(exists(playbook_yaml_gz_file))

            # Serve content from those files.  Because reading from the URL
            # takes precedence over reading local files, we can leave the dump
            # file in place.
            responses.add(
                responses.GET, CONTENT_URL_BASE + 'config.yaml',
                body=open(config_yaml_file, 'r').read(), status=200
            )
            responses.add(
                responses.GET, CONTENT_URL_BASE + 'rule_content.yaml.gz',
                body=open(content_yaml_gz_file, 'rb').read(), status=200
            )
            responses.add(
                responses.GET, CONTENT_URL_BASE + 'playbook_content.yaml.gz',
                body=open(playbook_yaml_gz_file, 'rb').read(), status=200
            )
            # We don't add the uncompressed versions here because the
            # compressed versions take precedence.  If the uncompressed
            # versions are requested, they should cause a failure.

            # Delete stuff to check that read works...
            Playbook.objects.all().delete()  # delete before rules
            Rule.objects.all().delete()  # surprisingly this works...
            call_command(
                'import_content', '--remote-url', CONTENT_URL_BASE,
            )
            self.assertEqual(len(responses.calls), 3)
            self.assertGreater(Rule.objects.count(), 0)
            self.assertGreater(Playbook.objects.count(), 0)

            # Coverage test - rule content available but not playbooks.
            responses.reset()
            responses.add(
                responses.GET, CONTENT_URL_BASE + 'config.yaml',
                body=open(config_yaml_file, 'r').read(), status=200
            )
            responses.add(
                responses.GET, CONTENT_URL_BASE + 'rule_content.yaml.gz',
                body=open(content_yaml_gz_file, 'rb').read(), status=200
            )
            responses.add(
                responses.GET, CONTENT_URL_BASE + 'playbook_content.yaml.gz',
                status=404
            )
            responses.add(
                responses.GET, CONTENT_URL_BASE + 'playbook_content.yaml',
                status=404
            )

            # Delete stuff to check that read works...
            Playbook.objects.all().delete()  # delete before rules
            Rule.objects.all().delete()  # surprisingly this works...
            # Also test that URL without trailing slash is handled.
            self.assertEqual(CONTENT_URL_BASE[-1], '/')
            # And test that --compress and --dump are ignored with --remote-url
            with self.assertLogs('api.management.commands.import_content', level='INFO') as logs:
                call_command(
                    'import_content', '--remote-url', CONTENT_URL_BASE[:-1],
                    '--compress', '--dump'
                )
                self.assertIn(
                    "Importing content from remote URL",
                    logs.output[0]
                )
                self.assertIn(
                    "Ignoring '--compress' option when using remote URL",
                    logs.output[1]
                )
                self.assertIn(
                    "Ignoring '--dump' option when using remote URL",
                    logs.output[2]
                )
            self.assertEqual(len(responses.calls), 4)
            self.assertGreater(Rule.objects.count(), 0)
            self.assertEqual(Playbook.objects.count(), 0)
            # not a great result but better than a crash

        # Neither of these should exist afterward either
        self.assertFalse(exists(content_yaml_gz_file))
        self.assertFalse(exists(playbook_yaml_gz_file))

    @responses.activate
    def test_content_load_from_url_failures(self):

        # First, check that a missing config.yaml is handled.
        responses.add(
            responses.GET, CONTENT_URL_BASE + 'config.yaml',
            status=404
        )
        # This should be the only thing that's requested, other URls should
        # fail here.

        call_command(
            'import_content', '--remote-url', CONTENT_URL_BASE,
        )
        self.assertEqual(len(responses.calls), 1)

        # Test that a server error is handled.
        responses.reset()
        responses.add(
            responses.GET, CONTENT_URL_BASE + 'config.yaml',
            status=500
        )
        call_command(
            'import_content', '--remote-url', CONTENT_URL_BASE,
        )
        self.assertEqual(len(responses.calls), 1)

        # Test that missing content is handled.
        responses.reset()
        config_yaml_file = join(PATH_TO_TEST_CONTENT_REPO, 'content/config.yaml')
        responses.add(
            responses.GET, CONTENT_URL_BASE + 'config.yaml',
            body=open(config_yaml_file, 'r').read(), status=200
        )
        responses.add(
            responses.GET, CONTENT_URL_BASE + 'rule_content.yaml.gz',
            status=404
        )
        responses.add(
            responses.GET, CONTENT_URL_BASE + 'rule_content.yaml',
            status=404
        )
        # Playbook content should not be requested if rule content is missing.

        call_command(
            'import_content', '--remote-url', CONTENT_URL_BASE,
        )
        self.assertEqual(len(responses.calls), 3)


class NoDataImportContentTestCase(ImportContentTestCase):
    """
    Test that the content import command works with NO existing data.
    """
    fixtures = ['basic_test_ruleset', 'system_types', 'rule_categories', 'pathways']

    # All the tests of ImportContentTestCase should also work when we do not
    # have the basic_test_data already loaded...


class CoverageTestCase(TestCase):
    """
    All those tests to ensure we have good code coverage.
    """
    def test_update_model_from_config_no_config(self):
        self.assertIsNone(update_model_from_config(Rule, None, 'rule_id'))
        # Check log?

    def test_update_model_from_config_empty_config(self):
        self.assertTrue(update_model_from_config(Rule, {}, 'rule_id'))

    def test_load_config_no_file(self):
        self.assertFalse(load_config_from_file('/'))

    def test_load_database_maps_failures(self):
        # Have to set up various tables without loading fixtures.
        from api.models import RuleCategory, RuleImpact, Pathway, Tag, RuleSet
        from api.management.commands.import_content import load_database_maps

        # No RuleCategory
        with self.assertRaisesRegex(Exception, 'Category data is not loaded'):
            load_database_maps()

        RuleCategory.objects.create(name='Availability', id=1)

        # No RuleImpact
        with self.assertRaisesRegex(Exception, 'Impact data is not loaded'):
            load_database_maps()

        RuleImpact.objects.create(name='Critical', id=1)

        # No Pathway data
        with self.assertRaisesRegex(Exception, 'Pathway data is not loaded'):
            load_database_maps()

        Pathway.objects.create(resolution_risk_name='Collision of moons', id=1)

        # No Tag data
        with self.assertRaisesRegex(Exception, 'Rule tag data is not loaded'):
            load_database_maps()

        Tag.objects.create(name='Tag1')

        # No RuleSet data
        with self.assertRaisesRegex(Exception, 'Ruleset data is not loaded'):
            load_database_maps()

        RuleSet.objects.create(module_starts_with='plugins')

        # No SystemType data
        with self.assertRaisesRegex(Exception, 'System type data is not loaded'):
            load_database_maps()

        # Success path is tested in other code...

    def test_ruleset_not_found(self):
        from api.models import RuleSet
        from api.management.commands.import_content import find_ruleset_model
        self.assertEqual(RuleSet.objects.count(), 0)
        with self.assertRaisesRegex(ValueError, "No ruleset found with a prefix for 'foo'"):
            find_ruleset_model({'python_module': 'foo'})

    def test_rule_tags_not_found(self):
        from api.management.commands.import_content import load_all_rule_tags
        self.assertFalse(load_all_rule_tags([{'tags': ['foo']}]))

    def test_read_playbook_failures(self):
        playbook_file = join(PATH_TO_TEST_CONTENT_REPO, 'playbook.yaml')
        from api.management.commands.import_content import read_playbook
        with FileDeleter(playbook_file):
            # First: no name but first task is named
            playbook_content = [{
                'tasks': [{'name': 'test'}]
            }]
            yaml.dump(playbook_content, open(playbook_file, 'w'))
            _, name = read_playbook(PATH_TO_TEST_CONTENT_REPO, 'playbook.yaml')
            self.assertEqual(name, 'test')

            # Second: no name and no tasks
            playbook_content = [{
                'tasks': [{'module': 'test'}]
            }]
            yaml.dump(playbook_content, open(playbook_file, 'w'))
            _, name = read_playbook(PATH_TO_TEST_CONTENT_REPO, 'playbook.yaml')
            self.assertEqual(name, 'Unknown playbook')

            # Third: no name and no tasks
            playbook_content = [{
                'tasks': [{'module': 'test'}]
            }]
            yaml.dump(playbook_content, open(playbook_file, 'w'))
            _, name = read_playbook(PATH_TO_TEST_CONTENT_REPO, 'playbook.yaml')
            self.assertEqual(name, 'Unknown playbook')

    def test_generate_playbook_failures(self):
        from api.management.commands.import_content import generate_playbook_content
        from tempfile import TemporaryDirectory
        from os import mkdir

        with TemporaryDirectory() as temp_dir:
            # Step 1: no 'playbooks' directory
            self.assertIsNone(generate_playbook_content(temp_dir))

            playbooks_dir = join(temp_dir, 'playbooks')
            mkdir(playbooks_dir)
            playbook_dir = join(playbooks_dir, 'rhel_host')
            mkdir(playbook_dir)
            # Step 2: file walk finds file not ending with fixit.yml
            yaml.dump([{'name': 'step 2'}], open(join(playbook_dir, 'playbook.yml'), 'w'))
            # Step 3: fix_type() finds a file not ending with _fixit.yml
            yaml.dump([{'name': 'step 3'}], open(join(playbook_dir, 'fixit.yml'), 'w'))

            playbooks = generate_playbook_content(temp_dir)
            self.assertIsNotNone(playbooks)
            # The way this test is constructed, the temp_dir name is included
            # in the playbook rule ID, so we don't control that.  Instead,
            # just look at the only playbook that we should have got there...
            rule_id = f'{basename(temp_dir)}|playbooks'
            rule_fix = rule_id + 'fix'
            self.assertIn(rule_fix, playbooks)
            playbook_3 = playbooks[rule_fix]
            self.assertEqual(playbook_3['description'], 'step 3')
            self.assertEqual(playbook_3['play'], '- name: step 3\n')
            self.assertEqual(playbook_3['path'], '/playbooks/rhel_host/fixit.yml')
            # rule_id contains the temp_dir name
            self.assertEqual(playbook_3['rule_id'], rule_id)
            self.assertEqual(playbook_3['type'], 'fix')
            self.assertIsNone(playbook_3['version'])

    def test_command_no_repo_path(self):
        # Check that it actually logs the right messages
        with self.assertLogs('api.management.commands.import_content', level='INFO') as logs:
            call_command('import_content')
        self.assertIn('You need to set a content repo path', logs.output[0])
        with self.assertLogs('api.management.commands.import_content', level='INFO') as logs:
            call_command('import_content', '-c', '/foo')
        self.assertIn('Cannot find path /foo', logs.output[0])

    def test_command_load_failures(self):
        config_yaml_file = join(PATH_TO_TEST_CONTENT_REPO, 'content/config.yaml')
        # None of these should exist beforehand
        self.assertTrue(exists(config_yaml_file))

        # Missing config file.
        # Not sure why but
        with FileMisplacer(config_yaml_file):
            with self.assertLogs('api.management.commands.import_content', level='INFO') as logs:
                call_command(
                    'import_content', '-c', PATH_TO_TEST_CONTENT_REPO,
                )
            # Check that it actually logs the right messages
            self.assertIn(
                "ERROR:api.management.commands.import_content:Path "
                "'/home/pwayper/Code/insights/advisor-backend/api/test_content' does not contain "
                "config.yaml in main or content/ directories",
                logs.output
            )
            self.assertIn(
                'ERROR:api.management.commands.import_content:Could not load '
                'content configuration - exiting',
                logs.output
            )


class FixtureCoverageTestCase(TestCase):
    """
    All those tests to ensure we have good code coverage.
    """
    fixtures = [
        'basic_test_ruleset', 'system_types', 'rule_categories',
        'upload_sources', 'basic_test_data'
    ]

    def test_update_model_from_config_transformer_returns_none(self):
        # Set up a transformer that just returns a None; this should be
        # skipped in the import loop.
        def transformer(data):
            return None

        self.assertIsNone(update_model_from_config(
            Rule, {'id': 'rule_id'}, 'rule_id', transformer
        ))
