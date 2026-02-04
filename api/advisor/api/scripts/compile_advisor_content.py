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
from os import path, walk
import subprocess
import yaml
import zlib

import logging

logger = logging.getLogger(__name__)

##############################################################################
# Read the Insights plugin content and playbook directories and produce the
# 'dumped' files that Advisor needs to import the content.  This saves us
# having to transmit the directories as zip files and unpack them and load
# them in the Advisor container.  Everything has to be done without access to
# the Advisor database, and preferably with only standard Python libraries.
##############################################################################


content_fields = {'generic', 'more_info', 'reason', 'resolution', 'summary'}


##############################################################################
# Dump file reading and writing
##############################################################################

RULE_CONTENT_YAML_FILE = 'rule_content.yaml'
PLAYBOOK_CONTENT_YAML_FILE = 'playbook_content.yaml'


def dump_yaml(content, yaml_filename):
    """
    Dump data to a YAML file, compressing it if it ends with the .gz extension.
    """
    with open(yaml_filename, 'wb') as fh:
        dump_data = yaml.dump(content).encode('utf-8')
        if yaml_filename.endswith('.gz'):
            # Write with max compression and gzip header
            dump_data = zlib.compress(dump_data, level=9, wbits=25)
        fh.write(dump_data)


##############################################################################
# Content reading
##############################################################################


def get_field_content(plugin_path, field):
    """
    If the content MarkDown file for this field exists in this path, return
    its content, otherwise return None.
    """
    markdown_file = path.join(plugin_path, f"{field}.md")
    if not path.exists(markdown_file):
        return None
    with open(markdown_file, 'r') as fd:
        return fd.read()


def add_markdown_fields(base_data, base_path):
    """
    Add any found Markdown fields to the base data.  base_data is modified.
    """
    for field in content_fields:
        content = get_field_content(base_path, field)
        if content is not None:
            base_data[field] = content


def read_plugin_content(plugin_path):
    """
    Read the content in the plugin path and populate a dict with it.  This
    includes both the plugin.yaml file and any metadata files
    """
    # We know there's a plugin.yaml file here because that's what tells us
    # this is a plugin directory and to read the plugin content.
    with open(path.join(plugin_path, 'plugin.yaml'), 'r') as fd:
        plugin_data = yaml.load(fd, yaml.Loader)
    add_markdown_fields(plugin_data, plugin_path)
    return plugin_data


def read_rule_content(plugin_data, rule_path):
    """
    Read the content in the rule path and populate a dict with it.  This
    includes both the plugin.yaml file and any metadata files
    """
    # We know there's a metadata.yaml file here because that's what tells us
    # this is a rule directory and to read the rule content.
    rule_content = dict(plugin_data)
    metadata_filename = path.join(rule_path, 'metadata.yaml')
    with open(metadata_filename, 'r') as fd:
        metadata = yaml.load(fd, yaml.Loader)
    # The actual rule metadata always supplies settings, right?
    assert metadata, f"Metadata file at {metadata_filename} must have settings"
    rule_content.update(metadata)
    add_markdown_fields(rule_content, rule_path)
    return rule_content


def rule_path_to_id(rule_path):
    """
    Transform the path into its plugin_name|ERROR_KEY format.
    """
    error_key = path.basename(rule_path)
    plugin_path = path.dirname(rule_path)
    plugin_name = path.basename(plugin_path)
    rule_id = f"{plugin_name}|{error_key}"
    return rule_id


def generate_rule_content(content_dir):
    """
    Go through the content directory and construct it into rule data.
    This looks for the `plugin.yaml` as the base directory of a plugin, and
    then the directories underneath that for the rule data.

    Originally I thought it would be worth using this code just for bulk
    import, and then using other code for when we only wanted to pick up
    just the updates since the last time a rule was changed in the database.
    But it turns out this is fast enough, at least in testing so far, that
    it's not worth yet trying to write code that reads the `git diff --since`
    output and just parses those things.
    """
    all_rule_data = list()
    this_plugin_dir = 'no directory'
    # The tree structure of the rule content dir is something like this:
    # api/test_content/content/
    # ├── config.yaml
    # └── fixture_data
    #     ├── README.md
    #     └── test
    #         ├── plugin.yaml
    #         ├── Acked_rule
    #         │   ├── generic.md
    #         │   ├── metadata.yaml
    #         │   ├── more_info.md
    #         │   ├── reason.md
    #         │   ├── resolution.md
    #         │   └── summary.md
    # We search for either the `plugin.yaml` or `metadata.yaml` files to
    # then get the rule data.  The 'plugin' here is 'test' and the 'error_key'
    # (though we don't refer to it) is 'Acked_rule'.  Because this is a
    # depth-first search, the plugin_data will remain the same across all
    # error keys, and will be read before the metadata.
    plugin_data = dict()
    for this_path, dirs, files in walk(content_dir):
        if 'plugin.yaml' in files:
            this_plugin_dir = this_path
            # This is the plugin part of the rule content, which loads the
            # 'default' content for this rule.  This is then copied and
            # overwritten by the rule content.
            plugin_data = read_plugin_content(this_path)
        # By tradition, rules have an upper-case error key.  Guess what the
        # test data fixtures do not have?  So no 'path.basename(this_path).isupper()'
        # test here.  And really we shouldn't assume that error keys will
        # always be upper case - what distinguishes a rule content directory
        # is that it's got a metadata.yaml file.
        elif 'metadata.yaml' in files:
            assert this_path.startswith(this_plugin_dir)
            # There's a weird extra condition in the content server manager
            # code that looks for paths with no yaml files, but we don't seem
            # to see any of those in the content repository.
            rule_id = rule_path_to_id(this_path)
            rule_content = read_rule_content(plugin_data, this_path)
            rule_content['rule_id'] = rule_id
            all_rule_data.append(rule_content)

    return all_rule_data


##############################################################################
# Playbook directory processing
##############################################################################

def get_playbook_name(playbook_data, playbook_filename):
    """
    Read the playbook and find its name, possibly having to grab it from the
    first task.
    """
    first = playbook_data[0]
    if not isinstance(first, dict):
        logger.error("Playbook %s is malformed", playbook_filename)
        return 'Unknown playbook'
    if 'name' in first:
        return first['name']
    logger.warning("Playbook %s has no name - trying to find first task?", playbook_filename)
    if not ('tasks' in first and isinstance(first['tasks'], list)):
        logger.error("Playbook %s has no tasks", playbook_filename)
        return 'Unknown playbook'
    if not (first['tasks'] and 'name' in first['tasks'][0]):
        logger.error("Playbook %s has no named first task", playbook_filename)
        return 'Unknown playbook'
    return first['tasks'][0]['name']


def read_playbook(this_path, file):
    """
    Read the playbook, and grab a few things from it.  We don't want to store
    the actual YAML, we store the raw file content, but OTOH we do need to
    know the description.
    """
    playbook_filename = path.join(this_path, file)
    with open(playbook_filename, 'r') as fh:
        playbook_content = fh.read()
    playbook_data = yaml.load(playbook_content, yaml.Loader)
    assert len(playbook_data) > 0, f"Playbook {playbook_filename} empty?"
    assert isinstance(playbook_data[0], dict), f"Playbook {playbook_filename} not a dict?"
    name = get_playbook_name(playbook_data, playbook_filename)
    return (playbook_content, name)


def find_git_root(playbook_dir):
    """
    Find the root of the git repository.
    """
    command = ['git', '-C', playbook_dir, 'rev-parse', '--show-toplevel']
    result = subprocess.run(command, capture_output=True, text=True)
    return result.stdout.strip()


def find_git_hashes(playbook_dir):
    """
    Read the git log to determine the latest hash for each file.  More or less
    drawn from the content server.
    """
    command = ['git', '-C', playbook_dir, 'log', '--stat', '--name-only', "--pretty=hash:%H"]
    last_hash = None
    hash_for_file = dict()
    git_proc = subprocess.run(command, capture_output=True)
    for line in git_proc.stdout.decode().splitlines():
        # line = line.strip()  -- necessary?
        if not line:
            continue
        if line.startswith('hash:'):
            last_hash = line[5:]
            continue
        if not line.endswith('fixit.yml'):
            continue
        # Line here now is the file path and name, starting from the root of
        # the repository, which might not be the 'playbook_dir' base.
        if line not in hash_for_file:
            hash_for_file[line] = last_hash

    return hash_for_file


def generate_playbook_content(playbook_dir):
    """
    Go through the playbook content directory and get a list of playbooks.

    Advisor currently does not care what's in the Playbook model, it is never
    served.  It only cares that they exist, and RHINENG-12950 will simplify
    this down to a simple count in the Rule data.  So we do the minimum we
    have to at this stage.
    """
    if not path.exists(path.join(playbook_dir, 'playbooks')):
        logger.error(
            f"Directory {playbook_dir} does not seem to have the playbooks directory"
        )
        return

    # In generating content we should not refer to the database.  It's
    # tempting to cheat here and include the resolution ID, but we can't
    # store that in a dump...

    playbook_for_rule = dict()

    def fix_type(file):
        if file.endswith('_fixit.yml'):
            return file[:-len('_fixit.yml')]
        else:
            return 'fix'

    hash_for_file = find_git_hashes(playbook_dir)
    git_root = find_git_root(playbook_dir)
    # Note that this also has to cope with being given test data that's not
    # in a git repository.  It seems to work now.

    for this_path, dirs, files in walk(path.join(playbook_dir, 'playbooks')):
        # If we ever find a playbook repository that uses anything other than
        # 'rhel_host' as its system type... then we need to change to something
        # like...
        # for dir_name in dirsp
        #     if dir_name in system_type_set:
        #         # remember this path and associate with this system type
        # Rules are still only associated with one system type though so we
        # rely on the system type definition in the rule.
        if this_path.endswith('rhel_host'):
            rule_id = rule_path_to_id(path.dirname(this_path))
            # We're going to store some playbooks that might not appear in the
            # database here...
            for file in files:
                if not file.endswith('fixit.yml'):
                    continue
                (playbook_content, description) = read_playbook(this_path, file)
                # This key must match the construction of the `rule_id_type`
                # annotation below, as the unique key we're comparing to.
                fix = fix_type(file)
                key = rule_id + fix

                # Construct absolute path
                playbook_abs_path = path.join(this_path, file)
                # Convert to relative path from git root for hash lookup
                playbook_rel_path = path.relpath(playbook_abs_path, git_root)

                playbook_for_rule[key] = {
                    'rule_id': rule_id,
                    'type': fix,
                    'play': playbook_content,
                    'description': description,
                    'path': playbook_abs_path,
                    'version': hash_for_file.get(playbook_rel_path)
                }

    return playbook_for_rule


##############################################################################
# Main command
##############################################################################


if __name__ == '__main__':
    logging.basicConfig(
        level=logging.INFO,
        format='%(levelname)s: %(message)s',
        stream=__import__('sys').stdout
    )
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--content-repo-path', '-c', type=str, required=True,
        help='The path to the Insights content repository',
    )
    parser.add_argument(
        '--playbook-repo-path', '-p', type=str,
        help='The path to the Insights playbook repository (or -c dir)',
    )
    parser.add_argument(
        '--compress', '-z', default=False, action='store_true',
        help="Compress dumped content"
    )

    args = parser.parse_args()
    if not path.exists(args.content_repo_path):
        logger.error(f"Cannot find path {args.content_repo_path}")
    playbook_repo_path = args.playbook_repo_path
    if not playbook_repo_path:
        playbook_repo_path = args.content_repo_path

    content = generate_rule_content(args.content_repo_path)
    logger.info(f"{len(content)} rules loaded")
    playbooks = generate_playbook_content(playbook_repo_path)
    logger.info(f"{len(playbooks)} playbooks loaded")
    gz_extension = '.gz' if args.compress else ''
    dump_yaml(content, f'{RULE_CONTENT_YAML_FILE}{gz_extension}')
    dump_yaml(playbooks, f'{PLAYBOOK_CONTENT_YAML_FILE}{gz_extension}')
