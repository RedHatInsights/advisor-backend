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

from datetime import datetime
from os import path
import pytz
import requests
import yaml
import zlib

from django.conf import settings
from django.core.management.base import BaseCommand
from django.db.models import F, CharField, Value
from django.db.models.functions import Concat
from django.db.models.base import ModelBase
from django.utils.dateparse import parse_datetime

from api.models import (
    Ack, Host, Pathway, Playbook, Resolution, ResolutionRisk, Rule,
    RuleCategory, RuleImpact, RuleSet, SystemType, Tag,
)
from api.scripts.compile_advisor_content import (
    dump_yaml, generate_rule_content, generate_playbook_content
)

import logging

logger = logging.getLogger(__name__)


##############################################################################
# Dump file reading and writing
##############################################################################

RULE_CONTENT_YAML_FILE = 'rule_content.yaml'
PLAYBOOK_CONTENT_YAML_FILE = 'playbook_content.yaml'


def filename_for_dump(repo_path, filename, compress=False):
    """
    Create the dump filename.  If there's a compressed variant,
    or we've been asked to compress, then add the .gz extension.
    """
    if compress:
        filename += '.gz'
    dump_filename = path.join(repo_path, filename)
    if path.exists(dump_filename + '.gz'):
        return dump_filename + '.gz'
    return dump_filename


def load_previous_dump(yaml_filename):
    """
    Load data from a previously dumped YAML file, decompressing it if it ends
    with the .gz extension.
    """
    with open(yaml_filename, 'rb') as fh:
        dump_data = fh.read()
        if yaml_filename.endswith('.gz'):
            # wbits=25 means expect the gzip header here.
            dump_data = zlib.decompress(dump_data, wbits=25)
        return yaml.load(dump_data.decode('utf-8'), yaml.Loader)


def load_previous_dump_from_url(url):
    """
    Load data from a previously dumped YAML file from a remote URL,
    including searching for a .gz compressed file.  Returns None if neither
    file is available.
    """
    compressed = True
    response = requests.get(url + '.gz')
    if response.status_code == 404:
        compressed = False
        response = requests.get(url)
    if response.status_code != 200:
        # Log the actual message returned here.
        logger.error(
            f"Failed to load dump from {url} ({compressed=}):"
            f"{response.status_code} {response.reason}"
        )
        return None
    dump_data = response.content
    if compressed:
        # wbits=25 means expect the gzip header here.
        dump_data = zlib.decompress(dump_data, wbits=25)
    return yaml.load(dump_data.decode('utf-8'), yaml.Loader)


##############################################################################
# Main model update function
##############################################################################

def update_model_from_config(
    queryset, config_data, key_field, transformer=None, delete_missing=False,
):
    """
    A bulk insert/update for each row in the config, using a mapper function
    to translate that row into model fields, which are then inserted or
    updated as necessary.  `config_data` has been pre-formatted by the caller
    to be a dictionary keyed to the key_field in the model, and with the
    value as a dictionary linking the model fields to their values in the
    config.  For example, the `impact` config would be mabulated into:
    config_data = {
        'Best Practice': {
            'name': 'Best Practice',
            'impact': 1
        }, ...
    }

    The transformer function allows the row data (the dictionary of the value)
    to be transformed while being read.  This allows update_model_from_config
    to be used on the large rule content without having to create an entirely
    new dictionary with all those values.  Hopefully this will save memory,
    without being any slower.

    If you need to do any filtering, annotating or select_related'ing, supply
    this in your queryset.  The underlying model will be used where necessary.
    """
    # If the 'queryset' is just a model, construct a queryset from it
    if isinstance(queryset, ModelBase):
        model_class = queryset
        queryset = queryset.objects.all()
    else:
        model_class = queryset.model

    if config_data is None:
        logger.error(
            "Error: update_model_from_config(%s, NONE, %s) cannot be given "
            "`None` as the config data",
            model_class.__name__, key_field
        )
        return

    logger.info(
        "update_model_from_config(%s, %d rows of config data, %s, "
        "transformer=%s, delete_missing=%s)",
        model_class.__name__, len(config_data), key_field,
        (transformer.__name__ if transformer else None), delete_missing,
    )
    if transformer is None:
        def transformer(x):
            return x

    # Even faster path - no data (and not expected to delete anything)
    if not config_data and (not delete_missing):
        logger.info(f"... No data provided for load of {model_class.__name__} - exiting")
        return True
    # Fast path:
    if not queryset.exists():
        logger.info(f"... Bulk creating {len(config_data)} {model_class.__name__} objects")
        return model_class.objects.bulk_create([
            model_class(**transformer(row_val))
            for row_val in config_data.values()
            if transformer(row_val)
            # Remove nulls from your data first...
        ])

    # Otherwise work out which rows need to be updated and which to be inserted.
    # We start by reading all of this query and indexing it by key field.
    model_data = {
        getattr(row, key_field): row
        for row in queryset
    }
    logger.debug(
        "... > loaded %s rows of %s data", len(model_data), model_class.__name__
    )
    to_insert = []
    to_update = []
    update_fields = set()

    def update_permute(config_row, database_row):
        updated = False
        for field, value in config_row.items():
            if getattr(database_row, field) != value:
                logger.debug(f"in {config_row}, {field} {getattr(database_row, field)} != {value}")
                update_fields.add(field)
                setattr(database_row, field, value)
                updated = True
        if updated:
            return database_row
        else:
            return None

    # This deals with the items in the config that match items in the database,
    # and new items in the config that aren't yet in the database.  We deal with
    # possible deletes after this...
    logger.debug(f"... iterating over {config_data.keys()}")
    for key, config_row in config_data.items():
        row = transformer(config_row)
        if row is None:
            # Transformer found it couldn't relate this row to a
            # key.  So we throw this row away here.
            logger.warning(
                "... Data for key '%s' could not be transformed into a %s "
                "- discarding.",
                key, model_class.__name__,
            )
            continue
        # Your key better not be None here...
        # Also, we don't try/except here because if we wrote something wrong
        # in update_permute and that raises a KeyError then we insert when
        # we should update
        if key in model_data:
            updated_row = update_permute(row, model_data[key])
            if updated_row is not None:  # i.e. if row has changed
                to_update.append(updated_row)
        else:
            to_insert.append(model_class(**row))

    # Now do the inserts and updates in bulk
    if to_insert:
        logger.info(f"... Creating {len(to_insert)} {model_class.__name__} objects")
        model_class.objects.bulk_create(to_insert)
    if to_update:
        logger.info(f"... Updating {len(to_update)} {model_class.__name__} objects")
        model_class.objects.bulk_update(to_update, update_fields)

    if delete_missing:
        # Convenient set difference...
        surplus_to_db = set(queryset.values_list(key_field, flat=True)) - set(config_data.keys())
        if surplus_to_db:
            logger.info(f"... Deleting {len(surplus_to_db)} {model_class.__name__} objects")
            queryset.filter(
                **{key_field + '__in': surplus_to_db}
            ).delete()


##############################################################################
# Configuration reading
##############################################################################

# We want to avoid having to load config without putting it in the database,
# so we just hard set this here.  Probably not going to change, right?
content_fields = {'generic', 'more_info', 'reason', 'resolution', 'summary'}
# Lookups based purely from config
resolution_risk_to_risk = dict()  # Taken from config rather than DB lookup...
system_type_to_id = dict()


def transform_config(config_dict, value_field):
    """
    Most of the config we care about here just has one other field that we
    care about.  For RuleImpact that's 'impact', for ResolutionRisk that's
    'risk'.
    """
    return {
        key: (
            {'name': key, value_field: value}
        )
        for key, value in config_dict.items()
    }


def import_config(config):
    """
    Load the various config-based models.
    """
    # The impact config has one 'null' key, which we do not allow.
    if None in config['impact']:
        del config['impact'][None]

    # Read the config models first
    update_model_from_config(
        RuleImpact, transform_config(config['impact'], 'impact'), 'name'
    )
    update_model_from_config(
        ResolutionRisk, transform_config(config['resolution_risk'], 'risk'), 'name'
    )

    def transform_tags(tags_dict):
        # We need to go into the values of each group of tags, so we can't use
        # the transform_config function.
        return {
            tag: {'name': tag}
            for group_name, tag_list in tags_dict.items()
            for tag in tag_list
        }

    update_model_from_config(
        Tag, transform_tags(config['tags']), 'name'
    )

    # ... these save reading the database for data which is now in the database...
    global resolution_risk_to_risk
    resolution_risk_to_risk = config['resolution_risk']
    return True


def load_config_from_file(repo_path):
    """
    Load the configuration file, and update the models we get from that.
    """
    config_file = path.join(repo_path, 'content/config.yaml')
    if not path.exists(config_file):
        config_file = path.join(repo_path, 'config.yaml')
        if not path.exists(config_file):
            logger.error(
                f"Path '{repo_path}' does not contain config.yaml in main or "
                f"content/ directories")
            return False

    with open(config_file, 'r') as fh:
        config = yaml.safe_load(fh)
    logger.info(f"Loaded {len(config.keys())} keys from config.yaml from {repo_path}")

    return import_config(config)


def load_config_from_url(base_url):
    """
    Load the configuration file from a URL, and update the models we get from that.
    """
    url = base_url + 'config.yaml'
    response = requests.get(url)
    if response.status_code != 200:
        logger.error(f"Failed to load config from URL: {url}")
        return False
    config = yaml.safe_load(response.content)
    logger.info(f"Loaded {len(config.keys())} keys from config.yaml from {url}")

    return import_config(config)


##############################################################################
# Content reading
##############################################################################


# Lookups drawn from the database, though some are populated from config
category_to_id = dict()
impact_to_id = dict()
resolution_risk_to_pathway_id = dict()
tag_to_model = dict()
ruleset_prefix_to_model = dict()
rule_id_to_db_id = dict()


def load_database_maps():
    """
    Preload lookups that are needed to quickly resolve content fields into
    Django model fields.  Some of this comes from fixtures, so we warn about
    loading those beforehand.  Some of this comes from data loaded from the
    config, where we want to relate it directly to the database 'id' field
    after it's been put in the database.
    """
    global category_to_id
    category_to_id = {c.name: c.id for c in RuleCategory.objects.all()}
    if not category_to_id:
        raise Exception("Category data is not loaded - do `loaddata rule_categories`")

    global impact_to_id
    impact_to_id = {i.name: i.id for i in RuleImpact.objects.all()}
    if not impact_to_id:
        raise Exception("Impact data is not loaded - check content repository config")

    global resolution_risk_to_pathway_id
    resolution_risk_to_pathway_id = {
        p.resolution_risk_name: p.id for p in Pathway.objects.all()
    }
    if not resolution_risk_to_pathway_id:
        raise Exception("Pathway data is not loaded - do `loaddata pathways_prod`")

    # We need to get the tag data from the database because we need the tag
    # models to insert via the through model
    global tag_to_model
    tag_to_model = {
        tag.name: tag
        for tag in Tag.objects.all()
    }
    if not tag_to_model:
        raise Exception("Rule tag data is not loaded - check content repository config")

    global ruleset_prefix_to_model
    ruleset_prefix_to_model = {
        ruleset.module_starts_with: ruleset
        for ruleset in RuleSet.objects.all()
    }
    if not ruleset_prefix_to_model:
        raise Exception("Ruleset data is not loaded - do `loaddata rulesets`")

    global system_type_to_id
    system_type_to_id = {
        str(st): st.id
        for st in SystemType.objects.all()
    }
    if not system_type_to_id:
        raise Exception("System type data is not loaded - do `loaddata system_types`")


def load_rule_id_map():
    # Used in rule resolution and tag linking, but MUST be used after rules are
    # loaded!
    global rule_id_to_db_id
    rule_id_to_db_id = {
        rule.rule_id: rule.id
        for rule in Rule.objects.all()
    }


def find_ruleset_model(content_row):
    """
    Look up the ruleset for this rule.  This is somewhat complicated because
    the lookup is on the prefix of the python module name, so we can't do a
    direct dictionary lookup.
    """
    for prefix, model in ruleset_prefix_to_model.items():
        if content_row['python_module'].startswith(prefix):
            return model
    raise ValueError(f"No ruleset found with a prefix for '{content_row['python_module']}'")


def rule_content_to_model_fields(content_row):
    """
    Copy the data specific to a rule into a new dictionary, suitable for
    using to create or update a Rule model.  Does a fair bit of data
    conversion and massaging.
    """
    rule_row = {
        field: content_row[field]
        for field in (
            'rule_id', 'description', 'reboot_required', 'likelihood',
            'node_id', 'generic', 'reason', 'more_info'
        )
    }
    rule_row['ruleset'] = find_ruleset_model(content_row)
    # Change names of foreign key relationships to IDs
    # rule_content['category_id'] = category_to_id[rule_content['category']]
    # del rule_content['category']
    # Calculated values
    rule_row['active'] = (content_row['status'] == 'active')
    rule_row['likelihood'] = int(content_row['likelihood'])
    rule_row['total_risk'] = int((
        rule_row['likelihood'] + resolution_risk_to_risk[content_row['resolution_risk']]
    ) / 2)  # average
    if content_row['publish_date']:
        # For reasons I haven't traced down yet, when being modified by our
        # test functions the publish_date is read as a string but then output
        # without quotes, and when read without quotes the yaml Loader
        # 'helpfully' converts it to a datetime.  So we need to special case...
        publish_date = content_row['publish_date']
        if not isinstance(publish_date, datetime):
            publish_date = parse_datetime(content_row['publish_date'])
        # Make it timezone aware...
        rule_row['publish_date'] = publish_date.replace(
            tzinfo=pytz.timezone('GMT')
        )
    # Write the generic content in the summary only if the rule doesn't have
    # a summary of its own
    rule_row['summary'] = content_row.get('summary', content_row['generic'])
    if rule_row['node_id'] is None:
        rule_row['node_id'] = ''
    rule_row['category_id'] = category_to_id[content_row['category']]
    rule_row['impact_id'] = impact_to_id[content_row['impact']]
    rule_row['pathway_id'] = resolution_risk_to_pathway_id.get(
        content_row['resolution_risk'], None
    )
    # Tags get loaded in a separate bulk process because of the many-to-many
    # relationship.

    return rule_row


def load_all_rules(rule_content):
    """
    Load the rule data using our model loader...
    """
    rule_dict = {
        rule['rule_id']: rule  # don't transform here, saves memory?
        for rule in rule_content
    }
    update_model_from_config(
        Rule.objects.select_related('ruleset'),
        rule_dict, 'rule_id', rule_content_to_model_fields
    )


def load_all_rule_tags(rule_content):
    """
    Load the rule tag data, using our model loader on the through model.
    Because the content we're sending is unwrapped per rule, we have to
    construct that into a 'rule_tag' row, and then transform that to
    actual IDs when being loaded.
    """
    # By this point all rules and tags should be loaded, and the
    # rule_id_to_db and tag_to_model look ups should be populated.
    tags_not_in_model = [
        tag
        for row in rule_content
        for tag in row['tags']
        if tag not in tag_to_model
    ]
    if tags_not_in_model:
        logger.error(
            f"Found tags mentioned in rule but not in model: {tags_not_in_model}.  "
            f"Content is inconsistent, needs to be checked."
        )
        return False
    rule_tag_content = {
        # Unwrap both Rule and Tag data into an intermediary form
        row['rule_id'] + tag: {
            'rule_id': rule_id_to_db_id[row['rule_id']],
            'tag': tag_to_model[tag]
        }
        for row in rule_content
        for tag in row['tags']
    }

    update_model_from_config(
        Rule.tags.through.objects.annotate(
            rule_id_tag=Concat(F('rule__rule_id'), F('tag__name'))
        ).select_related('tag'), rule_tag_content, 'rule_id_tag',
    )


def load_all_resolutions(rule_content):
    """
    Load the resolution data from the rule content.  Because each resolution
    in the rule content list is tied directly to a single rule, we have to
    use a local transformer that refers to these local lookups.
    """
    # Need to map rule IDs to database ids...
    # global rule_id_to_db_id
    logger.info(
        'Resolutions: mapping %d risk names to their IDs',
        ResolutionRisk.objects.count()
    )
    resolution_risk_to_db_id = {
        rr.name: rr.id
        for rr in ResolutionRisk.objects.all()
    }

    def rule_to_resolution(content_row):
        return {
            'rule_id': rule_id_to_db_id[content_row['rule_id']],
            'system_type_id': system_type_to_id[content_row['product_code'] + '/' + content_row['role']],
            'resolution': content_row['resolution'],
            'resolution_risk_id': resolution_risk_to_db_id[content_row['resolution_risk']]
        }

    logger.info(
        'Resolutions: mapping %d (rule,system_type_id)s to their content row',
        len(rule_content)
    )
    resolution_content = {
        # rule_id_to_db_id[content_row['rule_id']]: content_row
        str(rule_id_to_db_id[content_row['rule_id']]) + ',' + str(
            system_type_to_id[content_row['product_code'] + '/' + content_row['role']]
        ): content_row
        for content_row in rule_content
    }
    update_model_from_config(
        Resolution.objects.annotate(rule_id_sys_type=Concat(
            F('rule_id'), Value(','), F('system_type_id'), output_field=CharField()
            # Need to set output_field here to allow 'in' comparison when
            # deleting.
        )), resolution_content, 'rule_id_sys_type', rule_to_resolution,
        delete_missing=True
    )
    logger.info('Resolutions: finished')


def load_all_autoacks(rule_content):
    """
    Set up acks for rules that are marked with the autoack tag.  The unique
    key for the Ack model on this is effectively (rule_id, org_id), with the
    added caveat that we need to only look at acks created by Red Hat.  So
    we have to construct that expanded content ourselves.
    """
    all_org_ids = list(Host.objects.distinct('org_id').order_by().values_list('org_id', flat=True))
    logger.debug(f"{all_org_ids=}")
    # Build the list of autoacks that the content implies
    autoacks_from_content = {
        row['rule_id'] + org_id: {
            # We're leaving account null now...
            'rule_id': rule_id_to_db_id[row['rule_id']],
            'org_id': org_id,
            'created_by': settings.AUTOACK['CREATED_BY'],
            'justification': settings.AUTOACK['JUSTIFICATION'],
        }
        for row in rule_content
        for org_id in all_org_ids
        if settings.AUTOACK['TAG'] in row['tags']
    }
    logger.debug(f"{autoacks_from_content=}")

    update_model_from_config(
        Ack.objects.filter(
            created_by=settings.AUTOACK['CREATED_BY']
        ).annotate(
            rule_id_org_id=Concat(F('rule__rule_id'), F('org_id'))
        ), autoacks_from_content, 'rule_id_org_id',
        delete_missing=True
    )


def import_content(rule_content):
    """
    Feed that to all the functions that put that data into the database; they
    should not change the rule content.  Each should have a 'fast path' that
    does a bulk insert if there is no existing data in the database.
    """
    load_all_rules(rule_content)
    load_rule_id_map()  # Must happen after rules are loaded!
    load_all_rule_tags(rule_content)
    load_all_autoacks(rule_content)
    load_all_resolutions(rule_content)
    return True


def process_content_from_path(repo_path):
    """
    Load the ruleset and rules data.  The old content import used to be given
    a nice list of rule data, but now we have to traverse the file system and
    get all that data ourselves.

    Once that's done we have a complete collection of the rule content in
    memory.  We then
    """
    # We want to organise this into as few database operations as possible.
    # That means that we do our complete scan of the content directory first,
    # compiling everything into memory, and then load each model in bulk.
    dump_filename = filename_for_dump(repo_path, RULE_CONTENT_YAML_FILE)
    if path.exists(dump_filename):
        logger.info("Loading dumped content from %s", dump_filename)
        rule_content = load_previous_dump(dump_filename)
    else:
        logger.info("Reading content directory at %s", repo_path)
        rule_content = generate_rule_content(repo_path)
    return import_content(rule_content)


def dump_content(repo_path, compress=False):
    """
    Just load the content and dump it.
    """
    dump_filename = filename_for_dump(repo_path, RULE_CONTENT_YAML_FILE, compress)
    rule_content = generate_rule_content(repo_path)
    dump_yaml(rule_content, dump_filename)


def process_content_from_url(base_url):
    """
    Process content from a URL, kind of like getting it from a dump.  This
    also attempts to find a compressed version at that URL.
    """
    rule_content = load_previous_dump_from_url(base_url + 'rule_content.yaml')
    if not rule_content:
        logger.error("Failed to load rule content from %s", base_url)
        return False
    return import_content(rule_content)


##############################################################################
# Playbook directory processing
##############################################################################

def load_all_playbooks(all_playbook_data):
    """
    Load the playbook data, as above.  A lot of the heavy lifting has been
    done in the generate_playbook_content function above to get this data
    into the right format.
    """
    # Playbooks are unique by (resolution, type), so we need to construct that
    # as an annotation and then refer to that; we don't then need to include
    # this in the new/update data.
    # Now we're actually resolving data we can refer to the database
    rule_id_to_resolution_id = {
        re['rule__rule_id']: re['id']
        for re in Resolution.objects.values('id', 'rule__rule_id')
    }

    def playbook_transformer(content_row):
        if content_row['rule_id'] not in rule_id_to_resolution_id:
            # Is this the point at which we filter out playbooks that
            # definitely don't have an associated rule?
            return
        return {
            'resolution_id': rule_id_to_resolution_id[
                content_row['rule_id']
            ],
            'type': content_row['type'],
            'play': content_row['play'],
            'description': content_row['description'],
            'path': content_row['path'],
            'version': content_row['version']
        }

    update_model_from_config(
        Playbook.objects.annotate(
            rule_id_type=Concat(F('resolution__rule__rule_id'), F('type'))
        ), all_playbook_data, 'rule_id_type',
        transformer=playbook_transformer
    )


def process_playbooks_from_path(repo_path):
    """
    Load the playbook data, in much the same way that we process content.
    """
    dump_filename = filename_for_dump(
        repo_path, PLAYBOOK_CONTENT_YAML_FILE
    )
    if path.exists(dump_filename):
        logger.info("Loading dumped content from %s", dump_filename)
        playbook_content = load_previous_dump(dump_filename)
    else:
        logger.info("Reading playbook content in %s", repo_path)
        playbook_content = generate_playbook_content(repo_path)
    load_all_playbooks(playbook_content)


def dump_playbooks(repo_path, compress=False):
    """
    Get playbook content and dump it.
    """
    dump_filename = filename_for_dump(
        repo_path, PLAYBOOK_CONTENT_YAML_FILE, compress
    )
    playbook_content = generate_playbook_content(repo_path)
    dump_yaml(playbook_content, dump_filename)


def process_playbooks_from_url(base_url):
    """
    Load the playbook data from a URL.  This includes searching for compressed
    content at that URL.
    """
    logger.info("Reading playbook content from %s", base_url)
    playbook_content = load_previous_dump_from_url(base_url + 'playbook_content.yaml')
    if not playbook_content:
        logger.error("Failed to load playbook content from %s", base_url)
        return False
    return load_all_playbooks(playbook_content)


##############################################################################
# Main command
##############################################################################


class Command(BaseCommand):
    help = 'Import rule content from repository'

    def add_arguments(self, parser):
        parser.add_argument(
            '--content-repo-path', '-c', type=str,
            help='The path to the Insights content repository',
        )
        parser.add_argument(
            '--dump', '-d', default=False, action='store_true',
            help="Dump rule content and playbooks data",
        )
        parser.add_argument(
            '--playbook-repo-path', '-p', type=str,
            help='The path to the Insights playbook repository',
        )
        parser.add_argument(
            '--remote-url', '-u', type=str,
            help="Remote base URL to import content/playbooks from",
        )
        parser.add_argument(
            '--compress', '-z', default=False, action='store_true',
            help="Compress dumped content"
        )

    def handle(self, *args, **options):
        """
        Import the content's config, then the content.
        """
        if options['remote_url']:
            if not options['remote_url'].endswith('/'):
                options['remote_url'] += '/'
            logger.info("Importing content from remote URL")
            if options['compress']:
                logger.info("Ignoring '--compress' option when using remote URL")
            if options['dump']:
                logger.info("Ignoring '--dump' option when using remote URL")
            # We expect to get the config, content and playbooks from the
            # remote URL base path, possibly with .gz extensions.
            if not load_config_from_url(options['remote_url']):
                logger.error(
                    "Could not load content configuration from remote URL - "
                    "exiting"
                )
                return
            load_database_maps()
            if not process_content_from_url(options['remote_url']):
                logger.error("Could not process content from URL - exiting")
                return
            if not process_playbooks_from_url(options['remote_url']):
                logger.error("Could not process playbooks from URL - exiting")
                return
            return

        if not options['content_repo_path']:
            logger.error("You need to set a content repo path")
            return
        if not path.exists(options['content_repo_path']):
            logger.error(f"Cannot find path {options['content_repo_path']}")
            return

        playbook_repo_path = options['playbook_repo_path'] or options['content_repo_path']
        if options['dump']:
            dump_content(options['content_repo_path'], options['compress'])
            dump_playbooks(playbook_repo_path, options['compress'])

        else:
            if not load_config_from_file(options['content_repo_path']):
                logger.error("Could not load content configuration - exiting")
                return
            load_database_maps()  # some of which is loaded from config in models.
            # These don't return 'false' if it fails - check the logs for
            # individual things loading or not loading.
            process_content_from_path(options['content_repo_path'])
            process_playbooks_from_path(playbook_repo_path)
