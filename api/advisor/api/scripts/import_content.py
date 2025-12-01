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

"""
import_content - import rule content into a ruleset.

This module provides functions which can be tested independently, and are
then glued together in the main body of the script.

The script gets from the Insights Content server a list of every rule and
it's data.  This does not contain any timestamps of how recently content was
changed, so we have to fetch each rule model in turn and save every single
one.

TODO: work on tracking what's changed between the rule content and the model.
"""

from datetime import datetime
import os
from django.conf import settings
from django.db.models import Count, Exists, OuterRef
from django.utils.timezone import make_aware

from api import models  # noqa
from advisor_logging import logger  # noqa
from kafka_utils import send_webhook_event  # noqa

expected_playbook_keys = (
    'version', 'description', 'path', 'play', 'resolution_type'
)

# Cache any model we're going to look up values from.  If you fill the cache
# with load_model_cache(), then don't add the model here.
model_cache = {models.SystemType: {}}

# For deactivated rules, populate this dict with the accounts to which to send notifications
# {
#   account1_org_id : {'account':<account>, 'org_id':<org_id>, 'rule_info': [{deactivated_rule1_info}, {deactivated_rule2_info}, ...]},
#   account2_org_id : {'account':<account>, 'org_id':<org_id>, 'rule_info': [{deactivated_rule_info}, ]},
# }
deactivated_rule_accounts = dict()


def update_model_with_content(model, config, field, update=False):
    """
    Update a model from a dictionary in our config.  The model's 'name' field
    is used to search the config dictionary, and the given field name is used
    to store the value.  We also update a cache dictionary that can be used
    in content processing.

    When update=False, we assume the config contains every model object
    that should exist.  The absence of one in the config signals that the
    one in the database should be deleted.

    When update=True, the config is assumed to be an update with new models
    and updated values.  If a model is not found in the config, it remains
    unchanged.
    """
    # We remove the keys that are found in the config when they match the
    # one in the database, and delete models when they don't appear in the
    # config (and update=False).  After looking at all the keys in the
    # database, we should be left with the list of names to add from the
    # config to the database.

    # Faster to perform one query and step through it comparing to our
    # in-memory structure.
    stats = {'added': 0, 'updated': 0, 'same': 0, 'deleted': 0}
    # Make sure we've got a cache for this model
    if model not in model_cache:
        model_cache[model] = {}
    cache = model_cache[model]

    for model_obj in model.objects.all():
        if model_obj.name in config:
            if field is not None:
                # Model has name=value data
                field_val = getattr(model_obj, field)
                if field_val == config[model_obj.name]:
                    stats['same'] += 1
                else:
                    stats['updated'] += 1
                    # Update the model if necessary
                    setattr(model_obj, field, config[model_obj.name])
                    model_obj.save()
                    logger.info("Updated config {rr} to {v}".format(
                        rr=model_obj.name, v=field_val
                    ))
            else:
                # Model just has name data, and model is in config; same.
                stats['same'] += 1

            # Save this in our cache
            cache[model_obj.name] = model_obj
            # Remove updated model from config, don't add it later.
            del config[model_obj.name]
        elif not update:
            # Model in database no longer in config - delete.
            stats['deleted'] += 1
            logger.info(f"Deleted {model_obj}")
            model_obj.delete()
        else:
            # Save this in our cache anyway
            cache[model_obj.name] = model_obj
            stats['same'] += 1

    # OK, now the only items in config left are ones we need to add to the
    # database.
    for (name, value) in config.items():
        if field is not None:
            model_obj = model(**{
                'name': name, field: value
            })
        else:
            model_obj = model(name=name)
        stats['added'] += 1
        model_obj.save()
        # Save the new model in our cache
        cache[model_obj.name] = model_obj
        logger.info("Saved new {rr}({v})".format(
            rr=name, v=value
        ))

    return stats


def update_resolution_risks_with_content(config, update=False):
    if 'resolution_risk' not in config:
        return
    return update_model_with_content(
        model=models.ResolutionRisk,
        config=config['resolution_risk'],
        field='risk',
        update=update
    )


def update_impacts_with_content(config, update=False):
    if 'impact' not in config:
        return
    return update_model_with_content(
        model=models.RuleImpact,
        config=config['impact'],
        field='impact',
        update=update
    )


def update_tags_with_content(config, update=False):
    if 'tags' not in config:
        return
    # The tags is a two-tiered structure in the content, but we don't care
    # about the structure, we just want a list of names.
    all_tags = {
        tag: 1
        for tag_list in config['tags'].values()
        for tag in tag_list
    }
    # field=None means data is name-only, not name: value; just store name
    return update_model_with_content(
        model=models.Tag,
        config=all_tags,
        field=None,
        update=update
    )


def get_system_type(rule_api):
    """
    Get the resolution with the product code and role, via the SystemType.
    """
    system_type_tuple = (rule_api['role'], rule_api['product_code'])
    if system_type_tuple in model_cache[models.SystemType]:
        system_type = model_cache[models.SystemType][system_type_tuple]
    else:
        system_type = models.SystemType.objects.get(
            role=system_type_tuple[0], product_code=system_type_tuple[1]
        )
        model_cache[models.SystemType][system_type_tuple] = system_type
    return system_type


def snapshot_object(inst, fields):
    """
    Provide a snapshot of an object, which is simply a dictionary of the
    named fields and their associated attribute values in the instance.
    This is then used in changed_from_snapshot() to check if any of the fields
    have changed.
    """
    return {
        field: getattr(inst, field)
        for field in fields
    }


def changed_from_snapshot(inst, fields, snapshot):
    """
    Have any of the given fields changed between the instance and the snapshot?
    """
    for field in fields:
        if snapshot[field] != getattr(inst, field):
            # In most rule content the node_id is a string, but in a few rogue rules it's an integer
            # So check if they still have the same value even though they are different types
            if field == 'node_id' and str(snapshot[field]) == str(getattr(inst, field)):
                continue
            logger.debug("Field %s changed from %s to %s", field, getattr(inst, field), snapshot[field])
            return True

    return False


def load_model_cache(model, key_field='name'):
    """
    Load the model cache for this model, indexed on the key field's value.
    We flush the cache here because the database will change underneath the
    """
    cache = {}
    for model_obj in model.objects.all():
        cache[getattr(model_obj, key_field)] = model_obj
    model_cache[model] = {}


def get_foreign_key_object(model, value, field='name'):
    """
    Get a field from our model cache, or fall back to a direct query if not
    found for some reason.  The assumption is that the cache has been fully
    loaded with all the possible values found in the content, and therefore
    all lookups will match.  But just in case...
    """
    if model in model_cache:
        if value in model_cache[model]:
            return model_cache[model][value]
        else:
            # We default to querying the 'name' field for these lookups.
            # Instead of doing multiple queries, just get the list of matches
            # and look at it directly.
            recs = list(model.objects.filter(**{field: value}))
            if not recs:
                return None
            elif len(recs) > 1:
                raise KeyError(f"Too many matches on supposedly unique '{field}' field: [{recs}]")
            else:
                model_cache[model][value] = recs[0]
                return recs[0]
    else:
        # If we haven't loaded the cache for this model yet, then that's a
        # programming error.
        raise KeyError(f"You need to fill the cache for {model} before you use it")


def update_ruleset_with_content(content):
    """
    Update all the rules in the ruleset, identified in the content with the
    `ruleset_startswith` prefix and in the models by the
    `ruleset_description` description, with the content.

    This functions steps through the rules present in the content and adds,
    updates or leaves unchanged the rules in the database.  Because of this,
    there is no way to delete rules - but you can just supply the rules that
    have changed or are new.
    """
    logger.info("*** Updating rules from content")
    # Fields which can be copied as is.  Everything else needs some kind of
    # special handling.
    standard_fields = ('description', 'reboot_required', 'summary', )
    # Fields where nulls are converted to ''
    null_to_blank_fields = ('generic', 'reason', 'more_info', 'node_id')
    # So the fields we actually need to track are:
    fields_we_might_change = standard_fields + null_to_blank_fields + (
        'publish_date', 'active', 'category',
        'impact', 'likelihood', 'total_risk',
    )
    # Note that we never delete a rule here.  We assume that old rules get
    # deactivated instead.  It's using a Paranoid model anyway.
    stats = {'added': 0, 'updated': 0, 'same': 0, 'deleted': 0}

    if models.RuleSet.objects.count() == 0:
        logger.error("Rulesets not loaded - no rules can be imported.  Load fixtures!")
        return stats
    ruleset_startswith = {
        rs.module_starts_with: rs
        for rs in models.RuleSet.objects.all()
    }

    load_model_cache(models.RuleCategory)
    load_model_cache(models.RuleImpact)
    load_model_cache(models.Tag)

    # Get a list of all currently known accounts and org_id for autoacking rules.
    account_org_id_list = list(models.Host.objects.distinct().order_by().values('account', 'org_id'))

    def update_publish_date(instance, date_value):
        # If the date is presented and it's value is a valid date, set it
        # in the instance.  Otherwise, set it to null.
        if date_value and date_value != 'null':
            publish_date = None
            # Try a few different date formats to try to convert publish_date
            for date_format in ['%Y-%m-%d %H:%M:%S', '%Y-%m-%d %H:%M', '%Y-%m-%d']:
                try:
                    # Do explicit conversion so we get a timezone-aware object rather than a naive one.
                    publish_date = make_aware(datetime.strptime(date_value, date_format))
                    break
                except ValueError:
                    pass

            if publish_date:
                # If the rule in the DB has a date newer/same as the rule in the content, do nothing
                # else set the publish_date to the date set in the rule metadata
                if instance.publish_date and instance.publish_date >= publish_date:
                    return
                instance.publish_date = publish_date
            else:
                instance.publish_date = None
        else:
            instance.publish_date = None

    disable_cve_rules = os.getenv('DISABLE_CVE_RULES', 'true').lower() == 'true'

    def disable_cve_rule(rule_content):
        if disable_cve_rules:
            # CVE rule if it has cve tag
            if 'cve' in rule_content.get('tags', []):
                return True
        return False

    def add_autoacks_for_rule(rule_content):
        # Add acks for autoack tagged rule for all known accounts, but only if there isn't
        # an existing ack for that rule/account.
        # This handles existing accounts, new accounts are handled in advisor-service
        rule = models.Rule.objects.get(rule_id=rule_content['rule_id'])
        new_acks = []
        for account_org_id in account_org_id_list:
            if not models.Ack.objects.filter(rule=rule, org_id=account_org_id['org_id']).exists():
                new_ack = models.Ack(rule=rule, org_id=account_org_id['org_id'], account=account_org_id['account'])
                new_ack.justification = settings.AUTOACK['JUSTIFICATION']
                new_ack.created_by = settings.AUTOACK['CREATED_BY']
                new_acks.append(new_ack)
        if new_acks:
            models.Ack.objects.bulk_create(new_acks)

    def remove_autoacks_for_rule(rule_content):
        # If the rule content has the autoack tag removed, then remove any autoacks for that rule
        rule = models.Rule.objects.get(rule_id=rule_content['rule_id'])
        models.Ack.objects.filter(rule=rule, created_by=settings.AUTOACK['CREATED_BY']).delete()

    def set_pathway(rule_content, rule_db):
        """
        # If the rule_content doesn't have component or resolution risk then set the rule_db's pathway to null
        # If the corresponding pathway doesn't exist then set the rule_db's pathway to null
        # If the rule_db doesn't have rule_content's pathway, then add it
        # If the rule_db has a different pathway then update the rule_db's pathway
        """
        content_component = rule_content.get('component')
        content_res_risk = rule_content.get('resolution_risk')
        if not (content_component and content_res_risk):
            # rule_content doesn't have a component or resolution risk - set the rule_db's pathway to null
            if rule_db.pathway:
                logger.info("Updated pathway '%s' - removed rule '%s'", rule_db.pathway, rule_db,)
            rule_db.pathway = None
            rule_db.save()
            return

        try:
            pathway = models.Pathway.objects.get(component=content_component, resolution_risk_name=content_res_risk)
            # If we've made to here then the pathway exists in the DB and the
            # rule_content matches it, so either ... The rule_db doesn't have
            # a pathway or has a different pathway - add/update the rule_db's
            # pathway
            if not rule_db.pathway or rule_db.pathway != pathway:
                rule_db.pathway = pathway
                rule_db.save()
                logger.info("Updated pathway '%s' + added rule '%s'", pathway, rule_db)
        except models.Pathway.DoesNotExist:
            # pathway for rule_content's component/resolution risk combo
            # doesn't exist so set the rule_db's pathway to null
            if rule_db.pathway:
                logger.info("Removed pathway from rule '%s'", rule_db)
                rule_db.pathway = None
                rule_db.save()

    def handle_notif_action(rule_db, rule_content, notif_action):
        """
        Run when the notif_action field in the rule content is populated
        If the rule is transitioning from active to inactive, then the rule is made inactive to either be enhanced or
           retired permanently.
           - In that case, send notifications to users currently affected by the rule

        If the rule is transitioning from inactive to active and the notif_action is enhance, then the rule has
           just been enhanced and is being activated again.
           - In that case, update the rule's publish_date to the current time to indicate the rule was enhanced
        """
        notif_action = notif_action.lower()
        if rule_db.active and rule_content['status'] == 'inactive':
            # The rule is being deactivated, either for enhancement or permanent retirement
            if notif_action.startswith('enhance') or notif_action.startswith('retire'):
                logger.info("Rule '%s' is being deactivated with notif_action '%s'", rule_content['rule_id'], notif_action)
                get_deactivated_rule_accounts(rule_db, notif_action)
            return

        if not rule_db.active and rule_content['status'] == 'active' and notif_action.startswith('enhance'):
            # The rule is becoming active again after being enhanced, set publish_date to the current time
            update_publish_date(rule_db, datetime.strftime(datetime.utcnow(), '%Y-%m-%d %H:%M:%S'))

    # This is probably a bit slow, since we have to request each rule from
    # the database one by one.  But the API content is non-normalised - it
    # contains multiple rule objects for the same rule if it has different
    # resolutions.  We try to re-normalise that into a rule and one or more
    # resolutions.
    logger.info("(we seem to have %d rules to import)", len(content))
    for rule_api in content:
        # Filter out rules we don't want to see
        # Ignore content for rules that don't have the vital fields we need.
        if 'python_module' not in rule_api:
            logger.warning(
                "'python_module' not found as key in rule_api keys: %s",
                ', '.join(sorted(rule_api.keys()))
            )
            continue
        if 'rule_id' not in rule_api:
            logger.warning(
                "'rule_id' not found as key in rule_api keys: %s",
                ', '.join(sorted(rule_api.keys()))
            )
            continue

        # Select the ruleset that this rule belongs to, if there's one defined
        ruleset_model = None
        for startswith, ruleset in ruleset_startswith.items():
            if rule_api['python_module'].startswith(startswith):
                ruleset_model = ruleset
                break
        if not ruleset_model:
            continue

        # OK, does the rule exist in our database?
        logger.debug("Processing rule '%s' from the content ...", rule_api['rule_id'])
        rule_search = models.Rule.objects.filter(
            ruleset=ruleset_model, rule_id=rule_api['rule_id']
        )
        if rule_search.exists():
            logger.debug("Found rule '%s' in the database", rule_search[0].rule_id)
            # Yes - OK, fetch and check if it needs updating.  If only we had some
            # way to find out only those rules that had been updated since the
            # last time we looked...
            # Since rule_id is unique within the Advisor ruleset, there should
            # only be one item in the list.
            rule_model = rule_search[0]
            # First save the original field values we may update:
            original_values = snapshot_object(rule_model, fields_we_might_change)
            for field in standard_fields:
                if field in rule_api:
                    setattr(rule_model, field, rule_api[field])

            # Update publish date
            update_publish_date(rule_model, rule_api['publish_date'])

            # If the content has notif_action set, check if the rule is transitioning from active <-> inactive
            notif_action = rule_api.get('notif_action')
            if notif_action:
                handle_notif_action(rule_model, rule_api, notif_action)

            # Fields that we convert null to blanks:
            for field in null_to_blank_fields:
                setattr(rule_model, field, rule_api[field] if rule_api[field] else '')
            # If we have no 'summary' field, copy its content from the 'generic'
            # field.
            if rule_model.generic and not rule_model.summary:
                # The summary field was removed from rule content but we maintain it in the DB as a copy of generic
                rule_model.summary = rule_model.generic
            # Fields that we convert null to zero:
            for field in ('likelihood',):
                setattr(rule_model, field, rule_api[field] if rule_api[field] else 0)
            rule_model.active = False if disable_cve_rule(rule_api) else rule_api['status'] == 'active'

            rule_model.category = get_foreign_key_object(
                models.RuleCategory, rule_api['category']
            )
            rule_model.impact = get_foreign_key_object(
                models.RuleImpact, rule_api['impact'] if rule_api['impact'] else 'null'
            )
            # Calculate total risk
            rule_model.total_risk = int(
                (rule_model.likelihood + rule_model.impact.impact) / 2
            )

            # If the rule object has changed, then update the database.
            if changed_from_snapshot(
                rule_model, fields_we_might_change, original_values
            ):
                stats['updated'] += 1
                logger.info("Updated rule '%s'", rule_model)
                rule_model.save()
            else:
                stats['same'] += 1
                logger.debug("No changes in '%s' - not saving", rule_model)

            if rule_api['resolution'] and rule_api['resolution_risk']:
                # Rule content also includes resolution information - the rule
                # may be duplicated several times for different resolutions.
                # Have to look up the resolution with the product code and role,
                # via the SystemType.
                system_type = get_system_type(rule_api)
                resolution_search = models.Resolution.objects.filter(
                    rule=rule_model, system_type=system_type
                )
                # Assertion: resolution risks always exist here and are unique by name
                risk_obj = model_cache[models.ResolutionRisk][rule_api['resolution_risk']]
                if resolution_search.exists():
                    # Try updating the resolution:
                    # Once again we rely on the uniqueness of rule and system types
                    resolution_model = resolution_search[0]
                    if hash(resolution_model.resolution) != hash(rule_api['resolution']) or \
                            resolution_model.resolution_risk != risk_obj:
                        resolution_model.resolution = rule_api['resolution']
                        resolution_model.resolution_risk = risk_obj
                        resolution_model.save()
                        logger.info("Updated %s", resolution_model)

                    # Check if the playbooks for this resolution need updating
                else:
                    # New resolution - create it
                    resolution_model = models.Resolution(
                        rule=rule_model, system_type=system_type,
                        resolution=rule_api['resolution'],
                        resolution_risk=risk_obj,
                    )
                    resolution_model.save()
                    logger.info("Saved new %s", resolution_model)
                # Add/update/delete playbooks
                update_playbook_models(resolution_model, rule_api['playbooks'])

        else:
            # Rule not found in ruleset - create some new content.  This seems
            # similar enough to the update code - not sure how we can do it
            # once though.
            # First the rule:
            logger.info("Rule '%s' not found in database - adding it", rule_api['rule_id'])
            rule_props = {
                'ruleset': ruleset_model,
                'rule_id': rule_api['rule_id'],
                'active': False if disable_cve_rule(rule_api) else rule_api['status'] == 'active',
                'category': get_foreign_key_object(
                    models.RuleCategory, rule_api['category']
                ),
                'impact': get_foreign_key_object(
                    models.RuleImpact, rule_api['impact'] if rule_api['impact'] else 'null'
                ),
            }
            for field in standard_fields:
                if field in rule_api:
                    rule_props[field] = rule_api[field]
            for field in null_to_blank_fields:
                rule_props[field] = rule_api[field] if rule_api[field] else ''
            if 'generic' in rule_props and 'summary' not in rule_props:
                rule_props['summary'] = rule_props['generic']
            for field in ('likelihood',):
                rule_props[field] = rule_api[field] if rule_api[field] else 0
            # Calculate total risk
            rule_props['total_risk'] = int(
                (rule_props['likelihood'] + rule_props['impact'].impact) / 2
            )

            rule_model = models.Rule(**rule_props)
            # Update publish date if it's valid
            update_publish_date(rule_model, rule_api['publish_date'])

            stats['added'] += 1
            logger.info("Saved %s", rule_model)
            rule_model.save()

            if rule_api['resolution'] and rule_api['resolution_risk']:
                # Guaranteed no resolution if it's a new rule.
                system_type = get_system_type(rule_api)
                resolution_model = models.Resolution(
                    rule=rule_model, system_type=system_type,
                    resolution=rule_api['resolution'],
                    resolution_risk=model_cache[models.ResolutionRisk][rule_api['resolution_risk']],
                )
                logger.info("Saved new resolution %s", resolution_model)
                resolution_model.save()
                # And guaranteed no playbooks for a new resolution
                update_playbook_models(resolution_model, rule_api['playbooks'])

        set_pathway(rule_api, rule_model)

        # Now we have a rule model, we can check its tags.  We need to add
        # tags that the model doesn't have but the content does, and remove
        # tags that the model has but the content doesn't.
        tags_only_in_model = {
            tag.name: tag
            for tag in rule_model.tags.all()
        }
        for tag in rule_api['tags']:
            if tag in tags_only_in_model:
                tags_only_in_model.pop(tag)
            else:
                # Tag in content but not in model - add it.
                if tag in model_cache[models.Tag]:
                    tag_model = model_cache[models.Tag][tag]
                else:
                    tag_model, created = models.Tag.objects.get_or_create(name=tag)
                    model_cache[models.Tag][tag] = tag_model
                logger.info(f"Adding new tag '{tag}' to rule {rule_model.rule_id}")
                rule_model.tags.add(tag_model)
                if tag == settings.AUTOACK['TAG']:
                    add_autoacks_for_rule(rule_api)
        # If after removing all the content's tags from the model we still
        # have tags, then those need to be deleted:
        for tag_to_delete, tag_model in tags_only_in_model.items():
            rule_model.tags.remove(tag_model)
            logger.info(f"Removing old tag '{tag_to_delete}' from rule {rule_model.rule_id}")
            if tag_to_delete == settings.AUTOACK['TAG']:
                remove_autoacks_for_rule(rule_api)

    # Check for any rules in the DB that aren't in the content and set them as inactive in the DB
    # Todo: This could become an expensive check as the rule list grows larger, find a nicer/better way
    db_rules = set(models.Rule.objects.values_list('rule_id', flat=True))
    content_rules = set([rule['rule_id'] for rule in content if rule.get('rule_id')])
    extra_db_rules = db_rules.difference(content_rules)
    for extra_db_rule in extra_db_rules:
        logger.debug("Rule '%s' exists in the DB but is missing in the content, performing delete.", extra_db_rule)
        #  We used to mark the rule as inactive here
        #  This logic was remnant of the "historical reporting" era
        #  We have since done away with historical reporting
        #  We now delete rules that were found in the database
        #  but were found in the latest content batch
        #  This should only CASCADE delete linked RuleRating
        #  Ack, Hostack, CurrentReport and Resolution objects
        models.Rule.objects.filter(rule_id=extra_db_rule).delete()
        stats['deleted'] += 1

    # if any rules where deactivated, send notifications to customers who were affected by those rules
    if deactivated_rule_accounts:
        send_deactivated_rule_notifications()

    return stats


def update_playbook_models(resolution_model, playbooks_content):
    """
    Check if the playbook(s) associated with this resolution need updating

    Compare the version (git commit hash) of the playbooks to determine if any need updating
    """
    if not (playbooks_content or resolution_model.playbook_set.exists()):
        # nothing to do if they both have no playbooks
        return

    db_playbook_types = set(resolution_model.playbook_set.values_list('type', flat=True))
    # Add/update any playbooks in the content that are missing/different from the playbooks in the DB
    for playbook_content in playbooks_content:
        missing_keys = [key for key in expected_playbook_keys if key not in playbook_content]
        if missing_keys:
            logger.warning("Playbook data %s is missing keys %s", playbook_content, missing_keys)
            continue
        # Don't look up the database for each playbook, just check our set
        if playbook_content['resolution_type'] in db_playbook_types:
            # Should only be at most 1 playbook in the set with a particular type, so get should be safe to use
            db_playbook = resolution_model.playbook_set.get(
                type=playbook_content['resolution_type']
            )
            if db_playbook.version != playbook_content['version']:
                db_playbook.description = playbook_content['description']
                db_playbook.path = playbook_content['path']
                db_playbook.play = playbook_content['play']
                db_playbook.version = playbook_content['version']
                db_playbook.save()  # only if updated
                logger.info("Updated {t} playbook for {r}".format(
                    t=playbook_content['resolution_type'], r=resolution_model))
        else:
            db_playbook = models.Playbook(
                resolution=resolution_model,
                type=playbook_content['resolution_type'],
                play=playbook_content['play'],
                description=playbook_content['description'],
                path=playbook_content['path'],
                version=playbook_content['version'],
            )
            db_playbook.save()
            logger.info("Created {t} playbook for {r}".format(
                t=playbook_content['resolution_type'], r=resolution_model
            ))

    # Remove any existing playbooks from the DB that aren't in the content anymore
    # Get a set of the playbook types for both the content and database
    content_playbook_types = set([
        playbook['resolution_type']
        for playbook in playbooks_content
    ])
    for playbook_type in db_playbook_types.difference(content_playbook_types):
        playbook = resolution_model.playbook_set.get(type=playbook_type)
        playbook.delete()
        logger.info("Removed {p} from {r}".format(p=playbook, r=resolution_model))


def get_deactivated_rule_accounts(rule, notif_action):
    """
    Get the accounts and their systems that are affected by this (soon to be) deactivated rule, but ignore
    accounts that have acked the rule.

    Populates the deactivated_rule_accounts dict which is used for sending notifications to those accounts that were
    affected by the rule, telling them the rule has been deactivated.
    """
    # Fields from the deactivated rule used in the notification email template
    deactivated_rule = {
        'rule_id': rule.rule_id,
        'rule_description': rule.description,
        'total_risk': rule.total_risk,
        'affected_systems': 0,
        'deactivation_reason': 'Enhancement' if notif_action.startswith('enhance') else 'Retirement'
    }

    # Find accounts and the count of their systems currently being impacted by the deactivated rule, but ignore
    # accounts that have acked the rule (no need to notify them about the rule being deactivated)
    account_org_ids_systems_list = list(models.CurrentReport.objects
                                        .filter(rule=rule)
                                        .exclude(Exists(models.Ack.objects.filter(rule=rule, org_id=OuterRef('org_id'))))
                                        .values('account', 'org_id')
                                        .annotate(affected_systems=Count('host_id')))

    if not account_org_ids_systems_list:
        logger.info("No accounts to notify about deactivated rule '%s'", rule.rule_id)
        return

    # Populate the deactivated_rule_notifications list with the account org id and the deactivated rule information
    # encoded as notifications service events (handy when sending the events later)
    for account_org_id_systems in account_org_ids_systems_list:
        account = account_org_id_systems['account']
        org_id = account_org_id_systems['org_id']
        deactivated_rule['affected_systems'] = account_org_id_systems['affected_systems']

        event = {'metadata': {}, 'payload': deactivated_rule.copy()}
        logger.info("Account %s org_id %s is affected by deactivated rule '%s'", account, org_id, rule.rule_id)
        if org_id in deactivated_rule_accounts:
            deactivated_rule_accounts[org_id]['rule_info'].append(event)
        else:
            deactivated_rule_accounts[org_id] = {'account': account, 'org_id': org_id, 'rule_info': [event]}


def send_deactivated_rule_notifications():
    """
    Send notifications to all the accounts in deactivated_rule_accounts
    """
    from uuid import uuid4

    for org_id, account_org_id_obj in deactivated_rule_accounts.items():
        # Create kafka message structure, as per
        # https://consoledot.pages.redhat.com/notifications-docs/dev/user-guide/send-notification.html
        account = account_org_id_obj['account']
        notification = {
            'id': str(uuid4()),
            'bundle': 'rhel',
            'application': 'advisor',
            'event_type': 'deactivated-recommendation',
            'timestamp': datetime.utcnow().isoformat(),
            'account_id': account,
            'org_id': org_id,
            'context': {},
            'events': account_org_id_obj['rule_info']
        }
        logger.info("Sending notification about deactivated rule(s) to users in account %s org_id %s: %s", account, org_id, notification)
        try:
            send_webhook_event(notification)
        except Exception as e:
            logger.info("Problem sending deactivated recommendation notification to account %s org_id %s: %s", account, org_id, e)


def import_all(config, content):
    stats = {
        'resolution_risks': update_resolution_risks_with_content(config),
        'impacts': update_impacts_with_content(config),
        'tags': update_tags_with_content(config),
        'content': update_ruleset_with_content(content),
    }
    return stats
