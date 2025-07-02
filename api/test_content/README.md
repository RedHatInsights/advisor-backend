# Advisor test rule content

This is the content repository that matches the content in the Advisor
backend's test rules, which are normally set up in its `basic_test_data.json`
fixture file.  This repository is laid out in the same way with the same
directory and file structures that the standard (internal) Insights rule
content and playbook content repositories contain.

The main purpose of this repository is to test the Advisor content import
process.  There are two parts to this:

1. Existing rules and configuration in the fixture should not change when
   this content repository is imported.
2. There will be other rules in this repository that exercise the full
   feature suite of the content import process, and match the varied way that
   rule content is set out in the existing Insights content repository.
