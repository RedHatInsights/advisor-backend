#!/usr/bin/env python3
"""
Compare host IDs across three tables via GABI:
  - HBI hosts table (source of truth, via HBI GABI)
  - Cyndi table inventory.hosts (via Advisor GABI)
  - advisor_inventory_host (via Advisor GABI)

Usage:
    ./scripts/compare_inventory_tables.py --env stage --org-id 12345678
    ./scripts/compare_inventory_tables.py --env prod --org-id 12345678
    ./scripts/compare_inventory_tables.py --env stage --find-diffs  # find orgs with count differences
    ./scripts/compare_inventory_tables.py --env stage  # queries all orgs (total counts only)

Authentication uses `oc whoami -t` by default, or pass --auth <token>.
"""

import argparse
import subprocess
import sys

import requests

ADVISOR_GABI_URLS = {
    "prod": "https://gabi-advisor-prod.apps.crcp01ue1.o9m8.p1.openshiftapps.com:443/query",
    "stage": "https://gabi-advisor-stage.apps.crcs02ue1.urby.p1.openshiftapps.com:443/query",
}

HBI_GABI_URLS = {
    "prod": "https://gabi-host-inventory-prod.apps.crcp01ue1.o9m8.p1.openshiftapps.com/query",
    "stage": "https://gabi-host-inventory-stage.apps.crcs02ue1.urby.p1.openshiftapps.com/query",
}

HBI_QUERY = "SELECT id FROM hbi.hosts WHERE org_id = '{org_id}' AND insights_id IS NOT NULL AND insights_id != '00000000-0000-0000-0000-000000000000' ORDER BY id"
CYNDI_QUERY = 'SELECT id FROM "inventory"."hosts" WHERE org_id = \'{org_id}\' ORDER BY id'
NEW_TABLE_QUERY = "SELECT inventory_id FROM advisor_inventory_host WHERE org_id = '{org_id}' ORDER BY inventory_id"

COUNT_HBI_QUERY = "SELECT COUNT(*) FROM hbi.hosts WHERE insights_id IS NOT NULL AND insights_id != '00000000-0000-0000-0000-000000000000'"
COUNT_CYNDI_QUERY = 'SELECT COUNT(*) FROM "inventory"."hosts"'
COUNT_NEW_TABLE_QUERY = "SELECT COUNT(*) FROM advisor_inventory_host"

PER_ORG_HBI_QUERY = "SELECT org_id, COUNT(*) FROM hbi.hosts WHERE insights_id IS NOT NULL AND insights_id != '00000000-0000-0000-0000-000000000000' GROUP BY org_id ORDER BY org_id"
PER_ORG_CYNDI_QUERY = 'SELECT org_id, COUNT(*) FROM "inventory"."hosts" GROUP BY org_id ORDER BY org_id'
PER_ORG_NEW_TABLE_QUERY = "SELECT org_id, COUNT(*) FROM advisor_inventory_host GROUP BY org_id ORDER BY org_id"

HBI_HOST_DETAILS_QUERY = "SELECT id, insights_id FROM hbi.hosts WHERE org_id = '{org_id}' AND insights_id IS NOT NULL AND insights_id != '00000000-0000-0000-0000-000000000000' ORDER BY id"
NEW_TABLE_DETAILS_QUERY = "SELECT inventory_id, insights_id FROM advisor_inventory_host WHERE org_id = '{org_id}' ORDER BY inventory_id"


def get_oc_token():
    try:
        result = subprocess.run(
            ["oc", "whoami", "-t"], capture_output=True, text=True, check=True
        )
        return result.stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("ERROR: Could not get token from 'oc whoami -t'. Pass --auth <token> instead.")
        sys.exit(1)


def run_query(url, query, token):
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    payload = {"query": query}

    resp = requests.post(url, json=payload, headers=headers, timeout=120)
    if resp.status_code != 200:
        print(f"ERROR: GABI returned {resp.status_code}")
        print(resp.text)
        sys.exit(1)

    data = resp.json()
    if data.get("error"):
        print(f"ERROR from GABI: {data['error']}")
        sys.exit(1)

    return data


def extract_ids(gabi_response):
    """Extract the first column from each row as a set of IDs (skip header row)."""
    rows = gabi_response.get("result", [])
    if len(rows) < 2:
        return set()
    return set(row[0] for row in rows[1:])


def extract_id_map(gabi_response):
    """Extract (col0 -> col1) mapping from a two-column query result (skip header)."""
    rows = gabi_response.get("result", [])
    if len(rows) < 2:
        return {}
    return {row[0]: row[1] for row in rows[1:]}


def compare_org(advisor_url, hbi_url, org_id, token):
    print(f"\n{'='*70}")
    print(f"Comparing tables for org_id: {org_id}")
    print(f"{'='*70}")

    print("\nQuerying HBI table (source of truth)...")
    hbi_data = run_query(hbi_url, HBI_QUERY.format(org_id=org_id), token)
    hbi_ids = extract_ids(hbi_data)
    print(f"  Found {len(hbi_ids)} hosts")

    print("Querying Cyndi table (inventory.hosts)...")
    cyndi_data = run_query(advisor_url, CYNDI_QUERY.format(org_id=org_id), token)
    cyndi_ids = extract_ids(cyndi_data)
    print(f"  Found {len(cyndi_ids)} hosts")

    print("Querying new table (advisor_inventory_host)...")
    new_data = run_query(advisor_url, NEW_TABLE_QUERY.format(org_id=org_id), token)
    new_ids = extract_ids(new_data)
    print(f"  Found {len(new_ids)} hosts")

    print(f"\n--- Results vs HBI (source of truth) ---")
    cyndi_missing = hbi_ids - cyndi_ids
    cyndi_extra = cyndi_ids - hbi_ids
    new_missing = hbi_ids - new_ids
    new_extra = new_ids - hbi_ids

    print(f"  HBI hosts:                          {len(hbi_ids)}")
    print(f"  Cyndi missing from HBI:             {len(cyndi_missing)}")
    print(f"  Cyndi extra (not in HBI):           {len(cyndi_extra)}")
    print(f"  advisor_inventory missing from HBI: {len(new_missing)}")
    print(f"  advisor_inventory extra (not in HBI): {len(new_extra)}")

    all_match = not cyndi_missing and not cyndi_extra and not new_missing and not new_extra

    if all_match:
        print("\n  MATCH: All three tables contain the same host IDs.")
    else:
        print("\n  MISMATCH: Tables differ.")
        if cyndi_missing:
            print(f"\n  IDs in HBI but missing from Cyndi ({len(cyndi_missing)}):")
            for host_id in sorted(cyndi_missing):
                print(f"    - {host_id}")
        if cyndi_extra:
            print(f"\n  IDs in Cyndi but not in HBI ({len(cyndi_extra)}):")
            for host_id in sorted(cyndi_extra):
                print(f"    - {host_id}")
        if new_missing:
            print(f"\n  IDs in HBI but missing from advisor_inventory ({len(new_missing)}):")
            for host_id in sorted(new_missing):
                print(f"    - {host_id}")
        if new_extra:
            print(f"\n  IDs in advisor_inventory but not in HBI ({len(new_extra)}):")
            for host_id in sorted(new_extra):
                print(f"    - {host_id}")

    return all_match


def find_org_diffs(advisor_url, hbi_url, token):
    print(f"\n{'='*70}")
    print("Finding org_ids with host count differences")
    print(f"{'='*70}")

    print("\nQuerying per-org counts from HBI (source of truth)...")
    hbi_data = run_query(hbi_url, PER_ORG_HBI_QUERY, token)
    hbi_rows = hbi_data.get("result", [])
    hbi_counts = {row[0]: int(row[1]) for row in hbi_rows[1:]} if len(hbi_rows) > 1 else {}
    print(f"  Found {len(hbi_counts)} orgs in hbi.hosts")

    print("Querying per-org counts from Cyndi table...")
    cyndi_data = run_query(advisor_url, PER_ORG_CYNDI_QUERY, token)
    cyndi_rows = cyndi_data.get("result", [])
    cyndi_counts = {row[0]: int(row[1]) for row in cyndi_rows[1:]} if len(cyndi_rows) > 1 else {}
    print(f"  Found {len(cyndi_counts)} orgs in inventory.hosts")

    print("Querying per-org counts from new table...")
    new_data = run_query(advisor_url, PER_ORG_NEW_TABLE_QUERY, token)
    new_rows = new_data.get("result", [])
    new_counts = {row[0]: int(row[1]) for row in new_rows[1:]} if len(new_rows) > 1 else {}
    print(f"  Found {len(new_counts)} orgs in advisor_inventory_host")

    all_orgs = sorted(set(hbi_counts.keys()) | set(cyndi_counts.keys()) | set(new_counts.keys()))
    diffs = []
    for org_id in all_orgs:
        h = hbi_counts.get(org_id, 0)
        c = cyndi_counts.get(org_id, 0)
        n = new_counts.get(org_id, 0)
        if h != c or h != n:
            diffs.append((org_id, h, c, n))

    print(f"\n--- Results ---")
    print(f"  Total orgs checked: {len(all_orgs)}")
    print(f"  Orgs with matching counts: {len(all_orgs) - len(diffs)}")
    print(f"  Orgs with differences: {len(diffs)}")

    if diffs:
        print(f"\n  {'Org ID':<20} {'HBI':>10} {'Cyndi':>10} {'New Table':>10}")
        print(f"  {'-'*20} {'-'*10} {'-'*10} {'-'*10}")
        for org_id, h, c, n in diffs:
            print(f"  {org_id:<20} {h:>10} {c:>10} {n:>10}")

        orgs_with_extra = [(org_id, h, c, n) for org_id, h, c, n in diffs if n > h]
        if orgs_with_extra:
            print(f"\n{'='*70}")
            print("Extra hosts in advisor_inventory_host (not in HBI)")
            print(f"{'='*70}")
            for org_id, h, c, n in orgs_with_extra:
                print(f"\n  --- org_id: {org_id} (HBI: {h}, advisor_inventory: {n}, extra: {n - h}) ---")
                hbi_data = run_query(hbi_url, HBI_HOST_DETAILS_QUERY.format(org_id=org_id), token)
                hbi_ids = extract_ids(hbi_data)
                new_data = run_query(advisor_url, NEW_TABLE_DETAILS_QUERY.format(org_id=org_id), token)
                new_map = extract_id_map(new_data)
                extra_ids = set(new_map.keys()) - hbi_ids
                print(f"  {'inventory_id':<40} {'insights_id':<40}")
                print(f"  {'-'*40} {'-'*40}")
                for host_id in sorted(extra_ids):
                    print(f"  {host_id:<40} {new_map[host_id]:<40}")
    else:
        print("\n  All orgs have matching host counts across all three tables.")


def compare_counts(advisor_url, hbi_url, token):
    print(f"\n{'='*70}")
    print("Comparing total row counts (all orgs)")
    print(f"{'='*70}")

    print("\nQuerying HBI table count (source of truth)...")
    hbi_data = run_query(hbi_url, COUNT_HBI_QUERY, token)
    hbi_count = int(hbi_data.get("result", [[], [0]])[1][0])
    print(f"  hbi.hosts:              {hbi_count}")

    print("Querying Cyndi table count...")
    cyndi_data = run_query(advisor_url, COUNT_CYNDI_QUERY, token)
    cyndi_count = int(cyndi_data.get("result", [[], [0]])[1][0])
    print(f"  inventory.hosts:        {cyndi_count}")

    print("Querying new table count...")
    new_data = run_query(advisor_url, COUNT_NEW_TABLE_QUERY, token)
    new_count = int(new_data.get("result", [[], [0]])[1][0])
    print(f"  advisor_inventory_host: {new_count}")

    print(f"\n  HBI vs Cyndi:     {hbi_count - cyndi_count:+d}")
    print(f"  HBI vs New Table: {hbi_count - new_count:+d}")


def main():
    parser = argparse.ArgumentParser(
        description="Compare host IDs between Cyndi and advisor_inventory_host via GABI"
    )
    parser.add_argument(
        "--env", choices=["prod", "stage"], default="stage",
        help="Target environment (default: stage)"
    )
    parser.add_argument(
        "--org-id", type=str, default=None,
        help="Org ID to compare host IDs. If omitted, only total counts are compared."
    )
    parser.add_argument(
        "--find-diffs", action="store_true",
        help="Find org_ids where host counts differ between tables."
    )
    parser.add_argument(
        "--auth", type=str, default=None,
        help="Bearer token. Defaults to output of 'oc whoami -t'."
    )
    args = parser.parse_args()

    advisor_url = ADVISOR_GABI_URLS[args.env]
    hbi_url = HBI_GABI_URLS[args.env]
    token = args.auth or get_oc_token()

    print(f"Advisor GABI: {advisor_url}")
    print(f"HBI GABI:     {hbi_url}")
    print(f"Environment:  {args.env}")

    if args.org_id:
        match = compare_org(advisor_url, hbi_url, args.org_id, token)
        sys.exit(0 if match else 1)
    elif args.find_diffs:
        find_org_diffs(advisor_url, hbi_url, token)
    else:
        compare_counts(advisor_url, hbi_url, token)


if __name__ == "__main__":
    main()
