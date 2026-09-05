#!/usr/bin/env python3
"""Check the winget manifests beside this script against Microsoft's
schemas (docs/design/distribution.md): each file's ManifestType picks
its schema, the three must be there, and they must name one package and
one version. The schemas are fetched from the winget-cli repository, so
this runs where the network is; it needs pyyaml and jsonschema."""

import json
import pathlib
import sys
import urllib.request

import jsonschema
import yaml

HERE = pathlib.Path(__file__).parent
SCHEMA_VERSION = "1.6.0"
BASE = (
    "https://raw.githubusercontent.com/microsoft/winget-cli/master/"
    f"schemas/JSON/manifests/v{SCHEMA_VERSION}/"
)
SCHEMAS = {
    "version": "manifest.version",
    "installer": "manifest.installer",
    "defaultLocale": "manifest.defaultLocale",
}


def schema(kind):
    with urllib.request.urlopen(f"{BASE}{SCHEMAS[kind]}.{SCHEMA_VERSION}.json", timeout=60) as r:
        return json.load(r)


def main():
    files = sorted(HERE.glob("*.yaml"))
    if not files:
        sys.exit("no manifests found")
    seen = {}
    identities = set()
    for path in files:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        kind = doc.get("ManifestType")
        if kind not in SCHEMAS:
            sys.exit(f"{path.name}: ManifestType {kind!r} is not one of {sorted(SCHEMAS)}")
        if kind in seen:
            sys.exit(f"{path.name}: a second {kind} manifest; {seen[kind]} is one already")
        try:
            jsonschema.validate(doc, schema(kind))
        except jsonschema.ValidationError as e:
            sys.exit(f"{path.name}: {e.message} (at {'/'.join(str(p) for p in e.absolute_path)})")
        seen[kind] = path.name
        identities.add((doc["PackageIdentifier"], doc["PackageVersion"]))
        print(f"{path.name}: a valid {kind} manifest")
    missing = sorted(set(SCHEMAS) - set(seen))
    if missing:
        sys.exit(f"manifests missing: {missing}")
    if len(identities) != 1:
        sys.exit(f"the manifests disagree on the package or the version: {sorted(identities)}")
    identifier, version = identities.pop()
    print(f"{identifier} {version}: the three manifests agree")


if __name__ == "__main__":
    main()
