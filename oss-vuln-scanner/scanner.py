#!/usr/bin/env python3
"""
oss-vuln-scanner
================
Reads a project's dependency manifest (package.json or pom.xml),
queries the OSV.dev vulnerability database for known CVEs against
each dependency, prints a report, and caches results in a local
SQLite database so repeat scans don't re-query unchanged packages.

This is a scaled-down version of what software composition analysis (SCA)
tools do - a personal learning project to practise supply chain security
concepts (SCA, vulnerability databases, package ecosystems).

Usage:
    python scanner.py path/to/package.json
    python scanner.py path/to/pom.xml
"""

import json
import re
import sqlite3
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

import requests

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
DB_PATH = Path(__file__).parent / "vuln_cache.db"


@dataclass
class Dependency:
    name: str
    version: str
    ecosystem: str  # "npm" or "Maven"


@dataclass
class ScanResult:
    dependency: Dependency
    vulnerability_ids: list = field(default_factory=list)


# ---------------------------------------------------------------------
# Manifest parsing
# ---------------------------------------------------------------------

def parse_package_json(path: Path) -> list[Dependency]:
    data = json.loads(path.read_text())
    deps = []
    for section in ("dependencies", "devDependencies"):
        for name, version_range in data.get(section, {}).items():
            # Strip range prefixes like ^, ~, >= to get a concrete version
            # for lookup purposes. Real-world use should resolve exact
            # installed versions from a lockfile instead.
            version = re.sub(r"^[\^~>=<\s]+", "", version_range)
            deps.append(Dependency(name=name, version=version, ecosystem="npm"))
    return deps


def parse_pom_xml(path: Path) -> list[Dependency]:
    ns = {"m": "http://maven.apache.org/POM/4.0.0"}
    tree = ET.parse(path)
    root = tree.getroot()

    # Handle poms both with and without the default namespace declared
    deps_nodes = root.findall(".//m:dependencies/m:dependency", ns)
    if not deps_nodes:
        deps_nodes = root.findall(".//dependencies/dependency")
        ns = {}

    deps = []
    for node in deps_nodes:
        group_id = _find_text(node, "groupId", ns)
        artifact_id = _find_text(node, "artifactId", ns)
        version = _find_text(node, "version", ns) or "unknown"
        if group_id and artifact_id:
            deps.append(Dependency(
                name=f"{group_id}:{artifact_id}",
                version=version,
                ecosystem="Maven",
            ))
    return deps


def _find_text(node, tag, ns):
    if ns:
        el = node.find(f"m:{tag}", ns)
    else:
        el = node.find(tag)
    return el.text.strip() if el is not None and el.text else None


def parse_manifest(path: Path) -> list[Dependency]:
    if path.name == "package.json":
        return parse_package_json(path)
    if path.suffix == ".xml" and "pom" in path.name:
        return parse_pom_xml(path)
    raise ValueError(f"Unsupported manifest type: {path.name}")


# ---------------------------------------------------------------------
# SQLite cache
# ---------------------------------------------------------------------

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scan_cache (
            ecosystem   TEXT NOT NULL,
            name        TEXT NOT NULL,
            version     TEXT NOT NULL,
            vuln_ids    TEXT NOT NULL,
            scanned_at  TEXT NOT NULL,
            PRIMARY KEY (ecosystem, name, version)
        )
    """)
    conn.commit()
    return conn


def get_cached(conn, dep: Dependency):
    row = conn.execute(
        "SELECT vuln_ids FROM scan_cache WHERE ecosystem=? AND name=? AND version=?",
        (dep.ecosystem, dep.name, dep.version),
    ).fetchone()
    if row is None:
        return None
    return json.loads(row[0])


def save_cache(conn, dep: Dependency, vuln_ids: list[str]):
    conn.execute(
        """INSERT OR REPLACE INTO scan_cache (ecosystem, name, version, vuln_ids, scanned_at)
           VALUES (?, ?, ?, ?, datetime('now'))""",
        (dep.ecosystem, dep.name, dep.version, json.dumps(vuln_ids)),
    )
    conn.commit()


# ---------------------------------------------------------------------
# OSV.dev querying
# ---------------------------------------------------------------------

def query_osv_batch(deps: list[Dependency]) -> dict:
    """Queries OSV.dev's batch endpoint for all deps not already cached.
    Returns a dict keyed by (ecosystem, name, version) -> [vuln ids]."""

    queries = [
        {"package": {"name": d.name, "ecosystem": d.ecosystem}, "version": d.version}
        for d in deps
    ]

    response = requests.post(OSV_BATCH_URL, json={"queries": queries}, timeout=30)
    response.raise_for_status()
    results = response.json().get("results", [])

    output = {}
    for dep, result in zip(deps, results):
        vulns = result.get("vulns", [])
        output[(dep.ecosystem, dep.name, dep.version)] = [v["id"] for v in vulns]
    return output


# ---------------------------------------------------------------------
# Main scan flow
# ---------------------------------------------------------------------

def scan(manifest_path: Path) -> list[ScanResult]:
    deps = parse_manifest(manifest_path)
    conn = init_db()

    to_query = []
    results = []

    for dep in deps:
        cached = get_cached(conn, dep)
        if cached is not None:
            results.append(ScanResult(dep, cached))
        else:
            to_query.append(dep)

    if to_query:
        fresh = query_osv_batch(to_query)
        for dep in to_query:
            vuln_ids = fresh.get((dep.ecosystem, dep.name, dep.version), [])
            save_cache(conn, dep, vuln_ids)
            results.append(ScanResult(dep, vuln_ids))

    conn.close()
    return results


def print_report(results: list[ScanResult]):
    vulnerable = [r for r in results if r.vulnerability_ids]
    clean = [r for r in results if not r.vulnerability_ids]

    print(f"\nScanned {len(results)} dependencies "
          f"({len(vulnerable)} with known vulnerabilities, {len(clean)} clean)\n")

    if vulnerable:
        print("VULNERABLE DEPENDENCIES:")
        for r in vulnerable:
            d = r.dependency
            print(f"  [{d.ecosystem}] {d.name}@{d.version}")
            for vid in r.vulnerability_ids:
                print(f"      -> {vid}  (https://osv.dev/vulnerability/{vid})")
    else:
        print("No known vulnerabilities found in scanned dependencies.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python scanner.py <path-to-package.json-or-pom.xml>")
        sys.exit(1)

    manifest = Path(sys.argv[1])
    if not manifest.exists():
        print(f"File not found: {manifest}")
        sys.exit(1)

    scan_results = scan(manifest)
    print_report(scan_results)
