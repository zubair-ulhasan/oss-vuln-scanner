# oss-vuln-scanner

A small Python tool that reads a project's `package.json` or `pom.xml`,
checks every listed dependency against the [OSV.dev](https://osv.dev)
vulnerability database, and prints a report of any known CVEs found.
Results are cached in a local SQLite database so repeat scans are fast
and don't re-query unchanged packages.

## Why this project exists

Software composition analysis (SCA) - finding known vulnerabilities in the open-source packages a project
depends on - is a core part of software supply chain security. This is a deliberately small version of the idea,
built as a personal learning project to practise dependency vulnerability scanning, package ecosystems
(npm/Maven) and the concepts around SBOMs, SCA and vulnerability databases.

## Setup

```bash
pip install -r requirements.txt
```

## Usage

```bash
python scanner.py path/to/package.json
python scanner.py path/to/pom.xml
```

Two sample manifests are included for a quick test run:

```bash
python scanner.py package.json      # npm example (lodash, express, jest)
python scanner.py sample-pom.xml    # Maven example (commons-compress, jackson-databind)
```

## Example output

```
Scanned 3 dependencies (1 with known vulnerabilities, 2 clean)

VULNERABLE DEPENDENCIES:
  [npm] lodash@4.17.15
      -> GHSA-p6mc-m468-83gw  (https://osv.dev/vulnerability/GHSA-p6mc-m468-83gw)
```

## How it works

1. **Parse** - extracts `{name, version, ecosystem}` for every
   dependency from the manifest (handles both namespaced and
   non-namespaced `pom.xml` files).
2. **Cache check** - looks up each dependency in a local SQLite table
   before making any network call.
3. **Batch query** - anything not cached is sent to OSV.dev's
   `querybatch` endpoint in a single request rather than one call per
   dependency.
4. **Report + cache** - prints results and writes fresh lookups back
   to SQLite for next time.

## Possible extensions

- Resolve exact versions from `package-lock.json` / lockfiles instead
  of the manifest's version *range*
- Add a `--fail-on-critical` flag for CI/CD pipeline gating
- Generate a CycloneDX or SPDX-format SBOM alongside the report
- Add severity scoring by cross-referencing NVD/CVSS data
