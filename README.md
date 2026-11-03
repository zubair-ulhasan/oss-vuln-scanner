# oss-vuln-scanner

The tool in this repository is in the [`oss-vuln-scanner/`](oss-vuln-scanner/) folder: a small Python command-line scanner for software composition analysis (SCA), which means finding known vulnerabilities in the open-source packages a project depends on.

It reads a project's `package.json` (npm) or `pom.xml` (Maven), checks every dependency against the [OSV.dev](https://osv.dev) vulnerability database in one batched request, and prints the known advisories it finds. A local SQLite cache avoids re-querying packages that were already checked.

Tested on an intentionally vulnerable Node.js app: 36 dependencies scanned, 7 flagged as vulnerable.

## Quick start

Requires Python 3.

```bash
cd oss-vuln-scanner
pip install -r requirements.txt
python scanner.py package.json
python scanner.py sample-pom.xml
```

How it works, example output and possible extensions are covered in [`oss-vuln-scanner/README.md`](oss-vuln-scanner/README.md).
