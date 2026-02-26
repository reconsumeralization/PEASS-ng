#!/usr/bin/env python3
"""Build a compact WinPEAS definitions file from WES-NG definitions.zip."""

from __future__ import annotations

import argparse
import csv
import io
import json
import tempfile
import zipfile
from collections import defaultdict
from pathlib import Path
from urllib.request import urlretrieve


DEFAULT_DEFINITIONS_URL = "https://raw.githubusercontent.com/bitsadmin/wesng/master/definitions.zip"


def _read_csv_from_zip(zip_file: zipfile.ZipFile, prefix: str) -> list[dict]:
    target = next((name for name in zip_file.namelist() if name.startswith(prefix)), None)
    if not target:
        return []
    with zip_file.open(target, "r") as raw:
        return list(csv.DictReader(io.TextIOWrapper(raw, encoding="utf-8-sig")))


def build_definitions(definitions_zip: Path) -> dict:
    with zipfile.ZipFile(definitions_zip, "r") as zf:
        cve_file = next(name for name in zf.namelist() if name.startswith("CVEs_"))
        generated = cve_file.split("_", 1)[1].split(".", 1)[0]

        rows = _read_csv_from_zip(zf, "CVEs_")
        rows.extend(_read_csv_from_zip(zf, "Custom_"))

    products: dict[str, dict[str, dict[str, str]]] = defaultdict(dict)
    for row in rows:
        if not (row.get("Exploits") or "").strip():
            continue

        product = (row.get("AffectedProduct") or "").strip()
        if not product:
            continue
        if "windows" not in product.lower():
            continue

        cve = (row.get("CVE") or "").strip()
        kb = (row.get("BulletinKB") or "").strip()
        vuln_key = cve or f"KB{kb}"
        if not vuln_key:
            continue

        if vuln_key in products[product]:
            continue

        products[product][vuln_key] = {
            "cve": cve,
            "kb": kb,
            "severity": (row.get("Severity") or "").strip(),
            "impact": (row.get("Impact") or "").strip(),
        }

    data = {"generated": generated, "products": {}}
    for product in sorted(products):
        entries = [products[product][key] for key in sorted(products[product])]
        data["products"][product] = entries

    return data


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--definitions-url", default=DEFAULT_DEFINITIONS_URL)
    parser.add_argument("--definitions-zip", default="")
    parser.add_argument(
        "--output",
        default=str(Path("build_lists") / "windows_version_exploits.json"),
    )
    args = parser.parse_args()

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if args.definitions_zip:
        definitions_zip = Path(args.definitions_zip)
        if not definitions_zip.exists():
            raise FileNotFoundError(f"Definitions zip not found: {definitions_zip}")
    else:
        with tempfile.TemporaryDirectory(prefix="wesng_defs_") as temp_dir:
            temp_zip = Path(temp_dir) / "definitions.zip"
            urlretrieve(args.definitions_url, str(temp_zip))
            data = build_definitions(temp_zip)
            output_path.write_text(json.dumps(data, separators=(",", ":")) + "\n", encoding="utf-8")
    if args.definitions_zip:
        data = build_definitions(definitions_zip)
        output_path.write_text(json.dumps(data, separators=(",", ":")) + "\n", encoding="utf-8")

    total_products = len(data["products"])
    total_entries = sum(len(v) for v in data["products"].values())
    print(
        f"Generated {output_path} (date={data['generated']}, products={total_products}, vulnerabilities={total_entries})"
    )


if __name__ == "__main__":
    main()
