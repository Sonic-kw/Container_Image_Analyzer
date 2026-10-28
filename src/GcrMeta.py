"""Uzupelnia rozmiar i date wgrania obrazow distroless w scans.jsonl.

Katalog gcr.io nie daje tych pol (Hub daje je w API tagow), wiec dla
wierszy distroless:
  arch_size       = suma `size` warstw z manifestu amd64 (gcr.io/v2/.../manifests/<digest>)
  tag_last_pushed = `timeUploadedMs` tego digestu z gcr.io/v2/<repo>/tags/list

Bez skanowania - tylko metadane rejestru. Zrodlo zapisane w *_source.
"""

from __future__ import annotations

import argparse
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

import requests

from hub_http import MANIFEST_ACCEPT, TIMEOUT, build_session

log = logging.getLogger("gcrmeta")

GCR_HOST = "gcr.io"


def layer_size(session: requests.Session, repo: str, digest: str) -> int:
    response = session.get(
        f"https://{GCR_HOST}/v2/{repo}/manifests/{digest}",
        headers={"Accept": MANIFEST_ACCEPT},
        timeout=TIMEOUT,
    )
    response.raise_for_status()
    layers = response.json().get("layers")
    if not layers:
        raise ValueError(f"{repo}@{digest}: manifest bez warstw (indeks?)")
    return sum(int(layer["size"]) for layer in layers)


def uploaded_at(manifests: dict, digest: str) -> str:
    entry = manifests.get(digest)
    if not entry or not entry.get("timeUploadedMs"):
        raise ValueError(f"{digest}: brak timeUploadedMs w tags/list")
    moment = datetime.fromtimestamp(int(entry["timeUploadedMs"]) / 1000, tz=timezone.utc)
    return moment.isoformat().replace("+00:00", "Z")


def fill(path: Path) -> int:
    rows = [json.loads(line) for line in path.open(encoding="utf-8") if line.strip()]
    session = build_session(use_cache=False)
    tag_lists: dict[str, dict] = {}
    filled = 0
    for row in rows:
        if row.get("variant") != "distroless":
            continue
        repo = row["repo_key"].removeprefix(f"{GCR_HOST}/")
        digest = row["arch_digest"]
        if repo not in tag_lists:
            response = session.get(f"https://{GCR_HOST}/v2/{repo}/tags/list", timeout=TIMEOUT)
            response.raise_for_status()
            tag_lists[repo] = response.json().get("manifest", {})
        row["arch_size"] = layer_size(session, repo, digest)
        row["arch_size_source"] = "gcr_manifest_layers"
        row["tag_last_pushed"] = uploaded_at(tag_lists[repo], digest)
        row["tag_last_pushed_source"] = "gcr_time_uploaded"
        filled += 1
        log.info("%s: %d B, %s", repo, row["arch_size"], row["tag_last_pushed"])

    tmp = path.with_suffix(".tmp")
    with tmp.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    tmp.replace(path)
    return filled


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--in", dest="in_path", type=Path, default=Path("results/scans.jsonl"))
    args = p.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    log.info("uzupelniono %d wierszy distroless", fill(args.in_path))


if __name__ == "__main__":
    main()
