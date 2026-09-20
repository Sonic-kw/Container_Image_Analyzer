import requests
from requests.adapters import HTTPAdapter
from requests_cache import CachedSession
from urllib3.util import Retry
from dataclasses import dataclass
from pathlib import Path
import logging
from typing import Any
from dotenv import load_dotenv
import os


HUB_API     = "https://hub.docker.com/v2"
HUB_LIBRARY = HUB_API + "/repositories/library/"
HUB_SEARCH  = HUB_API + "/search/repositories/" 
PAGE_SIZE  = 100
MAX_PAGE=200
TIMEOUT    = (10, 30)
USER_AGENT = "pwr-thesis-fetcher/0.1"
SEARCH_QUERIES = [ "python", "java", "nodejs"]
load_dotenv()
token = os.environ["DOCKER_HUB_PAT"]
log = logging.getLogger("hub_catalog")


@dataclass(frozen=True, slots=True)
class HttpClient:
    namespace: str
    name: str
    pull_count: int | None
    star_count: int | None
    last_updated: str | None
    is_official: bool
    source: str
    query: str | None
    fetched_at: str
    raw: dict[str, Any]

def build_session(cache_name: str = "cache/hub_api") -> requests.Session:
    retry = Retry(
        total=5,
        backoff_factor=1.5,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=("GET",),
        respect_retry_after_header=True,
    )
    Path(cache_name).parent.mkdir(parents=True, exist_ok=True)
    session: requests.Session = CachedSession(cache_name, backend="sqlite", expire_after=24 * 3600)
    session = requests.Session()
    session.mount("https://", HTTPAdapter(max_retries=retry))
    return session

def build_repo_catalog(session: requests.Session, queries: list[str], out_path: Path, search_pages: int) -> int:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    seen: set[str] = set()
    with out_path.open("w", encoding="utf-8") as handle:
        def emit(repo: Repo) -> None:
            if repo.key in seen:
                return
            seen.add(repo.key)
            handle.write(json.dumps(repo.to_record(), ensure_ascii=False) + "\n")

def main():
    session = build_session()
    total = build_catalog(session, SEARCH_QUERIES, "results/catalog.jsonl", 2)







