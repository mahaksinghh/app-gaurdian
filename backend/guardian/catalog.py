import argparse
import tempfile
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Literal

import httpx
from pydantic import BaseModel, Field, model_validator

from .models import Cve

CATALOG_NAME = "CISA Known Exploited Vulnerabilities"
CATALOG_URL = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"
CATALOG_LICENSE = "https://github.com/cisagov/kev-data/blob/develop/LICENSE"
MAX_CATALOG_BYTES = 4 * 1024 * 1024


class KevEntry(BaseModel):
    cveID: Cve
    vendorProject: str = Field(max_length=256)
    product: str = Field(max_length=256)
    dateAdded: date
    requiredAction: str = Field(max_length=3000)


class Assessment(BaseModel):
    source: str = CATALOG_NAME
    source_url: str = CATALOG_URL
    license: str = "CC0-1.0"
    license_url: str = CATALOG_LICENSE
    catalog_version: str
    released_at: datetime
    stale: bool
    applicability: Literal["human-review-required"] = "human-review-required"
    matches: list[KevEntry]
    unlisted_ids: list[Cve]


class Catalog(BaseModel):
    catalogVersion: str = Field(max_length=80)
    dateReleased: datetime
    count: int = Field(ge=1, le=20_000)
    vulnerabilities: list[KevEntry] = Field(max_length=20_000)

    @model_validator(mode="after")
    def validate_release(self) -> "Catalog":
        if self.dateReleased.tzinfo is None:
            raise ValueError("Catalog timestamp requires a timezone.")
        if len({entry.cveID for entry in self.vulnerabilities}) != self.count or len(self.vulnerabilities) != self.count:
            raise ValueError("Catalog entries are missing or duplicated.")
        return self

    def assessment(self, codes: list[str]) -> Assessment:
        by_id = {entry.cveID: entry for entry in self.vulnerabilities}
        unique = list(dict.fromkeys(codes))
        return Assessment(
            catalog_version=self.catalogVersion,
            released_at=self.dateReleased,
            stale=datetime.now(timezone.utc) - self.dateReleased > timedelta(days=14),
            matches=[by_id[code] for code in unique if code in by_id],
            unlisted_ids=[code for code in unique if code not in by_id],
        )


def load(path: Path) -> Catalog:
    with path.open("rb") as file:
        data = file.read(MAX_CATALOG_BYTES + 1)
    if len(data) > MAX_CATALOG_BYTES:
        raise ValueError("The catalog exceeds its supported size.")
    return Catalog.model_validate_json(data)


def fetch(path: Path) -> None:
    data = bytearray()
    with httpx.Client(timeout=15, follow_redirects=False, trust_env=False) as client:
        with client.stream("GET", CATALOG_URL) as response:
            response.raise_for_status()
            for part in response.iter_bytes():
                if len(part) > MAX_CATALOG_BYTES - len(data):
                    raise ValueError("The catalog exceeds its supported size.")
                data.extend(part)
    catalog = Catalog.model_validate_json(bytes(data))
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as output:
        temporary_path = Path(output.name)
        try:
            output.write(catalog.model_dump_json().encode())
            output.flush()
            temporary_path.replace(path)
        finally:
            temporary_path.unlink(missing_ok=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("fetch", "verify"))
    parser.add_argument("path", type=Path)
    arguments = parser.parse_args()
    if arguments.command == "fetch":
        fetch(arguments.path)
    checked = load(arguments.path)
    print(f"{CATALOG_NAME}: {checked.catalogVersion}, {checked.count} entries.")
