# AGENTS.md

## Purpose

This file captures the project-specific behavior and working rules for humans and coding agents in this repository.
It should track the code in `main.py`, not stale assumptions from earlier iterations.

## Project scope

- This is an OpenCTI external-import connector for Double Extortion Platform (DEP) announcements.
- The connector authenticates against DEP AWS Cognito, fetches announcement records from the DEP REST API, converts them to STIX 2.1, and sends bundles to OpenCTI with `update=True`.
- The connector scope is `report,incident,identity,indicator`.
- The implementation is split across the `dep_connector/` package (`models.py`, `converter_to_stix.py`, `client_api.py`, `config_loader.py`, `connector.py`) with `main.py` as the thin entrypoint.

## Runtime and configuration truths

- Config is loaded from `OPENCTI_CONFIG_FILE` if set; otherwise from `config.yml` next to `main.py`.
- Environment variables override YAML values through `pycti.get_config_variable`.
- `DEP_CLIENT_ID` is required at startup even though `config.yml.sample` leaves it blank. Missing it raises `ValueError`.
- The runtime loop is infinite: `run()` executes one cycle, then sleeps for `CONNECTOR_RUN_INTERVAL`.
- Local Docker Compose mounts `./config.yml` into `/app/config.yml` for the `dep-connector` service.
- The local stack pins OpenCTI services to `6.8.13`; the connector manifest declares support for OpenCTI `>= 6.8.13`.
- The container image runs `python main.py` as the non-root `app` user on Python 3.12.

## DEP fetch behavior

- Authentication uses AWS Cognito `InitiateAuth` with `USER_PASSWORD_AUTH`.
- The connector expects `AuthenticationResult.IdToken` from the login response and uses it as the DEP API `Authorization` header.
- DEP fetches always send:
  - `ts`
  - `te`
  - `dset`
  - `full=true`
- `extended=true` is sent only when `DEP_EXTENDED_RESULTS=true`.
- `DEP_DSET` defaults to `ext`, so the connector can query alternate DEP datasets when required.

## State management

- The connector stores only one state key in OpenCTI worker state: `last_run`.
- First run window: `now - DEP_LOOKBACK_DAYS`.
- Subsequent run window: `last_run - DEP_OVERLAP_HOURS`.
- Invalid or non-string `last_run` values are ignored with a warning.
- State is persisted only after the processing loop finishes: `{"last_run": end.isoformat()}`.
- The overlap window is intentional and should be preserved to catch late DEP updates.

## Input parsing and normalization

- DEP records are parsed through a frozen Pydantic dataclass: `LeakRecord(extra="allow")`.
- Unknown DEP fields are tolerated and ignored unless explicitly mapped.
- `annLink` is repaired for a known scrape bug:
  - `https//...` -> `https://...`
  - `http//...` -> `http://...`
- `site` and `victimDomain` are stripped; empty strings become `None`.
- `sector`, `actor`, and `country` are whitespace-normalized; empty strings, `n/a`, and `none` become `None`.
- Indicator domain extraction prefers `victimDomain`, then falls back to `site`.
- Domain normalization uses `urlsplit`, extracts the hostname, and lowercases it.
- `annDescription` is URL-decoded with `urllib.parse.unquote` before the report or incident is created.

## Filtering rules

- Whole DEP items are skipped only when `DEP_SKIP_EMPTY_VICTIM=true` and `victim` is empty, `n/a`, or `none`.
- Invalid DEP payload entries are skipped with warnings; they should not abort the whole fetch cycle.
- Low-quality actor values are filtered from intrusion-set creation:
  - `unknown`
  - `unk`
  - `anonymous`
  - `unattributed`
  - `undisclosed`
  - `not disclosed`
  - `not-disclosed`
  - `ransomware group`
  - `ransomware gang`
  - `threat actor`
  - `attacker`

## STIX authoring conventions

- Every emitted object and relationship is authored by the same identity:
  - name: `DigIntLab`
  - type: `Identity`
  - identity_class: `organization`
  - contact: `https://doubleextortion.com/`
- Every emitted object and relationship created from DEP content carries the label `DigIntLab`.
- Confidence is consistently taken from `DEP_CONFIDENCE`.
- Bundles are deduplicated by STIX ID before sending to OpenCTI.
- Prefer deterministic IDs for DEP-derived entities and relationships to keep re-imports idempotent.

## Data model mappings

### Primary object

- Controlled by `DEP_PRIMARY_OBJECT` (default: `report`).
- `report`: each announcement is wrapped in a STIX `Report` container whose `object_refs` includes all correlated entities and relationships. This is the default and preferred mode for Knowledge Graph analysis.
- `incident`: each announcement is modeled as a standalone STIX `Incident` with explicit relationship edges (`targets`, `attributed-to`, `indicates`).

### Report (default mode)

- One report is created per DEP announcement.
- The report is always created, even when no victim identity is created.
- Deterministic report ID is based on normalized DEP `hashid`:
  - `report--uuid5(NAMESPACE_URL, "dep-announcement:<hashid>")`
- Report name format:
  - `DEP announcement - <victim>`
  - fallback to `victimDomain`
  - fallback to `Unknown Victim`
- `published` is derived from the DEP `date` at `00:00:00Z`.
- `report_types`: `["threat-report"]`
- Report custom properties (when present):
  - `dep_actor`
  - `dep_country`
- Report labels always include `DigIntLab`, plus one label per announcement type:
  - `dep:announcement-type:<lowercased enum value>`
- Report external reference prefers `annLink`; if absent, it falls back to `site`.
- `annTitle` is attached as the external reference description when present.
- `object_refs` contains all objects in the bundle (author identity, victim, indicators, intrusion set, country, sector, and all relationships between them).

### Incident (incident mode)

- One incident is created per DEP announcement.
- The incident is always created, even when no victim identity is created.
- Deterministic incident ID is based on normalized DEP `hashid`:
  - `incident--uuid5(NAMESPACE_URL, "dep-announcement:<hashid>")`
- Incident name format:
  - `DEP announcement - <victim>`
  - fallback to `victimDomain`
  - fallback to `Unknown Victim`
- `created` is derived from the DEP `date` at `00:00:00Z`.
- Incident custom properties:
  - `incident_type: cybercrime`
  - `first_seen`
  - `dep_actor` when present
  - `dep_country` when present
- Incident labels always include `DigIntLab`, plus one label per announcement type:
  - `dep:announcement-type:<lowercased enum value>`
- Incident external reference prefers `annLink`; if absent, it falls back to `site`.
- `annTitle` is attached as the external reference description when present.

### Victim

- Victim is modeled as `Identity` with `identity_class="organization"`.
- No victim identity is created when `victim` is missing.
- Deterministic victim ID uses `pycti.Identity.generate_id(victim_name, identity_class="organization")`.
- Victim external references may include:
  - DEP announcement URL with source `dep`
  - victim site URL with source `victim-site`
- Victim description is only used for fallback enrichment:
  - `Industry sector: <sector>` when a sector exists but sector identities are disabled
  - `Reported revenue: <revenue>` when revenue is present

### Sector

- Sector is modeled as `Identity` with `identity_class="class"`.
- Sector is created only when:
  - `DEP_CREATE_SECTOR_IDENTITIES=true`
  - sector is present
  - victim identity exists
- Sector IDs are deterministic and based on the lowercased sector value.

### Actor

- DEP `actor` is modeled as `IntrusionSet`, not `ThreatActor`.
- Rationale: DEP actor values are usually operational labels, not strong real-world identity claims.
- Intrusion sets are created only when:
  - `DEP_CREATE_INTRUSION_SETS=true`
  - actor is present
  - actor is not in the low-quality filter list
- Deterministic intrusion-set ID:
  - `intrusion-set--uuid5(NAMESPACE_URL, "dep-actor:<actor>")`

### Country

- Country is modeled as `Location`.
- Country locations are created only when:
  - `DEP_CREATE_COUNTRY_LOCATIONS=true`
  - country is present
  - victim identity exists
- Deterministic country location ID:
  - `location--uuid5(NAMESPACE_URL, "dep-country:<country>")`
- Always set both:
  - `name=<country>`
  - `country=<country>`
- Preserve the OpenCTI-specific custom property:
  - `x_opencti_location_type: Country`

### Indicators

- Indicator creation is optional and controlled by:
  - `DEP_ENABLE_SITE_INDICATOR`
  - `DEP_ENABLE_HASH_INDICATOR`
- Site/domain indicator:
  - created from normalized `victimDomain` or `site`
  - pattern: `[domain-name:value = '<domain>']`
- Hash indicator:
  - created from normalized `hashid`
  - supported hash lengths:
    - `32` -> `MD5`
    - `40` -> `SHA-1`
    - `64` -> `SHA-256`
  - pattern: `[file:hashes.'<type>' = '<hash>']`
- Indicator IDs are deterministic because they are generated from the STIX pattern.
- Indicator `valid_from` uses current UTC processing time, so timestamps are not deterministic even though IDs are.
- Indicators are also linked to the victim with `related-to`.
- In incident mode, indicators are linked to the incident with `indicates`.
- In report mode, indicators are included in the report's `object_refs` and can also have explicit `related-to -> victim` edges.

## Relationships emitted

### In report mode (default)

- `victim -> sector` with `part-of`
- `victim -> country` with `located-at`
- `indicator -> victim` with `related-to`
- `intrusion-set -> sector` with `targets`
- `intrusion-set -> country` with `targets`
- `sector -> country` with `related-to`

All of the above, plus the victim, indicators, and intrusion set, are referenced in the Report's `object_refs`. There is no `attributed-to` edge from the Report itself because the Report is a container, not a relationship endpoint.

### In incident mode

- `incident -> victim` with `targets`
- `victim -> sector` with `part-of`
- `incident -> intrusion-set` with `attributed-to`
- `victim -> country` with `located-at`
- `indicator -> victim` with `related-to`
- `intrusion-set -> sector` with `targets`
- `intrusion-set -> country` with `targets`
- `sector -> country` with `related-to`
- `indicator -> incident` with `indicates`

These links are created automatically when both related objects exist. There are no extra compatibility flags for the cross-entity links.

## Feature flags and important knobs

- Boolean feature flags:
  - `DEP_EXTENDED_RESULTS`
  - `DEP_ENABLE_SITE_INDICATOR`
  - `DEP_ENABLE_HASH_INDICATOR`
  - `DEP_SKIP_EMPTY_VICTIM`
  - `DEP_CREATE_SECTOR_IDENTITIES`
  - `DEP_CREATE_INTRUSION_SETS`
  - `DEP_CREATE_COUNTRY_LOCATIONS`
- Important non-boolean knobs:
  - `DEP_PRIMARY_OBJECT` (default: `report`; valid values: `report`, `incident`)
  - `DEP_DSET`
  - `DEP_LOOKBACK_DAYS`
  - `DEP_OVERLAP_HOURS`
  - `DEP_CONFIDENCE`
  - `DEP_LOGIN_ENDPOINT`
  - `DEP_API_ENDPOINT`
  - `DEP_API_KEY`
  - `DEP_USERNAME`
  - `DEP_PASSWORD`
  - `DEP_CLIENT_ID`

## Coding conventions for this repo

- Keep IDs deterministic for DEP-derived entities.
- Preserve the current object model unless the user explicitly asks for a schema change.
- Prefer normalization helpers and central filters over ad-hoc string cleanup.
- Keep optional enrichment behind the existing feature flags.
- Do not reintroduce removed compatibility flags for cross-entity relationships.
- If you change modeling, update `README.md`, `config.yml.sample`, and `AGENTS.md` together.
- If you touch report, incident, or indicator generation, verify idempotency assumptions still hold under `update=True`.

## Validation and local workflow

- When developing or changing code, testing is required before considering the work complete.
- In this repository, Docker is required for meaningful runtime validation.
- Install dependencies:
  - `task install`
- Format code:
  - `task format`
- Check formatting only:
  - `task format-check`
- Run lint:
  - `task lint`
- Run type checks:
  - `task type-check`
- Main quality gate:
  - `task format check type-check`
- Docker-based runtime validation can be satisfied by either:
  - building and running the connector image directly
  - using `docker compose up` with the local stack when broader integration checks are needed
- Never start the connector before the OpenCTI API/platform is ready and reachable.
- During Docker-based validation, wait for OpenCTI readiness first, then start the connector.

Use `task format check type-check` for complete local checks before considering code changes done.

There is a `task test` target, but there is currently no first-party test suite in this repository. Do not assume automated test coverage exists.
For code changes, do not stop at static checks alone; perform Docker-based runtime validation as well.

## File map

- Connector entrypoint: `main.py`
- Data models (enums, LeakRecord): `dep_connector/models.py`
- STIX converter: `dep_connector/converter_to_stix.py`
- DEP API client (auth + fetch): `dep_connector/client_api.py`
- Configuration loader: `dep_connector/config_loader.py`
- Connector orchestration (run cycle): `dep_connector/connector.py`
- Package re-export: `dep_connector/__init__.py`
- Sample connector config: `config.yml.sample`
- Local development stack: `docker-compose.yml`
- Runtime image definition: `Dockerfile`
- User-facing docs: `README.md`
- Marketplace metadata: `__metadata__/connector_manifest.json`
- Task automation: `Taskfile.yml`
