# Double Extortion OpenCTI Connector

The Double Extortion connector ingests ransomware and data-leak announcements published on the DoubleExtortion platform and converts them into STIX entities in OpenCTI.

<img width="2548" height="1274" alt="image" src="https://github.com/user-attachments/assets/02391fb2-3387-4a76-9824-aea18922c351" />

## Features

- Authenticates against the DoubleExtortion AWS Cognito identity provider.
- Collects Double Extortion announcements and models them as **Reports** (default) or **Incidents** (configurable via `DEP_PRIMARY_OBJECT`).
- Creates **Organization** identities for victims.
- Optionally materializes **Intrusion Sets** from DEP actor names.
- Optionally materializes **Country** locations and links victims to them.
- Automatically links intrusion sets to sectors, intrusion sets to countries, and sectors to countries when those entities are created.
- Generates optional **Indicators** for advertised victim domains and leak hash identifiers.
- Adds announcement-type and dataset labels across DEP-derived STIX objects (for example `dep:announcement-type:pii` and `dep:dataset:ext`).
- Supports querying one or more Double Extortion Platform datasets via `DEP_DATASETS`.
- Maintains connector state with a configurable overlap window to capture late DEP updates.
- Uses stable identifiers (based on DEP `hashid`) for both reports and incidents so refreshed DEP records update existing objects.
- Filters low-quality actor values such as `unknown`, `anonymous`, or `ransomware group` before creating intrusion sets.
- Normalizes DEP values before STIX generation, including victim domains, sector/actor/country strings, and URL-decoded announcement descriptions.

<img width="2552" height="1283" alt="image (1)" src="https://github.com/user-attachments/assets/948b906a-8677-4326-959c-5483e4e14451" />
<img width="1759" height="1081" alt="image (2)" src="https://github.com/user-attachments/assets/15784093-3899-475a-a4bd-166a2e40c018" />

## Running locally

1. Copy `config.yml.sample` to `config.yml` and update it with your DEP credentials and OpenCTI configuration.

2. Copy `.env_example` to `.env` and update it with your OpenCTI configuration.

3. Run the services:

   ```bash
   docker compose up
   ```

## Configuration

All configuration values can be supplied via the `config.yml` file or through environment variables. Environment variables take precedence over YAML values. The connector loads `config.yml` from the project root by default, or from `OPENCTI_CONFIG_FILE` when that variable is set.

### Required values

| YAML path       | Environment variable | Description                                        |
| --------------- | -------------------- | -------------------------------------------------- |
| `opencti.url`   | `OPENCTI_URL`        | URL of your OpenCTI platform.                      |
| `opencti.token` | `OPENCTI_TOKEN`      | API token for OpenCTI.                             |
| `dep.username`  | `DEP_USERNAME`       | Username for the Double Extortion Platform portal. |
| `dep.password`  | `DEP_PASSWORD`       | Password for the portal.                           |
| `dep.api_key`   | `DEP_API_KEY`        | API key issued by the Double Extortion Platform.   |
| `dep.client_id` | `DEP_CLIENT_ID`      | AWS Cognito App Client ID. Required at startup.    |

### Optional values

| YAML path                      | Environment variable           | Default                                                   | Description                                                                                                                                                                                                                  |
| ------------------------------ | ------------------------------ | --------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `connector.interval`           | `CONNECTOR_RUN_INTERVAL`       | `3600`                                                    | Interval in seconds between executions.                                                                                                                                                                                      |
| `dep.confidence`               | `DEP_CONFIDENCE`               | `70`                                                      | Confidence score attached to generated STIX objects.                                                                                                                                                                         |
| `dep.login_endpoint`           | `DEP_LOGIN_ENDPOINT`           | `https://cognito-idp.eu-west-1.amazonaws.com/`            | Cognito login endpoint.                                                                                                                                                                                                      |
| `dep.api_endpoint`             | `DEP_API_ENDPOINT`             | `https://api.eu-ep1.doubleextortion.com/v1/dbtr/privlist` | REST endpoint for announcements.                                                                                                                                                                                             |
| `dep.lookback_days`            | `DEP_LOOKBACK_DAYS`            | `7`                                                       | Days to look back on the first run.                                                                                                                                                                                          |
| `dep.overlap_hours`            | `DEP_OVERLAP_HOURS`            | `72`                                                      | Hours to overlap from the previous per-dataset `last_run` when fetching, to catch late updates.                                                                                                                              |
| `dep.extended_results`         | `DEP_EXTENDED_RESULTS`         | `true`                                                    | Request extended leak information by adding `extended=true` to DEP API requests.                                                                                                                                             |
| `dep.datasets`                 | `DEP_DATASETS`                 | `ext`                                                     | Comma-separated or YAML-list dataset selection. Accepts official API values (`ext`, `prv`, `nws`, `vnd`, `dds`, `frm`) and long aliases such as `extortion`, `privacy`, `opennews`/`news`, `vandalism`, `ddos`, and `forum`. |
| `dep.enable_site_indicator`    | `DEP_ENABLE_SITE_INDICATOR`    | `true`                                                    | Create a domain indicator per victim.                                                                                                                                                                                        |
| `dep.enable_hash_indicator`    | `DEP_ENABLE_HASH_INDICATOR`    | `true`                                                    | Create a hash indicator when a hash is provided.                                                                                                                                                                             |
| `dep.skip_empty_victim`        | `DEP_SKIP_EMPTY_VICTIM`        | `true`                                                    | Skip items where victim is empty, `n/a`, or `none`.                                                                                                                                                                          |
| `dep.create_sector_identities` | `DEP_CREATE_SECTOR_IDENTITIES` | `true`                                                    | Create sector identities and link victims with a `part-of` relationship.                                                                                                                                                     |
| `dep.create_intrusion_sets`    | `DEP_CREATE_INTRUSION_SETS`    | `true`                                                    | Create intrusion sets from DEP actor values and link incidents with `attributed-to` (incident mode only).                                                                                                                    |
| `dep.primary_object`           | `DEP_PRIMARY_OBJECT`           | `report`                                                  | Primary object: `report` wraps all objects in a STIX Report container; `incident` creates a standalone Incident object.                                                                                                      |
| `dep.create_country_locations` | `DEP_CREATE_COUNTRY_LOCATIONS` | `true`                                                    | Create country locations and link victim identities with `located-at`.                                                                                                                                                       |

### DEP request behavior

Each DEP fetch sends:

- `ts`
- `te`
- `dset`
- `full=true`

When multiple datasets are configured, the connector loops over them and sends one DEP request per dataset.

Dataset aliases are normalized to the short API codes before requests are sent. For example, `ddos` becomes `dds` and `vandalism` becomes `vnd`.

The connector adds `extended=true` only when `DEP_EXTENDED_RESULTS=true`.

## Why `IntrusionSet` for DEP actor values

DEP `actor` values are modeled as STIX `IntrusionSet` objects instead of `ThreatActor` by default.

- DEP actor strings usually represent campaign/operator labels, not high-confidence real-world identities.
- `IntrusionSet` is a safer semantic fit for recurring malicious activity clusters.
- This avoids over-claiming attribution when source data quality is limited.
- It supports targeting analysis directly through `attributed-to` (incident -> intrusion set, in incident mode) and `targets` links from intrusion sets to sectors and countries.

A `ThreatActor` model can be adopted later if the feed includes stronger attribution context (persona, role, motivation, sophistication).

## Docker

A Dockerfile is provided to run the connector in a containerized environment. Build the image with:

```bash
docker build -t opencti-connector-dep .
```

Then run it by passing the required configuration as environment variables or by mounting an updated `config.yml`:

```bash
docker run --rm \
  -e OPENCTI_URL=https://your-opencti \
  -e OPENCTI_TOKEN=changeme \
  -e DEP_USERNAME=username \
  -e DEP_PASSWORD=password \
  -e DEP_API_KEY=apikey \
  -e DEP_CLIENT_ID=aws-cognito-client-id \
  opencti-connector-dep
```

## Development notes

- The project uses [**go-task**](https://github.com/go-task/task) with a `Taskfile.yml` to streamline common development commands.
- The project uses [**uv**](https://docs.astral.sh/uv/) as the Python virtual environment and dependency management tool.
- `task test` runs the first-party pytest suite under `tests/`, covering dataset parsing, connector runtime helpers including run-window behavior, and STIX conversion behavior.
- The connector stores `last_run_by_dataset` in OpenCTI worker state and applies the overlap (`DEP_OVERLAP_HOURS`) independently per dataset. Adding a new dataset later starts that dataset from the full `DEP_LOOKBACK_DAYS` window without affecting the existing ones.
- Reports and incidents are created with deterministic IDs derived from DEP `hashid`, and bundles are sent with `update=True`, so repeated records update existing objects instead of creating duplicates.
- In `report` mode each announcement is wrapped in a STIX `Report` object whose `object_refs` contains all correlated entities (victim, indicators, intrusion set, country, sector and their relationships). This produces a pre-correlated Knowledge Graph view directly in OpenCTI, consistent with most other connectors and feeds.
- In `incident` mode the announcement is modeled as a STIX `Incident` with explicit `targets`, `attributed-to`, and `indicates` relationships.
- Sector names are normalized before sector-identity generation to reduce duplicates caused by inconsistent casing or whitespace in DEP data.
- The API occasionally URL-encodes announcement descriptions. The connector automatically decodes the description before sending it to OpenCTI.
- DEP `annLink` values are repaired for a known scrape bug (`https//...` or `http//...`) before they are used as external references.
- DEP actor and country values can be materialized as entities using `DEP_CREATE_INTRUSION_SETS` and `DEP_CREATE_COUNTRY_LOCATIONS`.
- DEP actor and country values are also stored in the primary object custom properties (`dep_actor`, `dep_country`) for source traceability.
- Generated indicators are also linked to the victim with `related-to` so those indicator nodes are connected in the Knowledge Graph.
- Cross-entity links are automatic: intrusion set -> sector (`targets`), intrusion set -> country (`targets`), and sector -> country (`related-to`) when both entities are present.
- Generic low-quality actor values (for example `unknown`, `anonymous`, `ransomware group`) are ignored for intrusion-set creation.
- To reload the connector code in the platform, run: `docker compose build dep-connector; docker compose up -d dep-connector; docker compose logs -f dep-connector`

## License

This project is released under the [MIT License](LICENSE).
