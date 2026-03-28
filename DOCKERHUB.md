# DigIntLab DEP — OpenCTI Connector

An [OpenCTI](https://github.com/OpenCTI-Platform/OpenCTI) external-import connector that ingests ransomware and data-leak announcements from the [Double Extortion Platform (DEP)](https://doubleextortion.com/) and converts them into STIX 2.1 entities.

> **Requires OpenCTI >= 6.8.13** and valid DEP credentials: username, password, API key, and Cognito client ID.

---

## What it does

- Authenticates against the DEP AWS Cognito identity provider
- Polls the DEP REST API on a configurable interval
- Models each DEP announcement as an OpenCTI **Report** by default, or an **Incident** when `DEP_PRIMARY_OBJECT=incident`
- Creates **Organization** identities for victims
- Optionally creates **Sector** identities, **Intrusion Sets**, and **Country** locations
- Optionally generates **Indicators** for victim domains and leak hash identifiers
- Adds announcement-type and dataset labels such as `dep:announcement-type:pii` and `dep:dataset:ext`
- Maintains per-dataset connector state with an overlap window to catch late DEP updates

---

## Quick start

The simplest way to run the connector is to mount a `config.yml` file at `/app/config.yml`:

```bash
docker run --rm \
  -v "$(pwd)/config.yml:/app/config.yml:ro" \
  opencti/connector-digintlab-dep:rolling
```

Environment variables override values from `config.yml`. A minimal env-only example is:

```bash
docker run --rm \
  -e OPENCTI_URL=https://your-opencti \
  -e OPENCTI_TOKEN=your-token \
  -e CONNECTOR_ID=change-me \
  -e CONNECTOR_TYPE=EXTERNAL_IMPORT \
  -e CONNECTOR_NAME="DEP Connector" \
  -e CONNECTOR_SCOPE=report,incident,identity,indicator \
  -e DEP_USERNAME=your-username \
  -e DEP_PASSWORD=your-password \
  -e DEP_API_KEY=your-api-key \
  -e DEP_CLIENT_ID=your-cognito-client-id \
  opencti/connector-digintlab-dep:rolling
```

---

## Configuration

The connector loads configuration from `OPENCTI_CONFIG_FILE` when set, otherwise from `/app/config.yml`. Environment variables take precedence over YAML values.

### Required

| Environment variable | Description                                                     |
| -------------------- | --------------------------------------------------------------- |
| `OPENCTI_URL`        | URL of your OpenCTI platform                                    |
| `OPENCTI_TOKEN`      | OpenCTI API token                                               |
| `CONNECTOR_ID`       | Unique connector identifier                                     |
| `CONNECTOR_TYPE`     | Connector type, typically `EXTERNAL_IMPORT`                     |
| `CONNECTOR_NAME`     | Connector display name                                          |
| `CONNECTOR_SCOPE`    | Connector scope, typically `report,incident,identity,indicator` |
| `DEP_USERNAME`       | DEP portal username                                             |
| `DEP_PASSWORD`       | DEP portal password                                             |
| `DEP_API_KEY`        | API key issued by DEP                                           |
| `DEP_CLIENT_ID`      | AWS Cognito App Client ID                                       |

### Optional

| Environment variable           | Default                                                   | Description                                                                                                                                                                                                    |
| ------------------------------ | --------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `CONNECTOR_RUN_INTERVAL`       | `3600`                                                    | Polling interval in seconds                                                                                                                                                                                    |
| `DEP_CONFIDENCE`               | `70`                                                      | Confidence score on generated STIX objects                                                                                                                                                                     |
| `DEP_LOOKBACK_DAYS`            | `7`                                                       | Days to look back on first run                                                                                                                                                                                 |
| `DEP_OVERLAP_HOURS`            | `72`                                                      | Overlap hours from previous run to catch late updates                                                                                                                                                          |
| `DEP_DATASETS`                 | `ext`                                                     | DEP datasets to query. Accepts comma-separated short API codes (`ext`, `prv`, `nws`, `vnd`, `dds`, `frm`) or long aliases such as `extortion`, `privacy`, `opennews`/`news`, `vandalism`, `ddos`, and `forum`. |
| `DEP_PRIMARY_OBJECT`           | `report`                                                  | Primary STIX object to emit: `report` or `incident`                                                                                                                                                            |
| `DEP_EXTENDED_RESULTS`         | `true`                                                    | Request extended DEP results                                                                                                                                                                                   |
| `DEP_ENABLE_SITE_INDICATOR`    | `true`                                                    | Create a domain indicator per victim                                                                                                                                                                           |
| `DEP_ENABLE_HASH_INDICATOR`    | `true`                                                    | Create a hash indicator when a hash is provided                                                                                                                                                                |
| `DEP_SKIP_EMPTY_VICTIM`        | `true`                                                    | Skip items where victim name is empty, `n/a`, or `none`                                                                                                                                                        |
| `DEP_CREATE_SECTOR_IDENTITIES` | `true`                                                    | Create sector identities and link victims with `part-of`                                                                                                                                                       |
| `DEP_CREATE_INTRUSION_SETS`    | `true`                                                    | Create intrusion sets from DEP actor values                                                                                                                                                                    |
| `DEP_CREATE_COUNTRY_LOCATIONS` | `true`                                                    | Create country locations and link victims with `located-at`                                                                                                                                                    |
| `DEP_LOGIN_ENDPOINT`           | `https://cognito-idp.eu-west-1.amazonaws.com/`            | Cognito login endpoint                                                                                                                                                                                         |
| `DEP_API_ENDPOINT`             | `https://api.eu-ep1.doubleextortion.com/v1/dbtr/privlist` | DEP REST endpoint                                                                                                                                                                                              |

---

## Docker Compose

A full `docker-compose.yml` with a local OpenCTI stack is available in the [source repository](https://github.com/DigintLab/opencti-connector).

```yaml
dep-connector:
  image: opencti/connector-digintlab-dep:rolling
  restart: always
  volumes:
    - ./config.yml:/app/config.yml:ro
  environment:
    - OPENCTI_URL=http://opencti:8080
    - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
    - DEP_USERNAME=${DEP_USERNAME}
    - DEP_PASSWORD=${DEP_PASSWORD}
    - DEP_API_KEY=${DEP_API_KEY}
    - DEP_CLIENT_ID=${DEP_CLIENT_ID}
```

When multiple datasets are configured, the connector loops over them and issues one DEP API request per dataset. Dataset aliases are normalized to the short API codes before the request is sent, for example `ddos -> dds` and `vandalism -> vnd`.

State is tracked per dataset, so adding a new dataset later starts that dataset from the normal lookback window instead of inheriting the already-advanced state of the previously configured datasets.

---

## Links

- [Source code](https://github.com/DigintLab/opencti-connector)
- [Double Extortion Platform](https://doubleextortion.com/)
- [OpenCTI documentation](https://docs.opencti.io/)
- [MIT License](https://github.com/DigintLab/opencti-connector/blob/main/LICENSE)
