# DigIntLab DEP — OpenCTI Connector

An [OpenCTI](https://github.com/OpenCTI-Platform/OpenCTI) external-import connector that ingests ransomware and data-leak announcements from the [Double Extortion Platform (DEP)](https://doubleextortion.com/) and converts them into STIX 2.1 entities.

> **Requires OpenCTI ≥ 6.8.13** — A valid DEP subscription (username, password, and API key) is needed.

---

## What it does

- Authenticates against the DEP AWS Cognito identity provider
- Polls the DEP REST API on a configurable interval and maps each announcement to an OpenCTI **Report** by default, or an **Incident** when `DEP_PRIMARY_OBJECT=incident`
- Creates **Organization** identities for victim companies
- Optionally creates **Sector** identities and links victims via a `part-of` relationship
- Optionally generates **Indicators** for victim domains and leak hash identifiers
- Links generated indicators to the victim with `related-to`
- Attaches announcement-type labels (e.g. `dep:announcement-type:pii`) to the primary object
- Maintains connector state with a configurable overlap window to capture late DEP updates

---

## Quick start

    docker run --rm \
      -e OPENCTI_URL=https://your-opencti \
      -e OPENCTI_TOKEN=your-token \
      -e DEP_USERNAME=your-username \
      -e DEP_PASSWORD=your-password \
      -e DEP_API_KEY=your-api-key \
      -e DEP_CLIENT_ID=your-cognito-client-id \
      opencti/connector-digintlab-dep:latest

---

## Configuration

All values can be set via environment variables (which take precedence) or via a mounted `config.yml`.

### Required

| Environment variable | Description                  |
| -------------------- | ---------------------------- |
| `OPENCTI_URL`        | URL of your OpenCTI platform |
| `OPENCTI_TOKEN`      | OpenCTI API token            |
| `DEP_USERNAME`       | DEP portal username          |
| `DEP_PASSWORD`       | DEP portal password          |
| `DEP_API_KEY`        | API key issued by DEP        |
| `DEP_CLIENT_ID`      | AWS Cognito App Client ID    |

### Optional

| Environment variable           | Default                                                   | Description                                           |
| ------------------------------ | --------------------------------------------------------- | ----------------------------------------------------- |
| `CONNECTOR_RUN_INTERVAL`       | `3600`                                                    | Polling interval in seconds                           |
| `DEP_CONFIDENCE`               | `70`                                                      | Confidence score on generated STIX objects            |
| `DEP_LOOKBACK_DAYS`            | `7`                                                       | Days to look back on first run                        |
| `DEP_OVERLAP_HOURS`            | `72`                                                      | Overlap hours from previous run to catch late updates |
| `DEP_DSET`                     | `ext`                                                     | Dataset to query (e.g. `ext`, `sanctions`)            |
| `DEP_PRIMARY_OBJECT`           | `report`                                                  | Primary STIX object to emit: `report` or `incident`   |
| `DEP_EXTENDED_RESULTS`         | `true`                                                    | Request extended leak information                     |
| `DEP_ENABLE_SITE_INDICATOR`    | `true`                                                    | Create a domain indicator per victim                  |
| `DEP_ENABLE_HASH_INDICATOR`    | `true`                                                    | Create a hash indicator when a hash is provided       |
| `DEP_SKIP_EMPTY_VICTIM`        | `true`                                                    | Skip items where victim name is empty or n/a          |
| `DEP_CREATE_SECTOR_IDENTITIES` | `true`                                                    | Create sector identities and link victims             |
| `DEP_LOGIN_ENDPOINT`           | `https://cognito-idp.eu-west-1.amazonaws.com/`            | Cognito login endpoint                                |
| `DEP_API_ENDPOINT`             | `https://api.eu-ep1.doubleextortion.com/v1/dbtr/privlist` | DEP REST endpoint                                     |

---

## Docker Compose

A full `docker-compose.yml` (including a local OpenCTI stack) is available in the [source repository](https://github.com/DigintLab/opencti-connector).

    dep-connector:
      image: opencti/connector-digintlab-dep:latest
      environment:
        - OPENCTI_URL=http://opencti:8080
        - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
        - DEP_USERNAME=${DEP_USERNAME}
        - DEP_PASSWORD=${DEP_PASSWORD}
        - DEP_API_KEY=${DEP_API_KEY}
        - DEP_CLIENT_ID=${DEP_CLIENT_ID}
      restart: always

---

## Links

- [Source code](https://github.com/DigintLab/opencti-connector)
- [Double Extortion Platform](https://doubleextortion.com/)
- [OpenCTI documentation](https://docs.opencti.io/)
- [MIT License](https://github.com/DigintLab/opencti-connector/blob/main/LICENSE)
