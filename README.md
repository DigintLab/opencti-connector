# Double Extortion OpenCTI Connector

The Double Extortion connector ingests ransomware and data leak announcements published on the DoubleExtortion platform and converts them into STIX entities inside OpenCTI.

<img width="2532" height="1032" alt="dfz" src="https://github.com/user-attachments/assets/3072e3ce-de67-45a7-a88e-58447066096d" />

## Features

- Authenticates against the DoubleExtortion AWS Cognito identity provider.
- Collects double extortion announcements and models them as **Incidents**.
- Creates **Organization** identities for victims.
- Generates optional **Indicators** for advertised victim domains and leak hash identifiers.
- Supports querying different Double Extortion Platform datasets via `DEP_DSET`.
- Maintains connector state to avoid re-ingesting older records.

<img width="2551" height="873" alt="Screenshot 2025-11-30 114440" src="https://github.com/user-attachments/assets/39027ed0-f2f4-4175-abdf-6b31ad78ef75" />

## Running locally

1. Copy `config.yml.sample` to `config.yml` and update it with your DEP credentials and OpenCTI configuration.

2. Copy `.env_example` to `.env` and update it with your OpenCTI configuration.

3. Run the services:

   ```bash
   docker compose up
   ```

## Configuration

All configuration values can be supplied via the `config.yml` file or through environment variables. Environment variables take precedence and follow the naming convention described below.

### Required values

| YAML path       | Environment variable | Description                                        |
| --------------- | -------------------- | -------------------------------------------------- |
| `opencti.url`   | `OPENCTI_URL`        | URL of your OpenCTI platform.                      |
| `opencti.token` | `OPENCTI_TOKEN`      | API token for OpenCTI.                             |
| `dep.username`  | `DEP_USERNAME`       | Username for the Double Extortion Platform portal. |
| `dep.password`  | `DEP_PASSWORD`       | Password for the portal.                           |
| `dep.api_key`   | `DEP_API_KEY`        | API key issued by the Double Extortion Platform.   |

### Optional values

| YAML path                   | Environment variable        | Default                                                   | Description                                        |
| --------------------------- | --------------------------- | --------------------------------------------------------- | -------------------------------------------------- |
| `connector.interval`        | `CONNECTOR_RUN_INTERVAL`    | `3600`                                                    | Interval in seconds between executions.            |
| `dep.client_id`             | `DEP_CLIENT_ID`             | `""`                                                      | AWS Cognito App Client ID (required).              |
| `dep.login_endpoint`        | `DEP_LOGIN_ENDPOINT`        | `https://cognito-idp.eu-west-1.amazonaws.com/`            | Cognito login endpoint.                            |
| `dep.api_endpoint`          | `DEP_API_ENDPOINT`          | `https://api.eu-ep1.doubleextortion.com/v1/dbtr/privlist` | REST endpoint for announcements.                   |
| `dep.lookback_days`         | `DEP_LOOKBACK_DAYS`         | `7`                                                       | Days to look back on the first run.                |
| `dep.extended_results`      | `DEP_EXTENDED_RESULTS`      | `true`                                                    | Request extended leak information.                 |
| `dep.dset`                  | `DEP_DSET`                  | `ext`                                                     | Dataset to query (for example `ext`, `sanctions`). |
| `dep.enable_site_indicator` | `DEP_ENABLE_SITE_INDICATOR` | `true`                                                    | Create a domain indicator per victim.              |
| `dep.enable_hash_indicator` | `DEP_ENABLE_HASH_INDICATOR` | `true`                                                    | Create a hash indicator when a hash is provided.   |
| `dep.skip_empty_victim`     | `DEP_SKIP_EMPTY_VICTIM`     | `false`                                                   | Skip items where victim is empty, `n/a`, or `none`. |

## Docker

A Dockerfile is provided to run the connector in a containerized environment. Build the image with:

```bash
docker build -t opencti-connector-dep .
```

Then run it by passing the required configuration as environment variables or mounting the updated `config.yml`:

```bash
docker run --rm \
  -e OPENCTI_URL=https://your-opencti \
  -e OPENCTI_TOKEN=changeme \
  -e DEP_USERNAME=username \
  -e DEP_PASSWORD=password \
  -e DEP_API_KEY=apikey \
  opencti-connector-dep
```

## Development notes

- The project uses [**go-task**](https://github.com/go-task/task) with a `Taskfile.yml` to streamline common development commands.
- The project uses [**uv**](https://docs.astral.sh/uv/) as the Python virtual environment and dependency management tool.
- The connector keeps track of the last successful execution timestamp in the OpenCTI worker state. Delete the state in OpenCTI to re-ingest older records.
- The API occasionally URL-encodes announcement descriptions. The connector automatically decodes the description before sending it to OpenCTI.
- Intrusion set creation is disabled by default because not every dataset represents a threat actor. If needed, adapt the logic in `DepConnector._process_item`.
- To reload the new code inside the platform using docker compose run: `docker compose build dep-connector; docker compose up -d dep-connector; docker compose logs -f dep-connector`

## License

This project is released under the [MIT License](LICENSE).
