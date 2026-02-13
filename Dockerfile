FROM python:3.12-slim AS builder
HEALTHCHECK NONE

ENV UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1 \
    UV_PYTHON_DOWNLOADS=never \
    UV_PYTHON=python3.12 \
    UV_NO_PROGRESS=1

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv
WORKDIR /app
RUN --mount=type=cache,target=/root/.cache \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync \
    --locked \
    --no-dev \
    --no-install-project --no-editable
COPY pyproject.toml uv.lock ./
COPY *.py ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-editable --no-dev

FROM python:3.12-slim AS runtime
HEALTHCHECK NONE

ENV PATH="/app/.venv/bin:${PATH}"

# kics-scan ignore-line
RUN apt update && apt install -y libmagic-dev

RUN adduser --system --no-create-home app
WORKDIR /app
COPY --from=builder /app /app
LABEL org.opencontainers.image.source=https://github.com/DigintLab/opencti-connector
LABEL org.opencontainers.image.description="The Double Extortion connector ingests ransomware and data leak announcements published on the DoubleExtortion platform and converts them into STIX entities inside OpenCTI."

USER app
ENTRYPOINT ["python", "main.py"]