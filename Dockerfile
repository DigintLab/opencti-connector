FROM python:3.11-slim

ENV CONNECTOR_HOME=/opt/opencti-connector
WORKDIR ${CONNECTOR_HOME}

RUN pip install --no-cache-dir --upgrade pip

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY connector.py config.yml ./

ENTRYPOINT ["python", "connector.py"]
