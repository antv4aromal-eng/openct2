FROM python:3.11-slim

WORKDIR /app

COPY packages/atip-sdk-python /app/packages/atip-sdk-python
COPY services/ingest-merger-worker/requirements.txt /app/requirements.txt

RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir -e /app/packages/atip-sdk-python

COPY services/ingest-merger-worker /app/services/ingest-merger-worker

ENV PYTHONUNBUFFERED=1

CMD ["python", "-m", "services.ingest-merger-worker.worker"]
