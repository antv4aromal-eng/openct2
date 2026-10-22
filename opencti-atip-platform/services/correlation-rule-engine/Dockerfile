FROM python:3.11-slim

WORKDIR /app

COPY packages/atip-sdk-python /app/packages/atip-sdk-python
COPY services/correlation-rule-engine/requirements.txt /app/requirements.txt

RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir -e /app/packages/atip-sdk-python

COPY services/correlation-rule-engine /app/services/correlation-rule-engine

ENV PYTHONUNBUFFERED=1

CMD ["python", "-m", "services.correlation-rule-engine.engine"]
