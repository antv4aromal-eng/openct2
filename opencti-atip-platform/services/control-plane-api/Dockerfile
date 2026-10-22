FROM python:3.11-slim

WORKDIR /app

COPY packages/atip-sdk-python /app/packages/atip-sdk-python
COPY services/control-plane-api/requirements.txt /app/requirements.txt

RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir -e /app/packages/atip-sdk-python

COPY services/control-plane-api /app/services/control-plane-api

ENV PYTHONUNBUFFERED=1
EXPOSE 8000

CMD ["uvicorn", "services.control-plane-api.main:app", "--host", "0.0.0.0", "--port", "8000"]
