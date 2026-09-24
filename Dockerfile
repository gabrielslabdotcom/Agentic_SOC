FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src
COPY scripts ./scripts

RUN pip install --no-cache-dir '.[cursor,discord]'

ENV PYTHONUNBUFFERED=1 \
    AGENTIC_SOC_APPLIANCE=1 \
    AGENTIC_SOC_DATA=/data \
    CASES_DB_PATH=/data/cases.sqlite \
    AUTONOMY_STATE_FILE=/data/autonomy_state.json

EXPOSE 8080
VOLUME /data

CMD ["python", "scripts/appliance.py"]
