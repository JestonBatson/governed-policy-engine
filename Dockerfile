FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir .

ENV AUDIT_LOG_PATH=/data/audit.jsonl
CMD ["uvicorn", "govpolicy.api:app", "--host", "0.0.0.0", "--port", "8000"]
