FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    tshark \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

COPY pyproject.toml .
RUN pip install --no-cache-dir .

COPY multi_agent.py .
COPY agents/ agents/

ENV PYTHONUNBUFFERED=1
CMD ["multi-agent-hunt"]
