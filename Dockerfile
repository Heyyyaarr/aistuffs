FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    tshark \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

COPY multi_agent.py pyproject.toml .
COPY agents/ agents/
RUN pip install --no-cache-dir .

ENV PYTHONUNBUFFERED=1
CMD ["multi-agent-hunt"]
