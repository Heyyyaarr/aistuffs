FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    tshark \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY multi_agent.py .
COPY agents/ agents/

ENV PYTHONUNBUFFERED=1
CMD ["python", "multi_agent.py"]
