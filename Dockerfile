FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY constraints.txt pyproject.toml README.md ./
COPY src ./src
COPY examples ./examples

RUN apt-get update \
    && apt-get install -y --no-install-recommends libpcap0.8 \
    && rm -rf /var/lib/apt/lists/* \
    && python -m pip install --upgrade pip \
    && pip install --no-cache-dir -c constraints.txt .

ENTRYPOINT ["dns-latency-probe"]
CMD ["--help"]
