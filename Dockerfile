FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY constraints.txt pyproject.toml README.md ./
COPY src ./src
COPY examples ./examples

RUN python -m pip install --upgrade pip \
    && pip install --no-cache-dir -c constraints.txt .

ENTRYPOINT ["dns-latency-probe"]
CMD ["--help"]
