FROM debian:stable-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY constraints.txt pyproject.toml README.md ./
COPY src ./src
COPY examples ./examples

RUN apt-get update \
    && printf 'wireshark-common wireshark-common/install-setuid boolean false\n' | debconf-set-selections \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        libpcap0.8 \
        tshark \
        python3.13 \
        python3-pip \
    && rm -rf /var/lib/apt/lists/* \
    && python3.13 -m pip install --break-system-packages --upgrade pip \
    && python3.13 -m pip install --break-system-packages --no-cache-dir -c constraints.txt .

ENTRYPOINT ["dns-latency-probe"]
CMD ["--help"]
