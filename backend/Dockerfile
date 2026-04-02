FROM python:3.12-slim

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    nmap \
    wget \
    curl \
    unzip \
    ca-certificates \
    perl \
    && rm -rf /var/lib/apt/lists/*

# Install Nikto (not available as a package on all Debian variants)
RUN git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto \
    && printf '#!/bin/sh\nexec perl /opt/nikto/program/nikto.pl "$@"\n' > /usr/local/bin/nikto \
    && chmod +x /usr/local/bin/nikto

# Install nuclei (stable mirror + retries)
ARG NUCLEI_VERSION=3.6.2
RUN mkdir -p /opt/nuclei \
    && curl -L --retry 5 --retry-delay 2 --fail \
      "https://sourceforge.net/projects/nuclei.mirror/files/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip/download" \
      -o /tmp/nuclei.zip \
    && unzip -q /tmp/nuclei.zip -d /opt/nuclei \
    && mv /opt/nuclei/nuclei /usr/local/bin/nuclei \
    && chmod +x /usr/local/bin/nuclei \
    && rm -f /tmp/nuclei.zip

WORKDIR /app

COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir -r /app/backend/requirements.txt

COPY backend /app/backend

WORKDIR /app

EXPOSE 8000

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
