FROM python:3.12-slim

# System deps: nmap (network scans) + curl (healthchecks) + unzip (nuclei install)
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap \
        curl \
        unzip \
    && rm -rf /var/lib/apt/lists/*

# Install Nuclei v3
ARG NUCLEI_VERSION=3.3.9
RUN curl -sL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" \
        -o /tmp/nuclei.zip \
    && unzip -q /tmp/nuclei.zip -d /usr/local/bin/ \
    && rm /tmp/nuclei.zip \
    && chmod +x /usr/local/bin/nuclei

WORKDIR /app

# Persistent data dirs — overridden by named volumes in compose
RUN mkdir -p /app/data /app/reports

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Pre-download Nuclei templates on build (optional — speeds up first scan)
RUN nuclei -update-templates -silent || true

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
