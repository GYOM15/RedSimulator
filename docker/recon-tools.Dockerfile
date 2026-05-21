FROM python:3.11-slim

# --- Installer les outils de reconnaissance ---

# nmap
RUN apt-get update && apt-get install -y \
    nmap \
    wget \
    unzip \
    dnsutils \
    && rm -rf /var/lib/apt/lists/*

# ffuf (derniere version)
RUN wget -q https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_amd64.tar.gz \
    && tar -xzf ffuf_2.1.0_linux_amd64.tar.gz -C /usr/local/bin/ ffuf \
    && rm ffuf_2.1.0_linux_amd64.tar.gz \
    && chmod +x /usr/local/bin/ffuf

# subfinder
RUN wget -q https://github.com/projectdiscovery/subfinder/releases/download/v2.6.7/subfinder_2.6.7_linux_amd64.zip \
    && unzip -q subfinder_2.6.7_linux_amd64.zip -d /tmp/subfinder \
    && mv /tmp/subfinder/subfinder /usr/local/bin/subfinder \
    && rm -rf subfinder_2.6.7_linux_amd64.zip /tmp/subfinder \
    && chmod +x /usr/local/bin/subfinder

# Dependances Python
RUN pip install --no-cache-dir flask python-nmap

# Copier le service API
COPY docker/recon_service.py /app/recon_service.py

# Copier les wordlists
COPY data/wordlists/ /app/wordlists/

WORKDIR /app
EXPOSE 8081
CMD ["python", "recon_service.py"]
