FROM kalilinux/kali-rolling

LABEL org.opencontainers.image.source="https://github.com/hum4nG0D/AutoRecon"

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-venv git ca-certificates curl \
    seclists bind9-dnsutils dnsrecon enum4linux \
    feroxbuster gobuster ffuf dirb dirsearch \
    hydra impacket-scripts nbtscan nikto nmap nfs-common \
    onesixtyone oscanner redis-tools rsync \
    smbclient smbmap snmp sslscan sipvicious tnscmd10g whatweb \
    openssh-client \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md LICENSE /opt/AutoRecon/
COPY autorecon/ /opt/AutoRecon/autorecon/

RUN python3 -m venv /opt/autorecon-venv \
    && /opt/autorecon-venv/bin/pip install --no-cache-dir /opt/AutoRecon

ENV PATH="/opt/autorecon-venv/bin:${PATH}"
# The image runs the same program as the host; these presets only adapt it
# to the container: results live at /results and the portal binds all
# interfaces so published ports can reach it.
ENV AUTORECON_RESULTS=/results
ENV AUTORECON_PORTAL_HOST=0.0.0.0

RUN install -d -m 700 /root/.cache/AutoRecon \
    && curl --fail --location --silent --show-error --retry 3 \
        --connect-timeout 10 --max-time 180 \
        --proto '=https' --proto-redir '=https' \
        --output /root/.cache/AutoRecon/linpeas.sh \
        https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh \
    && test -s /root/.cache/AutoRecon/linpeas.sh \
    && chmod 600 /root/.cache/AutoRecon/linpeas.sh

EXPOSE 8787
WORKDIR /results
ENTRYPOINT ["autorecon"]
