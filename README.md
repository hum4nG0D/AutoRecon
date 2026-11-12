# AutoRecon

AutoRecon runs port and service enumeration, then saves raw scan output and reports for each target. This is the [hum4nG0D fork](https://github.com/hum4nG0D/AutoRecon) of [AutoRecon](https://github.com/AutoRecon/AutoRecon). It is licensed under [GPLv3](LICENSE).

Run scans only against systems you are authorized to assess.

## Platforms

- **Kali Linux** is the supported target for a native install (below) — the scanning tools are packaged for it, and the test suite is verified on Kali's Python.
- **macOS, Windows, and other Linux distributions** should use the [Docker image](#docker) (below). It bundles the full Kali toolset — including `nuclei` — and needs nothing on the host except Docker. Do not run `install.sh` on macOS; use Docker.

## Install on Kali Linux

AutoRecon calls external tools. Install the tools and `pipx` first:

```bash
sudo apt update
sudo apt install pipx seclists curl bind9-dnsutils dnsrecon enum4linux feroxbuster gobuster ffuf hydra impacket-scripts nbtscan nikto nmap nfs-common onesixtyone oscanner redis-tools rsync smbclient smbmap snmp sslscan sipvicious tnscmd10g whatweb openssh-client
```

From a clone of this fork, install or update AutoRecon:

```bash
bash install.sh
```

The script installs this checkout with `pipx`, refreshes the SSH and web proof plugins in an existing user plugin directory, and caches [LinPEAS](https://github.com/peass-ng/PEASS-ng) for optional authenticated scans. Re-run it after pulling updates. Python dependencies are installed by `pipx`; the system scanning tools above are installed by `apt`.

If `autorecon` is not found after installation, run `pipx ensurepath`, open a new shell, and retry.

For alternate directory enumeration tools, install `dirb` or `dirsearch` if desired and select one with `--dirbuster.tool`.

## Quick start

```bash
autorecon 192.0.2.10
autorecon --list plugins
```

Results go to `~/results` by default (created automatically); override with `-o`. Every scan also starts the local web portal at http://127.0.0.1:8787 — open it while the scan runs to watch progress, or afterwards to browse reports. Stop the portal with `autorecon stop`; pass `--no-portal` to skip starting it.

Each target gets its own directory:

```text
~/results/192.0.2.10/
├── report/   # reports, notes, and optional AI summaries
└── scans/    # raw tool output and suggested manual commands
```

The default output root is `~/results` if `-o` is omitted. Suggested password testing commands in `scans/_manual_commands.txt` are for manual use; the default SMTP user enumeration plugin may invoke Hydra.

## Common options

| Option | Purpose |
| --- | --- |
| `-o "$HOME/results"` | Choose the output root. |
| `--ports T:22,80,443` | Scan selected TCP ports. |
| `--dirbuster.tool gobuster` | Choose a directory enumeration tool; `feroxbuster` is the default. |
| `--exclude-tags proof` | Skip the web proof plugin. |
| `--force-services tcp/22/ssh` | Run service checks for a known service without port discovery. |
| `--timeout 60` | Abandon the whole run after N minutes. |
| `--target-timeout 30` | Abandon one target after N minutes. |
| `--tool-timeout 20` | Terminate any single plugin command after N minutes (default 15; `0` = no limit). |
| `-vv` | Show more console detail. |
| `--accessible` | Use screen reader friendly console output. |

Run `autorecon --help` for the full option list.

## Command reference

### Core scanning

```bash
autorecon 192.0.2.10                          # basic scan; results → ~/results, portal auto-starts
autorecon 192.0.2.10 -v                       # show commands as they run
autorecon 192.0.2.10 -vv                      # full command detail
autorecon 192.0.2.10 -o /tmp/engagement       # custom results root
autorecon 192.0.2.10 --ports T:22,80,443,U:53 # specific ports only
autorecon 192.0.2.10 --tags default,signatures       # add signature scanning (opt-in)
autorecon 192.0.2.10 --exclude-tags proof,bruteforce
autorecon -t targets.txt                      # scan a target list
autorecon 10.0.0.0/24                         # CIDR range
autorecon 192.0.2.10 --timeout 60             # abandon the whole run after 60 min
autorecon 192.0.2.10 --target-timeout 30      # abandon one target after 30 min
autorecon 192.0.2.10 --no-portal              # don't start the web portal
autorecon 192.0.2.10 --single-target          # write output straight into -o dir
autorecon --list plugins                      # list all plugins and tags
```

### Portal

```bash
autorecon portal                     # portal standalone (indexes ~/results)
autorecon stop                       # stop the auto-started portal
autorecon stop --results-dir /other  # stop the portal for a different results root
```

### Proof-of-exploit checks

```bash
# Standalone against one origin (no full scan needed)
autorecon-proof --allow-origin http://192.0.2.10:8080 --output proof.json

# Pick modules (default: all in-band modules; ssrf/xxe need --oob)
autorecon-proof --allow-origin http://192.0.2.10:8080 --output proof.json \
    --module ssti --module command-injection

# Blind checks via interactsh (needs internet; some ISP filters block oast.*)
autorecon-proof --allow-origin http://192.0.2.10:8080 --output proof.json \
    --oob interactsh --oob-timeout 15

# Authenticated target, exact endpoints via manifest
autorecon-proof --allow-origin https://192.0.2.10 --output proof.json \
    --headers-file auth-headers.json --manifest entries.json
```

The same knobs exist mid-scan as plugin flags: `--proof-web-probes.modules sqli lfi`, `--proof-web-probes.oob interactsh`, `--proof-web-probes.headers-file`, `--proof-web-probes.timeout`.

### Signature scanning (nuclei)

```bash
autorecon 192.0.2.10 --tags default,signatures       # enable (nuclei self-updates each run)

autorecon 192.0.2.10 --tags default,signatures \
    --signature-scan.severity critical high \
    --signature-scan.tags cve sqli \
    --signature-scan.templates /path/to/custom-templates \
    --signature-scan.rate-limit 50 \
    --signature-scan.extras '-header "X-Auth: token"'

    --signature-scan.skip-update     # skip the per-run nuclei/template update
    --signature-scan.no-bridge       # don't auto-confirm matches via proof modules
    --signature-scan.disable-oob     # no nuclei interactsh callbacks
    --signature-scan.oob interactsh  # callback provider for blind bridge checks
```

### AI reports (ChatGPT plan)

```bash
autorecon-ai login                     # one-time browser sign-in (run on the host, not in Docker)
autorecon-ai status                    # check connection
autorecon-ai models                    # list available models
autorecon 192.0.2.10 --ai              # auto-review during the scan
autorecon 192.0.2.10 --ai --ai-model <slug> --ai-max-chunks 50

# Manual flow: preview the redacted input before sending
autorecon-ai report ~/results/192.0.2.10
less ~/results/192.0.2.10/report/ai-report-input.txt
autorecon-ai report ~/results/192.0.2.10 --model <slug> --send
autorecon-ai logout
```

In Docker, sign-in must happen on the host (the browser callback cannot reach a container), then mount the host config directory — note the path is platform-specific:

```bash
# Linux host:
-v "$HOME/.config/AutoRecon:/root/.config/AutoRecon"
# macOS host (platformdirs uses Application Support on macOS):
-v "$HOME/Library/Application Support/AutoRecon:/root/.config/AutoRecon"
```

### Authenticated SSH checks

```bash
autorecon 192.0.2.10 --linpeas -u audit -i ~/.ssh/audit_key     # full scan + LinPEAS

autorecon-linpeas 192.0.2.10 -u audit -i ~/.ssh/audit_key       # LinPEAS only (default port 22)
autorecon-linpeas 192.0.2.10 -u audit -i ~/.ssh/audit_key -p 2222 -o ~/results-rerun --ai
```

Plugin-level equivalents: `--ssh-authenticated-host-checks.username`, `.identity-file`, `.linpeas-timeout`, `.linpeas-section`.

### Docker (macOS / Windows / non-Kali)

```bash
docker build --platform linux/amd64 -t autorecon .

docker run --rm -p 127.0.0.1:8787:8787 -v "$HOME/results:/results" \
    autorecon 192.0.2.10 -vv

docker run --rm -p 127.0.0.1:8787:8787 -v "$HOME/results:/results" \
    -v "$HOME/.config/AutoRecon:/root/.config/AutoRecon" \
    autorecon 192.0.2.10 --ai --tags default,signatures

docker run --rm -p 127.0.0.1:8787:8787 -v "$HOME/results:/results" autorecon portal

docker compose build
docker compose run --rm --service-ports autorecon 192.0.2.10 -vv

git pull && docker build --platform linux/amd64 -t autorecon .   # update
```

### Day-two operations

```bash
autorecon stop                                                  # stop the portal
docker container prune                                          # clean stopped scan containers
less ~/results/<target>/scans/_manual_commands.txt              # suggested follow-ups
cat ~/results/<target>/report/proof-findings.md                 # consolidated findings
```

The program and the Docker image are the same binary with two environment presets, so flags never differ between host and container.

## Docker

The Dockerfile builds this checkout using Kali tools. The image has no wrapper script: the container entrypoint **is** the `autorecon` CLI, preset with two environment variables (`AUTORECON_RESULTS=/results`, `AUTORECON_PORTAL_HOST=0.0.0.0`), so Docker behaves exactly like a local install — one command runs the scan, starts the web portal, and creates the results directory if needed. Mount a host results directory to keep the output after the container exits — Docker creates it automatically when missing:

```bash
docker build --platform linux/amd64 -t autorecon .
docker run --rm -p 127.0.0.1:8787:8787 -v "$HOME/results:/results" autorecon 192.0.2.10
```

Open http://127.0.0.1:8787 while the scan runs to watch progress live; the portal stops when the scan ends. Verbosity and AI options pass straight through:

```bash
docker run --rm -p 127.0.0.1:8787:8787 -v "$HOME/results:/results" autorecon 192.0.2.10 -vv
docker run --rm -p 127.0.0.1:8787:8787 -v "$HOME/results:/results" autorecon 192.0.2.10 --ai
```

For `--ai`, connect ChatGPT on the host first and mount the session into the container (on macOS the host config dir is `~/Library/Application Support/AutoRecon`, not `~/.config/AutoRecon` — sign-in only works on the host, never inside a container): add `-v "$HOME/.config/AutoRecon:/root/.config/AutoRecon"` on Linux, or `-v "$HOME/Library/Application Support/AutoRecon:/root/.config/AutoRecon"` on macOS. Run the portal on its own with `docker run --rm -p 127.0.0.1:8787:8787 -v "$HOME/results:/results" autorecon portal`. On Linux you can add `--network host` and omit the `-p` flag.

Stopping: the portal stops automatically when the scan ends (the container exits and takes the portal with it). `docker stop <container>` ends a detached container and its scan together. To stop just the portal inside a still-running container, use `docker exec <container> autorecon stop`.

### Shorter commands

`-p` and `-v` are the two places the container touches your machine (your port 8787, your `~/results`), which is why they can't be baked into the image. Two ways to type less:

- **Shell alias** (shortest — add to `~/.zshrc`): then `autorecon 192.0.2.10 -vv` just works:

  ```bash
  autorecon() { docker run --rm -p 127.0.0.1:8787:8787 -v "$HOME/results:/results" autorecon "$@"; }
  ```

- **Docker Compose** (no alias needed; flags live in `docker-compose.yml`):

  ```bash
  docker compose build
  docker compose run --rm --service-ports autorecon 192.0.2.10 -vv
  ```

Proof-of-exploit checks run automatically against every web service the scan finds; no flag is needed. The container runs as root by default, so files written to the host results directory may be root-owned.

## Local web portal

The portal starts automatically with every scan and stays available afterwards, serving http://127.0.0.1:8787. To run it on its own:

```bash
autorecon portal
```

Stop it with `autorecon stop`. The portal listens on your computer only. It indexes existing `~/results/<target>/` folders, including scans started from another terminal with `autorecon 192.0.2.10`. New scans started in the portal have separate run folders under `~/results/portal-runs/`. Connect ChatGPT with `autorecon-ai login` in a local terminal before enabling AI in the portal.

To run the portal as a user service after login:

```bash
mkdir -p "$HOME/.config/systemd/user"
cp autorecon/portal/autorecon-portal.service "$HOME/.config/systemd/user/"
systemctl --user daemon-reload
systemctl --user enable --now autorecon-portal.service
```

The service assumes pipx installed `autorecon-portal` in `~/.local/bin`; adjust `ExecStart` if your pipx app directory differs.

## Web proof checks

Default HTTP scans include bounded GET-parameter proof checks: server-side template expression evaluation, OS command injection, SQL injection (time-based), local file inclusion, plus blind SSRF and XXE when an out-of-band callback provider is enabled. Each module uses nonce-tagged probes and requires a deterministic signal — evaluated arithmetic, delays that track requested SLEEP durations, file-content markers, or a callback interaction carrying the probe nonce — before reporting `confirmed`; an inconclusive result is not proof of safety, and blind checks without a configured callback report `skipped`. The plugin saves JSON evidence and a text summary in `scans/`.

Run the verifier for one origin without a full scan:

```bash
autorecon-proof --allow-origin http://192.0.2.10:8080 --output proof-evidence.json
```

Select specific modules (default: all six; `ssrf` and `xxe` need `--oob`):

```bash
autorecon-proof --allow-origin http://192.0.2.10:8080 --output proof-evidence.json --module ssti --module command-injection --module sqli --module lfi --module ssrf --module xxe
```

Use `--proof-web-probes.manifest` during a scan to select exact URLs and parameters, `--proof-web-probes.modules` to select modules, or `--proof-web-probes.headers-file` for authenticated web headers. Run `autorecon-proof --help` for the standalone equivalents. Review evidence before sharing it.

### Out-of-band (blind) checks

SSRF and XXE cannot be proven in-band, so they need a callback provider. AutoRecon implements the interactsh wire protocol directly (no external client binary) and talks to ProjectDiscovery's open OOB service — the server sees only random nonce subdomains, never target data:

```bash
autorecon-proof --allow-origin http://192.0.2.10:8080 --output proof-evidence.json --oob interactsh
```

Blind checks correlate nonce-tagged callback URLs: `confirmed` only when an interaction carrying the probe nonce arrives. Polling is bounded (per-callback `--oob-timeout`, default 10 s, and a run-level budget). Without `--oob`, blind checks report `skipped` — they are never silently downgraded. The same options exist on scans as `--proof-web-probes.oob` and `--proof-web-probes.oob-timeout`, or set `AUTORECON_OOB=interactsh`. For self-hosting, `autorecon.proofmodules.callbacks.InteractshProvider` accepts a server via `server=` and an auth `token=`. Note: some ISPs' security filters block the public `oast.*` domains; the provider reports this with a clear error.

POST endpoints can be tested through the manifest (auto-discovery stays GET-only for safety) by adding `method`, `body_template` (must contain `{value}`), and an optional `content_type` to an entry:

```json
[{"url": "http://192.0.2.10:8080/api/lookup", "parameter": "q",
  "method": "POST", "body_template": "{\"q\": \"{value}\"}", "content_type": "application/json"}]
```

### Findings everywhere

Confirmed proof checks surface in three more places: the scan writes a consolidated `report/proof-findings.md` (severity-ordered, evidence-linked) when a run finishes; the portal's per-target **Findings** tab lists every finding with severity/status badges; and the AI report leads with a machine-confirmed findings digest so verified exploits rank above anything inferred from raw scan output.

## Signature scanning (opt-in)

For detection breadth, the `signature-scan` plugin runs [nuclei](https://github.com/projectdiscovery/nuclei) (10,000+ community templates) against each HTTP service. It is **not** part of the default scan — enable it explicitly:

```bash
autorecon <target> --tags default,signatures
docker run --rm -p 127.0.0.1:8787:8787 -v "$HOME/results:/results" autorecon <target> --tags default,signatures
```

On a native Kali install, install nuclei first (a `linux_amd64` binary from the [releases page](https://github.com/projectdiscovery/nuclei/releases), or `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`); the Docker image ships it.

Every run, the plugin first checks for and applies nuclei binary and template updates (`nuclei -update -ut`); disable with `--signature-scan.skip-update`. Tune the scan with `--signature-scan.severity`, `--signature-scan.templates`, `--signature-scan.tags`, `--signature-scan.rate-limit`, `--signature-scan.timeout`, `--signature-scan.extras`, or `--signature-scan.disable-oob` to turn off nuclei's interactsh callbacks. Output lands in `scans/*_signatures.jsonl` (raw) and `scans/*_signatures.json` (normalized).

Signature matches are **detections, not proofs**: they are recorded with status `matched` and appear in their own "unverified detections" section of `report/proof-findings.md` and with a distinct badge in the portal's Findings tab. By default, the **confirmation bridge** then re-runs each matched finding's input through the proof module for its class (sqli, command injection, SSTI, LFI, SSRF, XXE — mapped from the template's tags): matches that verify are upgraded to `confirmed` with full probe evidence, burning down the false-positive backlog the way Netsparker's proof engine does. Disable with `--signature-scan.no-bridge`, and pass `--signature-scan.oob interactsh` to give blind bridge checks their callback provider.

## Authenticated SSH checks

Provide a username and private key for read-only SSH host checks. The target's host key must already be trusted in your local `known_hosts` file:

```bash
autorecon -o "$HOME/results" 192.0.2.10 --ssh-authenticated-host-checks.username audit --ssh-authenticated-host-checks.identity-file ~/.ssh/audit_key
```

Add LinPEAS to a full scan, or rerun only LinPEAS on a known SSH port:

```bash
autorecon -o "$HOME/results" 192.0.2.10 --linpeas -u audit -i ~/.ssh/audit_key
autorecon-linpeas 192.0.2.10 -o "$HOME/results" -u audit -i ~/.ssh/audit_key
```

The short command defaults to port 22; use `-p` for another port and a different `-o` root to keep rerun output separate. LinPEAS saves readable, raw, and error output separately. Use `--ssh-authenticated-host-checks.linpeas-script` to supply your own copy.

## AI reports

AI reporting is opt-in. If your account supports [Sign in with ChatGPT](https://developers.openai.com/siwc/token-sharing-open-source), `--ai` signs you in if needed, reviews completed scans, and writes a concise final report:

```bash
autorecon -o "$HOME/results" 192.0.2.10 --ai
```

Automatic mode sends redacted scan text as scans finish, without a preview step. For a reviewable manual submission, create and inspect the local preview first:

```bash
autorecon-ai login
autorecon-ai models
autorecon-ai report "$HOME/results/192.0.2.10"
less "$HOME/results/192.0.2.10/report/ai-report-input.txt"
autorecon-ai report "$HOME/results/192.0.2.10" --model MODEL_SLUG --send
```

You can edit `ai-report-input.txt` before `--send`; the command sends that saved text. Basic redaction can miss sensitive data, so inspect it before submission. The report files are:

- `report/ai-report.md` — short final findings.
- `report/ai-report-reviews.md` — detailed per-scan reviews.
- `report/ai-report-input.txt` — redacted input preview.

Use `--ai-model` for automatic model selection and `--ai-max-chunks` to change its request limit; the manual command uses `--max-chunks`. If a request limit interrupts a run, completed reviews remain available. Use `autorecon-ai logout` to disconnect the account.
