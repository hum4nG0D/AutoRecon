# AutoRecon

AutoRecon runs port and service enumeration, then saves raw scan output and reports for each target. This is the [hum4nG0D fork](https://github.com/hum4nG0D/AutoRecon) of [AutoRecon](https://github.com/AutoRecon/AutoRecon). It is licensed under [GPLv3](LICENSE).

Run scans only against systems you are authorized to assess.

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
autorecon -o "$HOME/results" 192.0.2.10
autorecon --list plugins
```

Each target gets its own directory:

```text
~/results/192.0.2.10/
├── report/   # reports, notes, and optional AI summaries
└── scans/    # raw tool output and suggested manual commands
```

The default output root is `./results` if `-o` is omitted. Suggested password testing commands in `scans/_manual_commands.txt` are for manual use; the default SMTP user enumeration plugin may invoke Hydra.

## Common options

| Option | Purpose |
| --- | --- |
| `-o "$HOME/results"` | Choose the output root. |
| `--ports T:22,80,443` | Scan selected TCP ports. |
| `--dirbuster.tool gobuster` | Choose a directory enumeration tool; `feroxbuster` is the default. |
| `--exclude-tags proof` | Skip the web proof plugin. |
| `--force-services tcp/22/ssh` | Run service checks for a known service without port discovery. |
| `-vv` | Show more console detail. |
| `--accessible` | Use screen reader friendly console output. |

Run `autorecon --help` for the full option list.

## Docker

The Dockerfile builds this checkout using Kali tools. Mount a host results directory and pass `-o /results` so output persists outside the container:

```bash
docker build -t autorecon:local .
mkdir -p "$HOME/results"
docker run --rm --network host -v "$HOME/results:/results" autorecon:local autorecon -o /results --disable-keyboard-control 192.0.2.10
```

This example uses host networking on Linux. The container runs as root by default, so files written to the host results directory may be root-owned.

First-time `--ai` sign-in requires a browser and a loopback callback on `127.0.0.1`. Run `--ai` on the host unless you separately configure browser access and persistent authentication for the container.

## Local web portal

After `bash install.sh`, start the portal and open [http://127.0.0.1:8787](http://127.0.0.1:8787):

```bash
autorecon-portal --results-dir "$HOME/results"
```

The portal stays available independently of scans. It indexes existing `~/results/<target>/` folders, including scans started from another terminal with `autorecon -o "$HOME/results" TARGET`. New scans started in the portal have separate run folders under `~/results/portal-runs/`. The portal listens on your computer only. Connect ChatGPT with `autorecon-ai login` in a local terminal before enabling AI in the portal.

To run the portal as a user service after login:

```bash
mkdir -p "$HOME/.config/systemd/user"
cp autorecon/portal/autorecon-portal.service "$HOME/.config/systemd/user/"
systemctl --user daemon-reload
systemctl --user enable --now autorecon-portal.service
```

The service assumes pipx installed `autorecon-portal` in `~/.local/bin`; adjust `ExecStart` if your pipx app directory differs.

## Web proof checks

Default HTTP scans include bounded GET-parameter proof checks: server-side template expression evaluation and OS command injection. Each module uses nonce-tagged probes and requires two independent evaluations before reporting `confirmed`; an inconclusive result is not proof of safety. The plugin saves JSON evidence and a text summary in `scans/`.

Run the verifier for one origin without a full scan:

```bash
autorecon-proof --allow-origin http://192.0.2.10:8080 --output proof-evidence.json
```

Select specific modules (default: all):

```bash
autorecon-proof --allow-origin http://192.0.2.10:8080 --output proof-evidence.json --module ssti --module command-injection
```

Use `--proof-web-probes.manifest` during a scan to select exact URLs and parameters, `--proof-web-probes.modules` to select modules, or `--proof-web-probes.headers-file` for authenticated web headers. Run `autorecon-proof --help` for the standalone equivalents. Review evidence before sharing it.

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
