# AutoRecon

This is a fork from https://github.com/AutoRecon/AutoRecon.git

## Prerequisites (Kali Linux)

AutoRecon calls external scanning tools. Install them once with `apt`; `pipx` and `bash install.sh` do not install these system packages. The command below includes `pipx`, which the installer requires.

```bash
sudo apt update
sudo apt install pipx seclists curl dnsrecon enum4linux feroxbuster gobuster impacket-scripts nbtscan nikto nmap onesixtyone oscanner redis-tools smbclient smbmap snmp sslscan sipvicious tnscmd10g whatweb
```

If you use the optional `ffuf` directory example or the manual Hydra example below, install those tools too:

```bash
sudo apt install ffuf hydra
```

## Install or update this fork

From a clone of this repository, run:

```bash
bash install.sh
```

After installing the prerequisites, the script installs this checkout with `pipx`, refreshes this fork's plugins in an existing AutoRecon installation, and downloads the latest `linpeas.sh` from the [official PEASS-ng release](https://github.com/peass-ng/PEASS-ng/releases/latest) into your user cache. Re-run `bash install.sh` after pulling repository updates to refresh AutoRecon and LinPEAS. The cached script is only used when you enable it for an authenticated scan.

## Example commands

Replace the example target, username, key, and wordlist paths with your own. Run scans only against systems you are authorized to assess.

### Start a scan

```bash
autorecon 192.0.2.10
autorecon -o ./results 192.0.2.10
autorecon --list plugins
```

### Evidence based web proof checks

The proof plugin automatically discovers GET inputs from up to 20 same-origin HTML pages linked within two hops of each web service root, then tests up to 20 inputs for server-side template expression evaluation. It sends one plain control value and two randomized arithmetic expressions, then marks a result **confirmed** only when both expressions evaluate in the response. This is a narrow check: an inconclusive result does not mean the endpoint is safe. It does not run commands, follow redirects, submit POST forms, or attempt browser-based XSS. Requests are limited to each service's exact scheme, host, and port.

Run a full AutoRecon scan without a manifest; results use AutoRecon's normal `results/` directory:

```bash
autorecon 192.0.2.10
```

To run only this verifier against one web origin, use:

```bash
autorecon-proof --allow-origin http://192.0.2.10:8080 --output proof-evidence.json
```

You can optionally select exact endpoints with a JSON manifest. Each URL must already contain the selected parameter:

```json
[
  {"url": "http://192.0.2.10:8080/search?q=test", "parameter": "q"}
]
```

Run the verifier with that manifest and inspect its JSON evidence and matching text summary:

```bash
autorecon-proof --manifest proof-targets.json \
  --allow-origin http://192.0.2.10:8080 \
  --output proof-evidence.json
```

For an authenticated web session, place request headers in an owner-only local JSON file and pass `--headers-file` (or `--proof-web-probes.headers-file` during a scan). For example, `{"Cookie": "session=..."}` or `{"Authorization": "Bearer ..."}`. The tool does not directly include these headers in evidence; review response excerpts in case the server echoed a secret. Do not put secrets directly in the manifest URL; other query values are used for requests but masked in the saved evidence.

To restrict the plugin during an AutoRecon scan, pass the same manifest. It selects entries that match each discovered HTTP service's exact origin. With or without a manifest, it writes `scans/tcpPORT/tcp_PORT_proof_web.json` plus a text summary under the target results directory. The text summary can participate in AutoRecon's optional `--ai` report:

```bash
autorecon 192.0.2.10 \
  --proof-web-probes.manifest proof-targets.json
```

Evidence contains payloads, response excerpts, and URL paths. Review it before sharing. Discovery is bounded to linked pages and GET inputs; JavaScript-generated routes and unlinked pages are not found automatically. Additional vulnerability verifiers are future stages; existing SSH host checks remain available separately below.

### Authenticated SSH checks

When AutoRecon finds SSH, this plugin collects host information if you supply both a username and private key. The target's SSH host key must already be trusted in your local `known_hosts` file.

```bash
autorecon 192.0.2.10 \
  --ssh-authenticated-host-checks.username audit \
  --ssh-authenticated-host-checks.identity-file ~/.ssh/audit_key
```

### Authenticated SSH scan with LinPEAS

Use the LinPEAS copy downloaded by `bash install.sh` with the `--linpeas` flag. AutoRecon saves readable plain text, the original output, and errors separately. LinPEAS has no time limit by default. To use your own script instead, pass `--ssh-authenticated-host-checks.linpeas-script /path/to/linpeas.sh`.

**Full scan with LinPEAS** (port discovery, service scans, authenticated SSH checks, and LinPEAS):

```bash
autorecon 192.168.1.30 --linpeas -u websec -i ~/.ssh/cs6035
```

To **rerun only LinPEAS** against an SSH service you already know is on port 22, use the dedicated command. It skips port discovery, Nmap service scans, and the built-in SSH host checks:

```bash
autorecon-linpeas 192.168.1.30 -u websec -i ~/.ssh/cs6035
```

For another SSH port, add `-p 2222`. To keep the results separate from previous scans, add `-o results/linpeas-rerun`.
Add `--ai` to this short command for the same automatic AI review workflow.

By default this rerun writes to `results/192.168.1.30/scans/tcp22/` and replaces the previous LinPEAS output files there.

Optional: limit LinPEAS to one section and set a 600-second time limit:

```bash
autorecon 192.0.2.10 \
  --linpeas -u audit -i ~/.ssh/audit_key \
  --ssh-authenticated-host-checks.linpeas-section system_information \
  --ssh-authenticated-host-checks.linpeas-timeout 600
```

### Optional AI report with your ChatGPT plan

This fork includes an optional `autorecon --ai` workflow and a separate `autorecon-ai` command for manual reports. A normal scan sends nothing to AI. Eligible ChatGPT Plus and Pro accounts can authorize the open-source [Sign in with ChatGPT](https://developers.openai.com/siwc/token-sharing-open-source) flow; this uses your plan allowance, with its usage limits, rather than an API key. OpenAI does not place these requests in your ChatGPT chat history. See the [OpenAI usage settings](https://chatgpt.com/#settings/Usage) to review or disconnect the app.

For the **automatic workflow**, run one command:

```bash
autorecon 192.168.1.30 --linpeas -u websec -i ~/.ssh/cs6035 --ai
```

If you have not signed in, AutoRecon opens the ChatGPT authorization page before scanning. It selects the first model available to your account; use `--ai-model MODEL_SLUG` if you want a specific model. As each scan finishes, AutoRecon saves its AI review in `results/192.168.1.30/report/ai-report-reviews.md`. After the target's scans finish, it writes the short final summary to `report/ai-report.md`. The redacted text sent to AI is saved in `report/ai-report-input.txt`. This mode transmits automatically without a manual preview. By default, target results use `scans/` for scan output and `report/` for reports; AutoRecon no longer creates empty `exploit/` or `loot/` folders.

The automatic mode uses up to 100 section requests per target by default; set `--ai-max-chunks N` to change the limit. If the limit or a ChatGPT plan limit is reached, completed reviews remain in `report/ai-report-reviews.md` and `report/ai-report.md` stays marked as in progress.

After `bash install.sh`, authorize AutoRecon in your browser and list the models available to your account:

```bash
autorecon-ai login
autorecon-ai status
autorecon-ai models
```

First create a **local-only preview** of exactly what the report command would send. It reads `.txt` and `.nmap` files from the target's `scans/` directory, excluding raw LinPEAS, error files, and files beginning with `_`. It masks common credential assignments and private-key blocks, but you must inspect the preview because scan output can contain other sensitive information.

```bash
autorecon-ai report results/192.0.2.10
less results/192.0.2.10/report/ai-report-input.txt
```

You can edit `report/ai-report-input.txt` to remove anything else you do not want to share. The submit command reads that saved preview, not the original scan files. Use a model slug from `autorecon-ai models`:

```bash
autorecon-ai report results/192.0.2.10 --model MODEL_SLUG --send
less results/192.0.2.10/report/ai-report.md
```

The final `report/ai-report.md` lists up to five important, actionable findings with source file and line references and a next step for each. Detailed per-scan reviews are saved separately in `report/ai-report-reviews.md`. Large files are split into labeled parts, with one AI request per part. One additional request consolidates the reviews. `--max-chunks` limits the number of section requests (24 by default). The command fails rather than silently dropping data. Use repeated `--file` options to choose specific files relative to the target results directory, or set a higher limit intentionally.

```bash
autorecon-ai report results/192.0.2.10 \
  --file scans/tcp22/tcp_22_ssh_authenticated_host_checks.txt \
  --file scans/tcp22/tcp_22_ssh_linpeas.txt

autorecon-ai report results/192.0.2.10 --model MODEL_SLUG --send

autorecon-ai logout
```

For the separate report command, `--send` is the step that transmits the saved preview. If your ChatGPT plan limit is reached, the command stops without switching to paid API billing. Credentials are stored with owner-only permissions under your user configuration directory, outside the repository.

The automatic mode is opt-in because scan output can contain sensitive information that the basic redaction may miss. Use the separate `autorecon-ai report` preview workflow above when you want to edit the input before sending it.

### Directory enumeration

The directory enumeration plugin runs when AutoRecon detects an HTTP service. It uses `feroxbuster` by default. Select another supported tool with:

```bash
autorecon 192.0.2.10 --dirbuster.tool gobuster
autorecon 192.0.2.10 --dirbuster.tool ffuf
```

### Brute force

AutoRecon writes suggested Hydra and Medusa commands to `results/<target>/scans/_manual_commands.txt`; it does not run them automatically. For an authorized SSH password test, a manual example is:

```bash
hydra -l audit -P /path/to/passwords.txt ssh://192.0.2.10
```

### Other useful options

```bash
# Scan selected TCP ports
autorecon 192.0.2.10 --ports T:22,80,443

# Increase console detail
autorecon -vv 192.0.2.10

# Run service checks against a known SSH service without port discovery
autorecon 192.0.2.10 --force-services tcp/22/ssh
```
