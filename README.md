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

After installing the prerequisites, the script installs this checkout with `pipx`, refreshes the SSH plugin in an existing AutoRecon installation, and downloads the latest `linpeas.sh` from the [official PEASS-ng release](https://github.com/peass-ng/PEASS-ng/releases/latest) into your user cache. Re-run `bash install.sh` after pulling repository updates to refresh AutoRecon and LinPEAS. The cached script is only used when you enable it for an authenticated scan.

## Example commands

Replace the example target, username, key, and wordlist paths with your own. Run scans only against systems you are authorized to assess.

### Start a scan

```bash
autorecon 192.0.2.10
autorecon -o ./results 192.0.2.10
autorecon --list plugins
```

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

If you have not signed in, AutoRecon opens the ChatGPT authorization page before scanning. It selects the first model available to your account; use `--ai-model MODEL_SLUG` if you want a specific model. As each scan finishes, AutoRecon sends its completed text output for a separate AI review and appends the review to `results/192.168.1.30/ai-report.md`. After the target's scans finish, it reviews any remaining text files and adds a consolidated summary to that same report. The redacted text sent to AI is also saved in `ai-report-input.txt`. This mode transmits automatically without a manual preview.

The automatic mode uses up to 100 section requests per target by default; set `--ai-max-chunks N` to change the limit. If the limit or a ChatGPT plan limit is reached, completed reviews remain in the report and the final summary is not written.

After `bash install.sh`, authorize AutoRecon in your browser and list the models available to your account:

```bash
autorecon-ai login
autorecon-ai status
autorecon-ai models
```

First create a **local-only preview** of exactly what the report command would send. It reads `.txt` and `.nmap` files from the target's `scans/` directory, excluding raw LinPEAS, error files, and files beginning with `_`. It masks common credential assignments and private-key blocks, but you must inspect the preview because scan output can contain other sensitive information.

```bash
autorecon-ai report results/192.0.2.10
less results/192.0.2.10/ai-report-input.txt
```

You can edit `ai-report-input.txt` to remove anything else you do not want to share. The submit command reads that saved preview, not the original scan files. Use a model slug from `autorecon-ai models`:

```bash
autorecon-ai report results/192.0.2.10 --model MODEL_SLUG --send
less results/192.0.2.10/ai-report.md
```

The report has a **Consolidated findings** section followed by a **Scan reviews** section for each selected scan file. Large files are split into labeled parts, with one AI request per part. One additional request consolidates the reviews. `--max-chunks` limits the number of section requests (24 by default). The command fails rather than silently dropping data. Use repeated `--file` options to choose specific files relative to the target results directory, or set a higher limit intentionally. Each review asks for source file and line references so you can verify findings in the original output.

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
