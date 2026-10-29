# AutoRecon

This is a fork from https://github.com/AutoRecon/AutoRecon.git

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

Download `linpeas.sh` to your scanning machine, then provide its local path. AutoRecon saves readable plain text, the original output, and errors separately.

```bash
autorecon 192.0.2.10 \
  --ssh-authenticated-host-checks.username audit \
  --ssh-authenticated-host-checks.identity-file ~/.ssh/audit_key \
  --ssh-authenticated-host-checks.linpeas-script /path/to/linpeas.sh
```

Limit LinPEAS to one section and allow up to 600 seconds:

```bash
autorecon 192.0.2.10 \
  --ssh-authenticated-host-checks.username audit \
  --ssh-authenticated-host-checks.identity-file ~/.ssh/audit_key \
  --ssh-authenticated-host-checks.linpeas-script /path/to/linpeas.sh \
  --ssh-authenticated-host-checks.linpeas-section system_information \
  --ssh-authenticated-host-checks.linpeas-timeout 600
```

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
