"""Normalization of signature-scanner (nuclei) output into AutoRecon evidence.

Signature matches are detections, not proofs: they are normalized with
status 'matched' and must never be presented as 'confirmed'. The
confirmation bridge re-runs a matched finding's input through the proof
module for its class and upgrades it only on a deterministic confirmation.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit, urlunsplit


def parse_nuclei_jsonl(path):
    """Parse nuclei -jsonl output into normalized finding dicts.

    Dedupes by (template-id, matched-at) and tolerates missing fields.
    """
    findings = []
    seen = set()
    with open(path, encoding='utf8', errors='replace') as source:
        for line in source:
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except ValueError:
                continue
            if not isinstance(item, dict):
                continue
            template_id = item.get('template-id') or item.get('id') or ''
            matched = item.get('matched-at') or item.get('host') or ''
            if not template_id and not matched:
                continue
            key = (template_id, matched)
            if key in seen:
                continue
            seen.add(key)
            info = item.get('info') if isinstance(item.get('info'), dict) else {}
            classification = info.get('classification') if isinstance(info.get('classification'), dict) else {}
            cwe = classification.get('cwe-id')
            if isinstance(cwe, list):
                cwe = cwe[0] if cwe else None
            reference = info.get('reference')
            if isinstance(reference, list):
                reference = reference[:5]
            findings.append({
                'schema_version': 2,
                'module': 'signature',
                'check': template_id or 'signature',
                'severity': str(info.get('severity') or 'info').lower(),
                'cwe': cwe,
                'status': 'matched',
                'url': matched,
                'parameter': None,
                'matched_at': matched,
                'template_id': template_id,
                'name': info.get('name'),
                'description': info.get('description'),
                'reference': reference,
                'cve': classification.get('cve-id'),
                'cvss_score': classification.get('cvss-score'),
                'tags': item.get('tags'),
                'tested_at': datetime.now(timezone.utc).isoformat(),
            })
    return findings


def write_signatures_json(path, findings):
    from autorecon.proofmodules.http import write_private_text
    payload = {'schema_version': 2, 'generator': 'signature-scan', 'findings': findings}
    write_private_text(path, json.dumps(payload, indent=2) + '\n')
    return path


def load_signatures(root):
    """Load normalized signature findings from every *_signatures.json under scans."""
    scans = Path(root).expanduser().resolve() / 'scans'
    if not scans.is_dir():
        return []
    findings = []
    for path in sorted(scans.rglob('*_signatures.json')):
        if not path.is_file():
            continue
        try:
            data = json.loads(path.read_text(encoding='utf8'))
        except (OSError, ValueError):
            continue
        for finding in data.get('findings', []):
            if isinstance(finding, dict):
                item = dict(finding)
                item.setdefault('evidence_file', str(path.relative_to(scans.parent)))
                findings.append(item)
    return findings


# Template tags / template-id keywords -> proof module that can confirm the class.
BRIDGE_MAP = (
    (('sqli', 'sql-injection'), 'sqli'),
    (('rce', 'command-injection', 'cmdi'), 'command-injection'),
    (('ssti', 'template-injection'), 'ssti'),
    (('lfi', 'path-traversal', 'file-inclusion'), 'lfi'),
    (('ssrf',), 'ssrf'),
    (('xxe',), 'xxe'),
)

# Values containing these substrings are likely the injected payload position.
PAYLOAD_MARKERS = ("'", '"', '`', '../', '{{', '$(', 'http://', 'https://',
                   '%27', '%22', '%2e', '%24', '%7b')


def bridge_module(finding):
    """Map a matched finding to the proof module for its class, or None."""
    tags = set(str(tag).lower() for tag in (finding.get('tags') or []) if tag)
    template_id = (finding.get('template_id') or '').lower()
    for keys, module in BRIDGE_MAP:
        if any(key in tags or key in template_id for key in keys):
            return module
    return None


def candidate_parameter(matched_url):
    """Pick the query parameter most likely to be the injection point."""
    parts = urlsplit(matched_url)
    if parts.scheme not in ('http', 'https') or not parts.query:
        return None
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    if not pairs:
        return None
    for name, value in pairs:
        if any(marker in value for marker in PAYLOAD_MARKERS):
            return name
    return pairs[0][0]


def bridge_findings(findings, output_path, oob=None, oob_timeout=10.0, limit=10):
    """Re-run matched findings through their class's proof module.

    Findings whose input confirms are upgraded in place to status
    'confirmed' with bridge_module/bridge_evidence recorded; everything
    else is left untouched as 'matched'.
    """
    from autorecon.proof import run_entries
    upgraded = 0
    for finding in findings:
        if upgraded >= limit:
            break
        if finding.get('status') != 'matched':
            continue
        matched = finding.get('matched_at') or finding.get('url') or ''
        module = bridge_module(finding)
        parameter = candidate_parameter(matched)
        if not module or not parameter:
            continue
        parts = urlsplit(matched)
        origin = urlunsplit((parts.scheme, parts.netloc, '', '', ''))
        entry = {'url': matched, 'parameter': parameter}
        try:
            result = run_entries([entry], origin, output_path, timeout=8,
                                 modules=[module], oob=oob, oob_timeout=oob_timeout)
        except (ValueError, OSError):
            continue
        if result['findings'] and result['findings'][0]['status'] == 'confirmed':
            finding['status'] = 'confirmed'
            finding['bridge_module'] = module
            finding['bridge_evidence'] = Path(output_path).name
            upgraded += 1
    return findings
