"""
prowler_tool — Prowler wrapper for LLM-driven agents.

Runs Prowler as a subprocess with JSON output and returns structured cloud
security findings. Replaces cloud_module.py (including its 6 hardcoded mock findings).

Prowler v3+ required:
    pip install prowler
    or
    prowler --version
"""
import json
import shutil
import subprocess
import logging
import tempfile
import os
from typing import Optional

logger = logging.getLogger(__name__)

_DEFAULT_TIMEOUT = 1200   # 20 min — AWS full audits can take a while
_VALID_PROVIDERS = {"aws", "azure", "gcp", "kubernetes"}


def run_prowler(
    provider: str          = "aws",
    profile:  Optional[str]= None,
    region:   Optional[str]= None,
    checks:   Optional[list]= None,
    services: Optional[list]= None,
    severity: Optional[str] = None,
    timeout:  int           = _DEFAULT_TIMEOUT,
) -> dict:
    """Run a Prowler cloud security audit and return structured findings."""
    if not shutil.which("prowler"):
        return {
            "error": "prowler is not installed or not in PATH. "
                     "Install: pip install prowler  or  brew install prowler"
        }

    provider = provider.lower()
    if provider not in _VALID_PROVIDERS:
        return {
            "error": f"Invalid provider '{provider}'. "
                     f"Must be one of: {_VALID_PROVIDERS}"
        }

    with tempfile.TemporaryDirectory() as tmpdir:
        out_file = os.path.join(tmpdir, "prowler_output")

        cmd = [
            "prowler", provider,
            "-o", tmpdir,
            "--output-filename", "prowler_output",
            "-M", "json",
            "--no-banner",
            "--ignore-exit-code-3",
        ]

        if profile:
            cmd += ["--profile", profile]
        if region:
            cmd += ["-f", region]
        if checks:
            cmd += ["-c", ",".join(checks)]
        if services:
            cmd += ["-s", ",".join(services)]
        if severity:
            cmd += ["--severity", severity]

        logger.info(f"[PROWLER] Running: {' '.join(cmd)}")
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            return {"error": f"prowler timed out after {timeout}s",
                    "provider": provider}
        except Exception as e:
            return {"error": f"prowler execution failed: {e}", "provider": provider}

        # Prowler exits 3 when there are FAIL findings (normal), 0 for all PASS
        if proc.returncode not in (0, 3):
            return {
                "error":    f"prowler exited {proc.returncode}",
                "stderr":   proc.stderr[:2000],
                "provider": provider,
            }

        # Locate the JSON output file (Prowler appends a timestamp)
        json_path = _find_json(tmpdir, "prowler_output")
        if not json_path:
            return {
                "error":    "prowler ran but produced no JSON output file",
                "stdout":   proc.stdout[:1000],
                "provider": provider,
            }

        with open(json_path, encoding="utf-8") as f:
            raw = f.read()

    findings = _parse_json(raw)
    failed   = [f for f in findings if f.get("status") == "FAIL"]
    passed   = len(findings) - len(failed)

    return {
        "provider":       provider,
        "total_checks":   len(findings),
        "total_fail":     len(failed),
        "total_pass":     passed,
        "findings":       failed,   # LLM only needs failures
        "error":          None,
    }


def _find_json(directory: str, prefix: str) -> Optional[str]:
    for name in os.listdir(directory):
        if name.startswith(prefix) and name.endswith(".json"):
            return os.path.join(directory, name)
    return None


def _parse_json(raw: str) -> list:
    try:
        data = json.loads(raw)
        if isinstance(data, list):
            items = data
        elif isinstance(data, dict):
            items = data.get("findings", [data])
        else:
            return []
    except json.JSONDecodeError:
        # Prowler sometimes outputs JSONL
        items = []
        for line in raw.splitlines():
            line = line.strip()
            if line:
                try:
                    items.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

    results = []
    for item in items:
        results.append({
            "check_id":    item.get("CheckID") or item.get("check_id", ""),
            "check_title": item.get("CheckTitle") or item.get("check_title", ""),
            "service":     item.get("ServiceName") or item.get("service_name", ""),
            "severity":    item.get("Severity") or item.get("severity", ""),
            "status":      item.get("Status") or item.get("status", ""),
            "resource":    item.get("ResourceId") or item.get("resource_id", ""),
            "region":      item.get("Region") or item.get("region", ""),
            "description": (item.get("Description") or item.get("description", ""))[:400],
            "remediation": _get_remediation(item),
            "risk":        (item.get("Risk") or item.get("risk", ""))[:300],
        })
    return results


def _get_remediation(item: dict) -> str:
    rem = item.get("Remediation") or item.get("remediation", "")
    if isinstance(rem, dict):
        return rem.get("Recommendation", {}).get("Text", str(rem))[:300]
    return str(rem)[:300]


run_prowler.__schema__ = {
    "name": "run_prowler",
    "description": (
        "Run a Prowler cloud security audit for AWS, Azure, GCP, or Kubernetes. "
        "Returns FAIL findings — misconfigurations, compliance violations, and "
        "exposed resources. Use checks or services to scope the audit."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "provider": {
                "type": "string",
                "enum": sorted(_VALID_PROVIDERS),
                "description": "Cloud provider to audit (default: 'aws').",
                "default": "aws",
            },
            "profile": {
                "type": "string",
                "description": "AWS CLI profile name (AWS only). Uses default credentials if omitted.",
            },
            "region": {
                "type": "string",
                "description": "Cloud region to audit (e.g. 'us-east-1'). Audits all regions if omitted.",
            },
            "checks": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Specific Prowler check IDs to run (e.g. ['s3_bucket_public_access', 'iam_root_hardware_mfa_enabled']).",
            },
            "services": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Limit audit to these cloud services (e.g. ['s3', 'iam', 'ec2']).",
            },
            "severity": {
                "type": "string",
                "description": "Only return findings at this severity or above (e.g. 'high').",
            },
            "timeout": {
                "type": "integer",
                "description": "Audit timeout in seconds (default 1200 / 20 min).",
                "default": _DEFAULT_TIMEOUT,
            },
        },
        "required": ["provider"],
    },
}
