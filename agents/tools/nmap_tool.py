"""
nmap_tool — Nmap wrapper for LLM-driven agents.

Runs nmap as a subprocess, parses XML output, and returns structured port/service
data the LLM can reason about. Replaces the hardcoded analysis in network_module.py.
"""
import shutil
import subprocess
import logging
import xml.etree.ElementTree as ET
from typing import Optional

logger = logging.getLogger(__name__)

_DEFAULT_TIMEOUT = 300   # seconds — nmap can be slow on large ranges


def run_nmap(
    target:  str,
    ports:   str           = "1-1000",
    flags:   Optional[list]= None,
    timeout: int           = _DEFAULT_TIMEOUT,
) -> dict:
    """Run an Nmap scan and return open ports with service/version details."""
    if not shutil.which("nmap"):
        return {
            "error": "nmap is not installed or not in PATH. "
                     "Install nmap: https://nmap.org/download.html"
        }

    cmd = [
        "nmap",
        "-sV",           # service/version detection
        "-p", ports,
        "-oX", "-",      # XML output to stdout
        "--open",        # only show open ports
        target,
    ]
    if flags:
        # Insert extra flags before the target (last element)
        cmd = cmd[:-1] + flags + [cmd[-1]]

    logger.info(f"[NMAP] Running: {' '.join(cmd)}")
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return {"error": f"nmap timed out after {timeout}s", "target": target}
    except FileNotFoundError:
        return {"error": "nmap binary not found", "target": target}
    except Exception as e:
        return {"error": f"nmap execution failed: {e}", "target": target}

    if proc.returncode not in (0, 1):   # nmap exits 1 when no hosts up
        return {
            "error":      f"nmap exited {proc.returncode}",
            "stderr":     proc.stderr[:1000],
            "target":     target,
        }

    return _parse_xml(proc.stdout, target)


def _parse_xml(xml_text: str, target: str) -> dict:
    if not xml_text.strip():
        return {"target": target, "hosts": [], "error": "nmap returned no output"}

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as e:
        return {"target": target, "hosts": [], "error": f"XML parse error: {e}"}

    hosts = []
    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue

        # IP address
        addr_el = host.find("address[@addrtype='ipv4']")
        if addr_el is None:
            addr_el = host.find("address")
        ip = addr_el.get("addr", "") if addr_el is not None else ""

        # Hostname
        hn_el = host.find("hostnames/hostname")
        hostname = hn_el.get("name", "") if hn_el is not None else ""

        # OS (best guess)
        os_match = host.find("os/osmatch")
        os_guess = os_match.get("name", "") if os_match is not None else ""

        # Open ports
        ports = []
        for port in host.findall("ports/port"):
            state_el = port.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            service_el = port.find("service")
            ports.append({
                "port":     int(port.get("portid", 0)),
                "protocol": port.get("protocol", "tcp"),
                "service":  service_el.get("name", "") if service_el is not None else "",
                "product":  service_el.get("product", "") if service_el is not None else "",
                "version":  service_el.get("version", "") if service_el is not None else "",
                "extra":    service_el.get("extrainfo", "") if service_el is not None else "",
                "cpe":      _cpe(service_el),
            })

        hosts.append({
            "ip":       ip,
            "hostname": hostname,
            "os_guess": os_guess,
            "ports":    ports,
        })

    return {
        "target": target,
        "hosts":  hosts,
        "total_open_ports": sum(len(h["ports"]) for h in hosts),
        "error":  None,
    }


def _cpe(service_el) -> str:
    if service_el is None:
        return ""
    cpe_el = service_el.find("cpe")
    return cpe_el.text if cpe_el is not None else ""


run_nmap.__schema__ = {
    "name": "run_nmap",
    "description": (
        "Run an Nmap port scan with service/version detection against a target. "
        "Returns open ports, detected services, versions, and CPE identifiers. "
        "Use CPE or product/version info with search_cve to find known CVEs."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "IP address, hostname, or CIDR range to scan.",
            },
            "ports": {
                "type": "string",
                "description": "Port range (e.g. '1-1000', '80,443,8080', '-' for all). Default: '1-1000'.",
                "default": "1-1000",
            },
            "flags": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Extra nmap flags (e.g. ['-sS', '-T4', '--script=banner']). Use carefully.",
            },
            "timeout": {
                "type": "integer",
                "description": "Scan timeout in seconds (default 300).",
                "default": _DEFAULT_TIMEOUT,
            },
        },
        "required": ["target"],
    },
}
