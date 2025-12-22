#!/usr/bin/env python3
"""
Generate template files (like data/templates/*) via LLM.

Features:
- Uses Azure OpenAI (env-driven) to generate realistic, syntax-correct templates.
- Supports predefined specs and custom specs via CLI flags.
- Avoids Markdown/code fences; strips refusals; ensures output not empty.
"""

from __future__ import annotations

import argparse
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Sequence

from openai import AzureOpenAI


# ------------------ Config ------------------

API_CONFIG = {
    "api_key": os.getenv("AZURE_OPENAI_API_KEY") or os.getenv("AZURE_OPENAI_KEY", "your_azure_openai_key"),
    "azure_endpoint": os.getenv("AZURE_OPENAI_ENDPOINT", "https://your-resource.openai.azure.com"),
    "api_version": os.getenv("AZURE_OPENAI_API_VERSION", "2024-12-01-preview"),
    "deployment": os.getenv("AZURE_OPENAI_DEPLOYMENT", "gpt-4o"),
}


@dataclass
class TemplateSpec:
    filename: str
    description: str
    requirements: Optional[str] = None  # extra constraints or examples


DEFAULT_SPECS: List[TemplateSpec] = [
    TemplateSpec("nginx_misconfig.conf", "Nginx server block with autoindex enabled and commented warnings."),
    TemplateSpec("vulnerable_flask_app.py", "Small Flask app with SQL injection in a query endpoint; runnable."),
    TemplateSpec("shadow_weak.txt", "Linux shadow-like entries with weak hashes (demo values)."),
    TemplateSpec("ftp_config.ini", "FTP connection config with host/port/user/pass and secure flags."),
    TemplateSpec("audit_log_sample.log", "System auth/audit log with timestamps and security events."),
    TemplateSpec("finance_report.csv", "CSV of financial metrics with headers and 3-5 rows."),
    TemplateSpec("db_schema.sql", "SQL schema with users/reports tables; includes CREATE TABLE statements."),
    TemplateSpec("sudoers", "Weak sudoers config with Defaults, Cmnd_Alias, and overly broad admin group."),
    TemplateSpec("passwd", "Linux passwd-like entries (demo values) matching shadow_weak users."),
    TemplateSpec("cron_backup.sh", "Shell script for nightly backup with hardcoded creds (weak), runnable."),
    TemplateSpec("sshd_config_weak", "OpenSSH config with weak settings (PermitRootLogin yes, PasswordAuthentication yes)."),
    TemplateSpec("cron.allow", "cron.allow sample allowing a few users; comment lines included."),
    TemplateSpec("cron.d/sample_job", "cron.d style entry running a periodic task with env and user specified."),
    TemplateSpec("resolv.conf", "DNS resolver config with search/domain and multiple nameservers."),
    TemplateSpec("hosts", "Sample /etc/hosts with localhost, IPv6 entries, and a couple of custom mappings."),
    TemplateSpec("aws_credentials", "AWS shared credentials file with multiple profiles and access keys."),
    TemplateSpec("aws_config", "AWS config file with region/output per profile; includes default and a profile."),
    TemplateSpec("gcp_service_account.json", "GCP service account key JSON with client_email/private_key."),
    TemplateSpec("azure_credentials", "Azure CLI-style credentials with tenant, subscription, client secrets."),
    TemplateSpec("kube_config", "Kubeconfig with multiple contexts/users/clusters, one using token auth."),
    TemplateSpec("ssh_config", "User ssh config with weak settings and proxyjump; includes IdentityFile."),
    TemplateSpec("authorized_keys", "authorized_keys sample with a couple of keys and command options."),
    TemplateSpec("known_hosts", "known_hosts entries for a few hosts with hashed and plain hostnames."),
    TemplateSpec("dockerconfig.json", "Docker registry auth config with auths and a plaintext token."),
    TemplateSpec(".npmrc", "npmrc with registry and an auth token (always-auth), plus proxy settings."),
    TemplateSpec(".pypirc", "pypirc with index servers and a token-based password."),
    TemplateSpec("proxychains.conf", "Proxychains config with socks4/socks5/http entries and chain types."),
    TemplateSpec("torrc", "Tor config snippet with SocksPort and a couple of ExitNodes."),
    TemplateSpec("curlrc", "curlrc with proxy, user credentials, and insecure setting."),
    TemplateSpec("auditd.conf", "auditd config with high max_log_file and lax space actions."),
    TemplateSpec("audit.rules", "audit rules covering auth, sudo, and key files, with a permissive example."),
    TemplateSpec("fail2ban.conf", "Fail2ban main config with weak bantime/findtime settings."),
    TemplateSpec("fail2ban.local", "Fail2ban override with jails toggled and low ban thresholds."),
    TemplateSpec("rsyslog.conf", "rsyslog config with default rules and a remote log forwarding target."),
    TemplateSpec("logrotate.conf", "logrotate config with weekly rotation and custom size/keep settings."),
    TemplateSpec("systemd_unit.service", "Systemd unit with Environment variables containing secrets."),
    TemplateSpec("supervisord.conf", "Supervisord config managing a couple of programs with env vars."),
    TemplateSpec("docker_compose.yaml", "Compose file with web + db services, weak passwords, exposed ports."),
    TemplateSpec("s3_policy.json", "Overly permissive S3 bucket policy (allow * actions from 0.0.0.0/0)."),
    TemplateSpec("iptables_rules.txt", "iptables filter table rules allowing broad access; include COMMIT."),
    TemplateSpec("app_env.env", "Env file with DB creds/API keys; simple KEY=VALUE format."),
    TemplateSpec("cloud_sql_dump.sql", "Partial SQL dump with INSERT rows for users and logs."),
    TemplateSpec("k8s_deploy.yaml", "Kubernetes Deployment manifest with 1 container, liveness probe, and env vars."),
    TemplateSpec("docker_compose.yaml", "Compose file with web + db services, weak passwords, exposed ports."),
]

REFUSAL_PATTERNS = [
    "i'm sorry",
    "cannot assist",
    "can't assist",
    "as an ai",
    "cannot help",
    "not able to help",
]


# ------------------ LLM Wrapper ------------------

class LLM:
    def __init__(self):
        if not API_CONFIG["api_key"] or "your_azure_openai_key" in API_CONFIG["api_key"]:
            raise RuntimeError("missing AZURE_OPENAI_API_KEY")
        if not API_CONFIG["azure_endpoint"] or "your-resource" in API_CONFIG["azure_endpoint"]:
            raise RuntimeError("missing AZURE_OPENAI_ENDPOINT")
        self.client = AzureOpenAI(
            api_key=API_CONFIG["api_key"],
            azure_endpoint=API_CONFIG["azure_endpoint"],
            api_version=API_CONFIG["api_version"],
        )
        self.deployment = API_CONFIG["deployment"]

    def generate(self, spec: TemplateSpec) -> str:
        system = (
            "You write realistic configuration/code/data templates for security simulations. "
            "Output raw file content only, no Markdown fences or commentary. "
            "Ensure syntax validity for the target format."
        )
        user = (
            f"Filename: {spec.filename}\n"
            f"Goal: {spec.description}\n"
            f"Requirements: {spec.requirements or 'Be concise and runnable/parseable.'}\n"
            "Avoid placeholders like TODO/<>; use plausible values."
        )
        resp = self.client.chat.completions.create(
            model=self.deployment,
            messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
            temperature=0.4,
        )
        text = (resp.choices[0].message.content or "").strip()
        text = strip_code_fence(text)
        if is_refusal(text):
            raise RuntimeError(f"LLM refusal for {spec.filename}: {text[:80]}")
        return text


# ------------------ Helpers ------------------

def strip_code_fence(text: str) -> str:
    if text.startswith("```"):
        text = text.strip("`")
        text = text.replace("json", "", 1).strip()
    if text.endswith("```"):
        text = text[:-3]
    return text.strip()


def is_refusal(text: str) -> bool:
    lowered = text.lower()
    return any(pat in lowered for pat in REFUSAL_PATTERNS)


def write_template(path: Path, content: str, overwrite: bool) -> None:
    if path.exists() and not overwrite:
        print(f"[skip] {path} exists (use --overwrite to replace)")
        return
    path.write_text(content, encoding="utf-8")
    print(f"[ok] wrote {path}")


def run(
    specs: Sequence[TemplateSpec],
    output_dir: Path,
    overwrite: bool,
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    llm = LLM()
    for spec in specs:
        try:
            content = llm.generate(spec)
            if not content:
                raise RuntimeError("empty content")
            write_template(output_dir / spec.filename, content, overwrite)
        except Exception as exc:
            print(f"[fail] {spec.filename}: {exc}")


def parse_specs_from_args(args: argparse.Namespace) -> List[TemplateSpec]:
    if not args.spec:
        return DEFAULT_SPECS
    specs: List[TemplateSpec] = []
    for item in args.spec:
        if ":" in item:
            filename, desc = item.split(":", 1)
        else:
            filename, desc = item, "Generated template"
        specs.append(TemplateSpec(filename.strip(), desc.strip()))
    return specs


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Generate template files via LLM.")
    parser.add_argument(
        "--output-dir",
        default="data/templates",
        help="Directory to write templates (default: data/templates)",
    )
    parser.add_argument(
        "--spec",
        action="append",
        help="Custom spec as 'filename:description'. Can repeat.",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite existing files.",
    )
    args = parser.parse_args(argv)
    specs = parse_specs_from_args(args)
    output_dir = Path(args.output_dir)
    try:
        run(specs, output_dir, args.overwrite)
    except RuntimeError as exc:
        print(f"Error: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
