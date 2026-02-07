#!/usr/bin/env python3
"""
PromptIntel → Nova Rules Sync

Fetches threat intelligence from PromptIntel API and generates Nova Framework rules.
Supports both the Prompts feed (malicious samples) and Agent Feed (molt threat intel).

Usage:
    export PROMPTINTEL_API_KEY="ak_..."

    # Sync prompts (recommended - higher confidence)
    python sync.py prompts

    # Sync molt/agent-feed (threat intel with IOCs)
    python sync.py molt

    # Sync both
    python sync.py all

Author: Xavier Marrugat
License: MIT
Repository: https://github.com/xampla/promptintel-nova-sync
"""

import argparse
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# =============================================================================
# Configuration
# =============================================================================

API_BASE = "https://api.promptintel.novahunting.ai/api/v1"
USER_AGENT = "PromptIntel-Nova-Sync/1.0"
RULES_DIR = Path(__file__).parent / "rules"

# =============================================================================
# API Client
# =============================================================================


def api_get(endpoint: str, api_key: str, params: Optional[Dict] = None) -> Optional[Dict]:
    """Make authenticated GET request to PromptIntel API."""
    url = f"{API_BASE}{endpoint}"
    if params:
        url += "?" + "&".join(f"{k}={v}" for k, v in params.items())

    headers = {
        "Authorization": f"Bearer {api_key}",
        "User-Agent": USER_AGENT,
        "Accept": "application/json",
    }

    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        print(f"API error: {e.code} {e.reason}", file=sys.stderr)
        return None
    except urllib.error.URLError as e:
        print(f"Network error: {e.reason}", file=sys.stderr)
        return None


def fetch_prompts(api_key: str) -> List[Dict]:
    """Fetch all prompts with pagination."""
    all_prompts = []
    page = 1

    while True:
        result = api_get("/prompts", api_key, {"page": page, "limit": 50})
        if not result or not result.get("data"):
            break

        all_prompts.extend(result["data"])

        pagination = result.get("pagination", {})
        if page >= pagination.get("pages", 1):
            break
        page += 1

    return all_prompts


def fetch_molt(api_key: str) -> List[Dict]:
    """Fetch agent feed (molt) threats."""
    result = api_get("/agent-feed", api_key)
    if result and result.get("success"):
        return [item for item in result.get("data", []) if not item.get("revoked")]
    return []


# =============================================================================
# Nova Rule Generation Utilities
# =============================================================================


def sanitize_name(name: str) -> str:
    """Convert string to valid Nova rule name."""
    name = re.sub(r"[^a-zA-Z0-9]", "_", name)
    name = re.sub(r"_+", "_", name).strip("_")
    if name and not name[0].isalpha():
        name = "R_" + name
    return name[:50] or "UnnamedRule"


def short_hash(s: str) -> str:
    """Generate short hash for unique naming."""
    return hashlib.md5(s.encode()).hexdigest()[:8]


def escape_nova_string(s: str) -> str:
    """Escape string for Nova rule syntax."""
    return s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")


def is_ip(value: str) -> bool:
    """Check if a string looks like a bare IPv4 address."""
    return bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", value))


def extract_keywords(text: str) -> List[str]:
    """Extract common injection patterns from text."""
    patterns = [
        r"ignore\s+(all\s+)?(previous|above|earlier)\s+(instructions?|guidelines?|prompts?)",
        r"disregard\s+(all\s+)?(previous|above)",
        r"forget\s+(your\s+)?(instructions?|guidelines?)",
        r"you\s+are\s+now",
        r"act\s+as\s+",
        r"pretend\s+(to\s+be|you)",
        r"system\s*prompt",
        r"developer\s*mode",
        r"do\s+anything\s+now",
        r"DAN\s+mode",
        r"jailbreak",
        r"override\s+(all|previous)",
    ]

    found = []
    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            found.append(match.group(0).lower())

    return found[:10]


def extract_recommendation_keywords(recommendation: str, description: str) -> List[str]:
    """Extract actionable keywords from recommendation_agent and description fields.

    Pulls quoted strings, bracket-enclosed patterns, and Unix paths/commands
    that can serve as keyword matchers for rules that would otherwise be LLM-only.
    """
    combined = f"{recommendation} {description}"
    found = []

    # Quoted strings: "inner rules", 'system_override_granted'
    for match in re.finditer(r'["\']([^"\']{5,60})["\']', combined):
        found.append(match.group(1))

    # Bracket-enclosed patterns: [SYSTEM MESSAGE], [SYSTEM]
    for match in re.finditer(r'\[([A-Z][A-Z_ ]{2,30})\]', combined):
        found.append(match.group(0))

    # Unix-style paths with 2+ segments: /proc/self/environ, ~/.clawdbot/.env
    for match in re.finditer(r'(?:[~]|/)[a-zA-Z0-9_./-]+/[a-zA-Z0-9_./-]+', combined):
        found.append(match.group(0))

    # Deduplicate preserving order
    seen = set()
    unique = []
    for kw in found:
        if kw.lower() not in seen:
            seen.add(kw.lower())
            unique.append(kw)

    return unique[:10]


# =============================================================================
# Prompts Feed → Nova Rules
# =============================================================================


def prompt_to_nova(prompt: Dict) -> Optional[str]:
    """Convert a prompt sample to a Nova rule."""
    # Use pre-crafted rule if available (hand-tuned, higher quality)
    nova_rule = prompt.get("nova_rule", "")
    if nova_rule and nova_rule.strip():
        return nova_rule.strip() + "\n"

    prompt_id = prompt.get("id", "")
    title = prompt.get("title", "Unknown")
    text = prompt.get("prompt", "")
    severity = prompt.get("severity", "medium")
    categories = prompt.get("categories", [])
    threats = prompt.get("threats", [])
    author = prompt.get("author", "PromptIntel")
    refs = prompt.get("reference_urls", [])

    if not text:
        return None

    rule_name = sanitize_name(f"PI_{short_hash(prompt_id)}_{title[:30]}")
    category = "/".join(categories) if categories else "promptintel"
    threat_list = ", ".join(threats[:3]) if threats else "prompt injection"

    # Extract keywords from the malicious text
    keywords = extract_keywords(text)

    # Build meta section
    meta = [
        f'        description = "{escape_nova_string(title[:100])}"',
        f'        author = "{escape_nova_string(author)}"',
        f'        category = "{category}"',
        f'        severity = "{severity}"',
        f'        threats = "{escape_nova_string(threat_list)}"',
        f'        uuid = "{prompt_id}"',
        f'        source = "promptintel-prompts"',
        f'        promptintel_url = "https://promptintel.novahunting.ai/prompts/{prompt_id}"',
    ]
    if refs:
        meta.append(f'        reference = "{escape_nova_string(refs[0][:200])}"')

    sections = ["    meta:\n" + "\n".join(meta)]

    # Build keywords section
    if keywords:
        kw_defs = [f'        $kw{i} = "{escape_nova_string(k)}"' for i, k in enumerate(keywords, 1)]
        sections.append("    keywords:\n" + "\n".join(kw_defs))
        condition = "any of keywords.*"
    else:
        # Use first meaningful line as pattern
        first_line = text.split("\n")[0].strip()[:250]
        if len(first_line) > 10:
            sections.append(f'    keywords:\n        $pattern = "{escape_nova_string(first_line)}"')
            condition = "keywords.$pattern"
        else:
            return None  # Skip if no useful pattern

    # Add semantic matching only when we have regex-extracted keywords.
    # When using first-line $pattern fallback, semantics is near-identical text — redundant.
    if keywords and len(text) > 30:
        sem_threshold = {"critical": 0.4, "high": 0.4, "medium": 0.5}.get(severity, 0.6)
        semantic_text = escape_nova_string(text[:300].replace("\n", " ").strip())
        sections.append(f'    semantics:\n        $semantic = "{semantic_text}" ({sem_threshold})')
        condition = f"{condition} or semantics.$semantic"

    sections.append(f"    condition:\n        {condition}")

    return f"rule {rule_name}\n{{\n" + "\n\n".join(sections) + "\n}\n"


# =============================================================================
# Molt Feed → Nova Rules
# =============================================================================


def molt_to_nova(item: Dict) -> Optional[str]:
    """Convert a molt threat intel item to a Nova rule."""
    item_id = item.get("id", "")
    title = item.get("title", "Unknown")
    description = item.get("description", "")
    severity = item.get("severity", "high")
    category = item.get("category", "threat")
    confidence = item.get("confidence", 0.7)
    action = item.get("action", "block")
    recommendation = item.get("recommendation_agent", "")
    iocs = item.get("iocs") or []
    source_url = item.get("source", "")
    expires_at = item.get("expires_at", "")
    fingerprint = item.get("fingerprint", "")

    rule_name = sanitize_name(f"Molt_{short_hash(item_id)}_{title[:25]}")

    # Build meta section
    meta = [
        f'        description = "{escape_nova_string(f"{title}. {description[:120]}")}"',
        f'        author = "PromptIntel Molt"',
        f'        category = "threat/{category}"',
        f'        severity = "{severity}"',
        f'        confidence = "{confidence}"',
        f'        action = "{action}"',
        f'        uuid = "{item_id}"',
        f'        fingerprint = "{fingerprint}"',
        f'        source = "promptintel-molt"',
        f'        promptintel_url = "https://promptintel.novahunting.ai/molt/{item_id}"',
    ]
    if source_url:
        meta.append(f'        reference = "{escape_nova_string(source_url[:200])}"')
    if expires_at:
        meta.append(f'        expires_at = "{expires_at}"')

    sections = ["    meta:\n" + "\n".join(meta)]

    # Build keywords from IOCs
    ioc_keywords = []
    for ioc in iocs[:15]:
        if isinstance(ioc, dict):
            value = ioc.get("value", "")
        elif isinstance(ioc, str):
            try:
                value = json.loads(ioc).get("value", ioc)
            except:
                value = ioc
        else:
            continue

        if value and 3 < len(str(value)) < 200:
            ioc_keywords.append(str(value))

    # When no IOCs, extract keywords from recommendation/description text
    if not ioc_keywords and recommendation:
        ioc_keywords = extract_recommendation_keywords(recommendation, description)

    if ioc_keywords:
        kw_defs = []
        for i, k in enumerate(ioc_keywords, 1):
            if is_ip(k):
                escaped_ip = k.replace(".", "\\.")
                kw_defs.append(f"        $ioc{i} = /\\b{escaped_ip}\\b/")
            else:
                kw_defs.append(f'        $ioc{i} = "{escape_nova_string(k)}"')
        sections.append("    keywords:\n" + "\n".join(kw_defs))

    # Build LLM section from recommendation_agent
    if recommendation:
        llm_prompt = escape_nova_string(recommendation[:500])
        sections.append(f'    llm:\n        $recommendation = "{llm_prompt}" (0.1)')

    # Build condition
    conditions = []
    if ioc_keywords:
        conditions.append("any of keywords.*")
    if recommendation:
        conditions.append("llm.$recommendation")

    if not conditions:
        return None

    sections.append(f"    condition:\n        {' or '.join(conditions)}")

    return f"rule {rule_name}\n{{\n" + "\n\n".join(sections) + "\n}\n"


# =============================================================================
# Main
# =============================================================================


def extract_rule_name(rule_text: str) -> str:
    """Extract rule name from the first line of a Nova rule."""
    match = re.match(r"rule\s+(\S+)", rule_text)
    return match.group(1) if match else f"Rule_{short_hash(rule_text)}"


def generate_header(source: str, count: int) -> str:
    """Generate file header."""
    return f"""# PromptIntel Nova Rules
#
# Auto-generated by promptintel-nova-sync
# Source: {source}
# Generated: {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")}
# Total rules: {count}
#
# Repository: https://github.com/xampla/promptintel-nova-sync
# PromptIntel: https://promptintel.novahunting.ai
# Nova Framework: https://github.com/Nova-Hunting/nova-framework

"""


def main():
    parser = argparse.ArgumentParser(
        description="Sync PromptIntel threat intel to Nova rules",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "source",
        choices=["prompts", "molt", "all"],
        help="Data source: prompts (samples), molt (threat intel), or all",
    )
    parser.add_argument(
        "--api-key",
        default=os.environ.get("PROMPTINTEL_API_KEY", ""),
        help="PromptIntel API key (or set PROMPTINTEL_API_KEY)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=RULES_DIR,
        help="Output directory for .nov files",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print rules without writing files",
    )

    args = parser.parse_args()

    if not args.api_key:
        print("Error: No API key. Set PROMPTINTEL_API_KEY or use --api-key", file=sys.stderr)
        sys.exit(1)

    args.output_dir.mkdir(parents=True, exist_ok=True)

    # Process prompts feed
    if args.source in ("prompts", "all"):
        print("Fetching prompts from PromptIntel...", file=sys.stderr)
        prompts = fetch_prompts(args.api_key)
        print(f"  Found {len(prompts)} prompts", file=sys.stderr)

        rules = [r for r in (prompt_to_nova(p) for p in prompts) if r]
        print(f"  Generated {len(rules)} rules", file=sys.stderr)

        if rules:
            if args.dry_run:
                for rule in rules:
                    print(rule)
            else:
                out_dir = args.output_dir / "promptintel"
                out_dir.mkdir(parents=True, exist_ok=True)
                for rule in rules:
                    name = extract_rule_name(rule)
                    (out_dir / f"{name}.nov").write_text(rule, encoding="utf-8")
                print(f"  Wrote {len(rules)} rules to {out_dir}/", file=sys.stderr)

    # Process molt feed
    if args.source in ("molt", "all"):
        print("Fetching molt feed from PromptIntel...", file=sys.stderr)
        molt = fetch_molt(args.api_key)
        print(f"  Found {len(molt)} threats", file=sys.stderr)

        rules = [r for r in (molt_to_nova(m) for m in molt) if r]
        print(f"  Generated {len(rules)} rules", file=sys.stderr)

        if rules:
            if args.dry_run:
                for rule in rules:
                    print(rule)
            else:
                out_dir = args.output_dir / "moltthreats"
                out_dir.mkdir(parents=True, exist_ok=True)
                for rule in rules:
                    name = extract_rule_name(rule)
                    (out_dir / f"{name}.nov").write_text(rule, encoding="utf-8")
                print(f"  Wrote {len(rules)} rules to {out_dir}/", file=sys.stderr)

    print("Done!", file=sys.stderr)


if __name__ == "__main__":
    main()
