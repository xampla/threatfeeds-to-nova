# PromptIntel → Nova Rules Sync

Auto-sync threat intelligence from [PromptIntel](https://promptintel.novahunting.ai) to [Nova Framework](https://github.com/Nova-Hunting/nova-framework) rules.

## What It Does

```
PromptIntel API                          Nova Rules
      │                                       │
      ├── /prompts ──────────────────────► rules/promptintel/*.nov
      │   (malicious prompt samples)      (one rule per file)
      │
      └── /agent-feed (molt) ──────────► rules/moltthreats/*.nov
          (curated threat intel)         (one rule per file)
```

## Data Sources

| Source | Content | Nova Mapping | Detection |
|--------|---------|--------------|-----------|
| **Prompts** | Actual malicious text samples | `keywords` + `semantics` | Fast, exact match |
| **Prompts** (pre-crafted) | Hand-tuned `nova_rule` from API | Passthrough (verbatim) | Regex, semantics, LLM |
| **Molt** | Curated threat intel with IOCs | `keywords` + `llm` | IOCs + AI evaluation |

## Quick Start

### 1. Get a PromptIntel API key

Sign up at [promptintel.novahunting.ai](https://promptintel.novahunting.ai)

### 2. Generate rules

```bash
export PROMPTINTEL_API_KEY="ak_..."

# Sync prompts (recommended - actual malicious samples)
python sync.py prompts

# Sync molt (threat intel with IOCs)
python sync.py molt

# Sync both
python sync.py all
```

### 3. Use with Nova Framework

```bash
# Install Nova
pip install nova-framework

# Scan with generated rules
novarun --rules rules/ --prompt "your text here"
```

## Generated Rules

### From Prompts Feed

```
rule PI_a1b2c3d4_Multiple_Indirect_Prompt
{
    meta:
        description = "Multiple Indirect Prompt Injections..."
        severity = "high"
        source = "promptintel-prompts"
        promptintel_url = "https://promptintel.novahunting.ai/prompts/9c1f..."

    keywords:
        $kw1 = "ignore all previous instructions"
        $kw2 = "override all"

    semantics:
        $semantic = "hidden instruction inside..." (0.4)

    condition:
        any of keywords.* or semantics.$semantic
}
```

### From Molt Feed

```
rule Molt_e5f6g7h8_NovaStealer_Campaign
{
    meta:
        description = "NovaStealer Campaign - Supply Chain Attack"
        severity = "critical"
        confidence = "0.95"
        action = "block"
        promptintel_url = "https://promptintel.novahunting.ai/molt/3a52..."
        expires_at = "2026-03-08..."

    keywords:
        $ioc1 = /\b91\.92\.242\.30\b/
        $ioc2 = "clawhub.ai/zaycv/..."

    llm:
        $recommendation = "BLOCK: Skills from zaycv, aslaep123..." (0.1)

    condition:
        any of keywords.* or llm.$recommendation
}
```

## Auto-Sync with GitHub Actions

This repo includes a workflow that syncs daily:

1. Add your API key as a repository secret: `PROMPTINTEL_API_KEY`
2. The workflow runs daily at 6:00 AM UTC
3. New rules are committed automatically

You can also trigger manually: Actions → Sync PromptIntel → Run workflow

## Integration with Your Project

### Option 1: Git Submodule

```bash
cd your-project
git submodule add https://github.com/xampla/promptintel-nova-sync rules/promptintel
```

### Option 2: Copy Rules

```bash
cp -r promptintel-nova-sync/rules/ your-project/rules/
```

### Option 3: Use as Dependency

```python
from nova import NovaMatcher
from pathlib import Path

# Load PromptIntel rules
rules_dir = Path("promptintel-nova-sync/rules")
for nov_file in rules_dir.glob("*.nov"):
    # Load and use rules...
```

## Credits

- **[Nova Framework](https://github.com/Nova-Hunting/nova-framework)** by Thomas Roccia ([@fr0gger_](https://twitter.com/fr0gger_))
- **[PromptIntel](https://promptintel.novahunting.ai)** - IoPC threat intelligence platform
- **[Carapace](https://github.com/xampla/carapace)** - Prompt injection detection plugin

## License

MIT License - See [LICENSE](LICENSE) for details.
