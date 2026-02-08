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
for nov_file in rules_dir.glob("**/*.nov"):
    # Load and use rules...
```

## Generated Rules

### Rule Naming Convention

All prompt rules use the prefix `PI_` followed by a type tag, a short hash (for uniqueness), and a descriptive name:

| Prefix | Meaning | Source |
|--------|---------|--------|
| `PI_AUTO_{hash}_{name}` | Auto-generated from prompt text | Regex keyword extraction + first-line pattern matching |
| `PI_HC_{hash}_{name}` | Hand-crafted by contributors | Pre-built `nova_rule` from the API, used verbatim |
| `Molt_AUTO_{hash}_{name}` | Auto-generated from threat intel | IOC keywords + LLM evaluation from molt feed |

Hand-crafted (`HC`) rules are typically higher quality — they use regex patterns, multiple semantic descriptions, LLM evaluation clauses, and complex conditions written by security researchers. Auto-generated (`AUTO`) rules are built programmatically from the raw prompt text.

## Limitations of Auto-Generated Rules

Auto-generated rules (`PI_AUTO_*`, `Molt_AUTO_*`) are built programmatically and have inherent limitations compared to hand-crafted (`PI_HC_*`) rules:

- **Keyword extraction is basic** — only ~12 hardcoded regex patterns are checked (e.g., "ignore previous instructions", "jailbreak"). Prompts that don't match any pattern fall back to a verbatim substring of the first line, which only detects exact copies of the original prompt.
- **No semantic intent descriptions** — hand-crafted rules use conceptual descriptions like `"enforce roleplay personality"` for semantic matching. Auto-generated rules skip semantics when using the first-line fallback since the text would be redundant with the keyword pattern.
- **Molt LLM clauses are passthrough** — the `recommendation_agent` field from the API is used as-is for the LLM evaluation prompt. It was written as agent guidance, not as a detection question, so it may not be optimally phrased for the Nova LLM engine.
- **No cross-rule correlation** — each rule is independent. Related threats from the same campaign are not grouped or chained.

For production use, prefer hand-crafted rules where available and treat auto-generated rules as a baseline that benefits from manual review. Contributing improved `nova_rule` fields back to PromptIntel directly improves rule quality for everyone.

## Rule Updates

Rules in this repository are synced from the PromptIntel API **daily at 06:00 UTC** via GitHub Actions. Each sync fetches the latest prompts and molt threat intel, regenerates all rule files, and auto-commits any changes.

- **New threats** appear as new `.nov` files within ~24 hours of being published on PromptIntel
- **Updated entries** (e.g., new IOCs added to a molt threat) are reflected on the next sync
- **Removed/revoked entries** — revoked molt entries are filtered out during sync; however, previously generated rule files are kept as historical record and are not deleted

## Manual Execution

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

## Credits

- **[Nova Framework](https://github.com/Nova-Hunting/nova-framework)** by Thomas Roccia ([@fr0gger_](https://twitter.com/fr0gger_))
- **[PromptIntel](https://promptintel.novahunting.ai)** - IoPC threat intelligence platform
- **[Carapace](https://github.com/xampla/carapace)** - Prompt injection detection plugin

## License

MIT License - See [LICENSE](LICENSE) for details.
