#!/usr/bin/env python3
"""
Remove the corpus artefact that makes the SSRF classes look separable.

The problem it fixes
--------------------
nuclei templates use a callback host (`{{interactsh-url}}`, `*.oast.pro`,
`*.oastify.com`, `interact.sh`) to observe blind SSRF. That host appears in
about two thirds of the positives. It was stripped from the negatives, because
leaving it there would have labelled an out-of-band host as benign in one class
and malicious in the other.

The result was a giveaway: a random forest gave the "contains an OOB host"
feature 63% of its importance, and removing that one feature dropped accuracy
from 0.955 to 0.696 and positive recall from 0.877 to 0.342. Nearly all the
apparent performance was the model recognising nuclei's test scaffolding, not
recognising SSRF.

The fix
-------
Rewrite the callback host to one neutral attacker-controlled domain in BOTH
classes. This is semantically faithful: a blind SSRF payload is an
attacker-controlled external URL, and whether it reads `interact.sh` or
`attacker-controlled.example` has no bearing on whether the server fetches it.
After normalization the host string carries no class information, so the model
has to rely on features that generalize.

What this exposes, and should be stated in the paper
----------------------------------------------------
Once the artefact is gone, a blind-SSRF positive and an open-redirect negative
are close to indistinguishable from the REQUEST alone: both are
`?url=<attacker host>`. That is not a defect of the data, it is the actual
limit of request-only detection, and it is the argument for the response-side
model.

Usage:
    python3 normalize_corpus_artefacts.py
"""

import json
import re

NEUTRAL_HOST = "attacker-controlled.example"

SCAFFOLD_HOST = re.compile(
    r"(?:\{\{interactsh-url\}\}"
    r"|(?:[\w-]+\.)*interact\.sh"
    r"|(?:[\w-]+\.)*oast\.(?:pro|live|site|fun|me|online)"
    r"|(?:[\w-]+\.)*oastify\.com"
    r"|(?:[\w-]+\.)*burpcollaborator\.net"
    r"|example-partner-api\.com)",
    re.I,
)

# The vulhub captures point the SSRF at an internal target under our control.
# The private IP (10.0.0.5) and the "secret_token" keyword are the legitimate,
# generalizable full_read signal and MUST stay. Only the unique literal token
# string is memorizable in the same way the OOB host was, so it is rewritten to
# a token-shaped placeholder that carries no per-collection uniqueness.
INTERNAL_TARGET_LITERAL = re.compile(r"INTERNAL-DEMO-TOKEN-[A-Za-z0-9]+")
INTERNAL_TARGET_PLACEHOLDER = "INTERNAL-TOKEN-REDACTED"

TARGETS = [
    ("SSRF_CVE_DATASET_NUCLEI.json", "SSRF_CVE_DATASET_NUCLEI.normalized.json"),
    ("SSRF_NEGATIVE_DATASET.json", "SSRF_NEGATIVE_DATASET.normalized.json"),
    ("SSRF_VULHUB_PAIRS.json", "SSRF_VULHUB_PAIRS.normalized.json"),
]


def normalize(obj, counter):
    """Rewrite callback hosts anywhere in the structure."""
    if isinstance(obj, str):
        new = SCAFFOLD_HOST.sub(NEUTRAL_HOST, obj)
        new = INTERNAL_TARGET_LITERAL.sub(INTERNAL_TARGET_PLACEHOLDER, new)
        if new != obj:
            counter[0] += 1
        return new
    if isinstance(obj, list):
        return [normalize(v, counter) for v in obj]
    if isinstance(obj, dict):
        return {k: normalize(v, counter) for k, v in obj.items()}
    return obj


def main():
    for src, dst in TARGETS:
        data = json.load(open(src, encoding="utf-8"))
        counter = [0]
        # Only the data itself is rewritten. Provenance (template paths, CVE
        # ids, reference URLs) is left alone so every row stays traceable.
        data["examples"] = normalize(data["examples"], counter)
        data["dataset_info"]["oob_host_normalized"] = True
        data["dataset_info"]["oob_host_normalized_to"] = NEUTRAL_HOST
        data["dataset_info"]["oob_host_strings_rewritten"] = counter[0]
        data["dataset_info"]["normalization_reason"] = (
            "nuclei's callback host appeared in most positives and in none of "
            "the negatives, so it acted as a label giveaway rather than a "
            "symptom of SSRF. Rewritten identically in both classes."
        )
        with open(dst, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
        print(f"{src} -> {dst}  ({counter[0]} strings rewritten)")


if __name__ == "__main__":
    main()
