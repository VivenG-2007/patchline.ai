"""
Strategy fingerprinting for remediation attempts.

PatchLine's architecture requires that "the same failed strategy must not
be blindly retried" (not just discouraged). Discouragement already exists —
memory_store's RAG retrieval surfaces a finding's own past failed attempt as
"[FAILED / UNVERIFIED ATTEMPT - AVOID REPEATING THIS STRATEGY]" prompt
context. But that's a soft signal the fix model can ignore; nothing
previously stopped attempt N+1 from generating the same patch attempt N
already failed with, worded slightly differently.

A hard block needs a stable identity for "the same strategy" that survives
minor rewording, since two fix summaries describing the same underlying
approach ("parameterize the SQL query" vs "use a parameterized query instead
of string concatenation") are the same strategy despite different exact
text. This module is intentionally NOT semantic (no embedding call, no LLM
judge) — it's a fast, deterministic, offline normalization + token-overlap
check used to decide "is this close enough to something that already failed
here that another verification cycle on it would be wasted." It scopes to
one finding's own retry history (Attempt 1 -> A, Attempt 2 -> B, ... per the
product spec's example) — NOT a cross-finding block, since a strategy that
failed for one finding can legitimately be correct for a different one;
cross-finding "prior art" stays a soft RAG signal by design (memory_store).
"""

from __future__ import annotations

import hashlib
import re
from typing import Optional

_NON_ALNUM_RE = re.compile(r"[^a-z0-9\s]")
_WHITESPACE_RE = re.compile(r"\s+")

# Common connective words that carry no strategy meaning of their own
# ("use the X instead of Y" vs "using X instead of a Y") — dropping them
# makes token-set comparison compare approaches, not phrasing.
_STOPWORDS = {
    "a", "an", "the", "to", "of", "in", "on", "for", "and", "or", "with",
    "instead", "by", "using", "use", "used", "this", "that", "is", "are",
    "was", "were", "be", "been", "it", "its", "as", "so", "not", "into",
}

# Above this Jaccard similarity (over 3-character shingles of the sorted,
# normalized token set — see strategy_similarity), two strategy summaries
# are treated as "the same strategy" even when their exact wording differs.
# Deliberately conservative: a false negative (letting a genuine repeat
# through) just costs one more verification cycle; a false positive
# (blocking a genuinely different, valid strategy) would incorrectly burn a
# bounded attempt slot. 0.6 was tuned against paraphrased-but-identical vs.
# genuinely-different strategy pairs — see tests/test_fingerprint.py.
DUPLICATE_STRATEGY_THRESHOLD = 0.6

_SHINGLE_SIZE = 3


def normalize_strategy_text(text: Optional[str]) -> str:
    """Lowercase, strip punctuation, drop stopwords and pure-digit tokens
    (WITHOUT mangling digits embedded in a word, e.g. "md5" must stay "md5",
    not become "md"), collapse whitespace. Deliberately lossy on purpose —
    comparing "the same underlying approach", not "the same sentence"."""
    if not text:
        return ""
    text = text.lower()
    text = _NON_ALNUM_RE.sub(" ", text)
    tokens = [t for t in _WHITESPACE_RE.split(text) if t]
    tokens = [t for t in tokens if t not in _STOPWORDS and not t.isdigit()]
    return " ".join(tokens)


def strategy_token_set(text: Optional[str]) -> set[str]:
    normalized = normalize_strategy_text(text)
    return set(normalized.split()) if normalized else set()


def strategy_fingerprint(summary: str, category: str = "", file: str = "") -> str:
    """Stable identity for a remediation strategy, scoped to the
    vulnerability category + file it applies to (identical wording could be
    a valid strategy for one finding and an exact repeat for another).
    Order-independent — two summaries with the same normalized token SET
    fingerprint identically regardless of word order or rewording, so this
    catches trivial rewordings that an exact-string comparison would miss.
    Word-level (not fuzzy) on purpose: this is a stable storage key, not a
    similarity score — fuzzy matching for near-duplicates lives in
    strategy_similarity / find_duplicate_strategy below."""
    tokens = sorted(strategy_token_set(summary))
    scope = f"{(category or '').strip().lower()}|{(file or '').strip().lower()}"
    canonical = f"{scope}|{' '.join(tokens)}"
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


def _shingles(text: str, n: int = _SHINGLE_SIZE) -> set[str]:
    if len(text) < n:
        return {text} if text else set()
    return {text[i : i + n] for i in range(len(text) - n + 1)}


def strategy_similarity(a: Optional[str], b: Optional[str]) -> float:
    """Jaccard similarity over character shingles of the sorted, normalized
    token set. Two design choices, both deliberate:
      - sorting the tokens before shingling makes this ORDER-INDEPENDENT
        (word-order differences between two paraphrases don't matter);
      - shingling CHARACTERS rather than comparing whole tokens catches
        morphological variants ("parameterize" vs "parameterized") that a
        plain word-set Jaccard would score as a complete mismatch, without
        needing a real stemmer.
    Returns 0.0 if either side normalizes to nothing."""
    tokens_a, tokens_b = sorted(strategy_token_set(a)), sorted(strategy_token_set(b))
    if not tokens_a or not tokens_b:
        return 0.0
    shingles_a, shingles_b = _shingles(" ".join(tokens_a)), _shingles(" ".join(tokens_b))
    if not shingles_a or not shingles_b:
        return 0.0
    intersection = len(shingles_a & shingles_b)
    union = len(shingles_a | shingles_b)
    return intersection / union if union else 0.0


def find_duplicate_strategy(candidate_summary: str, prior_summaries: list[str]) -> Optional[str]:
    """Returns the first prior summary `candidate_summary` duplicates
    (strategy_similarity >= DUPLICATE_STRATEGY_THRESHOLD, which also covers
    exact matches since identical text has similarity 1.0), or None if it's
    sufficiently different from every one of them."""
    if not candidate_summary:
        return None
    for prior in prior_summaries:
        if prior and strategy_similarity(candidate_summary, prior) >= DUPLICATE_STRATEGY_THRESHOLD:
            return prior
    return None
