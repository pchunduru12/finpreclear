"""Policy clause retrieval (plan: BM25 to start). Used by BOTH the data pipeline and the
gateway so training sees exactly the clauses serving would retrieve (no train/serve skew).

Two stages: (1) hard filter on applies_to (tool name or "*"), (2) BM25 rank on the
user request + tool name + argument keys. Clauses scoped to the exact tool are always kept.
"""
from __future__ import annotations

import json
import math
import re
from collections import Counter
from pathlib import Path
from typing import Iterable

from .schema import CheckRequest, PolicyClause

_TOKEN = re.compile(r"[a-z0-9]+")
_STOP = {"the", "a", "an", "of", "to", "and", "or", "in", "on", "for", "is", "are", "be", "by", "with", "that", "this", "any", "not"}


def tokenize(text: str) -> list[str]:
    return [t for t in _TOKEN.findall(text.lower().replace("_", " ")) if t not in _STOP]


class BM25:
    def __init__(self, docs: list[list[str]], k1: float = 1.5, b: float = 0.75):
        self.docs, self.k1, self.b = docs, k1, b
        self.n = len(docs)
        self.avgdl = sum(map(len, docs)) / max(self.n, 1)
        df = Counter(t for d in docs for t in set(d))
        self.idf = {t: math.log(1 + (self.n - f + 0.5) / (f + 0.5)) for t, f in df.items()}
        self.tf = [Counter(d) for d in docs]

    def score(self, query: list[str], i: int) -> float:
        dl, tf, s = len(self.docs[i]), self.tf[i], 0.0
        for q in query:
            if q in tf:
                f = tf[q]
                s += self.idf[q] * f * (self.k1 + 1) / (f + self.k1 * (1 - self.b + self.b * dl / self.avgdl))
        return s


class PolicyRetriever:
    def __init__(self, clauses: Iterable[PolicyClause], k: int = 5):
        self.clauses = list(clauses)
        self.k = k
        self._bm25 = BM25([tokenize(c.text + " " + " ".join(c.tags) + " " + " ".join(c.applies_to)) for c in self.clauses])
        self.version = _hash_clauses(self.clauses)

    @classmethod
    def from_jsonl(cls, path: str | Path, k: int = 5) -> "PolicyRetriever":
        rows = [json.loads(l) for l in Path(path).read_text().splitlines() if l.strip()]
        return cls([PolicyClause.model_validate(r) for r in rows], k=k)

    def retrieve(self, req: CheckRequest) -> list[PolicyClause]:
        tool = req.tool_call.name
        scoped = [i for i, c in enumerate(self.clauses) if tool in c.applies_to]
        general = [i for i, c in enumerate(self.clauses) if "*" in c.applies_to]
        q = tokenize(f"{req.user_request} {tool} {' '.join(req.tool_call.arguments.keys())}")
        ranked = sorted(general, key=lambda i: -self._bm25.score(q, i))
        keep = scoped + [i for i in ranked if i not in scoped]
        return [self.clauses[i] for i in keep[: max(self.k, len(scoped))]]


def _hash_clauses(clauses: list[PolicyClause]) -> str:
    import hashlib
    h = hashlib.sha256("\n".join(c.model_dump_json() for c in clauses).encode()).hexdigest()
    return f"policy-{h[:12]}"
