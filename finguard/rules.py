"""Deterministic pre-checks run by the gateway before (and alongside) the model.

Why rules exist next to a model: some controls are binary and must not depend on a
probabilistic judge (denylisted accounts, hard approval limits, IAM changes). A rule hit
gives the bank an exact, reproducible reason for SOX testing.

Design invariants (tested in tests/test_gateway_*):
- Rules only TIGHTEN. A rule produces block or escalate; the model can never downgrade it
  (the gateway takes the strictest verdict: block > escalate > allow).
- The ONLY allow a rule produces is the fast path for tools whose action_types tier is
  "low" (read-only), and only when no other rule fired. A read-only call that carries any
  destination (URL, email, domain, IP, or a destination-named argument) never fast-paths.
- Nothing the CALLER sends can loosen a rule. Context items and their trust labels are set
  by the caller, so rules never read them. Vendor master, approval and HR verification
  records come only from the gateway's own RecordsLookup (finguard/gateway/records.py).
  The request may only NAME an id (vendor_id, approval_id, employee_id).
- Missing or unclear data never passes. No lookup, lookup error, unknown vendor, no payee
  field, several different payees, unparseable or ambiguous amount, missing or unknown
  currency, arguments too large or deep to scan: each one escalates.
- Tool names are canonicalised (NFKC, invisible characters removed, casefold, look-alike
  letters folded, whitespace stripped) before any lookup, so `Submit_Payment ` is
  submit_payment.
- Scanning is LINEAR in input size (security review round 2, ReDoS): no backtracking-prone
  regexes. Strings are scanned with str.find/count, simple single-class regexes and splits.
  Per-value and per-request caps on destinations and dotted tokens; overflow escalates.
- Text is normalised before matching: NFKC, casefold, all dash variants -> "-", invisible
  format characters removed. For DENYLIST matching only, Cyrillic/Greek look-alikes are also
  folded to Latin and non-ASCII digits to ASCII (folding can only make a denylist hit more
  likely). For APPROVED-list matching nothing is folded and the host must be ASCII, so a
  look-alike host never matches an approved domain.
- Every hit carries short `evidence` (<= 160 chars) that is an exact quote from the request
  where possible, so schema.evidence_is_grounded() passes.

Mapping: R-DENY-* / R-VM-* / R-ACCT-SCRIPT -> payment fraud controls (SOX ITGC / AP controls,
P-AP-001, P-AP-002, P-PAY-002); R-EXT-* -> P-DATA-002 (OWASP LLM02); R-LIMIT-001 -> P-PAY-001;
R-HR-001 -> P-HR-001; R-IAM-001 -> P-IAM-001 (OWASP LLM06 excessive agency).
"""
from __future__ import annotations

import bisect
import hashlib
import json
import re
import sys
import unicodedata
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, NamedTuple, Optional

from .schema import CheckRequest, RiskCategory, Verdict, grounding_corpus
from .schema import normalize as _gnorm

if TYPE_CHECKING:  # avoid importing the gateway package at module import time
    from .gateway.records import RecordsLookup

RULES_FILE = Path(__file__).resolve().parent.parent / "configs" / "rules.json"

SEVERITY = {Verdict.ALLOW: 0, Verdict.ESCALATE: 1, Verdict.BLOCK: 2}

# Scan limits. Exceeding any of them escalates (never allows).
MAX_DEPTH = 32                  # nesting of dicts/lists in arguments
MAX_LEAVES = 5_000              # scalars + keys in arguments
MAX_URIS_PER_VALUE = 100
MAX_ATS_PER_VALUE = 100
MAX_DESTS_PER_VALUE = 50
MAX_DOTTED_PER_REQUEST = 2_000  # dotted tokens examined as possible domains / IPs
MAX_HITS_PER_RULE = 8
EVIDENCE_CHARS = 160


def strictest(*verdicts: Verdict) -> Verdict:
    """block > escalate > allow."""
    return max(verdicts, key=lambda v: SEVERITY[v])


@dataclass
class RuleHit:
    rule_id: str
    verdict: Verdict
    category: RiskCategory
    evidence: str
    reason: str
    policy_id: Optional[str] = None

    def to_dict(self) -> dict:
        d = asdict(self)
        d["verdict"], d["category"] = self.verdict.value, self.category.value
        return d


@dataclass
class RuleOutcome:
    hits: list[RuleHit] = field(default_factory=list)   # all stop hits (block/escalate)
    fast_path: Optional[RuleHit] = None                 # the low-tier allow, only when hits is empty

    @property
    def decisive(self) -> Optional[RuleHit]:
        """The strictest stop hit (first one on ties), or None."""
        if not self.hits:
            return None
        return max(self.hits, key=lambda h: SEVERITY[h.verdict])


# ------------------------------------------------------------------ normalisation (linear)

_EXTRA_DASHES = "−⁃˗⸺⸻﹘﹣－"
_TRAILING_PUNCT = ".,;:!?)]}>\"'`*"

# Lower-case Cyrillic / Greek letters that render like Latin letters (applied after casefold).
_CONFUSABLES = {
    "а": "a", "в": "b", "е": "e", "ё": "e", "к": "k", "м": "m", "н": "h", "о": "o", "р": "p",
    "с": "c", "т": "t", "у": "y", "х": "x", "ѕ": "s", "і": "i", "ї": "i", "ј": "j", "ԁ": "d",
    "ӏ": "l", "ԛ": "q", "ԝ": "w", "һ": "h", "ь": "b", "п": "n", "ɡ": "g", "ı": "i",
    "α": "a", "β": "b", "γ": "y", "ε": "e", "η": "n", "ι": "i", "κ": "k", "ν": "v", "ο": "o",
    "ρ": "p", "τ": "t", "υ": "u", "χ": "x", "ω": "w", "ϲ": "c", "ϳ": "j", "μ": "u",
}


def _build_tables() -> tuple[dict, dict]:
    """Translate tables, built once: BASE removes format chars (Cf) and maps dashes (Pd) to
    '-'; FOLD maps confusables to Latin and non-ASCII decimal digits to ASCII."""
    base: dict[int, Optional[str]] = {}
    fold: dict[int, str] = {ord(k): v for k, v in _CONFUSABLES.items()}
    for cp in range(128, sys.maxunicode + 1):
        ch = chr(cp)
        cat = unicodedata.category(ch)
        if cat == "Cf":
            base[cp] = None
        elif cat == "Pd" or ch in _EXTRA_DASHES:
            base[cp] = "-"
        elif cat == "Nd":
            d = unicodedata.decimal(ch, None)
            if d is not None:
                fold[cp] = str(d)
    base[0xAD] = None  # soft hyphen (Cf already, explicit for reviewers)
    return base, fold


_BASE_TABLE, _FOLD_TABLE = _build_tables()
_NON_ALNUM = re.compile(r"[^a-z0-9]+")
_NON_ASCII = re.compile(r"[^\x00-\x7f]")


def _base(s: str) -> str:
    """NFKC, casefold, Cf removed, dashes -> '-'. Not folded (used for approved-list matching)."""
    if s.isascii():
        return s.lower()
    return unicodedata.normalize("NFKC", s).casefold().translate(_BASE_TABLE)


def _fold(s: str) -> str:
    return s if s.isascii() else s.translate(_FOLD_TABLE)


def normalize_text(s: Any) -> str:
    """Denylist form: _base + look-alike / digit folding, trimmed of whitespace and trailing punctuation."""
    return _fold(_base(str(s))).strip().rstrip(_TRAILING_PUNCT).strip()


def alnum(s: Any) -> str:
    """Normalised text reduced to ASCII letters and digits: the form accounts are compared in.
    ('ACCT 9999–0001.' and 'acct-9999-0001' both -> 'acct99990001'.)"""
    return _NON_ALNUM.sub("", normalize_text(s))


def canonical_tool_name(name: Any) -> str:
    """The one form a tool name is looked up in (config, rules, judge, client registry)."""
    return _fold(_base(str(name))).strip()


def has_non_ascii_alnum(s: str) -> bool:
    """True if s (after NFKC) has a letter or digit outside ASCII: look-alike or mixed-script
    characters, which never belong in an account or routing identifier."""
    if s.isascii():
        return False
    t = unicodedata.normalize("NFKC", s)
    return any(m.group(0).isalnum() for m in _NON_ASCII.finditer(t))


_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")


@lru_cache(maxsize=8192)
def _key_tokens(key: str) -> frozenset:
    k = _CAMEL.sub("_", unicodedata.normalize("NFKC", key[:256]))
    return frozenset(t for t in _NON_ALNUM.split(normalize_text(k)) if t)


# ------------------------------------------------------------------ argument walking

_KEY = object()  # path marker: this leaf is a dict KEY (values smuggled in as keys are scanned too)


class _ScanLimit(Exception):
    pass


class _Leaf:
    """One scalar (or dict key) in the arguments, with lazily computed normal forms."""
    __slots__ = ("path", "raw", "is_key", "text", "_b", "_n", "_a")

    def __init__(self, path: tuple, raw: Any, is_key: bool):
        self.path, self.raw, self.is_key = path, raw, is_key
        self.text = raw if isinstance(raw, str) else str(raw)
        self._b = self._n = self._a = None

    @property
    def base(self) -> str:  # destination form: '\' treated as '/', as WHATWG URL parsing does
        if self._b is None:
            self._b = _base(self.text).replace("\\", "/")
        return self._b

    @property
    def norm(self) -> str:  # denylist form
        if self._n is None:
            self._n = _fold(self.base).strip().rstrip(_TRAILING_PUNCT).strip()
        return self._n

    @property
    def an(self) -> str:
        if self._a is None:
            self._a = _NON_ALNUM.sub("", self.norm)
        return self._a

    @property
    def keys(self) -> list[str]:
        return [p for p in self.path if isinstance(p, str)]

    @property
    def last_key(self) -> str:
        ks = self.keys
        return ks[-1] if ks else ""

    @property
    def where(self) -> str:
        return ".".join(str(p) for p in self.path if p is not _KEY) or "<root>"


def _walk(obj: Any, path: tuple, out: list, depth: int) -> None:
    if depth > MAX_DEPTH:
        raise _ScanLimit(f"arguments nested deeper than {MAX_DEPTH}")
    if len(out) > MAX_LEAVES:
        raise _ScanLimit(f"more than {MAX_LEAVES} argument values")
    if isinstance(obj, dict):
        for k, v in obj.items():
            ks = str(k)
            out.append(_Leaf(path + (ks, _KEY), ks, True))
            _walk(v, path + (ks,), out, depth + 1)
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            _walk(v, path + (i,), out, depth + 1)
    elif obj is None or isinstance(obj, bool):
        return
    elif isinstance(obj, (str, int, float, Decimal)):
        out.append(_Leaf(path, obj, False))


# ------------------------------------------------------------------ destination detection (linear)

class Dest(NamedTuple):
    matched: str
    host: str
    kind: str          # uri | email | ip | domain
    flags: frozenset   # userinfo, ipv6, pct, nohost, quoted, comment


_URI_END = re.compile(r"[\s\"'<>`{}|^]")
_SCHEME_TAIL = re.compile(r"[a-z][a-z0-9+.-]{0,31}$")
_DOMAIN_RUN = re.compile(r"[\w.-]{1,255}")
_PIECE_SPLIT = re.compile(r"[^\w.-]+")
_EMPTY: frozenset = frozenset()


class _Budget:
    def __init__(self) -> None:
        self.dotted = MAX_DOTTED_PER_REQUEST
        self.overflow: Optional[str] = None


def _scan(t: str, bare: bool, suffixes: frozenset, budget: _Budget) -> list[Dest]:
    """All destinations in already-normalised text t (see _Leaf.base). Linear in len(t):
    each '://' and '@' is handled once with bounded look-around, and bare domains come from
    one split. Hosts are returned unfolded and lower-case."""
    out: list[Dest] = []
    spans: list[tuple[int, int]] = []
    # 1. URIs, any scheme
    n = t.count("://")
    if n > MAX_URIS_PER_VALUE:
        budget.overflow = budget.overflow or f"more than {MAX_URIS_PER_VALUE} URIs in one value"
    elif n:
        i = t.find("://")
        while i != -1:
            m = _SCHEME_TAIL.search(t, max(0, i - 32), i)
            if m is None:
                i = t.find("://", i + 3)
                continue
            e = _URI_END.search(t, i + 3)
            end = e.start() if e else len(t)
            uri = t[m.start():end].rstrip(_TRAILING_PUNCT)
            rest = uri[i - m.start() + 3:]
            cut = len(rest)
            for c in "/?#":
                p = rest.find(c)
                if 0 <= p < cut:
                    cut = p
            auth = rest[:cut]
            flags = set()
            if "@" in auth:
                flags.add("userinfo")
            hostport = auth.rpartition("@")[2]
            if hostport.startswith("["):
                flags.add("ipv6")
                host = hostport[1:].partition("]")[0]
            else:
                host = hostport.partition(":")[0]
            if "%" in host:
                flags.add("pct")
            host = host.strip(".")
            if not host:
                flags.add("nohost")
            out.append(Dest(uri, host, "uri", frozenset(flags)))
            spans.append((m.start(), end))
            i = t.find("://", end)
    # 2. email addresses (outside URIs)
    n = t.count("@")
    if n > MAX_ATS_PER_VALUE:
        budget.overflow = budget.overflow or f"more than {MAX_ATS_PER_VALUE} '@' in one value"
    elif n:
        starts = [s for s, _ in spans]
        k = t.find("@")
        while k != -1:
            j = bisect.bisect_right(starts, k) - 1
            if j >= 0 and spans[j][0] <= k < spans[j][1]:
                k = t.find("@", k + 1)
                continue
            m = _DOMAIN_RUN.match(t, k + 1)
            dom = m.group(0) if m else ""
            win = t[max(0, k - 256):k]
            local = "" if (not win or win[-1].isspace()) else win.rsplit(None, 1)[-1]
            flags = set()
            if any(c in local for c in '"()\\'):
                flags.add("quoted")
            if t[k + 1:k + 2] in ("[", "("):
                flags.add("comment")
            host = dom.strip(".-")
            if host or flags:
                out.append(Dest(f"{local}@{dom}", host, "email", frozenset(flags)))
                spans.append((k - len(local), k + 1 + len(dom)))
            k = t.find("@", k + 1)
    # 3. bare domains and IPv4 (outside URIs and emails)
    if bare and budget.dotted > 0:
        if spans:
            spans.sort()
            parts, pos = [], 0
            for s, e in spans:
                if s > pos:
                    parts.append(t[pos:s])
                pos = max(pos, e)
            parts.append(t[pos:])
            t2 = " ".join(parts)
        else:
            t2 = t
        for p in _PIECE_SPLIT.split(t2.replace("_", " ")):
            if "." not in p:
                continue
            p = p.strip(".-")
            if "." not in p:   # sentence-final dot: not a domain, costs no budget
                continue
            budget.dotted -= 1
            if budget.dotted < 0:
                budget.overflow = budget.overflow or f"more than {MAX_DOTTED_PER_REQUEST} dotted tokens"
                break
            labels = p.split(".")
            if len(labels) == 4 and all(l.isdigit() and len(l) <= 3 for l in labels):
                out.append(Dest(p, p, "ip", _EMPTY))
                continue
            tld = labels[-1]
            if not ((tld.isalpha() and len(tld) >= 2) or tld.startswith("xn--")) or tld in suffixes:
                continue
            if all(0 < len(l) <= 63 and l[0] != "-" and l[-1] != "-" and l.replace("-", "").isalnum() for l in labels):
                out.append(Dest(p, p, "domain", _EMPTY))
    if len(out) > MAX_DESTS_PER_VALUE:
        budget.overflow = budget.overflow or f"more than {MAX_DESTS_PER_VALUE} destinations in one value"
        out = out[:MAX_DESTS_PER_VALUE]
    return out


def find_destinations(text: str, bare_domains: bool = True, non_domain_suffixes: tuple = ()) -> list[tuple[str, str]]:
    """(matched text, host) for every URI (any scheme), email address and, if bare_domains,
    IPv4 address and bare domain (label.tld). Linear time. A URI with no host yields host ""."""
    return [(d.matched, d.host) for d in _scan(_base(str(text)).replace("\\", "/"), bare_domains,
                                                frozenset(non_domain_suffixes), _Budget())]


def _norm_domains(listed: list[str], fold: bool) -> list[str]:
    out = []
    for s in listed:
        d = _base(str(s)).strip().strip(".")
        out.append(_fold(d) if fold else d)
    return [d for d in out if d]


def _host_in(host: str, listed: list[str], require_ascii: bool) -> bool:
    d = host.strip(".")
    if not d or (require_ascii and not d.isascii()):
        return False
    return any(d == x or d.endswith("." + x) for x in listed)


# ------------------------------------------------------------------ amounts, dates

def parse_amount(v: Any) -> tuple[Optional[Decimal], str]:
    """(value, status). status: ok | none (no digits at all) | ambiguous | bad.
    Accepted strings: 1200, 1200.5, 1,200.50, 1,000,000 (optionally with a currency code or
    symbol at either end). Ambiguous: one comma group with no decimal point ("30,000" could be
    30.000), three decimals after a single dot ("30.000"), dot grouping ("1.234.567"),
    comma decimals ("30.000,00"), other separators. Negative amounts are bad."""
    if isinstance(v, bool) or v is None:
        return None, "none"
    if isinstance(v, (int, float, Decimal)):
        try:
            d = Decimal(str(v))
        except InvalidOperation:
            return None, "bad"
        if not d.is_finite():
            return None, "bad"
        return (d, "ok") if d >= 0 else (None, "bad")
    s = normalize_text(v)
    if not any(c.isdigit() for c in s):
        return None, "none"
    s = s.strip(" $€£¥abcdefghijklmnopqrstuvwxyz")
    if s.startswith(("-", "(")) or s.endswith(")"):
        return None, "bad"
    if not s or s.strip("0123456789.,"):
        return None, "bad"
    dots, commas = s.count("."), s.count(",")
    if dots > 1:
        return None, "ambiguous"
    intpart, _, frac = s.partition(".")
    if commas:
        if dots and s.rfind(",") > s.rfind("."):
            return None, "ambiguous"
        groups = intpart.split(",")
        if not (1 <= len(groups[0]) <= 3 and all(len(g) == 3 for g in groups[1:]) and groups[0].isdigit()
                and all(g.isdigit() for g in groups[1:])):
            return None, "ambiguous"
        if len(groups) == 2 and not dots:
            return None, "ambiguous"
        intpart = "".join(groups)
    if not intpart.isdigit() or (dots and not frac.isdigit()):
        return None, "bad"
    if dots and commas == 0 and len(frac) == 3:
        return None, "ambiguous"
    return Decimal(intpart + ("." + frac if dots else "")), "ok"


def _parse_amount(v: Any) -> Optional[Decimal]:
    d, status = parse_amount(v)
    return d if status == "ok" else None


def _parse_ts(v: Any) -> Optional[datetime]:
    if not isinstance(v, str):
        return None
    try:
        ts = datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError:
        return None
    return ts if ts.tzinfo is not None else None  # naive timestamps are ambiguous -> invalid


# ------------------------------------------------------------------ per-request scan context

class _Ctx:
    def __init__(self, engine: "RuleEngine", req: CheckRequest, action_cfg: dict):
        self.e, self.req, self.cfg = engine, req, action_cfg
        self.tool = canonical_tool_name(req.tool_call.name)
        self.leaves: list[_Leaf] = []
        self.limit_error: Optional[str] = None
        try:
            _walk(req.tool_call.arguments, (), self.leaves, 0)
        except _ScanLimit as ex:
            self.limit_error = str(ex)
        except RecursionError:
            self.limit_error = "arguments nested too deeply"
        self.budget = _Budget()
        self._dests: dict[tuple, list[Dest]] = {}
        self._corpus: Optional[str] = None
        self._vals: list[str] = []
        self._counts: dict[str, int] = {}
        self._topq: dict[str, str] = {}
        self.hits: list[RuleHit] = []

    # evidence ------------------------------------------------------------
    def _is_grounded(self, ev: str) -> bool:
        """Same test as schema.evidence_is_grounded, with the normalised corpus cached."""
        e = _gnorm(ev)
        if len(e) < 8:
            return False
        if self._corpus is None:
            self._corpus = _gnorm(grounding_corpus(self.req))
            self._vals = [_gnorm(str(v)) for v in self.req.tool_call.arguments.values()]
        return e in self._corpus or any(e in v for v in self._vals)

    def quote(self, leaf: Optional[_Leaf] = None, hint: str = "") -> str:
        cands: list[str] = []
        if leaf is not None:
            t = leaf.text
            if hint:
                i = t.lower().find(hint.lower())
                if i >= 0:
                    cands.append(t[max(0, i - 20):i + len(hint) + 20][:EVIDENCE_CHARS])
            cands.append(t[:EVIDENCE_CHARS])
            top = leaf.path[0] if leaf.path and isinstance(leaf.path[0], str) else None
            if top is not None and top in self.req.tool_call.arguments:
                if top not in self._topq:
                    v = self.req.tool_call.arguments[top]
                    small = not isinstance(v, (dict, list)) and len(str(v)) <= 250
                    self._topq[top] = f"{json.dumps(top)}: {json.dumps(v, sort_keys=True)}" if small else ""
                if self._topq[top]:
                    cands.append(self._topq[top])
        for c in cands:
            if c and self._is_grounded(c):
                return c
        return self.req.tool_call.name[:EVIDENCE_CHARS]

    def hit(self, rule_id: str, verdict: Verdict, cat: RiskCategory, reason: str, policy: Optional[str],
            leaf: Optional[_Leaf] = None, hint: str = "") -> None:
        n = self._counts.get(rule_id, 0)
        self._counts[rule_id] = n + 1
        if n >= MAX_HITS_PER_RULE:
            return
        self.hits.append(RuleHit(rule_id, verdict, cat, self.quote(leaf, hint), reason[:300], policy))

    # destinations --------------------------------------------------------
    def dests(self, leaf: _Leaf, bare: bool) -> list[Dest]:
        k = (id(leaf), bare)
        if k not in self._dests:
            t = leaf.base
            if not bare and "://" not in t and "@" not in t:
                self._dests[k] = []
            else:
                self._dests[k] = _scan(t, bare, self.e._suffixes, self.budget)
        return self._dests[k]

    # payee fields --------------------------------------------------------
    def payee_class(self, leaf: _Leaf) -> Optional[str]:
        """None (not a payee field) | account | routing | info | generic."""
        if leaf.is_key:
            return None
        pc = self.e._payee
        keys = leaf.keys
        if not keys:
            return None
        explicit = leaf.last_key in pc["explicit"]
        if not explicit and not any(_key_tokens(k) & pc["trigger"] for k in keys):
            return None
        last = _key_tokens(leaf.last_key)
        if explicit:
            return "account"
        if last & pc["info"]:      # payee_name, account_holder, account_currency ...
            return "info"
        if last & pc["routing"]:   # routing_number, swift, bic, bank_code ...
            return "routing"
        if last & pc["strong"]:    # account, account_number, iban ...
            return "account"
        return "generic"           # bare "payee" / "beneficiary": account OR the master's name


# ------------------------------------------------------------------ engine

_PAYEE_DEFAULTS = {
    "trigger_tokens": ["account", "acct", "iban", "beneficiary", "payee", "routing", "swift", "bic", "aba", "bank"],
    "strong_tokens": ["account", "acct", "iban", "number", "num", "no"],
    "routing_tokens": ["routing", "swift", "bic", "aba", "sort", "branch", "transit", "code"],
    "info_tokens": ["name", "holder", "address", "city", "country", "street", "zip", "postcode", "state", "type",
                    "currency", "ccy", "label", "email", "phone", "memo", "note", "reference", "ref", "date"],
    "record_routing_fields": ["routing", "swift", "bic", "aba", "bank_code", "routing_number", "sort_code"],
}


class RuleEngine:
    """records: the gateway's RecordsLookup. Without one, every payee / approval / HR check
    escalates ("cannot verify"), it never passes. clock: injectable UTC now() for tests."""

    def __init__(self, config: dict, records: Optional["RecordsLookup"] = None,
                 clock: Optional[Callable[[], datetime]] = None):
        self.config = config
        self.records = records
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.version = config.get("version", "rules-unversioned")
        self.config_sha256 = hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()
        c = config
        self._tools = {name: {canonical_tool_name(t) for t in c.get(name, {}).get("tools", [])}
                       for name in ("external_destination", "payment_limit", "vendor_master",
                                    "vendor_bank_update", "direct_deposit")}
        self._always = {canonical_tool_name(k): v for k, v in c.get("always_escalate", {}).items()
                        if isinstance(v, dict)}
        den = c.get("denylist", {})
        self._deny_accts = [a for a in (alnum(x) for x in den.get("accounts", [])) if a]
        self._deny_domains = _norm_domains(den.get("email_domains", []), fold=True)
        ext = c.get("external_destination", {})
        self._approved = _norm_domains(ext.get("approved_domains", []), fold=False)
        self._dest_tokens = frozenset(ext.get("destination_key_tokens", []))
        self._exempt = set(ext.get("bare_domain_exempt_fields", []))
        self._suffixes = frozenset(s.lower() for s in ext.get("non_domain_suffixes", []))
        p = {**_PAYEE_DEFAULTS, **c.get("payee_fields", {})}
        self._payee = {"trigger": frozenset(p["trigger_tokens"]), "strong": frozenset(p["strong_tokens"]),
                       "routing": frozenset(p["routing_tokens"]), "info": frozenset(p["info_tokens"]),
                       "explicit": set(c.get("vendor_master", {}).get("arg_account_fields", []))
                       | set(c.get("vendor_bank_update", {}).get("arg_account_fields", [])),
                       "record_routing": list(p["record_routing_fields"])}

    @property
    def records_version(self) -> Optional[str]:
        return getattr(self.records, "version", None) if self.records is not None else None

    @classmethod
    def from_json(cls, path: str | Path = RULES_FILE, records: Optional["RecordsLookup"] = None) -> "RuleEngine":
        return cls(json.loads(Path(path).read_text()), records=records)

    def evaluate(self, req: CheckRequest, action_cfg: dict) -> RuleOutcome:
        ctx = _Ctx(self, req, action_cfg)
        if ctx.limit_error:
            ctx.hit("R-ARGS-001", Verdict.ESCALATE, RiskCategory.POLICY_VIOLATION,
                    f"Arguments cannot be fully checked ({ctx.limit_error}); human review required.", None)
        for check in (self._denylist, self._destinations, self._account_script, self._payment_limit,
                      self._vendor_master, self._vendor_bank_update, self._direct_deposit, self._always_escalate):
            check(ctx)
        outcome = RuleOutcome(hits=ctx.hits)
        if not ctx.hits and self.config.get("fast_path_low_tier", True) and action_cfg.get("tier") == "low":
            outcome.fast_path = RuleHit(
                rule_id="R-FAST-LOW", verdict=Verdict.ALLOW, category=RiskCategory.NONE,
                evidence=ctx.quote(), reason=f"Read-only low-tier tool '{ctx.tool}'; no deterministic rule fired.")
        return outcome

    # ---------------------------------------------------------- (a) denylist -> block
    def _denylist(self, ctx: _Ctx) -> None:
        """Every scalar and dict key, any depth, in folded form. Account: denylisted account
        (alphanumerics) is a substring. Domain: denylisted domain is a substring (covers URL
        hosts, userinfo tricks, emails and bare mentions in one linear test)."""
        for leaf in ctx.leaves:
            if self._deny_accts:
                an = leaf.an
                for acct in self._deny_accts:
                    if acct in an:
                        ctx.hit("R-DENY-ACCT", Verdict.BLOCK, RiskCategory.PAYMENT_FRAUD,
                                f"Denylisted account found in argument '{leaf.where}'.", "P-PAY-002", leaf)
            if self._deny_domains:
                n = leaf.norm
                for dom in self._deny_domains:
                    if dom in n:
                        ctx.hit("R-DENY-DOMAIN", Verdict.BLOCK, RiskCategory.DATA_EXFILTRATION,
                                f"Denylisted domain '{dom}' found in argument '{leaf.where}'.", "P-DATA-002", leaf, dom)

    # ---------------------------------------------------------- (b) destinations -> escalate
    def _destinations(self, ctx: _Ctx) -> None:
        """Runs on EVERY tool.
        - send_email / export_customer_data: every string and key, URIs + emails + IPs + bare domains.
        - Any tool: arguments under destination-named keys (url, recipient, bucket, ...) the same way;
          every other string is scanned for URIs and email addresses.
        - Read-only (tier low) tools: ANY destination, or any non-empty destination-named
          argument, escalates (R-EXT-003), so it can never fast-path.
        - URL with userinfo ('@' in the authority, incl. the '\\@' trick), bracketed IPv6 host,
          percent-encoded host, quoted or comment email syntax: escalate (R-EXT-002) even
          when the visible host is approved.
        - Unapproved host: escalate (R-EXT-001). Denylisted hosts are blocked by (a).
        - Too many destinations / tokens to check: escalate (R-EXT-004)."""
        whole = ctx.tool in self._tools["external_destination"]
        read_only = ctx.cfg.get("tier") == "low"
        for leaf in ctx.leaves:
            dest_key = any(_key_tokens(k) & self._dest_tokens for k in leaf.keys)
            if read_only and dest_key and not leaf.is_key and leaf.text.strip():
                ctx.hit("R-EXT-003", Verdict.ESCALATE, RiskCategory.DATA_EXFILTRATION,
                        f"Read-only tool '{ctx.tool}' was given a destination argument '{leaf.where}'.", "P-DATA-002", leaf)
                continue
            exempt = whole and len(leaf.path) == 1 and leaf.path[0] in self._exempt
            bare = (whole and not exempt) or dest_key or read_only
            for d in ctx.dests(leaf, bare):
                shown = d.host or d.matched[:80]
                if read_only:
                    ctx.hit("R-EXT-003", Verdict.ESCALATE, RiskCategory.DATA_EXFILTRATION,
                            f"Read-only tool '{ctx.tool}' was given a destination '{shown}' in '{leaf.where}'.",
                            "P-DATA-002", leaf, d.host)
                elif d.flags - {"nohost"}:
                    ctx.hit("R-EXT-002", Verdict.ESCALATE, RiskCategory.DATA_EXFILTRATION,
                            f"Destination in '{leaf.where}' uses deceptive or unparseable address syntax "
                            f"({', '.join(sorted(d.flags - {'nohost'}))}).", "P-DATA-002", leaf, d.host)
                elif _host_in(_fold(d.host), self._deny_domains, False):
                    continue  # blocked by (a)
                elif not _host_in(d.host, self._approved, True):
                    ctx.hit("R-EXT-001", Verdict.ESCALATE, RiskCategory.DATA_EXFILTRATION,
                            f"Destination '{shown}' in '{leaf.where}' is not on the approved list (P-DATA-002).",
                            "P-DATA-002", leaf, d.host)
        if ctx.budget.overflow:
            ctx.hit("R-EXT-004", Verdict.ESCALATE, RiskCategory.DATA_EXFILTRATION,
                    f"Arguments hold too many possible destinations to check ({ctx.budget.overflow}).", "P-DATA-002")

    # ---------------------------------------------------------- (c) look-alike characters in account fields
    def _account_script(self, ctx: _Ctx) -> None:
        """Account / routing identifiers are ASCII. A non-ASCII letter or digit (Cyrillic 'А',
        Arabic-Indic digits, mixed-script tokens) in such a field escalates on every tool; on
        money-movement tools a non-ASCII argument NAME escalates too."""
        money = ctx.tool in (self._tools["payment_limit"] | self._tools["vendor_master"]
                             | self._tools["vendor_bank_update"] | self._tools["direct_deposit"])
        for leaf in ctx.leaves:
            if leaf.is_key:
                if money and has_non_ascii_alnum(leaf.text):
                    ctx.hit("R-ACCT-SCRIPT", Verdict.ESCALATE, RiskCategory.PAYMENT_FRAUD,
                            f"Argument name '{leaf.where}' contains look-alike / non-ASCII characters.", "P-PAY-002", leaf)
                continue
            if ctx.payee_class(leaf) in ("account", "routing") and has_non_ascii_alnum(leaf.text):
                ctx.hit("R-ACCT-SCRIPT", Verdict.ESCALATE, RiskCategory.PAYMENT_FRAUD,
                        f"Account field '{leaf.where}' contains look-alike / mixed-script characters.", "P-PAY-002", leaf)

    # ---------------------------------------------------------- shared lookups
    def _arg_id(self, ctx: _Ctx, fields: list[str]) -> Optional[str]:
        args = ctx.req.tool_call.arguments
        return next((str(args[f]) for f in fields if f in args and args[f] not in (None, "")), None)

    def _master(self, ctx: _Ctx, cfg: dict, rule_id: str) -> Optional[dict]:
        """Vendor master record from RecordsLookup, or None after adding an escalate hit."""
        vid = self._arg_id(ctx, cfg.get("arg_vendor_fields", ["vendor_id"]))
        if vid is None:
            ctx.hit(rule_id, Verdict.ESCALATE, RiskCategory.POLICY_VIOLATION,
                    "No vendor_id in the call; the payee cannot be checked against the vendor master.", "P-PAY-002")
            return None
        leaf = next((l for l in ctx.leaves if not l.is_key and l.path[:1] == ("vendor_id",)), None)
        if self.records is None:
            ctx.hit(rule_id, Verdict.ESCALATE, RiskCategory.POLICY_VIOLATION,
                    "No systems-of-record lookup configured; the vendor master cannot be checked.", "P-PAY-002", leaf)
            return None
        try:
            rec = self.records.vendor_master(vid)
        except Exception as e:  # noqa: BLE001 - lookup failure must never pass
            ctx.hit(rule_id, Verdict.ESCALATE, RiskCategory.POLICY_VIOLATION,
                    f"Vendor master lookup failed ({type(e).__name__}); cannot verify the payee.", "P-PAY-002", leaf)
            return None
        if not rec or not (rec.get("account") or rec.get("accounts")):
            ctx.hit(rule_id, Verdict.ESCALATE, RiskCategory.PAYMENT_FRAUD,
                    f"Vendor '{vid[:40]}' has no approved vendor master record with a bank account.", "P-AP-003", leaf)
            return None
        return rec

    @staticmethod
    def _master_accounts(rec: dict) -> set[str]:
        accts = [rec.get("account")] + list(rec.get("accounts") or [])
        return {alnum(a) for a in accts if a}

    def _payee_leaves(self, ctx: _Ctx, cls: str) -> list[_Leaf]:
        return [l for l in ctx.leaves if l.text.strip() and ctx.payee_class(l) == cls]

    # ---------------------------------------------------------- (d) payee vs vendor master -> block
    def _vendor_master(self, ctx: _Ctx) -> None:
        """Payment tools. Every payee field (key words account / iban / beneficiary / payee /
        routing / swift / bic / bank*, any depth) must match the vendor master record:
        account-type fields vs the master account (mismatch -> block), routing-type fields vs
        the master routing codes (mismatch -> block; master has none -> escalate). No payee
        account field, or more than one distinct payee account value -> escalate."""
        cfg = self.config.get("vendor_master", {})
        if ctx.tool not in self._tools["vendor_master"]:
            return
        rec = self._master(ctx, cfg, "R-VM-001")
        if rec is None:
            return
        master = self._master_accounts(rec)
        names = {alnum(rec[f]) for f in ("name", "legal_name") if rec.get(f)}
        names.add(alnum(self._arg_id(ctx, cfg.get("arg_vendor_fields", ["vendor_id"])) or ""))  # payee_id = vendor_id
        accts = self._payee_leaves(ctx, "account")
        generic = [l for l in self._payee_leaves(ctx, "generic") if l.an not in names]
        if not accts:
            ctx.hit("R-VM-001", Verdict.ESCALATE, RiskCategory.POLICY_VIOLATION,
                    "Payment call has no recognised payee account field; cannot check it against the vendor master.",
                    "P-PAY-002")
            return
        distinct = {l.an for l in accts + generic}
        if len(distinct) > 1:
            ctx.hit("R-VM-003", Verdict.ESCALATE, RiskCategory.PAYMENT_FRAUD,
                    f"Payment call names {len(distinct)} different payee values; exactly one payee account is allowed.",
                    "P-PAY-002", (accts + generic)[1])
        for l in generic:
            if l.an not in master and not any(ch.isdigit() for ch in l.an):
                ctx.hit("R-VM-003", Verdict.ESCALATE, RiskCategory.PAYMENT_FRAUD,
                        f"Payee field '{l.where}' cannot be matched to the vendor master record.", "P-PAY-002", l)
        for l in accts + [g for g in generic if any(ch.isdigit() for ch in g.an)]:
            if l.an not in master:
                ctx.hit("R-VM-001", Verdict.BLOCK, RiskCategory.PAYMENT_FRAUD,
                        f"Payee account in '{l.where}' differs from the vendor master record (P-PAY-002).", "P-PAY-002", l)
        routing = {alnum(rec[f]) for f in self._payee["record_routing"] if rec.get(f)}
        for l in self._payee_leaves(ctx, "routing"):
            if not routing:
                ctx.hit("R-VM-001", Verdict.ESCALATE, RiskCategory.PAYMENT_FRAUD,
                        f"Routing field '{l.where}' cannot be verified: the vendor master holds no routing code.",
                        "P-PAY-002", l)
            elif l.an not in routing:
                ctx.hit("R-VM-001", Verdict.BLOCK, RiskCategory.PAYMENT_FRAUD,
                        f"Routing code in '{l.where}' differs from the vendor master record (P-PAY-002).", "P-PAY-002", l)

    # ---------------------------------------------------------- (e) vendor bank-detail change -> escalate
    def _vendor_bank_update(self, ctx: _Ctx) -> None:
        """update_vendor_bank_details: vendor must exist in the master (else escalate). A new
        account that differs from the master is the point of the tool, so it is not blocked;
        it escalates for the P-AP-001 out-of-band call-back. Denylisted accounts block via (a)."""
        cfg = self.config.get("vendor_bank_update", {})
        if ctx.tool not in self._tools["vendor_bank_update"]:
            return
        rec = self._master(ctx, cfg, "R-VM-002")
        if rec is None:
            return
        master = self._master_accounts(rec)
        for l in self._payee_leaves(ctx, "account") + self._payee_leaves(ctx, "routing"):
            if l.an not in master:
                ctx.hit("R-VM-002", Verdict.ESCALATE, RiskCategory.POLICY_VIOLATION,
                        "Bank-detail change for a vendor needs an out-of-band call-back to the number on "
                        "the vendor master record before it takes effect (P-AP-001).", "P-AP-001", l)

    # ---------------------------------------------------------- (f) direct deposit -> escalate without HR record
    def _direct_deposit(self, ctx: _Ctx) -> None:
        """update_direct_deposit escalates unless RecordsLookup.hr_verification(employee_id)
        returns a completed, unexpired HR-portal verification; if that record names the new
        account, the call's account fields must match it (P-HR-001)."""
        cfg = self.config.get("direct_deposit", {})
        if ctx.tool not in self._tools["direct_deposit"]:
            return
        r = "R-HR-001"
        eid = self._arg_id(ctx, cfg.get("arg_employee_fields", ["employee_id"]))
        if eid is None:
            ctx.hit(r, Verdict.ESCALATE, RiskCategory.POLICY_VIOLATION,
                    "Direct-deposit change names no employee; HR portal verification cannot be checked (P-HR-001).",
                    "P-HR-001")
            return
        lookup = getattr(self.records, "hr_verification", None) if self.records is not None else None
        try:
            rec = lookup(eid) if lookup is not None else None
            if rec and rec.get("status") != "verified":
                rec = None
            why = "no completed HR portal verification on record"
        except Exception as e:  # noqa: BLE001
            rec, why = None, f"HR verification lookup failed ({type(e).__name__})"
        if not rec:
            ctx.hit(r, Verdict.ESCALATE, RiskCategory.POLICY_VIOLATION,
                    f"Direct-deposit change for '{eid[:40]}': {why} (P-HR-001).", "P-HR-001")
            return
        if "expires" in rec:
            exp = _parse_ts(rec.get("expires"))
            if exp is None or exp <= self.clock():
                ctx.hit(r, Verdict.ESCALATE, RiskCategory.POLICY_VIOLATION,
                        "HR portal verification has expired or has no valid expiry (P-HR-001).", "P-HR-001")
                return
        if rec.get("account"):
            want = alnum(rec["account"])
            for l in self._payee_leaves(ctx, "account"):
                if l.an != want:
                    ctx.hit(r, Verdict.ESCALATE, RiskCategory.PAYMENT_FRAUD,
                            f"Account in '{l.where}' differs from the account verified in the HR portal (P-HR-001).",
                            "P-HR-001", l)

    # ---------------------------------------------------------- (g) agent limit / approval -> escalate
    def _approval_ok(self, approval_id: str, ctx: _Ctx, amt: Decimal, cur: str, payees: set[str]) -> tuple[bool, str]:
        try:
            rec = self.records.approval(approval_id) if self.records is not None else None
        except Exception as e:  # noqa: BLE001
            return False, f"approval lookup failed ({type(e).__name__})"
        if not rec:
            return False, "no such approval"
        if canonical_tool_name(rec.get("tool", "")) != ctx.tool:
            return False, "approval is for a different tool"
        if str(rec.get("currency", "")).strip().upper() != cur:
            return False, "approval currency differs"
        mx = _parse_amount(rec.get("amount_max"))
        if mx is None or amt > mx:
            return False, "amount above the approved maximum"
        pa = alnum(rec.get("payee_account") or "")
        if not pa or not payees or any(p != pa for p in payees):
            return False, "approval payee account differs"
        exp = _parse_ts(rec.get("expires"))
        if exp is None or exp <= self.clock():
            return False, "approval expired or has no valid expiry"
        return True, "ok"

    def _approval_candidates(self, ctx: _Ctx, cfg: dict) -> list[str]:
        """Approval ids NAMED in the call's own approval_id argument(s). Naming an id proves
        nothing: each is checked in RecordsLookup. Context text is never searched."""
        args = ctx.req.tool_call.arguments
        ids = [normalize_text(str(args[f])).upper() for f in cfg.get("approval_id_fields", ["approval_id"]) if args.get(f)]
        return list(dict.fromkeys(ids))[:5]

    def _payment_limit(self, ctx: _Ctx) -> None:
        """Payment tools. Every numeric value under a key with an amount word (amount, amt,
        total, subtotal, sum, value, price), at any depth including line_items[], is checked.
        The checked figure is the larger of the biggest single value and the biggest sum of
        one field across a list (e.g. line_items[*].amount). Ambiguous or unparseable numbers,
        negative amounts, missing / mixed / unknown currency -> escalate. Converted to the limit
        currency with the configured FX table (fake sample rates). Over the limit needs a
        matching approval from RecordsLookup."""
        cfg = self.config.get("payment_limit", {})
        if ctx.tool not in self._tools["payment_limit"]:
            return
        p = "P-PAY-001"
        amount_tokens = frozenset(cfg.get("amount_key_tokens", ["amount", "amt", "total", "subtotal", "sum", "value", "price"]))
        strict_tokens = frozenset(cfg.get("strict_amount_tokens", ["amount", "amt"]))
        cur_tokens = frozenset(cfg.get("currency_key_tokens", ["currency", "ccy"]))
        not_amount = frozenset(cfg.get("non_amount_key_tokens", ["date", "time", "id", "code", "type", "name", "ref",
                                                                 "reference", "rate"]))
        values: list[tuple[_Leaf, Decimal]] = []
        currencies: dict[str, _Leaf] = {}
        bad = False
        for leaf in ctx.leaves:
            if leaf.is_key:
                continue
            kt = _key_tokens(leaf.last_key)
            if kt & cur_tokens:
                c = normalize_text(leaf.text).upper()
                if c:
                    currencies.setdefault(c, leaf)
                continue
            if not kt & amount_tokens or kt & not_amount:
                continue
            d, status = parse_amount(leaf.raw)
            if status == "ok":
                values.append((leaf, d))
            elif status == "none" and not (kt & strict_tokens):
                continue
            else:
                bad = True
                what = {"ambiguous": "has an ambiguous number format", "none": "is not a number"}.get(status, "could not be parsed")
                ctx.hit("R-LIMIT-001", Verdict.ESCALATE, RiskCategory.POLICY_VIOLATION,
                        f"Payment amount in '{leaf.where}' {what}; cannot check the agent limit.", p, leaf)
        if not values and not bad:
            ctx.hit("R-LIMIT-001", Verdict.ESCALATE, RiskCategory.POLICY_VIOLATION,
                    "Payment call has no recognised amount field; cannot check the agent limit.", p)
            return
        if not currencies:
            ctx.hit("R-LIMIT-001", Verdict.ESCALATE, RiskCategory.POLICY_VIOLATION,
                    "Payment call states no currency; cannot check the agent limit.", p, values[0][0] if values else None)
            return
        if len(currencies) > 1:
            ctx.hit("R-LIMIT-001", Verdict.ESCALATE, RiskCategory.POLICY_VIOLATION,
                    f"Payment call mixes currencies ({', '.join(sorted(currencies))[:80]}); cannot check the agent limit.",
                    p, next(iter(currencies.values())))
            return
        cur, cur_leaf = next(iter(currencies.items()))
        limit = cfg.get("limit", {"amount": 25000, "currency": "USD"})
        fx = {k.upper(): v for k, v in cfg.get("fx_rates", {}).items() if not k.startswith("_")}
        rate = _parse_amount(fx.get(cur)) if cur in fx else None
        if rate is None or rate <= 0:
            ctx.hit("R-LIMIT-001", Verdict.ESCALATE, RiskCategory.POLICY_VIOLATION,
                    f"No FX rate configured for currency {cur[:12]}; human approval required.", p, cur_leaf)
            return
        if not values:
            return
        sums: dict[tuple, Decimal] = {}
        for leaf, d in values:
            if any(isinstance(x, int) for x in leaf.path):
                g = tuple("*" if isinstance(x, int) else x for x in leaf.path)
                sums[g] = sums.get(g, Decimal(0)) + d
        worst_leaf, worst = max(values, key=lambda x: x[1])
        if sums and max(sums.values()) > worst:
            worst = max(sums.values())
        lim = Decimal(str(limit.get("amount")))
        if worst * rate <= lim:
            return
        payees = {l.an for l in self._payee_leaves(ctx, "account")}
        why = [f"{a[:20]}: {self._approval_ok(a, ctx, worst, cur, payees)[1]}" for a in self._approval_candidates(ctx, cfg)]
        if any(w.endswith(": ok") for w in why):
            return
        detail = ("; ".join(why) if why else "no approval id")[:150]
        ctx.hit("R-LIMIT-001", Verdict.ESCALATE, RiskCategory.POLICY_VIOLATION,
                f"Amount {worst} {cur} (= {(worst * rate).quantize(Decimal('0.01'))} {limit.get('currency')}) exceeds "
                f"agent limit {lim} {limit.get('currency')} without a matching approval in the approvals system ({detail}).",
                p, worst_leaf)

    # ---------------------------------------------------------- (h) tools that always need a human
    def _always_escalate(self, ctx: _Ctx) -> None:
        spec = self._always.get(ctx.tool)
        if spec:
            ctx.hit(spec["rule_id"], Verdict.ESCALATE, RiskCategory(spec["category"]), spec["reason"], spec.get("policy_id"))
