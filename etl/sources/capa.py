"""Loader for mandiant/capa-rules -- the API-combination layer.

capa rules are the only curated, machine-readable, community-maintained
description of *which combinations of Windows APIs mean what*, and each one
carries its ATT&CK and MBC mapping. A rule is literally a boolean tree over
``api:`` features, which is exactly the question "what can this binary do?".

What this module does is flatten each rule to an **API-only feature program**: a
postfix opcode stream that the C++ runtime evaluates against a set of API ids
with no YAML, no JSON and no string hashing. Features capa can evaluate but we
cannot -- strings, bytes, numbers, mnemonics, characteristics -- become explicit
``UNKNOWN`` leaves rather than being silently dropped, because dropping them
would turn "this rule needs four things, one of which we can check" into a
confident false positive.

Two honest limits, both surfaced to the analyst rather than hidden:

  * capa's static scope requires the APIs to appear in the *same function*. An
    import-set match only proves they are all present somewhere in the binary.
  * ``UNKNOWN`` leaves mean a rule can be *satisfiable* without being *satisfied*.
    Callers evaluate twice -- unknowns false, then unknowns true -- to separate
    "Confirmed" from "Possible".
"""

from __future__ import annotations

import json
import re
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from normalize import canonical

# --------------------------------------------------------------------------
# Feature program opcodes. Mirrored by src/capa_eval.cpp -- keep in step.
# --------------------------------------------------------------------------

OP_API = 0x01  # + u32 api_id      push: api_id is in the target's API set
OP_UNKNOWN = 0x02  #                push: a feature we cannot evaluate
OP_TRUE = 0x03  #                   push: always satisfied (an `optional:` block)
OP_FALSE = 0x04  #                  push: statically unsatisfiable here
OP_AND = 0x10  # + u16 count        pop count, push their conjunction
OP_OR = 0x11  # + u16 count         pop count, push their disjunction
OP_NOT = 0x12  #                    pop 1, push its negation
OP_NOF = 0x13  # + u16 n + u16 cnt  pop cnt, push (at least n are true)

PROGRAM_VERSION = 1

#: `os:` and `format:` are the two non-API features we can answer with certainty:
#: this plugin only ever runs inside x64dbg, debugging a Windows PE. Resolving
#: them to TRUE/FALSE at build time instead of UNKNOWN keeps rules gated on
#: "os: linux" from being reported as possible on a Windows target.
_TRUE_OS_VALUES = {"windows"}
_TRUE_FORMAT_VALUES = {"pe"}

#: Statements that group children rather than testing anything themselves.
_BOOLEAN_STATEMENTS = {"and", "or", "not", "optional"}

#: Scope statements. capa uses these to require that the children match within
#: one basic block, instruction or call. We cannot enforce locality from an
#: import table, so we descend through them as a conjunction and let the
#: over-approximation be reported rather than pretending it does not exist.
_SCOPE_STATEMENTS = {
    "basic block",
    "instruction",
    "call",
    "function",
    "thread",
    "process",
    "span of calls",
}

#: Keys that are documentation, not logic.
_IGNORED_KEYS = {"description", "com/class", "com/interface"}

#: Feature keys naming a Windows API. `import:` names one in the import table;
#: `api:` names one that is called. Both are API evidence for our purposes.
_API_KEYS = {"api", "import"}

_N_OR_MORE_RE = re.compile(r"^(\d+)\s+or\s+more$")
_TECHNIQUE_RE = re.compile(r"\[([A-Z]\d{4}(?:\.\d+)*)\]\s*$")


@dataclass
class CapaRule:
    """A rule flattened to something the runtime can evaluate."""

    name: str
    namespace: str | None
    description: str | None
    attck: list[dict[str, str]] = field(default_factory=list)
    mbc: list[dict[str, str]] = field(default_factory=list)
    scope_static: str | None = None
    scope_dynamic: str | None = None
    is_lib: bool = False
    references: list[str] = field(default_factory=list)
    #: Normalized API names this rule mentions, in first-seen order. Includes
    #: names appearing only inside `optional:` blocks, which contribute no leaf.
    apis: list[str] = field(default_factory=list)
    has_unknown: bool = False
    #: Nested tuple tree; serialized to bytes by :func:`emit_program`.
    tree: Any = None

    def leaf_counts(self) -> tuple[int, int]:
        """Return ``(api_leaves, unknown_leaves)`` in the compiled program.

        The deciding measurement for how much an import table can say about this
        rule. Zero unknown leaves means every test is an API test, so a match is
        as sound as the import table itself; any unknown leaf means capa is also
        checking a string, constant or instruction we cannot observe.
        """
        return _count_leaves(self.tree)


# --------------------------------------------------------------------------
# Loading
# --------------------------------------------------------------------------


def load(rules_dir: Path) -> list[CapaRule]:
    """Parse every rule under ``rules_dir`` and compile its feature program."""
    raw: dict[str, dict] = {}
    for path in sorted(rules_dir.rglob("*.yml")):
        try:
            document = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise ValueError(f"{path}: {exc}") from exc
        if not isinstance(document, dict) or "rule" not in document:
            continue
        rule = document["rule"]
        name = (rule.get("meta") or {}).get("name")
        if not name:
            raise ValueError(f"{path}: rule has no meta.name")
        raw[name] = rule

    by_namespace: dict[str, list[str]] = {}
    for name, rule in raw.items():
        namespace = (rule.get("meta") or {}).get("namespace")
        if namespace:
            by_namespace.setdefault(namespace, []).append(name)

    return [_compile_rule(name, raw, by_namespace) for name in sorted(raw)]


def _compile_rule(
    name: str, raw: dict[str, dict], by_namespace: dict[str, list[str]]
) -> CapaRule:
    rule = raw[name]
    meta = rule.get("meta") or {}
    scopes = meta.get("scopes") or {}

    compiled = CapaRule(
        name=name,
        namespace=meta.get("namespace"),
        description=meta.get("description"),
        attck=[_parse_technique(t) for t in meta.get("att&ck") or ()],
        mbc=[_parse_technique(t) for t in meta.get("mbc") or ()],
        scope_static=scopes.get("static") if isinstance(scopes, dict) else None,
        scope_dynamic=scopes.get("dynamic") if isinstance(scopes, dict) else None,
        is_lib=bool(meta.get("lib")),
        references=[str(r) for r in meta.get("references") or ()],
    )

    state = _CompileState(raw=raw, by_namespace=by_namespace, rule=compiled)
    compiled.tree = state.compile_children(rule.get("features") or [], {name})
    return compiled


@dataclass
class _CompileState:
    """Carries the rule being built so leaves can record what they saw."""

    raw: dict[str, dict]
    by_namespace: dict[str, list[str]]
    rule: CapaRule

    def note_api(self, key: str) -> None:
        if key not in self.rule.apis:
            self.rule.apis.append(key)

    def note_unknown(self) -> None:
        self.rule.has_unknown = True

    # -- tree construction -------------------------------------------------

    def compile_children(self, children: Any, active: set[str]) -> Any:
        """Compile a list of sibling nodes into a conjunction."""
        if not isinstance(children, list):
            children = [children]
        nodes = [self.compile_node(child, active) for child in children]
        nodes = [n for n in nodes if n is not None]
        if not nodes:
            return ("true",)
        if len(nodes) == 1:
            return nodes[0]
        return ("and", nodes)

    def compile_node(self, node: Any, active: set[str]) -> Any:
        if node is None:
            return None
        if not isinstance(node, dict):
            # A bare scalar under a statement is not something capa emits.
            self.note_unknown()
            return ("unknown",)

        keys = [k for k in node if k not in _IGNORED_KEYS]
        if not keys:
            return None
        if len(keys) > 1:
            # capa statements carry exactly one logical key; anything else means
            # the schema moved and we should not guess.
            raise ValueError(f"{self.rule.name}: multiple keys in one node: {keys}")

        key = keys[0]
        value = node[key]

        if key in _BOOLEAN_STATEMENTS:
            return self._compile_boolean(key, value, active)
        if key in _SCOPE_STATEMENTS:
            return self.compile_children(value, active)

        count = _N_OR_MORE_RE.match(key)
        if count:
            children = value if isinstance(value, list) else [value]
            nodes = [self.compile_node(c, active) for c in children]
            nodes = [n for n in nodes if n is not None]
            return ("nof", int(count.group(1)), nodes)

        if key == "match":
            return self._compile_match(str(value), active)

        if key in _API_KEYS:
            return self._compile_api(str(value))

        if key == "os":
            return ("true",) if str(value).strip().lower() in _TRUE_OS_VALUES else ("false",)
        if key == "format":
            return (
                ("true",)
                if str(value).strip().lower() in _TRUE_FORMAT_VALUES
                else ("false",)
            )

        # Everything else -- string, number, bytes, mnemonic, characteristic,
        # offset, section, export, os, arch, format, count(...) -- is real
        # evidence capa uses that an import table cannot answer.
        self.note_unknown()
        return ("unknown",)

    def _compile_boolean(self, key: str, value: Any, active: set[str]) -> Any:
        children = value if isinstance(value, list) else [value]

        if key == "optional":
            # capa's `optional` is display-only: it never causes a rule to fail.
            # Compile the children anyway so their APIs land in the rule's API
            # list for the panel, then discard the result.
            for child in children:
                self.compile_node(child, active)
            return ("true",)

        nodes = [self.compile_node(child, active) for child in children]
        nodes = [n for n in nodes if n is not None]
        if not nodes:
            return ("true",)

        if key == "not":
            if len(nodes) != 1:
                nodes = [("and", nodes)]
            return ("not", nodes[0])
        if len(nodes) == 1:
            return nodes[0]
        return (key, nodes)

    def _compile_match(self, target: str, active: set[str]) -> Any:
        """Inline a referenced rule, or a whole namespace, resolving cycles."""
        if target in self.raw:
            if target in active:
                # Mutual recursion between rules: treat the back-edge as
                # unevaluable rather than looping forever.
                self.note_unknown()
                return ("unknown",)
            referenced = self.raw[target]
            return self.compile_children(
                referenced.get("features") or [], active | {target}
            )

        # A namespace reference matches any rule in it or below it.
        members = [
            name
            for namespace, names in self.by_namespace.items()
            if namespace == target or namespace.startswith(target + "/")
            for name in names
        ]
        members = [m for m in sorted(set(members)) if m not in active]
        if not members:
            self.note_unknown()
            return ("unknown",)

        nodes = [
            self.compile_children(
                self.raw[m].get("features") or [], active | {m}
            )
            for m in members
        ]
        return ("or", nodes) if len(nodes) > 1 else nodes[0]

    def _compile_api(self, value: str) -> Any:
        key = normalize_api_feature(value)
        if not key:
            self.note_unknown()
            return ("unknown",)
        self.note_api(key)
        return ("api", key)


def _count_leaves(node: Any) -> tuple[int, int]:
    """Count ``(api, unknown)`` leaves in a compiled tree."""
    if node is None:
        return 0, 0
    kind = node[0]
    if kind == "api":
        return 1, 0
    if kind == "unknown":
        return 0, 1
    if kind in ("true", "false"):
        return 0, 0
    if kind == "not":
        return _count_leaves(node[1])

    children = node[1] if kind in ("and", "or") else node[2]
    api = unknown = 0
    for child in children:
        child_api, child_unknown = _count_leaves(child)
        api += child_api
        unknown += child_unknown
    return api, unknown


def normalize_api_feature(value: str) -> str | None:
    """Turn a capa ``api:`` value into the key used everywhere else.

    ``kernel32.VirtualAllocEx`` -> ``VirtualAllocEx``, then folded by
    :func:`normalize.canonical` so it agrees with the index and with whatever
    x64dbg puts on screen. .NET method references keep their full spelling: they
    can never match a native import set, and that FALSE is the correct answer for
    a native target rather than an UNKNOWN that would inflate "Possible".
    """
    value = value.strip()
    if not value:
        return None
    if "::" in value:
        return value
    function = value.rsplit(".", 1)[-1] if "." in value else value
    return canonical(function) or None


def _parse_technique(entry: Any) -> dict[str, str]:
    """Split ``A::B::C [T1055.004]`` into its id and readable path."""
    text = str(entry).strip()
    match = _TECHNIQUE_RE.search(text)
    if not match:
        return {"id": "", "text": text}
    return {"id": match.group(1), "text": _TECHNIQUE_RE.sub("", text).strip()}


# --------------------------------------------------------------------------
# Program emission
# --------------------------------------------------------------------------


def emit_program(tree: Any, api_ids: dict[str, int]) -> bytes:
    """Serialize a compiled tree to the postfix opcode stream.

    Postfix so the C++ evaluator is a flat loop over a small stack -- no
    recursion, and therefore no way for a pathological rule to blow the stack
    inside x64dbg.
    """
    out = bytearray()
    _emit(tree, api_ids, out)
    return bytes(out)


def _emit(node: Any, api_ids: dict[str, int], out: bytearray) -> None:
    kind = node[0]

    if kind == "api":
        out.append(OP_API)
        out.extend(struct.pack("<I", api_ids[node[1]]))
    elif kind == "unknown":
        out.append(OP_UNKNOWN)
    elif kind == "true":
        out.append(OP_TRUE)
    elif kind == "false":
        out.append(OP_FALSE)
    elif kind == "not":
        _emit(node[1], api_ids, out)
        out.append(OP_NOT)
    elif kind in ("and", "or"):
        children = node[1]
        for child in children:
            _emit(child, api_ids, out)
        out.append(OP_AND if kind == "and" else OP_OR)
        out.extend(struct.pack("<H", len(children)))
    elif kind == "nof":
        _, threshold, children = node
        for child in children:
            _emit(child, api_ids, out)
        out.append(OP_NOF)
        out.extend(struct.pack("<HH", threshold, len(children)))
    else:
        raise ValueError(f"unknown node kind: {kind!r}")


# --------------------------------------------------------------------------
# Reference evaluator -- mirrored by src/capa_eval.cpp
# --------------------------------------------------------------------------


def evaluate(program: bytes, present: set[int], unknown_is_true: bool) -> bool:
    """Evaluate a feature program against a set of present API ids.

    Call twice per rule: ``unknown_is_true=False`` gives *Confirmed* (satisfied by
    APIs alone), ``True`` gives *Possible* (satisfied if the features we cannot
    check also hold).
    """
    stack: list[bool] = []
    offset = 0
    size = len(program)

    while offset < size:
        op = program[offset]
        offset += 1

        if op == OP_API:
            (api_id,) = struct.unpack_from("<I", program, offset)
            offset += 4
            stack.append(api_id in present)
        elif op == OP_UNKNOWN:
            stack.append(unknown_is_true)
        elif op == OP_TRUE:
            stack.append(True)
        elif op == OP_FALSE:
            stack.append(False)
        elif op == OP_NOT:
            stack.append(not stack.pop())
        elif op in (OP_AND, OP_OR):
            (count,) = struct.unpack_from("<H", program, offset)
            offset += 2
            operands = [stack.pop() for _ in range(count)]
            stack.append(all(operands) if op == OP_AND else any(operands))
        elif op == OP_NOF:
            threshold, count = struct.unpack_from("<HH", program, offset)
            offset += 4
            operands = [stack.pop() for _ in range(count)]
            stack.append(sum(operands) >= threshold)
        else:
            raise ValueError(f"bad opcode 0x{op:02x} at offset {offset - 1}")

    if len(stack) != 1:
        raise ValueError(f"program left {len(stack)} values on the stack")
    return stack[0]


def to_json(values: Any) -> str | None:
    return json.dumps(values, separators=(",", ":")) if values else None
