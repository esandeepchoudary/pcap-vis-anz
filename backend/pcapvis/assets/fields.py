"""Editable asset fields: the single list of what a consultant can set, and how values are validated.

Each field has an automatic value (derived from traffic, possibly empty) and an optional manual
override. Adding a field here makes it editable, exportable, and part of bundles.
"""

from dataclasses import dataclass
from typing import Any

PURDUE_LEVELS: tuple[float, ...] = (-1, 0, 1, 2, 3, 3.5, 4, 5, 6)
PURDUE_NAMES = {
    -1: "Unclassified",
    0: "Level 0 – Process",
    1: "Level 1 – Basic control",
    2: "Level 2 – Supervisory control",
    3: "Level 3 – Site operations",
    3.5: "Level 3.5 – Industrial DMZ",
    4: "Level 4 – Business network",
    5: "Level 5 – Enterprise",
    6: "External / Internet",
}
CRITICALITIES = ("low", "medium", "high", "critical")
MAX_TAGS = 20
MAX_TAG_LEN = 40
MAX_REASON = 1000


@dataclass(frozen=True)
class FieldSpec:
    name: str
    label: str
    kind: str  # text | longtext | level | choice | tags
    max_len: int = 200
    auto: bool = False  # can traffic provide a value?


FIELDS: dict[str, FieldSpec] = {
    f.name: f
    for f in (
        FieldSpec("name", "Name", "text", 200, auto=True),
        FieldSpec("asset_type", "Type", "text", 100, auto=True),
        FieldSpec("purdue_level", "Purdue level", "level", auto=True),
        FieldSpec("zone", "Zone", "text", 100),
        FieldSpec("criticality", "Criticality", "choice"),
        FieldSpec("vendor", "Vendor", "text", 200, auto=True),
        FieldSpec("model", "Model", "text", 200, auto=True),
        FieldSpec("firmware", "Firmware", "text", 200, auto=True),
        FieldSpec("serial", "Serial number", "text", 200, auto=True),
        FieldSpec("location", "Location", "text", 200, auto=True),
        FieldSpec("owner", "Owner", "text", 200),
        FieldSpec("tags", "Tags", "tags"),
        FieldSpec("notes", "Notes", "longtext", 10_000),
    )
}

EMPTY: dict[str, Any] = {name: ([] if f.kind == "tags" else None) for name, f in FIELDS.items()}
EMPTY["purdue_level"] = -1


class FieldError(ValueError):
    """A field name or value is invalid (message is safe to show)."""


def validate(field: str, value: Any) -> Any:
    """Normalise a manual value for ``field`` or raise FieldError."""
    spec = FIELDS.get(field)
    if spec is None:
        raise FieldError(f"Unknown asset field: {field!r}.")
    if spec.kind in ("text", "longtext"):
        if value is None:
            return None
        if not isinstance(value, str):
            raise FieldError(f"{spec.label} must be text.")
        value = value.strip() if spec.kind == "text" else value.rstrip()
        if len(value) > spec.max_len:
            raise FieldError(f"{spec.label} is longer than {spec.max_len} characters.")
        if spec.kind == "text" and any(c in value for c in "\r\n\t\x00"):
            raise FieldError(f"{spec.label} must be a single line.")
        if "\x00" in value:
            raise FieldError(f"{spec.label} contains invalid characters.")
        return value or None
    if spec.kind == "level":
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise FieldError("Purdue level must be a number.")
        if float(value) not in PURDUE_LEVELS:
            raise FieldError(
                "Purdue level must be one of " + ", ".join(f"{x:g}" for x in PURDUE_LEVELS) + "."
            )
        return int(value) if float(value).is_integer() else float(value)
    if spec.kind == "choice":
        if value is None:
            return None
        if value not in CRITICALITIES:
            raise FieldError("Criticality must be one of " + ", ".join(CRITICALITIES) + ".")
        return value
    if spec.kind == "tags":
        if not isinstance(value, list) or not all(isinstance(t, str) for t in value):
            raise FieldError("Tags must be a list of text values.")
        out: list[str] = []
        for t in value:
            t = t.strip()
            if not t:
                continue
            if len(t) > MAX_TAG_LEN or any(c in t for c in "\r\n\t\x00,"):
                raise FieldError(
                    f"Tags must be single words or short phrases (≤{MAX_TAG_LEN} characters, no commas)."
                )
            if t not in out:
                out.append(t)
        if len(out) > MAX_TAGS:
            raise FieldError(f"At most {MAX_TAGS} tags.")
        return out
    raise FieldError(f"Unsupported field kind {spec.kind}.")  # pragma: no cover


def validate_reason(reason: str | None) -> str:
    reason = (reason or "").strip()
    if len(reason) > MAX_REASON:
        raise FieldError(f"The reason is longer than {MAX_REASON} characters.")
    return reason


def effective(auto: dict, overrides: dict, field: str) -> Any:
    if field in overrides:
        return overrides[field]["value"]
    return auto.get(field, EMPTY[field])


def effective_all(auto: dict, overrides: dict) -> dict[str, Any]:
    return {f: effective(auto, overrides, f) for f in FIELDS}
