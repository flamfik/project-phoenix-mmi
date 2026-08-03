"""Deterministic hazard register and signed-review template for M7."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json


BENCH_RISK_SCHEMA = "phoenix-mmi.bench-risk-register/v1"


@dataclass(frozen=True)
class BenchRisk:
    risk_id: str
    hazard: str
    initial_severity: int
    initial_likelihood: int
    controls: tuple[str, ...]
    residual_severity: int
    residual_likelihood: int
    stop_condition: str

    @property
    def initial_score(self) -> int:
        return self.initial_severity * self.initial_likelihood

    @property
    def residual_score(self) -> int:
        return self.residual_severity * self.residual_likelihood


def build_bench_risk_register() -> dict[str, object]:
    """Return the fixed M7 hazard register and an unsigned review gate."""

    risks = (
        _risk(
            "M7-RISK-001",
            "reverse polarity or wrong connector pinout",
            5,
            3,
            ("AUTHORITATIVE_PINOUT", "POLARITY_CHECK", "KEYED_HARNESS"),
            5,
            1,
            "POLARITY_OR_PINOUT_UNCERTAINTY",
        ),
        _risk(
            "M7-RISK-002",
            "overcurrent or missing source protection",
            5,
            3,
            ("CURRENT_LIMIT", "INLINE_FUSE", "VISIBLE_CURRENT"),
            5,
            1,
            "UNEXPECTED_CURRENT_RISE",
        ),
        _risk(
            "M7-RISK-003",
            "ground loop or unintended electrical path",
            4,
            3,
            ("SINGLE_GROUND_PLAN", "ISOLATED_CAPTURE", "CONTINUITY_CHECK"),
            4,
            1,
            "GROUND_REFERENCE_UNCERTAINTY",
        ),
        _risk(
            "M7-RISK-004",
            "thermal event, odor, smoke or abnormal noise",
            5,
            2,
            ("CLEAR_WORK_AREA", "DIRECT_OBSERVATION", "POWER_CUTOFF"),
            5,
            1,
            "THERMAL_ODOR_SMOKE_OR_NOISE",
        ),
        _risk(
            "M7-RISK-005",
            "accidental firmware, EEPROM or configuration write",
            5,
            2,
            ("NO_UPDATE_MEDIA", "PASSIVE_CAPTURE_ONLY", "ACTION_ALLOWLIST"),
            5,
            1,
            "UNEXPECTED_WRITE_OR_UPDATE_PROMPT",
        ),
        _risk(
            "M7-RISK-006",
            "unplanned vehicle, gateway or live MOST connection",
            5,
            2,
            ("ISOLATED_UNIT", "NO_GATEWAY", "PORT_INVENTORY"),
            5,
            1,
            "UNPLANNED_NETWORK_OR_VEHICLE_CONNECTION",
        ),
        _risk(
            "M7-RISK-007",
            "electrostatic or mechanical damage",
            3,
            3,
            ("ESD_CONTROLS", "SECURE_FIXTURE", "INSULATED_TOOLS"),
            3,
            1,
            "PHYSICAL_FIXTURE_OR_ESD_CONTROL_LOSS",
        ),
        _risk(
            "M7-RISK-008",
            "abort or evidence-capture path unavailable",
            4,
            3,
            ("DUMMY_LOAD_REHEARSAL", "INDEPENDENT_CUTOFF", "CAPTURE_CHECK"),
            4,
            1,
            "LOSS_OF_CAPTURE_OR_INDEPENDENT_CUTOFF",
        ),
    )
    rows = []
    for risk in risks:
        row = asdict(risk)
        row["initial_score"] = risk.initial_score
        row["residual_score"] = risk.residual_score
        rows.append(row)
    register: dict[str, object] = {
        "schema": BENCH_RISK_SCHEMA,
        "register_version": "m7-session116-v1",
        "scoring": {
            "severity_range": [1, 5],
            "likelihood_range": [1, 5],
            "score_formula": "severity_times_likelihood",
            "automatic_acceptance": False,
        },
        "risks": rows,
        "approval_template": {
            "operator_signed": False,
            "independent_reviewer_signed": False,
            "review_fingerprint_recorded": False,
            "all_open_questions_closed": False,
            "approval_expiry_recorded": False,
        },
        "summary": {
            "risk_count": len(rows),
            "max_initial_score": max(row["initial_score"] for row in rows),
            "max_residual_score": max(row["residual_score"] for row in rows),
            "signed_review_complete": False,
        },
        "classification": {
            "risk_register_complete": True,
            "bench_risk_accepted": False,
            "bench_observation_authorized": False,
        },
        "publication_safety": {
            "operator_identity_included": False,
            "reviewer_identity_included": False,
            "signatures_included": False,
            "hardware_identifiers_included": False,
        },
    }
    validate_bench_risk_register(register)
    return register


def validate_bench_risk_register(register: dict[str, object]) -> None:
    """Validate scores and ensure the committed review remains unsigned."""

    if register.get("schema") != BENCH_RISK_SCHEMA:
        raise ValueError("unsupported bench risk schema")
    rows = register.get("risks")
    if not isinstance(rows, list) or len(rows) != 8:
        raise ValueError("bench risk row count differs")
    if len({row.get("risk_id") for row in rows}) != len(rows):
        raise ValueError("duplicate bench risk identifier")
    for row in rows:
        if (
            row.get("initial_score")
            != row.get("initial_severity") * row.get("initial_likelihood")
            or row.get("residual_score")
            != row.get("residual_severity") * row.get("residual_likelihood")
            or row.get("residual_score") > row.get("initial_score")
            or not row.get("controls")
            or not row.get("stop_condition")
        ):
            raise ValueError("invalid bench risk row")
    approval = register.get("approval_template")
    if not isinstance(approval, dict) or any(approval.values()):
        raise ValueError("committed risk review must remain unsigned")
    classification = register.get("classification")
    if not isinstance(classification, dict) or (
        classification.get("bench_risk_accepted") is not False
        or classification.get("bench_observation_authorized") is not False
    ):
        raise ValueError("bench risk authorization differs")


def bench_risk_fingerprint(register: dict[str, object]) -> str:
    """Fingerprint the public risk register without identities or signatures."""

    validate_bench_risk_register(register)
    return sha256(
        json.dumps(
            {
                "schema": register["schema"],
                "risks": register["risks"],
                "scoring": register["scoring"],
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _risk(
    risk_id: str,
    hazard: str,
    initial_severity: int,
    initial_likelihood: int,
    controls: tuple[str, ...],
    residual_severity: int,
    residual_likelihood: int,
    stop_condition: str,
) -> BenchRisk:
    return BenchRisk(
        risk_id,
        hazard,
        initial_severity,
        initial_likelihood,
        controls,
        residual_severity,
        residual_likelihood,
        stop_condition,
    )
