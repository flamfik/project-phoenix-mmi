"""Frozen, firmware-independent constraints for the Phoenix UI prototype."""

from __future__ import annotations

from dataclasses import asdict, dataclass


UI_CONSTRAINT_SCHEMA = "phoenix-mmi.ui-constraint-contract/v1"

ABSTRACT_INPUT_ACTIONS = (
    "ACTIVATE",
    "BACK",
    "FOCUS_NEXT",
    "FOCUS_PREVIOUS",
    "HOME",
)


@dataclass(frozen=True)
class ViewportConstraint:
    width: int
    height: int
    orientation: str
    evidence: str
    limitation: str


@dataclass(frozen=True)
class InputConstraint:
    actions: tuple[str, ...]
    focus_required: bool
    pointer_required: bool
    touch_required: bool
    hardware_mapping_status: str
    limitation: str


def build_ui_constraint_contract() -> dict[str, object]:
    """Return the deterministic, publication-safe M5 prototype contract."""

    viewport = ViewportConstraint(
        width=480,
        height=240,
        orientation="LANDSCAPE",
        evidence="Session 077 validated six unique 480x240 resource geometries",
        limitation=(
            "resource geometry does not establish the display controller, "
            "safe area, timing or pixel layout"
        ),
    )
    input_contract = InputConstraint(
        actions=ABSTRACT_INPUT_ACTIONS,
        focus_required=True,
        pointer_required=False,
        touch_required=False,
        hardware_mapping_status="NOT_ESTABLISHED",
        limitation=(
            "actions are host-side abstractions and are not hardware key "
            "codes, scan codes or vehicle messages"
        ),
    )
    contract: dict[str, object] = {
        "schema": UI_CONSTRAINT_SCHEMA,
        "contract_version": "m5-session093-v1",
        "prototype_scope": "OFFLINE_HOST_UI",
        "viewport": asdict(viewport),
        "input": asdict(input_contract),
        "interaction_invariants": {
            "deterministic_transitions_required": True,
            "visible_focus_required": True,
            "touch_only_path_allowed": False,
            "pointer_only_path_allowed": False,
            "vehicle_state_required": False,
            "network_required": False,
            "filesystem_required": False,
        },
        "asset_policy": {
            "allowed_sources": ["ORIGINAL", "SYNTHETIC"],
            "firmware_extracted_assets_allowed": False,
            "navigation_media_assets_allowed": False,
            "vehicle_identifiers_allowed": False,
            "license_provenance_required": True,
        },
        "budget_policy": {
            "numeric_cpu_budget_status": "NOT_ESTABLISHED",
            "numeric_memory_budget_status": "NOT_ESTABLISHED",
            "frame_timing_status": "NOT_ESTABLISHED",
            "prototype_must_report": [
                "DRAW_COMMAND_COUNT",
                "FOCUSABLE_NODE_COUNT",
                "STATE_COUNT",
                "SYNTHETIC_ASSET_BYTES",
            ],
            "limitation": (
                "host measurements must not be presented as MMI hardware "
                "performance"
            ),
        },
        "unresolved_boundaries": [
            "DISPLAY_PIXEL_LAYOUT",
            "DISPLAY_SAFE_AREA",
            "FIRMWARE_RENDERER",
            "FONT_RENDERER",
            "HARDWARE_INPUT_CODES",
            "RUNTIME_RESOURCE_LIFECYCLE",
        ],
        "authorization": {
            "offline_original_ui_code": True,
            "synthetic_fixture_rendering": True,
            "firmware_execution": False,
            "firmware_resource_replacement": False,
            "firmware_repacking": False,
            "installable_artifact_generation": False,
            "vehicle_communication": False,
            "protected_service_emulation": False,
        },
        "classification": {
            "viewport_geometry": "CONFIRMED_RESOURCE_GEOMETRY",
            "input_action_layer": "PROTOTYPE_ABSTRACTION",
            "hardware_mapping": "NOT_ESTABLISHED",
            "renderer_compatibility": "NOT_ESTABLISHED",
            "offline_prototype_ready": True,
        },
        "publication_safety": {
            "firmware_bytes_included": False,
            "payload_bytes_included": False,
            "extracted_resources_included": False,
            "raw_firmware_strings_included": False,
            "navigation_media_content_included": False,
            "vehicle_identifiers_included": False,
            "installable_artifacts_included": False,
            "original_or_synthetic_assets_only": True,
        },
    }
    validate_ui_constraint_contract(contract)
    return contract


def validate_ui_constraint_contract(contract: dict[str, object]) -> None:
    """Fail closed when a caller weakens the frozen Session 093 boundary."""

    if contract.get("schema") != UI_CONSTRAINT_SCHEMA:
        raise ValueError("unsupported UI constraint schema")
    viewport = contract.get("viewport")
    if not isinstance(viewport, dict) or (
        viewport.get("width"),
        viewport.get("height"),
    ) != (480, 240):
        raise ValueError("M5 viewport must remain 480x240")
    input_contract = contract.get("input")
    if not isinstance(input_contract, dict):
        raise ValueError("missing M5 input contract")
    actions = input_contract.get("actions")
    if (
        not isinstance(actions, (list, tuple))
        or tuple(actions) != ABSTRACT_INPUT_ACTIONS
    ):
        raise ValueError("M5 abstract input actions differ")
    if (
        input_contract.get("focus_required") is not True
        or input_contract.get("pointer_required") is not False
        or input_contract.get("touch_required") is not False
        or input_contract.get("hardware_mapping_status") != "NOT_ESTABLISHED"
    ):
        raise ValueError("M5 input safety boundary differs")
    assets = contract.get("asset_policy")
    if not isinstance(assets, dict) or (
        assets.get("firmware_extracted_assets_allowed") is not False
        or assets.get("navigation_media_assets_allowed") is not False
        or assets.get("allowed_sources") != ["ORIGINAL", "SYNTHETIC"]
    ):
        raise ValueError("M5 asset policy differs")
    authorization = contract.get("authorization")
    if not isinstance(authorization, dict):
        raise ValueError("missing M5 authorization boundary")
    forbidden = (
        "firmware_execution",
        "firmware_resource_replacement",
        "firmware_repacking",
        "installable_artifact_generation",
        "vehicle_communication",
        "protected_service_emulation",
    )
    if any(authorization.get(name) is not False for name in forbidden):
        raise ValueError("M5 forbidden operation was enabled")
