"""Central registry for strict Phoenix MMI machine-readable schemas."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Mapping

from .manifest import ArtifactManifest, MANIFEST_SCHEMA
from .parse_result import PARSE_RESULT_SCHEMA
from .checksum_experiments import CHECKSUM_EXPERIMENT_SCHEMA
from .structural_diff import STRUCTURAL_DIFF_SCHEMA


SCHEMA_REGISTRY_SCHEMA = "phoenix-mmi.schema-registry/v1"
Validator = Callable[[Mapping[str, object]], None]


@dataclass(frozen=True)
class SchemaDefinition:
    schema_id: str
    required_fields: tuple[str, ...]
    validator: Validator | None = None


@dataclass(frozen=True)
class ValidationResult:
    schema_id: str
    valid: bool
    errors: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_id": self.schema_id,
            "valid": self.valid,
            "errors": list(self.errors),
        }


def _validate_manifest(value: Mapping[str, object]) -> None:
    ArtifactManifest.from_dict(value)


def _validate_counts(value: Mapping[str, object]) -> None:
    for field in ("experiment_count",):
        if field in value and (
            not isinstance(value[field], int)
            or isinstance(value[field], bool)
            or value[field] < 0
        ):
            raise ValueError(f"{field} must be a non-negative integer")


class SchemaRegistry:
    def __init__(self, definitions: tuple[SchemaDefinition, ...]) -> None:
        ids = [item.schema_id for item in definitions]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate schema ID")
        self._definitions = {item.schema_id: item for item in definitions}

    @property
    def schema_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._definitions))

    def validate(self, value: Mapping[str, object]) -> ValidationResult:
        schema_id = value.get("schema")
        if not isinstance(schema_id, str):
            return ValidationResult("<absent>", False, ("schema field is absent",))
        definition = self._definitions.get(schema_id)
        if definition is None:
            return ValidationResult(schema_id, False, ("schema is not registered",))
        errors = [
            f"required field is absent: {field}"
            for field in definition.required_fields
            if field not in value
        ]
        if not errors and definition.validator is not None:
            try:
                definition.validator(value)
            except (KeyError, TypeError, ValueError) as error:
                errors.append(str(error))
        return ValidationResult(schema_id, not errors, tuple(errors))

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": SCHEMA_REGISTRY_SCHEMA,
            "schema_count": len(self._definitions),
            "schemas": [
                {
                    "schema_id": item.schema_id,
                    "required_fields": list(item.required_fields),
                    "custom_validator": item.validator is not None,
                }
                for item in sorted(
                    self._definitions.values(), key=lambda value: value.schema_id
                )
            ],
        }


DEFAULT_SCHEMA_REGISTRY = SchemaRegistry(
    (
        SchemaDefinition(
            MANIFEST_SCHEMA,
            (
                "schema",
                "manifest_id",
                "manifest_fingerprint",
                "artifact_count",
                "artifacts",
            ),
            _validate_manifest,
        ),
        SchemaDefinition(
            PARSE_RESULT_SCHEMA,
            (
                "schema",
                "parser_id",
                "family",
                "classification",
                "fully_validated",
                "regions",
                "diagnostics",
                "metrics",
            ),
        ),
        SchemaDefinition(
            CHECKSUM_EXPERIMENT_SCHEMA,
            (
                "schema",
                "experiment_count",
                "outcome_counts",
                "results",
                "unresolved_integrity_questions",
            ),
            _validate_counts,
        ),
        SchemaDefinition(
            STRUCTURAL_DIFF_SCHEMA,
            (
                "schema",
                "equal",
                "difference_count",
                "kind_counts",
                "differences",
            ),
        ),
    )
)


def build_public_schema_registry_summary(
    registry: SchemaRegistry = DEFAULT_SCHEMA_REGISTRY,
) -> dict[str, object]:
    return {
        "schema": "phoenix-mmi.schema-registry-summary/v1",
        "registry_schema": SCHEMA_REGISTRY_SCHEMA,
        "registered_schema_count": len(registry.schema_ids),
        "registered_schemas": list(registry.schema_ids),
        "unknown_schemas_rejected": True,
        "raw_artifact_bytes_included": False,
    }
