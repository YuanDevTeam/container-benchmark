"""Bounded disk checkpoints referencing existing immutable public reports.

Campaign and RoundLedger retain their current logical schema in memory. Only
the on-disk checkpoint replaces repeated assessments with verified references.
This is persistence deduplication, not a process-memory or history-size limit.
"""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

from .inputs import save
from .mac_full_collect import public_record
from .mac_full_plan import digest, is_sha256, scope_digest

MAX_JSON_BYTES = 32 * 1024 * 1024
ENCODING = "mac-full-report-assessments-v1"
_LIST_FIELDS = ("runs", "historicalPasses")
_MAP_FIELDS = ("primaryMeasurements", "currentPasses")
_ROW_FIELDS = (*_LIST_FIELDS, *_MAP_FIELDS)
_REFERENCE_FIELDS = {"runID", "reportSHA256", "assessmentSHA256", "scopeSHA256"}
_QUALIFICATION_KINDS = {"primary", "retest", "shared-regression", "final-qualification"}


def report_name(run_id):
    """Never interpret a retained run ID as a filesystem path."""
    if not isinstance(run_id, str) or not run_id.strip():
        raise ValueError("an exact nonempty run ID is required")
    return "report-" + digest({"reportID": run_id}) + ".json"


def _read_object(path, *, limit=MAX_JSON_BYTES):
    if type(limit) is not int or not 0 < limit <= MAX_JSON_BYTES:
        raise ValueError("JSON limit must remain within the existing bound")
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
        raise ValueError("explicit bounded JSON record required")
    with path.open("rb") as source:
        raw = source.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("JSON record grew beyond its read bound")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("JSON record must be an object")
    return value


def _rows(snapshot):
    ledger = snapshot.get("ledger")
    if not isinstance(ledger, dict):
        raise ValueError("checkpoint ledger is required")
    for field in _LIST_FIELDS:
        values = ledger.get(field)
        if not isinstance(values, list) or any(
            not isinstance(row, dict) for row in values
        ):
            raise ValueError("checkpoint ledger list differs")
        yield from values
    for field in _MAP_FIELDS:
        values = ledger.get(field)
        if not isinstance(values, dict):
            raise ValueError("checkpoint ledger index differs")
        for identifier, row in values.items():
            if not isinstance(row, dict) or row.get("windowID") != identifier:
                raise ValueError("checkpoint ledger index changes the exact window")
            yield row


def _proofs(snapshot):
    rows = snapshot.get("reports")
    if not isinstance(rows, list):
        raise ValueError("checkpoint report index is required")
    result = {}
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("checkpoint report index entry differs")
        run_id = row.get("runID")
        report_name(run_id)
        if run_id in result or not is_sha256(row.get("reportSHA256")):
            raise ValueError("duplicate or invalid retained report identity")
        result[run_id] = row
    return result


def _windows(snapshot):
    plan = snapshot.get("plan")
    rows = plan.get("windows") if isinstance(plan, dict) else None
    if not isinstance(rows, list):
        raise ValueError("checkpoint planned windows are required")
    result = {}
    for row in rows:
        identifier = row.get("windowID") if isinstance(row, dict) else None
        if not isinstance(identifier, str) or not identifier or identifier in result:
            raise ValueError("duplicate or invalid checkpoint window")
        result[identifier] = row
    return result


def _validate_row(snapshot, row, proofs, windows, assessment):
    proof = proofs.get(row.get("runID"))
    if proof is None or proof["reportSHA256"] != row.get("reportSHA256"):
        raise ValueError("ledger row does not reference its retained report")
    if not isinstance(assessment, dict):
        raise ValueError("ledger assessment must be an object")
    identifier = row.get("windowID")
    if not isinstance(identifier, str):
        raise ValueError("ledger row needs an exact window ID")
    manifest = windows.get(identifier)
    if manifest is None or (
        assessment.get("windowID") != row.get("windowID")
        or assessment.get("workloadVersion") != snapshot.get("workloadVersion")
        or assessment.get("scopeSHA256") != scope_digest(manifest)
    ):
        raise ValueError("ledger assessment changes its exact window or scope")
    stage = assessment.get("stage")
    if isinstance(stage, dict) and stage.get("kind") is not None:
        raise ValueError("legacy campaign stage proof requires the archived campaign")
    if proof.get("windowID") != row.get("windowID"):
        raise ValueError("retained report index changes the assessment window")


def _validate_views(snapshot, proofs):
    """Copied proof views cannot retag a canonical run's build or status."""
    runs = snapshot["ledger"]["runs"]
    canonical = {}
    for row in runs:
        run_id = row.get("runID")
        report_name(run_id)
        if run_id in canonical:
            raise ValueError("duplicate canonical ledger run")
        canonical[run_id] = row
    for row in _rows(snapshot):
        report_name(row.get("runID"))
        proof = proofs.get(row["runID"])
        if proof is None or proof["reportSHA256"] != row.get("reportSHA256"):
            raise ValueError("ledger row changes its retained report identity")
        if row != canonical.get(row.get("runID")):
            raise ValueError("copied ledger proof differs from its canonical run")


def reject_migrated_checkpoint(snapshot):
    """Reject campaign-specific source or measurement history before reading reports."""
    receipts = (
        "measurementEpoch",
        "publicationRepair",
        "publicationSourceUpdate",
        "hopBusinessEpoch",
        "hopBusinessSuccessor",
    )
    histories = (
        "controllerSourceUpdates",
        "peerStopSourceUpdates",
        "postMeasurementPeerReviews",
    )
    fields = [field for field in receipts if field in snapshot]
    fields += [field for field in histories if snapshot.get(field, []) != []]
    configuration = snapshot.get("runConfiguration")
    if (
        isinstance(configuration, dict)
        and "hopBusinessPeerGenerations" in configuration
    ):
        fields.append("hopBusinessPeerGenerations")
    if fields:
        raise ValueError(
            "checkpoint contains legacy campaign history; use its archived campaign: "
            + ", ".join(fields)
        )


def encode_checkpoint(snapshot):
    """Store references to exactly the published report assessments."""
    if not isinstance(snapshot, dict) or "checkpointEncoding" in snapshot:
        raise ValueError("encoding requires a logical checkpoint snapshot")
    reject_migrated_checkpoint(snapshot)
    proofs = _proofs(snapshot)
    windows = _windows(snapshot)
    _validate_views(snapshot, proofs)
    ledger = snapshot["ledger"]

    def encode_row(row):
        if "assessmentRef" in row:
            raise ValueError("logical checkpoint contains a disk assessment reference")
        result = {
            key: deepcopy(value) for key, value in row.items() if key != "assessment"
        }
        if "assessment" not in row:
            if row.get("runKind") in _QUALIFICATION_KINDS:
                raise ValueError("qualification run is missing its assessment")
            return result
        assessment = row["assessment"]
        if assessment != public_record({"acceptance": assessment}).get("acceptance"):
            raise ValueError("assessment is not its published value")
        _validate_row(snapshot, row, proofs, windows, assessment)
        result["assessmentRef"] = {
            "runID": row["runID"],
            "reportSHA256": row["reportSHA256"],
            "assessmentSHA256": digest(assessment),
            "scopeSHA256": assessment["scopeSHA256"],
        }
        return result

    result = {
        key: deepcopy(value) for key, value in snapshot.items() if key != "ledger"
    }
    result["ledger"] = {
        key: deepcopy(value) for key, value in ledger.items() if key not in _ROW_FIELDS
    }
    for field in _LIST_FIELDS:
        result["ledger"][field] = [encode_row(row) for row in ledger[field]]
    for field in _MAP_FIELDS:
        result["ledger"][field] = {
            key: encode_row(row) for key, row in ledger[field].items()
        }
    result["checkpointEncoding"] = ENCODING
    return result


def _retained(snapshot, output):
    output = Path(output)
    if output.is_symlink() or not output.is_dir():
        raise ValueError("retained reports require the explicit real output directory")
    output = output.resolve(strict=True)
    proofs = _proofs(snapshot)
    retained = {}
    for run_id, proof in proofs.items():
        report = _read_object(output / report_name(run_id))
        if digest(report) != proof["reportSHA256"]:
            raise ValueError("persisted conclusion changed since its checkpoint")
        retained[run_id] = report
    for report_hash in snapshot.get("reviewedReportSHA256s", []):
        if (
            not is_sha256(report_hash)
            or digest(_read_object(output / ("review-" + report_hash + ".json")))
            != report_hash
        ):
            raise ValueError("reviewed owner report changed since its checkpoint")
    return proofs, retained


def _validate_hydrated(snapshot, proofs, retained):
    windows = _windows(snapshot)
    for row in _rows(snapshot):
        if "assessmentRef" in row:
            raise ValueError("logical checkpoint still contains a disk reference")
        if "assessment" not in row:
            if row.get("runKind") in _QUALIFICATION_KINDS:
                raise ValueError("qualification run is missing its assessment")
            continue
        assessment = row["assessment"]
        _validate_row(snapshot, row, proofs, windows, assessment)
        report = retained[row["runID"]]
        if (
            report.get("runID") != row["runID"]
            or report.get("windowID") != row["windowID"]
            or report.get("workloadVersion") != snapshot.get("workloadVersion")
            or assessment != report.get("acceptance")
        ):
            raise ValueError("qualification does not match its exact retained report")
    _validate_views(snapshot, proofs)


def verify_retained_reports(snapshot, output):
    """Verify the exact reports needed to resume the logical checkpoint."""
    reject_migrated_checkpoint(snapshot)
    proofs, retained = _retained(snapshot, output)
    _validate_hydrated(snapshot, proofs, retained)


def read_checkpoint(path, output, *, limit=MAX_JSON_BYTES):
    value = _read_object(path, limit=limit)
    reject_migrated_checkpoint(value)
    encoded = "checkpointEncoding" in value
    encoding = value.pop("checkpointEncoding", None)
    if encoded and encoding != ENCODING:
        raise ValueError("unknown checkpoint encoding")
    proofs, retained = _retained(value, output)
    if encoded:
        for row in _rows(value):
            if "assessment" in row:
                raise ValueError("encoded checkpoint contains an inline assessment")
            if "assessmentRef" not in row:
                continue
            reference = row.pop("assessmentRef")
            if not isinstance(reference, dict) or set(reference) != _REFERENCE_FIELDS:
                raise ValueError("invalid assessment reference")
            if (
                reference["runID"] != row.get("runID")
                or reference["reportSHA256"] != row.get("reportSHA256")
                or not is_sha256(reference["assessmentSHA256"])
            ):
                raise ValueError("assessment reference changes its run or report")
            report = retained.get(reference["runID"], {})
            assessment = report.get("acceptance")
            if (
                not isinstance(assessment, dict)
                or assessment.get("scopeSHA256") != reference["scopeSHA256"]
            ):
                raise ValueError("assessment reference changes its report or scope")
            if digest(assessment) != reference["assessmentSHA256"]:
                raise ValueError("assessment reference changes its report or scope")
            row["assessment"] = deepcopy(assessment)
    _validate_hydrated(value, proofs, retained)
    return value


def write_checkpoint(path, snapshot, *, limit=MAX_JSON_BYTES):
    """Refuse an unreadable checkpoint before replacing the previous file."""
    if type(limit) is not int or not 0 < limit <= MAX_JSON_BYTES:
        raise ValueError("checkpoint limit must remain within the existing bound")
    value = encode_checkpoint(snapshot)
    # Match inputs.save exactly: indent=2, default ensure_ascii=True,
    # allow_nan=False, UTF-8 and its single trailing newline. Check chunks
    # before save opens a .partial file, without joining the whole encoding.
    size = 1
    encoder = json.JSONEncoder(indent=2, allow_nan=False)
    for chunk in encoder.iterencode(value):
        size += len(chunk.encode())
        if size > limit:
            raise ValueError("checkpoint would exceed its own read limit")
    save(Path(path), value)
