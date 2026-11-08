#!/usr/bin/env python3
"""Train/export a bounded, group-validated Android APK risk forest."""
from __future__ import annotations
import argparse
import hashlib
import json
import math
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import average_precision_score, f1_score, precision_score, recall_score, roc_auc_score, roc_curve
from sklearn.model_selection import GroupShuffleSplit

FEATURES = [
    "apk_present", "file_size_mib", "target_sdk", "permission_count",
    "risky_permission_count", "debuggable", "exported_components",
    "accessibility_services", "permission_sms", "permission_install_packages",
    "permission_overlay", "permission_accessibility", "permission_device_admin",
    "permission_contacts", "permission_call_log", "permission_location",
    "permission_record_audio", "permission_camera", "permission_boot",
    "dex_sms_api", "dex_package_install_api", "dex_dynamic_code_loading",
    "dex_process_execution", "dex_accessibility_api", "dex_device_admin_api",
    "dex_network_api", "elf_execve_symbol", "elf_system_symbol",
    "elf_ptrace_symbol", "elf_dlopen_symbol", "archive_entry_count_log1p",
    "archive_expanded_mib", "archive_anomaly", "format_anomaly",
    "static_analysis_supported", "static_analysis_complete",
    "native_content_engine_complete",
]
FORMAT = "ALAI-MV-FOREST/1"


def normalize_labels(series: pd.Series) -> np.ndarray:
    mapping = {
        "0": 0, "benign": 0, "clean": 0, "goodware": 0,
        "1": 1, "malware": 1, "malicious": 1,
    }
    normalized = series.astype(str).str.strip().str.lower()
    unknown = sorted(set(normalized) - set(mapping))
    if unknown:
        raise ValueError(f"Unknown labels: {unknown[:8]}; use benign/malware or 0/1")
    return normalized.map(mapping).to_numpy(dtype=np.int8)


def group_train_calibration_test(y: np.ndarray, groups: np.ndarray, seed: int):
    """Create disjoint package/family-group train, calibration and test partitions."""
    for attempt in range(60):
        outer = GroupShuffleSplit(n_splits=1, test_size=0.20, random_state=seed + attempt)
        train_cal_idx, test_idx = next(outer.split(np.zeros(len(y)), y, groups))
        inner = GroupShuffleSplit(n_splits=1, test_size=0.25, random_state=seed + 1000 + attempt)
        train_rel, calibration_rel = next(
            inner.split(np.zeros(len(train_cal_idx)), y[train_cal_idx], groups[train_cal_idx])
        )
        train_idx = train_cal_idx[train_rel]
        calibration_idx = train_cal_idx[calibration_rel]
        partitions = (train_idx, calibration_idx, test_idx)
        if all(len(np.unique(y[index])) == 2 for index in partitions):
            if all(min(np.bincount(y[index], minlength=2)) >= 10 for index in partitions):
                group_sets = [set(groups[index]) for index in partitions]
                if not (group_sets[0] & group_sets[1] or group_sets[0] & group_sets[2]
                        or group_sets[1] & group_sets[2]):
                    return train_idx, calibration_idx, test_idx
    raise ValueError(
        "Could not create group-disjoint train/calibration/test partitions "
        "with at least 10 examples per class in each partition"
    )

def export_tree(estimator, positive_class_index: int):
    tree = estimator.tree_
    nodes = []
    for index in range(tree.node_count):
        left = int(tree.children_left[index])
        right = int(tree.children_right[index])
        if left == right:
            counts = tree.value[index][0]
            total = float(np.sum(counts))
            score = float(counts[positive_class_index] / total) if total else 0.0
            nodes.append([-1, 0.0, -1, -1, score])
        else:
            nodes.append([
                int(tree.feature[index]), float(tree.threshold[index]),
                left, right, 0.0,
            ])
    return nodes


def train_dataset(
    input_csv: Path, output_json: Path, *, label_column: str, group_column: str,
    dataset_name: str, dataset_reference: str, dataset_license: str,
    target_fpr: float = 0.01, minimum_recall: float = 0.50,
    random_state: int = 20261108, estimators: int = 64,
) -> dict[str, Any]:
    if not 0.0001 <= target_fpr <= 0.05:
        raise ValueError("target_fpr must be between 0.0001 and 0.05")
    if not 0 <= minimum_recall <= 1:
        raise ValueError("minimum_recall must be between 0 and 1")
    if not 16 <= estimators <= 64:
        raise ValueError("estimators must be between 16 and 64")
    if not all(value.strip() for value in (dataset_name, dataset_reference, dataset_license)):
        raise ValueError("Dataset name, reference and license are required")

    frame = pd.read_csv(input_csv)
    required = set(FEATURES) | {label_column, group_column}
    missing = sorted(required - set(frame.columns))
    if missing:
        raise ValueError(f"Missing required CSV columns: {missing}")
    if label_column in FEATURES or group_column in FEATURES:
        raise ValueError("Label/group metadata must not be model features")

    y = normalize_labels(frame[label_column])
    groups = frame[group_column].fillna("").astype(str).to_numpy()
    if np.any(groups == ""):
        raise ValueError("Group identifiers cannot be empty")
    if len(frame) < 300 or len(np.unique(groups)) < 30:
        raise ValueError("At least 300 rows and 30 independent groups are required")
    if min(np.bincount(y, minlength=2)) < 50:
        raise ValueError("At least 50 benign and 50 malware examples are required")

    numeric = frame[FEATURES].apply(pd.to_numeric, errors="coerce")
    numeric = numeric.replace([np.inf, -np.inf], np.nan).fillna(0.0)
    x = numeric.clip(-1_000_000, 1_000_000).to_numpy(dtype=np.float32)
    train_idx, calibration_idx, test_idx = group_train_calibration_test(y, groups, random_state)
    train_groups = set(groups[train_idx])
    calibration_groups = set(groups[calibration_idx])
    test_groups = set(groups[test_idx])
    if (train_groups & calibration_groups) or (train_groups & test_groups) or (calibration_groups & test_groups):
        raise RuntimeError("Package/family leakage detected across partitions")

    model = RandomForestClassifier(
        n_estimators=estimators, max_depth=10, min_samples_leaf=3,
        max_features="sqrt", class_weight="balanced_subsample",
        bootstrap=True, n_jobs=-1, random_state=random_state,
    )
    model.fit(x[train_idx], y[train_idx])
    calibration_probabilities = model.predict_proba(x[calibration_idx])[:, list(model.classes_).index(1)]
    fpr_values, tpr_values, thresholds = roc_curve(y[calibration_idx], calibration_probabilities)
    eligible = [i for i, fpr in enumerate(fpr_values)
                if fpr <= target_fpr and math.isfinite(float(thresholds[i]))]
    if not eligible:
        raise ValueError("No finite threshold meets the requested FPR ceiling")
    best = max(eligible, key=lambda i: (tpr_values[i], thresholds[i]))
    threshold = float(thresholds[best])
    calibration_predicted = (calibration_probabilities >= threshold).astype(np.int8)
    calibration_fpr = float(np.mean(calibration_predicted[y[calibration_idx] == 0]))
    calibration_recall = float(recall_score(y[calibration_idx], calibration_predicted, zero_division=0))
    if calibration_fpr > target_fpr + 1e-9:
        raise RuntimeError("Calibration FPR exceeded the configured ceiling")
    if calibration_recall < minimum_recall:
        raise ValueError(f"Calibration recall {calibration_recall:.4f} is below the required {minimum_recall:.4f}")

    # The final test set is untouched during model fitting and threshold selection.
    probabilities = model.predict_proba(x[test_idx])[:, list(model.classes_).index(1)]
    predicted = (probabilities >= threshold).astype(np.int8)
    measured_fpr = float(np.mean(predicted[y[test_idx] == 0]))
    measured_recall = float(recall_score(y[test_idx], predicted, zero_division=0))
    if measured_fpr > target_fpr + 1e-9:
        raise ValueError(f"Untouched test FPR {measured_fpr:.4f} exceeded target {target_fpr:.4f}")
    if measured_recall < minimum_recall:
        raise ValueError(f"Untouched test recall {measured_recall:.4f} is below the required {minimum_recall:.4f}")

    dataset_sha = hashlib.sha256(input_csv.read_bytes()).hexdigest()
    model_id = hashlib.sha256((dataset_sha + "|" + "|".join(FEATURES)).encode()).hexdigest()[:20]
    positive_index = list(model.classes_).index(1)
    trees = [export_tree(tree, positive_index) for tree in model.estimators_]
    if any(len(tree) > 2047 for tree in trees):
        raise ValueError("A decision tree exceeds the mobile node limit")

    result = {
        "format": FORMAT,
        "model_version": "1.0.0",
        "model_id": model_id,
        "trained_at_utc": datetime.now(timezone.utc).isoformat(),
        "feature_schema_version": 1,
        "features": FEATURES,
        "decision_threshold": threshold,
        "dataset": {
            "name": dataset_name, "reference": dataset_reference,
            "license": dataset_license, "sha256": dataset_sha,
        },
        "training": {
            "samples": int(len(train_idx)),
            "benign": int(np.sum(y[train_idx] == 0)),
            "malware": int(np.sum(y[train_idx] == 1)),
            "independent_groups": int(len(train_groups)),
            "random_state": int(random_state),
        },
        "calibration": {
            "samples": int(len(calibration_idx)),
            "independent_groups": int(len(calibration_groups)),
            "fpr_at_threshold": calibration_fpr,
            "recall_at_threshold": calibration_recall,
            "threshold_selection_only": True,
        },
        "validation": {
            "samples": int(len(test_idx)),
            "benign": int(np.sum(y[test_idx] == 0)),
            "malware": int(np.sum(y[test_idx] == 1)),
            "independent_groups": int(len(test_groups)),
            "roc_auc": float(roc_auc_score(y[test_idx], probabilities)),
            "pr_auc": float(average_precision_score(y[test_idx], probabilities)),
            "fpr_at_threshold": measured_fpr,
            "recall_at_threshold": measured_recall,
            "precision_at_threshold": float(precision_score(y[test_idx], predicted, zero_division=0)),
            "f1_at_threshold": float(f1_score(y[test_idx], predicted, zero_division=0)),
            "target_fpr": target_fpr,
            "minimum_recall_gate": minimum_recall,
            "threshold_chosen_before_test": True,
        },
        "trees": trees,
    }
    output_json.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=output_json.parent, delete=False) as temp:
        json.dump(result, temp, separators=(",", ":"), allow_nan=False)
        temp.write("\n")
        temp_path = Path(temp.name)
    os.replace(temp_path, output_json)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--label-column", default="label")
    parser.add_argument("--group-column", default="family_group")
    parser.add_argument("--dataset-name", required=True)
    parser.add_argument("--dataset-reference", required=True)
    parser.add_argument("--dataset-license", required=True)
    parser.add_argument("--target-fpr", type=float, default=0.01)
    parser.add_argument("--minimum-recall", type=float, default=0.50)
    parser.add_argument("--random-state", type=int, default=20261108)
    parser.add_argument("--estimators", type=int, default=64)
    args = parser.parse_args()
    result = train_dataset(
        args.dataset, args.output, label_column=args.label_column,
        group_column=args.group_column, dataset_name=args.dataset_name,
        dataset_reference=args.dataset_reference, dataset_license=args.dataset_license,
        target_fpr=args.target_fpr, minimum_recall=args.minimum_recall,
        random_state=args.random_state, estimators=args.estimators,
    )
    print(json.dumps({
        "model_id": result["model_id"], "output": str(args.output),
        "training": result["training"], "validation": result["validation"],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
