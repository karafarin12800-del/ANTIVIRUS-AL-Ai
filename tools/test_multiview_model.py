import tempfile
import unittest
from pathlib import Path

import numpy as np
import pandas as pd

from train_multiview_model import FEATURES, train_dataset


class MultiViewTrainerTests(unittest.TestCase):
    def test_exports_group_validated_mobile_forest(self):
        rng = np.random.default_rng(41)
        rows = []
        for label, prefix in ((0, "benign"), (1, "malware-family")):
            for group_index in range(40):
                group = f"{prefix}-{group_index:03d}"
                for _ in range(12):
                    row = {name: float(rng.normal(0, 0.15)) for name in FEATURES}
                    row["apk_present"] = 1.0
                    row["risky_permission_count"] = float(
                        max(0, rng.normal(0.5 if label == 0 else 5.0, 0.3))
                    )
                    row["permission_sms"] = float(label if rng.random() > 0.05 else 0)
                    row["dex_dynamic_code_loading"] = float(label if rng.random() > 0.05 else 0)
                    row["static_analysis_supported"] = 1.0
                    row["static_analysis_complete"] = 1.0
                    row["label"] = label
                    row["family_group"] = group
                    rows.append(row)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            csv_path, model_path = root / "features.csv", root / "active-model.json"
            pd.DataFrame(rows).to_csv(csv_path, index=False)
            result = train_dataset(
                csv_path, model_path, label_column="label", group_column="family_group",
                dataset_name="synthetic-test-only", dataset_reference="unit-test",
                dataset_license="synthetic-test-fixture", target_fpr=0.01,
                minimum_recall=0.50, random_state=7, estimators=32,
            )
            self.assertTrue(model_path.is_file())
            self.assertEqual(result["format"], "ALAI-MV-FOREST/1")
            self.assertEqual(result["features"], FEATURES)
            self.assertEqual(len(result["trees"]), 32)
            self.assertLessEqual(result["validation"]["fpr_at_threshold"], 0.01)
            self.assertGreaterEqual(result["validation"]["recall_at_threshold"], 0.50)
            self.assertEqual(
                result["training"]["independent_groups"]
                + result["validation"]["independent_groups"], 80
            )
            self.assertTrue(all(len(tree) <= 2047 for tree in result["trees"]))

    def test_rejects_unknown_labels(self):
        frame = pd.DataFrame([{name: 0 for name in FEATURES}])
        frame["label"] = "uncertain"
        frame["family_group"] = "group-1"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            csv_path = root / "bad.csv"
            frame.to_csv(csv_path, index=False)
            with self.assertRaisesRegex(ValueError, "Unknown labels"):
                train_dataset(
                    csv_path, root / "out.json", label_column="label",
                    group_column="family_group", dataset_name="test",
                    dataset_reference="test", dataset_license="test",
                )


if __name__ == "__main__":
    unittest.main()
