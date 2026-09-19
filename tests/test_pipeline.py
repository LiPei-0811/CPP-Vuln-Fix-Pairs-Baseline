from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

from common import (  # noqa: E402
    canonical_records_sha256,
    load_config,
    load_jsonl,
    normalize_cpp_for_hash,
    parse_strict_json_object,
    validate_prediction_schema,
)
from prepare_sample import normalize_bool  # noqa: E402
from run_codebert_baseline import label_of  # noqa: E402
from run_qwen_direct import build_run_signature  # noqa: E402


class CommonTests(unittest.TestCase):
    def test_strict_json_distinguishes_markdown_recovery(self) -> None:
        payload = '{"vulnerable": false, "cwe": null, "location": [], "confidence": 1, "reason": "ok"}'
        self.assertIsNotNone(parse_strict_json_object(payload))
        self.assertIsNone(parse_strict_json_object(f"```json\n{payload}\n```"))

    def test_canonical_signature_ignores_machine_path_but_covers_label(self) -> None:
        row = {
            "sample_id": "s1",
            "sample_index": 1,
            "kind": "benign",
            "gold_vulnerable": False,
            "gold_label": 0,
            "pair_id": None,
            "pair_role": None,
            "code": "int f(void) { return 0; }",
            "func_name": "f",
            "cwe": None,
            "vul_lines": [],
            "code_lines": 1,
            "source_file": "D:/machine-a/data.jsonl",
        }
        moved = copy.deepcopy(row)
        moved["source_file"] = "E:/machine-b/data.jsonl"
        self.assertEqual(canonical_records_sha256([row]), canonical_records_sha256([moved]))
        moved["gold_label"] = 1
        self.assertNotEqual(canonical_records_sha256([row]), canonical_records_sha256([moved]))

    def test_schema_rejects_out_of_range_line(self) -> None:
        prediction = {
            "vulnerable": True,
            "cwe": "CWE-125",
            "location": [3],
            "confidence": 0.8,
            "reason": "越界读取",
        }
        valid, errors = validate_prediction_schema(prediction, code_lines=2)
        self.assertFalse(valid)
        self.assertTrue(any("函数总行数" in error for error in errors))

    def test_windows_utf8_bom_is_supported(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            config_path = temp / "config.json"
            jsonl_path = temp / "rows.jsonl"
            config_path.write_text(
                json.dumps({"output_dir": "./output"}, ensure_ascii=False),
                encoding="utf-8-sig",
            )
            jsonl_path.write_text('{"sample_id":"s1"}\n', encoding="utf-8-sig")
            config, _ = load_config(config_path)
            self.assertEqual(Path(config["output_dir"]), (temp / "output").resolve())
            self.assertEqual(load_jsonl(jsonl_path), [{"sample_id": "s1"}])

    def test_cpp_normalization_is_format_tolerant_but_literal_safe(self) -> None:
        compact = 'int f(){/* note */return value+1;}'
        formatted = 'int f ( ) {\n  return value + 1 ; // note\n}\n'
        self.assertEqual(normalize_cpp_for_hash(compact), normalize_cpp_for_hash(formatted))
        self.assertNotEqual(
            normalize_cpp_for_hash('puts("a b");'),
            normalize_cpp_for_hash('puts("ab");'),
        )
        self.assertNotEqual(
            normalize_cpp_for_hash("counter++;"),
            normalize_cpp_for_hash("counter + +other;"),
        )


class InputValidationTests(unittest.TestCase):
    def test_labels_are_strict(self) -> None:
        self.assertIs(normalize_bool(1), True)
        self.assertIs(normalize_bool(0), False)
        self.assertIsNone(normalize_bool(2))
        self.assertEqual(label_of({"target": "vulnerable"}), 1)
        with self.assertRaises(ValueError):
            label_of({"target": "unknown"})
        with self.assertRaises(ValueError):
            label_of({})

    def test_run_signature_changes_with_generation_settings(self) -> None:
        rows = [
            {
                "sample_id": "s1",
                "sample_index": 1,
                "kind": "benign",
                "gold_vulnerable": False,
                "gold_label": 0,
                "pair_id": None,
                "pair_role": None,
                "code": "int f(void) { return 0; }",
                "func_name": "f",
                "cwe": None,
                "vul_lines": [],
                "code_lines": 1,
            }
        ]
        with tempfile.TemporaryDirectory() as temp_dir:
            prompt = Path(temp_dir) / "prompt.txt"
            prompt.write_text("{code}", encoding="utf-8")
            config = {
                "experiment_name": "test",
                "experiment_slug": "test",
                "temperature": 0.0,
                "top_p": 1.0,
                "generation_seed": 1,
            }
            first = build_run_signature("model", rows, prompt, config)
            config["temperature"] = 0.7
            second = build_run_signature("model", rows, prompt, config)
            self.assertNotEqual(first, second)


class EvaluatorIntegrationTests(unittest.TestCase):
    def test_signature_and_strict_json_metrics(self) -> None:
        gold = {
            "sample_id": "s1",
            "sample_index": 1,
            "kind": "benign",
            "gold_vulnerable": False,
            "gold_label": 0,
            "pair_id": None,
            "pair_role": None,
            "code": "int f(void) { return 0; }",
            "func_name": "f",
            "cwe": None,
            "vul_lines": [],
            "code_lines": 1,
        }
        prediction = {
            "sample_id": "s1",
            "prediction": {
                "vulnerable": False,
                "cwe": None,
                "location": [],
                "confidence": 0.9,
                "reason": "no evidence",
            },
            "json_valid": True,
            "strict_json_valid": False,
            "schema_valid": True,
            "schema_errors": [],
            "semantic_warnings": [],
            "raw_output": "```json\n{}\n```",
            "run_signature": {
                "experiment_slug": "test",
                "gold_canonical_sha256": canonical_records_sha256([gold]),
                "schema_version": "1.1",
            },
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            config_path = temp / "config.json"
            gold_path = temp / "gold.jsonl"
            pred_path = temp / "pred.jsonl"
            metrics_path = temp / "metrics.json"
            cases_path = temp / "cases.csv"
            config_path.write_text(
                json.dumps(
                    {
                        "experiment_name": "test",
                        "experiment_slug": "test",
                        "output_dir": str(temp / "output"),
                        "prompt_version": "test-prompt",
                        "invalid_prediction_policy": "error",
                        "require_complete_predictions": True,
                    }
                ),
                encoding="utf-8",
            )
            gold_path.write_text(json.dumps(gold) + "\n", encoding="utf-8")
            pred_path.write_text(json.dumps(prediction) + "\n", encoding="utf-8")
            command = [
                sys.executable,
                str(SCRIPTS / "evaluate_predictions.py"),
                "--config",
                str(config_path),
                "--gold",
                str(gold_path),
                "--pred",
                str(pred_path),
                "--output",
                str(metrics_path),
                "--cases-output",
                str(cases_path),
            ]
            child_env = dict(os.environ)
            child_env["PYTHONIOENCODING"] = "utf-8"
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                encoding="utf-8",
                env=child_env,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, (completed.stderr or "") + (completed.stdout or ""))
            metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
            self.assertEqual(metrics["json_valid_rate"], 1.0)
            self.assertEqual(metrics["strict_json_valid_rate"], 0.0)
            self.assertEqual(metrics["json_recovered_rate"], 1.0)

            prediction["run_signature"]["gold_canonical_sha256"] = "bad"
            pred_path.write_text(json.dumps(prediction) + "\n", encoding="utf-8")
            rejected = subprocess.run(
                command,
                capture_output=True,
                text=True,
                encoding="utf-8",
                env=child_env,
                check=False,
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("运行签名校验失败", (rejected.stderr or "") + (rejected.stdout or ""))


if __name__ == "__main__":
    unittest.main()
