#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""将LineVul、CodeBERT或其他外部模型预测转换为统一严格评估格式。"""

from __future__ import annotations

import argparse  # 解析命令行参数。
import csv  # 读取CSV预测。
import json  # 写出JSONL。
from pathlib import Path  # 处理路径。

from common import (
    canonical_records_sha256,
    file_sha256,
    index_unique,
    load_jsonl,
    prediction_semantic_warnings,
    validate_prediction_schema,
)


def as_bool(value):
    """把外部标签严格转换成布尔值；无法识别时返回None。"""
    if type(value) is bool:
        return value
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "vulnerable", "positive"}:
        return True
    if text in {"0", "false", "no", "benign", "negative"}:
        return False
    return None


def parse_lines(value):
    """解析逗号、空格、分号或JSON数组形式的行号，并去除非法值与重复项。"""
    if value in (None, ""):
        return []
    if isinstance(value, str) and value.strip().startswith("["):
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            value = []
    if not isinstance(value, list):
        value = str(value).replace(";", ",").replace(" ", ",").split(",")
    output = []
    for item in value:
        try:
            parsed = int(item)
        except (TypeError, ValueError):
            continue
        if parsed > 0 and parsed not in output:
            output.append(parsed)
    return output


def main() -> None:
    """程序入口。"""
    parser = argparse.ArgumentParser(description="统一LineVul或CodeBERT预测")
    parser.add_argument("--input", required=True, help="外部模型CSV")
    parser.add_argument("--gold", required=True, help="sample_400.jsonl")
    parser.add_argument("--output", required=True, help="统一JSONL输出路径")
    parser.add_argument(
        "--source-name",
        default="external_baseline",
        help="外部模型或运行名称，用于防止混合不同来源预测",
    )
    parser.add_argument("--allow-partial", action="store_true", help="仅用于小规模调试，允许CSV未覆盖全部gold")
    args = parser.parse_args()

    gold_rows = load_jsonl(args.gold)
    gold = index_unique(gold_rows, "sample_id", "gold")
    gold_signature = canonical_records_sha256(gold_rows)
    input_path = Path(args.input).expanduser().resolve()
    with input_path.open("r", encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    csv_ids = [row.get("sample_id", "").strip() for row in rows]
    if any(not sample_id for sample_id in csv_ids):
        raise SystemExit("外部预测CSV存在空sample_id")
    if len(csv_ids) != len(set(csv_ids)):
        duplicates = sorted({sample_id for sample_id in csv_ids if csv_ids.count(sample_id) > 1})
        raise SystemExit(f"外部预测CSV存在重复sample_id，例如：{duplicates[:5]}")
    extra = sorted(set(csv_ids) - set(gold))
    missing = sorted(set(gold) - set(csv_ids))
    if extra:
        raise SystemExit(f"外部预测包含不在gold中的sample_id，例如：{extra[:5]}")
    if missing and not args.allow_partial:
        raise SystemExit(f"外部预测缺少{len(missing)}条gold样本；调试时可显式使用--allow-partial")

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        for row in rows:
            sample_id = row["sample_id"].strip()
            reference = gold[sample_id]
            probability = row.get("probability") or row.get("score")
            try:
                probability = float(probability) if probability not in (None, "") else -1.0
            except (TypeError, ValueError):
                probability = -1.0  # 让Schema校验明确记录非法概率。
            predicted_label = as_bool(row.get("predicted_label", row.get("label", "")))
            cwe = row.get("predicted_cwe") or None
            if isinstance(cwe, str):
                cwe = cwe.strip().upper() or None
            prediction = {
                "vulnerable": predicted_label,
                "cwe": cwe,
                "location": parse_lines(row.get("predicted_lines", "")),
                "confidence": probability,
                "reason": row.get("reason") or "external_baseline_prediction",
            }
            schema_valid, schema_errors = validate_prediction_schema(
                prediction,
                int(reference.get("code_lines") or 0) or None,
            )
            result = {
                "sample_id": sample_id,
                "prediction": prediction,
                "json_valid": True,
                "strict_json_applicable": False,
                "strict_json_valid": None,
                "json_recovered": None,
                "schema_valid": schema_valid,
                "schema_errors": schema_errors,
                "semantic_warnings": prediction_semantic_warnings(prediction),
                "latency_seconds": None,
                "raw_output": "",
                "run_signature": {
                    "source": "external_baseline_csv",
                    "source_name": args.source_name,
                    "input_sha256": file_sha256(input_path),
                    "gold_canonical_sha256": gold_signature,
                    "schema_version": "1.1",
                },
            }
            handle.write(json.dumps(result, ensure_ascii=False) + "\n")
    print(f"[OK] 已生成统一预测：{output_path}")
    print(f"[OK] 覆盖gold：{len(rows)}/{len(gold_rows)}；缺失：{len(missing)}")


if __name__ == "__main__":
    main()
