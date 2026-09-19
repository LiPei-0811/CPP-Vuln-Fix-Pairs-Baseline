#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""严格评估分类、配对敏感性、JSON/Schema有效率、CWE和Top-k定位指标。"""

from __future__ import annotations

import argparse  # 解析命令行参数。
import csv  # 写出逐样本案例表。
import hashlib  # 复核Qwen系统提示词签名。
import json  # 写出指标JSON。
import math  # 计算MCC。
from collections import Counter, defaultdict  # 统计类别、CWE和pair结果。
from pathlib import Path  # 处理路径。

from common import (
    canonical_records_sha256,
    file_sha256,
    index_unique,
    load_config,
    load_jsonl,
    parse_strict_json_object,
    resolve_path,
    validate_prediction_schema,
)


def safe_divide(numerator: float, denominator: float) -> float:
    """分类指标中分母为0时按0处理。"""
    return numerator / denominator if denominator else 0.0


def rate_or_none(numerator: float, denominator: float) -> float | None:
    """不可评估指标在分母为0时返回null，而不是容易误解的0%。"""
    return numerator / denominator if denominator else None


def binary_metrics(y_true: list[int], y_pred: list[int]) -> dict:
    """计算二分类混淆矩阵、Precision、Recall、F1和MCC。"""
    tp = sum(true == 1 and pred == 1 for true, pred in zip(y_true, y_pred))
    tn = sum(true == 0 and pred == 0 for true, pred in zip(y_true, y_pred))
    fp = sum(true == 0 and pred == 1 for true, pred in zip(y_true, y_pred))
    fn = sum(true == 1 and pred == 0 for true, pred in zip(y_true, y_pred))
    precision = safe_divide(tp, tp + fp)
    recall = safe_divide(tp, tp + fn)
    f1 = safe_divide(2 * precision * recall, precision + recall)
    denominator = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    mcc = safe_divide(tp * tn - fp * fn, denominator)
    return {
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "mcc": mcc,
    }


def top_k_hit(predicted, gold, k: int) -> bool | None:
    """判断预测位置前k项是否命中真实漏洞行；没有gold时返回None。"""
    if not gold:
        return None
    if not isinstance(predicted, list):
        predicted = []
    try:
        predicted_set = {int(value) for value in predicted[:k] if int(value) > 0}
        gold_set = {int(value) for value in gold if int(value) > 0}
    except (TypeError, ValueError):
        predicted_set = set()
        gold_set = {int(value) for value in gold if isinstance(value, int) and value > 0}
    return bool(predicted_set & gold_set)


def main() -> None:
    """程序入口。"""
    parser = argparse.ArgumentParser(description="严格评估漏洞检测预测结果")
    parser.add_argument("--config", required=True, help="配置文件路径")
    parser.add_argument("--gold", required=True, help="sample_400.jsonl路径")
    parser.add_argument("--pred", required=True, help="预测JSONL路径")
    parser.add_argument("--output", required=True, help="指标JSON输出路径")
    parser.add_argument("--cases-output", required=True, help="逐样本CSV输出路径")
    parser.add_argument(
        "--allow-partial",
        action="store_true",
        help="仅用于Smoke Test；允许预测少于gold。正式实验不得使用",
    )
    parser.add_argument(
        "--allow-signature-mismatch",
        action="store_true",
        help="仅用于历史结果审计；允许缺失或不匹配的运行签名，正式实验不得使用",
    )
    args = parser.parse_args()

    config, config_path = load_config(args.config)
    location_k = int(config.get("location_k", 5))
    invalid_policy = str(config.get("invalid_prediction_policy", "error"))
    if invalid_policy not in {"error", "skip"}:
        raise SystemExit("invalid_prediction_policy只能是error或skip")
    strict_complete = bool(config.get("require_complete_predictions", True)) and not args.allow_partial

    gold_rows = load_jsonl(args.gold)
    prediction_rows = load_jsonl(args.pred)
    gold = index_unique(gold_rows, "sample_id", "gold")
    predictions = index_unique(prediction_rows, "sample_id", "prediction")
    gold_ids = set(gold)
    prediction_ids = set(predictions)
    missing_ids = sorted(gold_ids - prediction_ids)
    extra_ids = sorted(prediction_ids - gold_ids)
    if extra_ids:
        raise SystemExit(f"预测文件包含{len(extra_ids)}个不在gold中的sample_id，例如：{extra_ids[:5]}")
    if strict_complete and missing_ids:
        raise SystemExit(
            f"正式评估要求预测完整覆盖gold，但缺少{len(missing_ids)}条，例如：{missing_ids[:5]}。"
            "Smoke Test请显式添加--allow-partial。"
        )

    signature_warnings: list[str] = []
    prediction_signature: dict = {}
    expected_gold_signature = canonical_records_sha256(gold_rows)
    if prediction_rows:
        signatures = [row.get("run_signature") for row in prediction_rows]
        if any(not isinstance(signature, dict) for signature in signatures):
            signature_warnings.append("预测记录缺少run_signature")
        else:
            serialized = {
                json.dumps(signature, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
                for signature in signatures
            }
            if len(serialized) != 1:
                signature_warnings.append("预测文件混入了多个不同的run_signature")
            else:
                prediction_signature = signatures[0]
                actual_gold_signature = prediction_signature.get("gold_canonical_sha256")
                if actual_gold_signature != expected_gold_signature:
                    signature_warnings.append(
                        "run_signature中的gold_canonical_sha256与当前gold不一致"
                    )
                expected_slug = config.get("experiment_slug")
                actual_slug = prediction_signature.get("experiment_slug")
                if actual_slug not in (None, expected_slug):
                    signature_warnings.append(
                        f"run_signature实验标识不一致：{actual_slug!r} != {expected_slug!r}"
                    )
                actual_prompt_version = prediction_signature.get("prompt_version")
                expected_prompt_version = config.get("prompt_version")
                if actual_prompt_version not in (None, expected_prompt_version):
                    signature_warnings.append(
                        "run_signature提示词版本与当前config.json不一致"
                    )
                is_qwen_signature = (
                    prediction_signature.get("source") == "qwen_direct"
                    or prediction_signature.get("model_name") is not None
                )
                if is_qwen_signature:
                    from run_qwen_direct import SYSTEM_PROMPT

                    default_prompt = (
                        Path(__file__).resolve().parents[1]
                        / "prompts"
                        / "direct_detection_zh.txt"
                    )
                    prompt_value = config.get("prompt_file") or default_prompt
                    expected_prompt_path = resolve_path(prompt_value, config_path.parent)
                    expected_prompt_sha256 = file_sha256(expected_prompt_path)
                    if prediction_signature.get("prompt_sha256") != expected_prompt_sha256:
                        signature_warnings.append(
                            "run_signature提示词SHA256与当前prompt_file不一致"
                        )
                    expected_system_prompt_sha256 = hashlib.sha256(
                        SYSTEM_PROMPT.encode("utf-8")
                    ).hexdigest()
                    if (
                        prediction_signature.get("system_prompt_sha256")
                        != expected_system_prompt_sha256
                    ):
                        signature_warnings.append("run_signature系统提示词SHA256不一致")
                    expected_model_name = str(
                        config.get("model_name", "Qwen/Qwen2.5-Coder-7B-Instruct")
                    )
                    if prediction_signature.get("model_name") != expected_model_name:
                        signature_warnings.append("run_signature模型名与当前config.json不一致")
                    expected_inference_config = {
                        "device_map": config.get("device_map", "auto"),
                        "max_input_chars": int(config.get("max_input_chars", 24000)),
                        "max_new_tokens": int(config.get("max_new_tokens", 384)),
                        "temperature": float(config.get("temperature", 0.0)),
                        "top_p": float(config.get("top_p", 1.0)),
                        "generation_seed": int(config.get("generation_seed", 20260916)),
                        "trust_remote_code": bool(config.get("trust_remote_code", False)),
                    }
                    if prediction_signature.get("inference_config") != expected_inference_config:
                        signature_warnings.append(
                            "run_signature推理参数与当前config.json不一致"
                        )
                    if prediction_signature.get("schema_version") != "1.1":
                        signature_warnings.append("Qwen预测签名Schema版本不是1.1")
                    if not isinstance(prediction_signature.get("inference_config"), dict):
                        signature_warnings.append("Qwen预测签名缺少inference_config")
    if signature_warnings and not args.allow_signature_mismatch:
        raise SystemExit(
            "预测运行签名校验失败：" + "；".join(signature_warnings)
            + "。历史结果审计时才可显式添加--allow-signature-mismatch。"
        )

    y_true: list[int] = []
    y_pred: list[int] = []
    cases: list[dict] = []
    json_valid_count = 0
    strict_json_applicable_count = 0
    strict_json_valid_count = 0
    json_recovered_count = 0
    schema_valid_count = 0
    invalid_count = 0
    semantic_warning_count = 0
    predicted_cwe_counts: Counter = Counter()
    cwe_evaluable = 0
    cwe_valid_prediction_count = 0
    cwe_correct = 0

    for reference in gold_rows:  # 按gold顺序输出，保证案例表稳定可复现。
        sample_id = reference["sample_id"]
        item = predictions.get(sample_id)
        if item is None:
            continue  # 仅allow-partial模式可能发生。
        prediction = item.get("prediction") if isinstance(item.get("prediction"), dict) else {}
        json_valid = bool(item.get("json_valid", False))
        if json_valid:
            json_valid_count += 1
        if type(item.get("strict_json_applicable")) is bool:
            strict_json_applicable = bool(item["strict_json_applicable"])
        else:
            strict_json_applicable = bool(item.get("raw_output"))
        if strict_json_applicable:
            strict_json_applicable_count += 1
            if type(item.get("strict_json_valid")) is bool:
                strict_json_valid = bool(item["strict_json_valid"])
            else:
                strict_json_valid = (
                    parse_strict_json_object(str(item.get("raw_output", ""))) is not None
                )
            if strict_json_valid:
                strict_json_valid_count += 1
            if json_valid and not strict_json_valid:
                json_recovered_count += 1
        else:
            strict_json_valid = None
        evaluator_schema_valid, evaluator_schema_errors = validate_prediction_schema(
            prediction,
            int(reference.get("code_lines") or 0) or None,
        )
        declared_schema_valid = item.get("schema_valid")
        declared_schema_errors = item.get("schema_errors", [])
        if type(declared_schema_valid) is bool:
            schema_valid = bool(declared_schema_valid) and evaluator_schema_valid
        else:
            schema_valid = evaluator_schema_valid
        schema_errors = []
        for error in [
            *(declared_schema_errors if isinstance(declared_schema_errors, list) else []),
            *evaluator_schema_errors,
        ]:
            if error not in schema_errors:
                schema_errors.append(error)
        if declared_schema_valid is False and not schema_errors:
            schema_errors.append("上游预测文件标记schema_valid=false")
        if schema_valid:
            schema_valid_count += 1
        semantic_warnings = item.get("semantic_warnings", [])
        if isinstance(semantic_warnings, list):
            semantic_warning_count += len(semantic_warnings)
        predicted_label = prediction.get("vulnerable")
        prediction_usable = json_valid and schema_valid and type(predicted_label) is bool
        true_label = int(bool(reference.get("gold_vulnerable")))
        classification_evaluated = True
        if not prediction_usable:
            invalid_count += 1
            if invalid_policy == "skip":
                classification_evaluated = False
                scored_label = None
            else:
                scored_label = 1 - true_label  # 无效输出按当前样本的错误分类计入。
        else:
            scored_label = int(predicted_label)
        if classification_evaluated:
            y_true.append(true_label)
            y_pred.append(int(scored_label))
        pred_location = prediction.get("location", [])
        gold_location = reference.get("vul_lines", [])
        if not gold_location:
            location_result = None
        elif prediction_usable:
            location_result = top_k_hit(pred_location, gold_location, location_k)
        else:
            location_result = False  # 有gold时，无效结构化输出按定位未命中处理。
        pred_cwe = prediction.get("cwe")
        if prediction_usable and prediction.get("vulnerable") is True:
            predicted_cwe_counts[str(pred_cwe)] += 1
        gold_cwe = reference.get("cwe")
        if true_label == 1 and gold_cwe not in (None, ""):
            cwe_evaluable += 1
            if prediction_usable:
                cwe_valid_prediction_count += 1
                cwe_correct += int(str(pred_cwe).upper() == str(gold_cwe).upper())
        cases.append(
            {
                "sample_id": sample_id,
                "pair_id": reference.get("pair_id"),
                "kind": reference.get("kind"),
                "gold_vulnerable": true_label,
                "raw_pred_vulnerable": predicted_label,
                "pred_vulnerable": scored_label,
                "classification_evaluated": classification_evaluated,
                "gold_cwe": gold_cwe,
                "pred_cwe": pred_cwe,
                "gold_location": json.dumps(reference.get("vul_lines", []), ensure_ascii=False),
                "pred_location": json.dumps(pred_location, ensure_ascii=False),
                "location_hit": location_result,
                "self_reported_confidence": prediction.get("confidence"),
                "reason": prediction.get("reason"),
                "json_valid": json_valid,
                "strict_json_applicable": strict_json_applicable,
                "strict_json_valid": strict_json_valid,
                "json_recovered": (
                    json_valid and not strict_json_valid if strict_json_applicable else None
                ),
                "schema_valid": schema_valid,
                "schema_errors": json.dumps(schema_errors, ensure_ascii=False),
                "latency_seconds": item.get("latency_seconds"),
            }
        )

    result = binary_metrics(y_true, y_pred)
    evaluated_cases = [case for case in cases if case["classification_evaluated"]]
    patched_cases = [case for case in evaluated_cases if case["kind"] == "patched"]
    benign_cases = [case for case in evaluated_cases if case["kind"] == "benign"]
    vulnerable_cases = [case for case in evaluated_cases if case["kind"] == "vulnerable"]
    patched_fp = sum(case["pred_vulnerable"] == 1 for case in patched_cases)
    benign_fp = sum(case["pred_vulnerable"] == 1 for case in benign_cases)
    location_cases = [case for case in cases if case["location_hit"] is not None]
    location_hits = sum(case["location_hit"] is True for case in location_cases)

    paired_groups: dict[str, list[dict]] = defaultdict(list)
    for case in evaluated_cases:
        if case.get("pair_id") and case.get("kind") in {"vulnerable", "patched"}:
            paired_groups[str(case["pair_id"])].append(case)
    pair_outcomes = Counter()
    pair_evaluable = 0
    for group in paired_groups.values():
        by_kind = {case["kind"]: case for case in group}
        if set(by_kind) != {"vulnerable", "patched"}:
            continue
        pair_evaluable += 1
        v_pred = int(by_kind["vulnerable"]["pred_vulnerable"])
        p_pred = int(by_kind["patched"]["pred_vulnerable"])
        pair_outcomes[f"vulnerable_{v_pred}_patched_{p_pred}"] += 1
    pair_success = pair_outcomes["vulnerable_1_patched_0"]

    result.update(
        {
            "experiment_name": config.get("experiment_name"),
            "experiment_slug": config.get("experiment_slug"),
            "gold_record_count": len(gold_rows),
            "total_prediction_records": len(prediction_rows),
            "matched_prediction_count": len(cases),
            "missing_prediction_count": len(missing_ids),
            "extra_prediction_count": len(extra_ids),
            "prediction_coverage_rate": rate_or_none(len(cases), len(gold_rows)),
            "complete_coverage_required": strict_complete,
            "classification_evaluated_count": len(y_true),
            "invalid_prediction_policy": invalid_policy,
            "invalid_prediction_count": invalid_count,
            "json_valid_count": json_valid_count,
            "json_valid_rate": rate_or_none(json_valid_count, len(cases)),
            "json_valid_note": "json_valid表示至少成功提取到JSON对象；不等同于原始输出严格只包含JSON。",
            "strict_json_applicable_count": strict_json_applicable_count,
            "strict_json_valid_count": strict_json_valid_count,
            "strict_json_valid_rate": rate_or_none(
                strict_json_valid_count, strict_json_applicable_count
            ),
            "json_recovered_count": json_recovered_count,
            "json_recovered_rate": rate_or_none(
                json_recovered_count, strict_json_applicable_count
            ),
            "schema_valid_count": schema_valid_count,
            "schema_valid_rate": rate_or_none(schema_valid_count, len(cases)),
            "semantic_warning_count": semantic_warning_count,
            "vulnerable_count": len(vulnerable_cases),
            "patched_count": len(patched_cases),
            "benign_count": len(benign_cases),
            "patched_false_positive_count": patched_fp,
            "patched_false_positive_rate": rate_or_none(patched_fp, len(patched_cases)),
            "benign_false_positive_count": benign_fp,
            "benign_false_positive_rate": rate_or_none(benign_fp, len(benign_cases)),
            "pair_evaluable_count": pair_evaluable,
            "pair_outcomes": dict(pair_outcomes),
            "paired_repair_sensitive_success_count": pair_success,
            "paired_repair_sensitive_success_rate": rate_or_none(pair_success, pair_evaluable),
            "predicted_cwe_counts_for_positive": dict(predicted_cwe_counts),
            "cwe_evaluable_count": cwe_evaluable,
            "cwe_valid_prediction_count": cwe_valid_prediction_count,
            "cwe_prediction_coverage_rate": rate_or_none(
                cwe_valid_prediction_count, cwe_evaluable
            ),
            "cwe_correct_count": cwe_correct,
            "cwe_accuracy": rate_or_none(cwe_correct, cwe_evaluable),
            "cwe_note": "分母为gold CWE非空的真实漏洞样本；无效结构化预测计为CWE错误，并单独报告有效预测覆盖率。",
            "location_k": location_k,
            "location_evaluable_count": len(location_cases),
            "location_hit_count": location_hits,
            "top_k_location_hit_rate": rate_or_none(location_hits, len(location_cases)),
            "location_status": "evaluated" if location_cases else "not_evaluable_no_ground_truth_lines",
            "confidence_note": "confidence是LLM自报置信度，未经校准，不作为概率或阈值决策依据。",
            "patched_label_note": "patched=0仅表示对应已知漏洞的修复版本，不代表形式化证明不存在其他漏洞。",
            "gold_canonical_sha256": expected_gold_signature,
            "prediction_run_signature": prediction_signature,
            "signature_warnings": signature_warnings,
            "signature_mismatch_allowed": args.allow_signature_mismatch,
        }
    )

    output_path = Path(args.output)
    cases_path = Path(args.cases_output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    cases_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    fieldnames = list(cases[0].keys()) if cases else ["sample_id", "kind"]
    with cases_path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(cases)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
