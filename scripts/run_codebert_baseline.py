#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""可选CodeBERT函数级二分类基线，含训练泄漏检查和统一预测输出。"""

from __future__ import annotations

import argparse  # 解析命令行参数。
import hashlib  # 计算代码指纹以检查训练/评测泄漏。
import json  # 读取数据并写出结果。
from pathlib import Path  # 处理路径。

from common import (
    CODE_NORMALIZATION_VERSION,
    canonical_records_sha256,
    file_sha256,
    index_unique,
    load_jsonl,
    normalize_cpp_for_hash,
    validate_prediction_schema,
)


def label_of(row):
    """严格读取0/1二分类标签，拒绝把未知字符串静默当成良性。"""
    value = row.get("gold_vulnerable", row.get("target", row.get("label")))
    if type(value) is bool:
        return int(value)
    if isinstance(value, (int, float)) and value in {0, 1}:
        return int(value)
    if isinstance(value, str):
        text = value.strip().lower()
        if text in {"1", "true", "yes", "vulnerable", "positive"}:
            return 1
        if text in {"0", "false", "no", "benign", "negative"}:
            return 0
    raise ValueError(f"无法识别的二分类标签：{value!r}")


def code_of(row):
    """读取函数代码。"""
    return str(row.get("code", row.get("func", row.get("function", ""))))


def normalized_hash(code: str):
    """按C/C++词法单元计算代码指纹。"""
    normalized = normalize_cpp_for_hash(code)
    return hashlib.sha1(normalized.encode("utf-8", "ignore")).hexdigest()


def main() -> None:
    """程序入口。"""
    parser = argparse.ArgumentParser(description="训练CodeBERT漏洞二分类基线")
    parser.add_argument("--train-file", required=True, help="独立训练集JSONL")
    parser.add_argument("--eval-file", required=True, help="sample_400.jsonl")
    parser.add_argument(
        "--validation-file",
        help="独立验证集JSONL；用于选最佳epoch，不能使用最终eval-file代替",
    )
    parser.add_argument("--output-dir", required=True, help="模型、预测和指标输出目录")
    parser.add_argument("--model-name", default="microsoft/codebert-base", help="CodeBERT模型名或本地路径")
    parser.add_argument("--epochs", type=float, default=2.0, help="训练轮数")
    parser.add_argument("--batch-size", type=int, default=8, help="batch大小")
    parser.add_argument("--max-length", type=int, default=512, help="最大Token长度")
    parser.add_argument("--seed", type=int, default=20260916, help="随机种子")
    parser.add_argument("--allow-overlap", action="store_true", help="仅调试使用；允许训练集与最终评测集代码重叠")
    args = parser.parse_args()

    try:
        import numpy as np
        from datasets import Dataset
        from sklearn.metrics import accuracy_score, f1_score, matthews_corrcoef, precision_score, recall_score
        from transformers import AutoModelForSequenceClassification, AutoTokenizer, DataCollatorWithPadding, Trainer, TrainingArguments
    except ImportError as exc:
        raise SystemExit("请先安装requirements.txt中的torch、transformers、datasets、scikit-learn和numpy") from exc

    train_rows = load_jsonl(args.train_file)
    eval_rows = load_jsonl(args.eval_file)
    index_unique(eval_rows, "sample_id", "eval")  # 评测集sample_id必须唯一。
    for split_name, rows in (("train", train_rows), ("eval", eval_rows)):
        for position, row in enumerate(rows, 1):
            if not code_of(row).strip():
                raise SystemExit(f"{split_name}第{position}条记录缺少函数代码")
            try:
                label_of(row)
            except ValueError as exc:
                raise SystemExit(f"{split_name}第{position}条记录标签非法：{exc}") from exc
    train_hashes = {normalized_hash(code_of(row)) for row in train_rows if code_of(row).strip()}
    eval_hashes = {normalized_hash(code_of(row)) for row in eval_rows if code_of(row).strip()}
    overlap_hashes = train_hashes & eval_hashes
    if overlap_hashes and not args.allow_overlap:
        raise SystemExit(
            f"检测到训练集与评测集存在{len(overlap_hashes)}个规范化代码重复，已阻止数据泄漏。"
            "仅调试时可显式使用--allow-overlap。"
        )
    train_projects = {str(row.get("project")) for row in train_rows if row.get("project")}
    eval_projects = {str(row.get("project")) for row in eval_rows if row.get("project")}
    project_overlap = sorted(train_projects & eval_projects)
    print(f"[INFO] 训练记录：{len(train_rows)}；评测记录：{len(eval_rows)}")
    print(f"[INFO] 规范化代码重复：{len(overlap_hashes)}")
    print(f"[INFO] 训练/评测项目重叠：{len(project_overlap)}")
    if project_overlap:
        print(f"[WARN] 当前不是project-disjoint评测；重叠项目示例：{project_overlap[:10]}")

    validation_rows = None
    validation_overlap_with_train = 0
    validation_overlap_with_eval = 0
    validation_original_count = 0
    if args.validation_file:
        raw_validation_rows = load_jsonl(args.validation_file)
        validation_original_count = len(raw_validation_rows)
        validation_rows = []
        for position, row in enumerate(raw_validation_rows, 1):
            code = code_of(row)
            if not code.strip():
                raise SystemExit(f"validation第{position}条记录缺少函数代码")
            try:
                label_of(row)
            except ValueError as exc:
                raise SystemExit(f"validation第{position}条记录标签非法：{exc}") from exc
            fingerprint = normalized_hash(code)
            if fingerprint in train_hashes:
                validation_overlap_with_train += 1
                continue
            if fingerprint in eval_hashes:
                validation_overlap_with_eval += 1
                continue
            validation_rows.append(row)
        if not validation_rows:
            raise SystemExit("验证集在去除训练/最终评测代码重叠后为空")
        print(
            "[INFO] 验证集原始记录："
            f"{validation_original_count}；去重后：{len(validation_rows)}；"
            f"与训练集规范化代码重叠并移除：{validation_overlap_with_train}；"
            f"与最终评测集重叠并移除：{validation_overlap_with_eval}"
        )
    else:
        print(
            "[WARN] 未提供--validation-file：训练期间不会查看最终eval-file，"
            "也不会按最终评测集选择最佳epoch。"
        )

    train_data = Dataset.from_list(
        [{"text": code_of(row), "labels": label_of(row)} for row in train_rows]
    )
    eval_data = Dataset.from_list(
        [{"text": code_of(row), "labels": label_of(row)} for row in eval_rows]
    )
    validation_data = (
        Dataset.from_list(
            [{"text": code_of(row), "labels": label_of(row)} for row in validation_rows]
        )
        if validation_rows is not None
        else None
    )
    tokenizer = AutoTokenizer.from_pretrained(args.model_name)

    def tokenize(batch):
        return tokenizer(batch["text"], truncation=True, max_length=args.max_length)

    train_data = train_data.map(tokenize, batched=True, remove_columns=["text"])
    eval_data = eval_data.map(tokenize, batched=True, remove_columns=["text"])
    if validation_data is not None:
        validation_data = validation_data.map(tokenize, batched=True, remove_columns=["text"])
    model = AutoModelForSequenceClassification.from_pretrained(args.model_name, num_labels=2)

    def compute_metrics(eval_prediction):
        logits, labels = eval_prediction
        predictions = np.argmax(logits, axis=-1)
        return {
            "accuracy": accuracy_score(labels, predictions),
            "precision": precision_score(labels, predictions, zero_division=0),
            "recall": recall_score(labels, predictions, zero_division=0),
            "f1": f1_score(labels, predictions, zero_division=0),
            "mcc": matthews_corrcoef(labels, predictions),
        }

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    common_args = {
        "output_dir": str(output_dir / "checkpoints"),
        "num_train_epochs": args.epochs,
        "per_device_train_batch_size": args.batch_size,
        "per_device_eval_batch_size": args.batch_size,
        "save_strategy": "epoch" if validation_data is not None else "no",
        "logging_steps": 50,
        "load_best_model_at_end": validation_data is not None,
        "report_to": [],
        "seed": args.seed,
        "data_seed": args.seed,
    }
    if validation_data is not None:
        common_args["metric_for_best_model"] = "f1"
    try:
        training_args = TrainingArguments(
            **common_args,
            eval_strategy="epoch" if validation_data is not None else "no",
        )
    except TypeError:
        training_args = TrainingArguments(
            **common_args,
            evaluation_strategy="epoch" if validation_data is not None else "no",
        )
    trainer_args = {
        "model": model,
        "args": training_args,
        "train_dataset": train_data,
        "data_collator": DataCollatorWithPadding(tokenizer),
        "compute_metrics": compute_metrics,
    }
    if validation_data is not None:
        trainer_args["eval_dataset"] = validation_data
    try:
        trainer = Trainer(**trainer_args, processing_class=tokenizer)
    except TypeError:
        trainer = Trainer(**trainer_args, tokenizer=tokenizer)
    trainer.train()
    prediction_output = trainer.predict(eval_data)
    logits = prediction_output.predictions
    shifted = logits - logits.max(axis=1, keepdims=True)
    probabilities = np.exp(shifted) / np.exp(shifted).sum(axis=1, keepdims=True)
    predicted_labels = np.argmax(logits, axis=-1)
    metrics = dict(prediction_output.metrics)
    train_label_counts = {
        str(label): sum(label_of(row) == label for row in train_rows) for label in (0, 1)
    }
    eval_label_counts = {
        str(label): sum(label_of(row) == label for row in eval_rows) for label in (0, 1)
    }
    metrics.update(
        {
            "train_record_count": len(train_rows),
            "eval_record_count": len(eval_rows),
            "normalized_code_overlap_count": len(overlap_hashes),
            "project_overlap_count": len(project_overlap),
            "project_overlap_examples": project_overlap[:20],
            "train_label_counts": train_label_counts,
            "eval_label_counts": eval_label_counts,
            "validation_file": args.validation_file,
            "validation_original_count": validation_original_count,
            "validation_record_count": len(validation_rows or []),
            "validation_overlap_with_train_removed": validation_overlap_with_train,
            "validation_overlap_with_eval_removed": validation_overlap_with_eval,
            "model_selection_used_final_eval": False,
            "code_normalization_version": CODE_NORMALIZATION_VERSION,
            "model_name": args.model_name,
            "epochs": args.epochs,
            "batch_size": args.batch_size,
            "max_length": args.max_length,
            "seed": args.seed,
        }
    )
    (output_dir / "codebert_metrics.json").write_text(
        json.dumps(metrics, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    predictions_path = output_dir / "codebert_predictions.jsonl"
    gold_signature = canonical_records_sha256(eval_rows)
    codebert_run_signature = {
        "source": "codebert_baseline",
        "model_name": args.model_name,
        "train_file_sha256": file_sha256(args.train_file),
        "validation_file_sha256": (
            file_sha256(args.validation_file) if args.validation_file else None
        ),
        "epochs": args.epochs,
        "batch_size": args.batch_size,
        "max_length": args.max_length,
        "code_normalization_version": CODE_NORMALIZATION_VERSION,
        "seed": args.seed,
        "gold_canonical_sha256": gold_signature,
        "schema_version": "1.1",
    }
    with predictions_path.open("w", encoding="utf-8") as handle:
        for row, label, probability in zip(eval_rows, predicted_labels, probabilities[:, 1]):
            prediction = {
                "vulnerable": bool(label),
                "cwe": None,
                "location": [],
                "confidence": float(probability),
                "reason": "codebert_function_level_prediction",
            }
            schema_valid, schema_errors = validate_prediction_schema(
                prediction, int(row.get("code_lines") or 0) or None
            )
            handle.write(
                json.dumps(
                    {
                        "sample_id": row["sample_id"],
                        "prediction": prediction,
                        "json_valid": True,
                        "strict_json_applicable": False,
                        "strict_json_valid": None,
                        "json_recovered": None,
                        "schema_valid": schema_valid,
                        "schema_errors": schema_errors,
                        "semantic_warnings": [],
                        "latency_seconds": None,
                        "raw_output": "",
                        "run_signature": codebert_run_signature,
                    },
                    ensure_ascii=False,
                )
                + "\n"
            )
    print(json.dumps(metrics, ensure_ascii=False, indent=2))
    print(f"[OK] 统一预测已写入：{predictions_path}")


if __name__ == "__main__":
    main()
