#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""验证最终样本是否真正使用精确PrimeVul漏洞—修复对，并检查良性样本泄漏。"""

from __future__ import annotations

import argparse  # 解析配置路径。
import hashlib  # 计算原始数据代码哈希。
import json  # 输出验证报告。
from collections import Counter, defaultdict  # 统计类别并按pair_id分组。
from pathlib import Path  # 处理路径。

from scripts.common import load_config, load_jsonl, normalize_cpp_for_hash


def code_hash(code: str) -> str:
    """计算精确代码SHA1。"""
    return hashlib.sha1(code.encode("utf-8", "ignore")).hexdigest()


def normalized_hash(code: str) -> str:
    """计算忽略格式和注释、但保留字面量内容的C/C++词法SHA1。"""
    normalized = normalize_cpp_for_hash(code)
    return hashlib.sha1(normalized.encode("utf-8", "ignore")).hexdigest()


def main() -> None:
    """执行标签、配对、差异证据和良性样本泄漏验证。"""
    parser = argparse.ArgumentParser(description="检查PrimeVul精确配对样本")
    parser.add_argument("--config", default="./config.json", help="配置文件路径")
    args = parser.parse_args()
    config, _ = load_config(args.config)
    paired_files = [Path(value) for value in config.get("paired_files", [])]
    if not paired_files:
        raise SystemExit("config.json缺少paired_files")
    sample_path = Path(config["output_dir"]) / "prepared" / "sample_400.jsonl"
    if not sample_path.exists():
        raise SystemExit(f"找不到样本文件：{sample_path}；请先运行prepare_sample.py")
    selected = load_jsonl(sample_path)
    paired_rows_by_file = {str(path.resolve()): load_jsonl(path) for path in paired_files}

    groups: dict[str, list[dict]] = defaultdict(list)
    for record in selected:
        if record.get("pair_id"):
            groups[str(record["pair_id"])].append(record)
    pair_errors: list[str] = []
    for pair_id, group in groups.items():
        if len(group) != 2:
            pair_errors.append(f"{pair_id}: count={len(group)}")
            continue
        by_kind = {item.get("kind"): item for item in group}
        if set(by_kind) != {"vulnerable", "patched"}:
            pair_errors.append(f"{pair_id}: kinds={sorted(by_kind)}")
            continue
        vulnerable = by_kind["vulnerable"]
        patched = by_kind["patched"]
        if vulnerable.get("gold_label") != 1 or patched.get("gold_label") != 0:
            pair_errors.append(f"{pair_id}: gold labels错误")
        if vulnerable.get("project") != patched.get("project"):
            pair_errors.append(f"{pair_id}: project不一致")
        if vulnerable.get("commit_id") != patched.get("commit_id"):
            pair_errors.append(f"{pair_id}: commit_id不一致")
        if vulnerable.get("code_hash") == patched.get("code_hash"):
            pair_errors.append(f"{pair_id}: 修复前后代码相同")
        if not (vulnerable.get("pair_changed_vulnerable_lines") or patched.get("pair_changed_patched_lines")):
            pair_errors.append(f"{pair_id}: 缺少补丁差异证据")
        for item, expected_target in ((vulnerable, 1), (patched, 0)):
            source_file = str(Path(item["source_file"]).resolve())
            rows = paired_rows_by_file.get(source_file)
            source_index = int(item["source_row"]) - 1
            if rows is None or not 0 <= source_index < len(rows):
                pair_errors.append(f"{pair_id}: source_file/source_row无效")
                continue
            if rows[source_index].get("target") != expected_target:
                pair_errors.append(f"{pair_id}: 原始target与kind不一致")

    paired_hashes = set()
    paired_normalized_hashes = set()
    paired_commit_keys = set()
    paired_target_counts = Counter()
    for path, rows in paired_rows_by_file.items():
        for row in rows:
            code = str(row.get("func", ""))
            if code:
                paired_hashes.add(code_hash(code))
                paired_normalized_hashes.add(normalized_hash(code))
            paired_commit_keys.add((str(row.get("project", "")), str(row.get("commit_id", ""))))
            paired_target_counts[row.get("target")] += 1

    benign_rows = [item for item in selected if item.get("kind") == "benign"]
    exact_overlap = [item["sample_id"] for item in benign_rows if item.get("code_hash") in paired_hashes]
    normalized_overlap = [
        item["sample_id"]
        for item in benign_rows
        if item.get("normalized_code_hash") in paired_normalized_hashes
    ]
    commit_overlap = [
        item["sample_id"]
        for item in benign_rows
        if (str(item.get("project", "")), str(item.get("commit_id", ""))) in paired_commit_keys
    ]
    selected_normalized_counts = Counter(item.get("normalized_code_hash") for item in selected)
    selected_normalized_duplicates = {
        value: count for value, count in selected_normalized_counts.items() if value and count > 1
    }
    benign_commit_counts = Counter(
        (str(item.get("project", "")), str(item.get("commit_id", ""))) for item in benign_rows
    )
    pair_role_missing = [
        item.get("sample_id")
        for item in selected
        if item.get("kind") in {"vulnerable", "patched"} and not item.get("pair_id")
    ]
    benign_with_pair_id = [
        item.get("sample_id") for item in benign_rows if item.get("pair_id") not in (None, "")
    ]
    counts = Counter(item.get("kind") for item in selected)
    requested = Counter({key: int(value) for key, value in config.get("sample_counts", {}).items()})
    expected_total = sum(requested.values())
    all_checks_passed = (
        len(selected) == expected_total
        and counts == requested
        and len(groups) == requested.get("vulnerable", 0)
        and not pair_errors
        and not exact_overlap
        and not normalized_overlap
        and not commit_overlap
        and not selected_normalized_duplicates
        and not pair_role_missing
        and not benign_with_pair_id
        and len({item.get("sample_id") for item in selected}) == len(selected)
    )
    report = {
        "paired_target_counts": dict(paired_target_counts),
        "selected_counts": dict(counts),
        "unique_pair_ids": len(groups),
        "pair_errors": pair_errors,
        "benign_exact_overlap_with_paired": len(exact_overlap),
        "benign_normalized_overlap_with_paired": len(normalized_overlap),
        "benign_project_commit_overlap_with_paired": len(commit_overlap),
        "selected_normalized_code_duplicate_group_count": len(selected_normalized_duplicates),
        "paired_sample_missing_pair_id_count": len(pair_role_missing),
        "benign_with_pair_id_count": len(benign_with_pair_id),
        "benign_unique_project_commit_count": len(benign_commit_counts),
        "benign_max_functions_per_project_commit": max(benign_commit_counts.values(), default=0),
        "sample_id_unique_count": len({item.get("sample_id") for item in selected}),
        "location_gold_available_count": sum(
            bool(item.get("vul_lines")) for item in selected if item.get("kind") == "vulnerable"
        ),
        "diff_evidence_pair_count": sum(
            bool(group[0].get("diff_evidence_available")) for group in groups.values() if group
        ),
        "all_checks_passed": all_checks_passed,
    }
    print(json.dumps(report, ensure_ascii=False, indent=2))
    if not all_checks_passed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
