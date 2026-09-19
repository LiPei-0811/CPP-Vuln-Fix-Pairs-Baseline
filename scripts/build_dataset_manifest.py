#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""为本地数据文件生成稳定的大小、记录数和SHA256清单。"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from common import file_sha256


def count_nonempty_lines(path: Path) -> int:
    """按二进制流统计非空JSONL记录，避免一次性载入大文件。"""
    count = 0
    with path.open("rb") as handle:
        for line in handle:
            if line.strip():
                count += 1
    return count


def main() -> None:
    parser = argparse.ArgumentParser(description="生成数据文件SHA256清单")
    parser.add_argument(
        "--dataset-dir",
        default=str(Path(__file__).resolve().parents[1] / "datasets"),
        help="数据目录",
    )
    parser.add_argument(
        "--output",
        help="清单输出路径；默认写入数据目录下dataset_manifest.json",
    )
    args = parser.parse_args()

    dataset_dir = Path(args.dataset_dir).expanduser().resolve()
    if not dataset_dir.is_dir():
        raise SystemExit(f"数据目录不存在：{dataset_dir}")
    output_path = (
        Path(args.output).expanduser().resolve()
        if args.output
        else dataset_dir / "dataset_manifest.json"
    )
    files = sorted(
        path
        for path in dataset_dir.iterdir()
        if path.is_file() and path.suffix.lower() in {".jsonl", ".json", ".csv", ".gz"}
        and path.resolve() != output_path.resolve()
    )
    if not files:
        raise SystemExit(f"数据目录中没有可登记的数据文件：{dataset_dir}")

    entries = []
    for path in files:
        entry = {
            "name": path.name,
            "size_bytes": path.stat().st_size,
            "sha256": file_sha256(path),
        }
        if path.suffix.lower() == ".jsonl":
            entry["record_count"] = count_nonempty_lines(path)
        entries.append(entry)
        print(f"[OK] {path.name}: {entry['sha256']}")

    manifest = {
        "manifest_version": "1.0",
        "source_repository_hint": "DLVulDet/PrimeVul",
        "source_commit": None,
        "download_date": None,
        "license_review_status": "not_recorded",
        "files": entries,
        "notes": [
            "SHA256、文件大小和JSONL记录数由本地文件直接计算。",
            "正式复现或公开分发前仍需补充准确source_commit、download_date和数据许可结论。",
        ],
    }
    output_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"[OK] 数据清单已写入：{output_path}")


if __name__ == "__main__":
    main()
