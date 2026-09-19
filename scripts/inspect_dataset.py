#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""检查PrimeVul及修复数据的文件格式、字段和类别分布。"""

from __future__ import annotations  # 启用较新的类型注解行为。

import argparse  # 导入命令行参数解析模块。
import csv  # 导入CSV读取模块。
import gzip  # 导入gzip压缩文件读取模块。
import json  # 导入JSON解析模块。
from collections import Counter  # 导入计数器统计标签和CWE。
from pathlib import Path  # 导入跨平台路径处理模块。

from common import load_config  # 统一解析配置和相对路径。

CODE_KEYS = ("func", "function", "code", "source", "snippet")  # 定义代码字段候选名称。
LABEL_KEYS = ("target", "label", "vulnerable", "is_vulnerable")  # 定义漏洞标签字段候选名称。
CWE_KEYS = ("cwe", "CWE", "cwe_id", "cwe_ids")  # 定义CWE字段候选名称。
PROJECT_KEYS = ("project", "repo", "repository", "project_name")  # 定义项目字段候选名称。
PATCH_KEYS = ("is_patched", "patched", "is_fix", "fixed", "status", "version_type")  # 定义修复状态字段候选名称。


def open_text(path: Path):
    """根据后缀打开普通文本或gzip文本。"""
    if path.suffix.lower() == ".gz":  # 判断文件是否为gzip压缩文件。
        return gzip.open(path, "rt", encoding="utf-8-sig")  # 返回UTF-8文本读取句柄。
    return path.open("r", encoding="utf-8-sig")  # 兼容Windows工具写入的UTF-8 BOM。


def load_rows(path: Path):
    """读取JSONL、JSON数组、JSON对象或CSV文件。"""
    suffixes = path.suffixes  # 获取文件的全部后缀。
    suffix = suffixes[-2] if path.suffix.lower() == ".gz" and len(suffixes) > 1 else path.suffix  # 得到压缩文件的实际数据后缀。
    if suffix.lower() == ".csv":  # 判断是否为CSV文件。
        with open_text(path) as handle:  # 打开CSV文本。
            yield from csv.DictReader(handle)  # 按字典记录逐行返回。
        return  # 结束CSV分支。
    with open_text(path) as handle:  # 打开JSON或JSONL文本。
        text = handle.read()  # 读取完整文本。
    if suffix.lower() == ".json":  # 判断是否为普通JSON文件。
        data = json.loads(text)  # 解析JSON。
        rows = data if isinstance(data, list) else [data]  # 将对象统一包装为列表。
        for position, row in enumerate(rows, 1):  # 遍历JSON记录。
            if not isinstance(row, dict):
                raise ValueError(f"{path}: JSON第{position}条记录必须是对象")
            yield row  # 返回当前记录。
        return  # 结束JSON分支。
    for line_number, line in enumerate(text.splitlines(), 1):  # 逐行读取JSONL。
        line = line.strip()  # 删除当前行首尾空白。
        if not line:  # 判断是否为空行。
            continue  # 跳过空行。
        try:  # 尝试解析当前行。
            row = json.loads(line)  # 将当前行解析为JSON。
        except json.JSONDecodeError as exc:  # 捕获非法JSON行。
            raise ValueError(f"{path}:{line_number}不是合法JSON：{exc}") from exc
        if not isinstance(row, dict):
            raise ValueError(f"{path}:{line_number}必须是JSON对象")
        yield row  # 返回当前记录。


def first_value(row: dict, keys):
    """读取候选字段中第一个非空值。"""
    for key in keys:  # 遍历候选字段名称。
        if key in row and row[key] not in (None, ""):  # 判断字段是否存在且非空。
            return row[key]  # 返回第一个有效字段值。
    return None  # 没有找到时返回空值。


def normalize_label(value):
    """将常见标签表达转换为0、1或None。"""
    if isinstance(value, bool):  # 处理布尔标签。
        return int(value)  # 将布尔值转成0或1。
    if isinstance(value, (int, float)) and value in {0, 1}:  # 只接受严格0/1数字标签。
        return int(value)  # 将数字转成0或1。
    if isinstance(value, str):  # 处理字符串标签。
        text = value.strip().lower()  # 统一字符串格式。
        if text in {"1", "true", "yes", "vulnerable", "positive"}:  # 判断正类字符串。
            return 1  # 返回漏洞标签。
        if text in {"0", "false", "no", "benign", "negative"}:  # 判断负类字符串。
            return 0  # 返回良性标签。
    return None  # 无法识别时返回None。


def inspect_file(path: Path, forced_kind: str | None = None):
    """打印单个数据文件的基本统计信息。"""
    rows = list(load_rows(path))  # 读取全部记录。
    labels = Counter(normalize_label(first_value(row, LABEL_KEYS)) for row in rows)  # 统计标签分布。
    cwes = Counter(str(first_value(row, CWE_KEYS)) for row in rows)  # 统计CWE分布。
    cwe_missing = sum(first_value(row, CWE_KEYS) in (None, "", []) for row in rows)  # 统计CWE缺失。
    line_label_count = sum(bool(row.get("vul_lines") or row.get("vulnerability_lines") or row.get("line_start")) for row in rows)  # 统计行级标注。
    fields = sorted(rows[0].keys()) if rows else []  # 获取第一条记录的字段列表。
    code_field = next((key for key in CODE_KEYS if key in fields), None)  # 自动识别代码字段。
    patch_field = next((key for key in PATCH_KEYS if key in fields), None)  # 自动识别修复状态字段。
    print(f"\n文件：{path}")  # 输出文件路径。
    print(f"记录数：{len(rows)}")  # 输出记录数。
    print(f"代码字段：{code_field}")  # 输出代码字段。
    print(f"修复字段：{patch_field}")  # 输出修复字段。
    print(f"标签分布：{dict(labels)}")  # 输出标签分布。
    print(f"常见CWE：{cwes.most_common(15)}")  # 输出CWE分布。
    print(f"CWE缺失：{cwe_missing}/{len(rows)}")  # 输出CWE缺失情况。
    print(f"包含行级标注的记录：{line_label_count}/{len(rows)}")  # 输出定位标注可用性。
    if forced_kind:  # 判断是否由配置强制指定类型。
        print(f"强制类型：{forced_kind}")  # 输出强制类型。
    print(f"字段列表：{fields}")  # 输出完整字段列表。
    missing_code = sum(not isinstance(first_value(row, CODE_KEYS), str) or not first_value(row, CODE_KEYS).strip() for row in rows)
    invalid_label = sum(normalize_label(first_value(row, LABEL_KEYS)) is None for row in rows)
    print(f"缺失或空代码：{missing_code}/{len(rows)}")
    print(f"非法或缺失标签：{invalid_label}/{len(rows)}")
    return missing_code == 0 and invalid_label == 0


def inspect_pair_structure(path: Path):
    """验证paired文件是否按“漏洞版本在前、修复版本在后”精确成对。"""
    rows = list(load_rows(path))  # 读取全部paired记录。
    if len(rows) % 2 != 0:  # 每个漏洞—修复对必须恰好包含两条记录。
        print(f"[ERROR] 配对记录数不是偶数：{len(rows)}")  # 输出结构错误。
        return False  # 返回验证失败。
    valid_pairs = 0  # 统计通过验证的配对数量。
    reversed_pairs = 0  # 统计0/1反向排列的配对数量。
    errors = []  # 保存少量错误示例。
    for offset in range(0, len(rows), 2):  # 每相邻两条记录组成一对。
        first = rows[offset]  # 读取本对第一条记录。
        second = rows[offset + 1]  # 读取本对第二条记录。
        first_label = normalize_label(first_value(first, LABEL_KEYS))  # 读取第一条标签。
        second_label = normalize_label(first_value(second, LABEL_KEYS))  # 读取第二条标签。
        if (first_label, second_label) == (0, 1):  # 允许检测到反向排列，但明确报告。
            reversed_pairs += 1  # 累计反向配对数。
            vulnerable, patched = second, first  # 临时换成漏洞在前、修复在后。
        elif (first_label, second_label) == (1, 0):  # 标准排列。
            vulnerable, patched = first, second  # 直接使用当前顺序。
        else:  # 既不是1/0也不是0/1。
            errors.append(f"第{offset + 1}-{offset + 2}行标签不是1/0配对：{first_label}/{second_label}")  # 记录错误。
            continue  # 检查下一对。
        vulnerable_project = str(first_value(vulnerable, PROJECT_KEYS) or "")  # 读取漏洞版本项目。
        patched_project = str(first_value(patched, PROJECT_KEYS) or "")  # 读取修复版本项目。
        vulnerable_commit = str(vulnerable.get("commit_id", vulnerable.get("commit", "")))  # 读取漏洞版本提交。
        patched_commit = str(patched.get("commit_id", patched.get("commit", "")))  # 读取修复版本提交。
        if not vulnerable_project or not patched_project:
            errors.append(f"第{offset + 1}-{offset + 2}行缺少项目字段")
            continue
        if not vulnerable_commit or not patched_commit:
            errors.append(f"第{offset + 1}-{offset + 2}行缺少commit_id")
            continue
        if vulnerable_project != patched_project:  # 检查项目一致性。
            errors.append(f"第{offset + 1}-{offset + 2}行项目不一致")  # 记录错误。
            continue  # 检查下一对。
        if vulnerable_commit != patched_commit:  # 检查提交一致性。
            errors.append(f"第{offset + 1}-{offset + 2}行commit_id不一致")  # 记录错误。
            continue  # 检查下一对。
        first_pair_key = first.get("big_vul_idx")  # 读取PrimeVul配对索引（若数据提供）。
        second_pair_key = second.get("big_vul_idx")  # 读取另一条配对索引。
        if first_pair_key not in (None, "") and second_pair_key not in (None, "") and first_pair_key != second_pair_key:  # 两侧都提供索引时必须一致。
            errors.append(f"第{offset + 1}-{offset + 2}行big_vul_idx不一致")  # 记录错误。
            continue  # 检查下一对。
        vulnerable_code = first_value(vulnerable, CODE_KEYS)
        patched_code = first_value(patched, CODE_KEYS)
        if vulnerable_code == patched_code:
            errors.append(f"第{offset + 1}-{offset + 2}行修复前后代码相同")
            continue
        valid_pairs += 1  # 当前漏洞—修复对验证通过。
    print(f"精确漏洞—修复对：{valid_pairs}/{len(rows) // 2}")  # 输出有效配对数量。
    print(f"标准target=1→0顺序：{len(rows) // 2 - reversed_pairs}对；反向0→1顺序：{reversed_pairs}对")  # 输出标签顺序。
    if errors:  # 如果存在结构错误。
        print(f"[ERROR] 配对结构错误数：{len(errors)}；示例：{errors[:5]}")  # 输出前五个错误。
        return False  # 返回验证失败。
    print("配对结构验证：通过")  # 明确输出验证结论。
    return True  # 返回验证成功。


def main():
    """程序入口。"""
    parser = argparse.ArgumentParser(description="检查PrimeVul和修复数据")  # 创建参数解析器。
    parser.add_argument("--config", required=True, help="配置文件路径")  # 添加配置参数。
    args = parser.parse_args()  # 解析命令行参数。
    config, _ = load_config(args.config)  # 读取配置，并相对于config位置解析路径。
    prime_files = list(config.get("primevul_files", []))  # 读取PrimeVul文件列表。
    paired_files = list(config.get("paired_files", []))  # 读取精确配对文件列表。
    patched_files = list(config.get("patched_files", []))  # 读取独立修复文件列表。
    if not prime_files and not paired_files and not patched_files:  # 判断是否完全没有数据路径。
        raise SystemExit("请先填写config.json中的primevul_files、paired_files或patched_files")  # 提示配置路径。
    all_ok = True  # 汇总文件存在性和配对结构检查结果。
    for file_name in prime_files:  # 遍历PrimeVul文件。
        path = Path(file_name)  # 转换为Path对象。
        if not path.exists():  # 检查文件是否存在。
            print(f"[ERROR] 文件不存在：{path}")  # 输出错误。
            all_ok = False  # 标记检查失败。
            continue  # 继续检查其他文件。
        all_ok = inspect_file(path) and all_ok  # 检查PrimeVul文件。
    for file_name in paired_files:  # 遍历精确配对文件。
        path = Path(file_name)  # 转换为Path对象。
        if not path.exists():  # 检查文件是否存在。
            print(f"[ERROR] 文件不存在：{path}")  # 输出错误。
            all_ok = False  # 标记检查失败。
            continue  # 继续检查其他文件。
        all_ok = inspect_file(path) and all_ok  # paired文件同时包含target=1和target=0。
        all_ok = inspect_pair_structure(path) and all_ok  # 进一步检查相邻记录是否构成精确漏洞—修复对。
    for file_name in patched_files:  # 遍历独立修复版本文件。
        path = Path(file_name)  # 转换为Path对象。
        if not path.exists():  # 检查文件是否存在。
            print(f"[ERROR] 文件不存在：{path}")  # 输出错误。
            all_ok = False  # 标记检查失败。
            continue  # 继续检查其他文件。
        all_ok = inspect_file(path, forced_kind="patched") and all_ok  # 按修复版本检查文件。
    overlap = set(map(str, paired_files)) & set(map(str, patched_files))  # 检查历史上的错误重复配置。
    if overlap:
        print(f"[ERROR] paired_files与patched_files发生重叠：{sorted(overlap)}")
        all_ok = False
    if not all_ok:
        raise SystemExit(1)  # 让自动化脚本能够感知检查失败。


if __name__ == "__main__":  # 判断是否直接运行本文件。
    main()  # 调用程序入口。

