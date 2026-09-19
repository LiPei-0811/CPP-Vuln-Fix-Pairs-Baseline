#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""构造“100个漏洞—修复精确配对 + 200个普通良性函数”的基线实验样本。"""

from __future__ import annotations

import argparse  # 解析命令行参数。
import csv  # 读取CSV格式数据。
import difflib  # 计算漏洞版本与修复版本的行级差异证据。
import gzip  # 读取gzip压缩数据。
import hashlib  # 生成稳定样本ID和代码指纹。
import json  # 读取配置、数据和写出结果。
import random  # 使用固定随机种子抽样。
import re  # 解析CWE编号。
from collections import Counter  # 统计类别、CWE和项目分布。
from pathlib import Path  # 处理文件路径。

from common import (  # 统一路径与安全代码规范化。
    CODE_NORMALIZATION_VERSION,
    load_config,
    normalize_cpp_for_hash,
)

CODE_KEYS = ("func", "function", "code", "source", "snippet")  # 候选代码字段。
LABEL_KEYS = ("target", "label", "vulnerable", "is_vulnerable")  # 候选标签字段。
CWE_KEYS = ("cwe", "CWE", "cwe_id", "cwe_ids")  # 候选CWE字段。
PROJECT_KEYS = ("project", "repo", "repository", "project_name")  # 候选项目字段。
DATE_KEYS = ("commit_date", "commit_time", "date", "timestamp")  # 候选时间字段。
PATCH_KEYS = ("is_patched", "patched", "is_fix", "fixed", "status", "version_type")  # 候选修复字段。


def open_text(path: Path):
    """打开普通文本文件或gzip压缩文本文件。"""
    if path.suffix.lower() == ".gz":  # 判断是否为gzip文件。
        return gzip.open(path, "rt", encoding="utf-8-sig")  # 以UTF-8文本方式打开gzip。
    return path.open("r", encoding="utf-8-sig")  # 兼容Windows工具写入的UTF-8 BOM。


def load_rows(path: Path):
    """读取JSONL、JSON数组、JSON对象或CSV数据。"""
    suffixes = path.suffixes  # 获取全部后缀。
    suffix = suffixes[-2] if path.suffix.lower() == ".gz" and len(suffixes) > 1 else path.suffix  # 获取真实数据后缀。
    if suffix.lower() == ".csv":  # 判断是否为CSV。
        with open_text(path) as handle:  # 打开CSV文件。
            yield from csv.DictReader(handle)  # 按字典逐行返回。
        return  # 结束CSV分支。
    with open_text(path) as handle:  # 打开JSON或JSONL文件。
        text = handle.read()  # 读取完整文本。
    if suffix.lower() == ".json":  # 判断是否为普通JSON。
        data = json.loads(text)  # 解析JSON。
        records = data if isinstance(data, list) else [data]  # 统一包装为列表。
        for position, record in enumerate(records, 1):  # 遍历JSON记录。
            if not isinstance(record, dict):
                raise ValueError(f"{path}: JSON第{position}条记录必须是对象")
            yield record  # 返回当前记录。
        return  # 结束JSON分支。
    for line_number, line in enumerate(text.splitlines(), 1):  # 逐行解析JSONL。
        line = line.strip()  # 删除首尾空白。
        if not line:  # 跳过空行。
            continue  # 继续下一行。
        try:  # 尝试解析JSON。
            record = json.loads(line)  # 解析当前行。
        except json.JSONDecodeError as exc:  # 捕获非法JSON。
            raise ValueError(f"{path}:{line_number}不是合法JSON：{exc}") from exc
        if not isinstance(record, dict):
            raise ValueError(f"{path}:{line_number}必须是JSON对象")
        yield record  # 返回当前记录。


def first_value(record: dict, keys, default=None):
    """读取多个候选字段中第一个非空值。"""
    for key in keys:  # 遍历候选字段。
        if key in record and record[key] not in (None, ""):  # 检查字段是否有效。
            return record[key]  # 返回第一个有效值。
    return default  # 没找到时返回默认值。


def normalize_bool(value):
    """把常见标签表达转换成布尔值。"""
    if isinstance(value, bool):  # 处理布尔值。
        return value  # 直接返回。
    if isinstance(value, (int, float)) and value in {0, 1}:  # 只接受严格0/1数字标签。
        return bool(value)  # 转成布尔值。
    if isinstance(value, str):  # 处理字符串。
        text = value.strip().lower()  # 统一大小写。
        if text in {"1", "true", "yes", "vulnerable", "positive"}:  # 判断漏洞标签。
            return True  # 返回True。
        if text in {"0", "false", "no", "benign", "negative"}:  # 判断良性标签。
            return False  # 返回False。
    return None  # 无法识别时返回None。


def normalize_cwe(value):
    """将CWE字段统一成CWE-数字形式。"""
    if value in (None, ""):  # 处理空值。
        return None  # 返回None。
    if isinstance(value, list):  # 处理列表形式。
        value = value[0] if value else None  # 取第一项。
    if value in (None, ""):  # 再次检查空值。
        return None  # 返回None。
    match = re.search(r"CWE[-_ ]?\d+", str(value), flags=re.I)  # 提取CWE编号。
    if match:  # 判断是否提取成功。
        return match.group(0).upper().replace("_", "-").replace(" ", "-")  # 返回规范格式。
    return str(value)  # 无法提取时保留原值。


def vulnerability_lines(record):
    """读取函数内相对漏洞行号。"""
    values = record.get("vul_lines", record.get("vulnerability_lines", []))  # 优先读取行号列表。
    if isinstance(values, int):  # 处理单个整数。
        values = [values]  # 包装成列表。
    clean = []  # 创建清洗列表。
    if isinstance(values, list):  # 判断是否为列表。
        for value in values:  # 遍历行号。
            try:  # 尝试转整数。
                clean.append(int(value))  # 保存行号。
            except (TypeError, ValueError):  # 忽略非法值。
                continue  # 继续处理。
    if clean:  # 如果已经取得行号。
        return clean  # 返回行号。
    start = record.get("line_start", record.get("start_line"))  # 读取起始行。
    end = record.get("line_end", record.get("end_line", start))  # 读取结束行。
    if start is None:  # 没有起始行。
        return []  # 返回空列表。
    try:  # 尝试转换行号。
        return list(range(int(start), int(end) + 1))  # 返回闭区间行号。
    except (TypeError, ValueError):  # 处理异常。
        return []  # 返回空列表。


def code_hash(code: str):
    """计算函数代码SHA1，用于排除数据重复。"""
    return hashlib.sha1(code.encode("utf-8", "ignore")).hexdigest()  # 返回代码哈希。


def normalized_code_hash(code: str):
    """按C/C++词法单元计算指纹，避免误删字符串字面量中的空白。"""
    normalized = normalize_cpp_for_hash(code)
    return hashlib.sha1(normalized.encode("utf-8", "ignore")).hexdigest()  # 返回规范化哈希。


def changed_line_numbers(vulnerable_code: str, patched_code: str):
    """计算修复前后发生变化的相对行号；它是补丁差异证据，不等同于漏洞行gold。"""
    vulnerable_lines = vulnerable_code.splitlines()  # 拆分漏洞版本行。
    patched_lines = patched_code.splitlines()  # 拆分修复版本行。
    matcher = difflib.SequenceMatcher(None, vulnerable_lines, patched_lines, autojunk=False)  # 构造稳定差异匹配器。
    vulnerable_changed = []  # 保存修复前发生变化的行号。
    patched_changed = []  # 保存修复后发生变化的行号。
    for tag, old_start, old_end, new_start, new_end in matcher.get_opcodes():  # 遍历差异块。
        if tag == "equal":  # 相同行不是补丁证据。
            continue
        vulnerable_changed.extend(range(old_start + 1, old_end + 1))  # 转换为1基修复前行号。
        patched_changed.extend(range(new_start + 1, new_end + 1))  # 转换为1基修复后行号。
    return vulnerable_changed, patched_changed  # 返回两侧差异行。


def normalize_record(record, source, row_number, kind, pair_id=None, pair_role=None, pair_cwe=None):
    """将原始记录转换成统一样本格式。"""
    code = first_value(record, CODE_KEYS, "")  # 读取函数代码。
    if not isinstance(code, str) or not code.strip():  # 检查代码有效性。
        return None  # 没有代码时舍弃。
    source_cwe = normalize_cwe(first_value(record, CWE_KEYS)) or pair_cwe  # 保存原始数据携带的CWE信息。
    cwe = source_cwe if kind in {"vulnerable", "patched"} else None  # 普通良性函数没有可解释为gold的CWE。
    source_identity = Path(source).name  # 只使用文件名，避免移动项目目录后sample_id变化。
    original_index = record.get("idx", row_number)  # 优先使用数据集原始索引。
    raw_id = f"{source_identity}:{original_index}:{kind}:{code_hash(code)}"  # 组成位置无关的稳定ID输入。
    return {  # 返回标准记录。
        "sample_id": hashlib.sha1(raw_id.encode("utf-8")).hexdigest()[:16],  # 生成稳定样本ID。
        "source_file": str(source),  # 保存来源文件。
        "source_row": row_number,  # 保存来源行号。
        "kind": kind,  # 保存vulnerable、patched或benign。
        "gold_vulnerable": kind == "vulnerable",  # 保存布尔真实标签。
        "gold_label": 1 if kind == "vulnerable" else 0,  # 保存数值真实标签。
        "pair_id": pair_id,  # 保存共享的配对ID。
        "pair_role": pair_role,  # 保存vulnerable或patched配对角色。
        "code": code,  # 保存函数代码。
        "code_hash": code_hash(code),  # 保存代码哈希。
        "normalized_code_hash": normalized_code_hash(code),  # 保存忽略空白的代码哈希。
        "cwe": cwe,  # 保存CWE。
        "source_cwe": source_cwe,  # 保留来源字段用于数据审计，不作为普通良性函数的gold CWE。
        "project": str(first_value(record, PROJECT_KEYS, "")),  # 保存项目名。
        "commit_date": str(first_value(record, DATE_KEYS, "")),  # 保存提交日期。
        "commit_id": str(record.get("commit_id", record.get("commit", ""))),  # 保存提交ID。
        "func_name": str(record.get("func_name", record.get("function_name", ""))),  # 保存函数名。
        "line_start": record.get("line_start", record.get("start_line")),  # 保存起始行。
        "line_end": record.get("line_end", record.get("end_line")),  # 保存结束行。
        "vul_lines": vulnerability_lines(record) if kind == "vulnerable" else [],  # 只有漏洞版本保存漏洞行。
        "code_lines": code.count("\n") + 1,  # 保存函数代码行数。
    }  # 结束标准记录。


def load_prime_records(paths):
    """读取普通PrimeVul文件，用于抽取200个普通良性函数。"""
    records = []  # 创建记录列表。
    for file_name in paths:  # 遍历普通数据文件。
        path = Path(file_name)  # 转换为Path对象。
        if not path.exists():  # 检查文件是否存在。
            raise FileNotFoundError(f"找不到PrimeVul文件：{path}")  # 抛出错误。
        for row_number, record in enumerate(load_rows(path), 1):  # 遍历记录。
            label = normalize_bool(first_value(record, LABEL_KEYS))  # 读取漏洞标签。
            if label is None:
                raise ValueError(f"{path}:{row_number}缺少合法0/1标签")
            if label is not False:  # 只使用明确的普通良性样本。
                continue  # 跳过漏洞和未知标签。
            item = normalize_record(record, path, row_number, kind="benign")  # 标准化良性记录。
            if item:  # 检查记录有效。
                records.append(item)  # 保存记录。
    return records  # 返回普通良性记录。


def pair_file(path: Path):
    """将paired文件按相邻的target=1和target=0组成精确漏洞—修复对。"""
    rows = list(load_rows(path))  # 读取paired文件全部记录。
    if len(rows) % 2 != 0:  # 检查记录数是否为偶数。
        raise ValueError(f"paired文件记录数不是偶数：{path}，记录数={len(rows)}")  # 抛出结构错误。
    pairs = []  # 创建配对列表。
    for offset in range(0, len(rows), 2):  # 每两条记录组成一对。
        first = rows[offset]  # 读取第一条。
        second = rows[offset + 1]  # 读取第二条。
        first_row_number = offset + 1  # 保存第一条在源文件中的真实行号。
        second_row_number = offset + 2  # 保存第二条在源文件中的真实行号。
        first_label = normalize_bool(first_value(first, LABEL_KEYS))  # 读取第一条标签。
        second_label = normalize_bool(first_value(second, LABEL_KEYS))  # 读取第二条标签。
        if first_label is False and second_label is True:  # 如果顺序刚好相反。
            first, second = second, first  # 交换成漏洞在前、修复在后。
            first_row_number, second_row_number = second_row_number, first_row_number  # 同步交换真实源行号。
            first_label, second_label = second_label, first_label  # 同步交换标签。
        if first_label is not True or second_label is not False:  # 检查是否为1/0配对。
            raise ValueError(f"paired文件第{offset + 1}-{offset + 2}行不是target=1/0配对")  # 抛出错误。
        first_project = first_value(first, PROJECT_KEYS, "")
        second_project = first_value(second, PROJECT_KEYS, "")
        first_commit = str(first.get("commit_id", first.get("commit", "")))
        second_commit = str(second.get("commit_id", second.get("commit", "")))
        if not first_project or not second_project:
            raise ValueError(f"paired文件第{offset + 1}-{offset + 2}行缺少项目字段")
        if not first_commit or not second_commit:
            raise ValueError(f"paired文件第{offset + 1}-{offset + 2}行缺少commit_id")
        if first_project != second_project:  # 检查项目一致。
            raise ValueError(f"paired文件第{offset + 1}-{offset + 2}行项目不一致")  # 抛出错误。
        if first_commit != second_commit:  # 检查提交一致。
            raise ValueError(f"paired文件第{offset + 1}-{offset + 2}行commit_id不一致")  # 抛出错误。
        first_pair_key = first.get("big_vul_idx")  # 读取PrimeVul提供的配对索引（若存在）。
        second_pair_key = second.get("big_vul_idx")  # 读取修复版本的配对索引（若存在）。
        if first_pair_key not in (None, "") and second_pair_key not in (None, "") and first_pair_key != second_pair_key:  # 两侧均有配对索引时必须一致。
            raise ValueError(f"paired文件第{offset + 1}-{offset + 2}行big_vul_idx不一致")  # 抛出错误。
        pair_identity = (  # 使用项目、提交和原始索引生成位置无关的配对ID。
            f"{path.name}:{first_value(first, PROJECT_KEYS, '')}:"
            f"{first.get('commit_id', '')}:{first.get('idx', offset)}:{second.get('idx', offset + 1)}"
        )
        pair_id = hashlib.sha1(pair_identity.encode("utf-8")).hexdigest()[:16]  # 生成共享配对ID。
        pair_cwe = normalize_cwe(first_value(first, CWE_KEYS)) or normalize_cwe(first_value(second, CWE_KEYS))  # 在两条记录之间传播CWE。
        vulnerable = normalize_record(first, path, first_row_number, "vulnerable", pair_id, "vulnerable", pair_cwe)  # 构造漏洞版本。
        patched = normalize_record(second, path, second_row_number, "patched", pair_id, "patched", pair_cwe)  # 构造修复版本。
        if vulnerable and patched:  # 检查两条记录都有效。
            if vulnerable["code_hash"] == patched["code_hash"]:  # 漏洞版本和修复版本不应是完全相同的代码。
                raise ValueError(f"paired文件第{offset + 1}-{offset + 2}行代码完全相同，不能作为有效修复对")  # 阻止无效配对进入样本。
            vulnerable_changed, patched_changed = changed_line_numbers(vulnerable["code"], patched["code"])  # 提取补丁差异行。
            for item in (vulnerable, patched):  # 两侧都保存同一配对的差异证据。
                item["pair_changed_vulnerable_lines"] = vulnerable_changed  # 修复前变化行，仅作diff证据。
                item["pair_changed_patched_lines"] = patched_changed  # 修复后变化行，仅作diff证据。
                item["diff_evidence_available"] = bool(vulnerable_changed or patched_changed)  # 标记是否取得差异。
            pairs.append({"pair_id": pair_id, "cwe": pair_cwe, "vulnerable": vulnerable, "patched": patched})  # 保存完整配对。
    return pairs  # 返回配对列表。


def load_pairs(paths):
    """读取多个paired文件。"""
    pairs = []  # 创建总配对列表。
    for file_name in paths:  # 遍历paired文件路径。
        path = Path(file_name)  # 转换为Path对象。
        if not path.exists():  # 检查文件存在。
            raise FileNotFoundError(f"找不到paired文件：{path}")  # 抛出错误。
        pairs.extend(pair_file(path))  # 解析并追加当前文件的配对。
    return pairs  # 返回全部配对。


def choose_pairs(pairs, count, priority_cwes, rng):
    """优先覆盖目标CWE并抽取完整函数对。"""
    if len(pairs) < count:  # 检查完整配对数量。
        raise ValueError(f"完整漏洞—修复对不足：需要{count}，实际{len(pairs)}")  # 抛出数量错误。
    groups = {cwe: [] for cwe in priority_cwes}  # 创建优先CWE分组。
    others = []  # 创建其他配对列表。
    for pair in pairs:  # 遍历全部配对。
        if pair.get("cwe") in groups:  # 判断是否为优先CWE。
            groups[pair["cwe"]].append(pair)  # 放入相应CWE分组。
        else:  # 处理其他或缺失CWE。
            others.append(pair)  # 放入其他列表。
    for group in groups.values():  # 遍历优先CWE分组。
        rng.shuffle(group)  # 打乱当前分组。
    selected = []  # 创建选中配对列表。
    while len(selected) < count:  # 轮转抽取优先CWE。
        changed = False  # 记录本轮是否抽到配对。
        for cwe in priority_cwes:  # 按优先CWE顺序循环。
            if groups[cwe] and len(selected) < count:  # 检查分组非空和数量未满。
                selected.append(groups[cwe].pop())  # 取出一个完整配对。
                changed = True  # 标记本轮有抽样。
        if not changed:  # 目标CWE配对都已抽空。
            break  # 结束轮转。
    remaining = count - len(selected)  # 计算还需要多少其他配对。
    if remaining > len(others):  # 防止目标CWE轮转后候选不足。
        raise ValueError(f"其他完整配对不足：需要补齐{remaining}，实际{len(others)}")
    selected.extend(rng.sample(others, remaining))  # 使用seed真正随机无放回抽样，而不是依赖文件顺序。
    rng.shuffle(selected)  # 打乱最终配对顺序。
    return selected[:count]  # 返回指定数量的完整配对。


def choose_benign(records, count, excluded_hashes, excluded_normalized_hashes, excluded_commit_keys, rng):
    """抽取不与paired数据在代码、规范化代码或项目提交层面重叠的普通良性函数。"""
    after_exact = [record for record in records if record["code_hash"] not in excluded_hashes]  # 排除完全相同代码。
    after_normalized = [record for record in after_exact if record["normalized_code_hash"] not in excluded_normalized_hashes]  # 排除仅空白不同的代码。
    unique_by_normalized_hash = {}  # 防止普通良性候选自身包含重复代码。
    for record in after_normalized:
        unique_by_normalized_hash.setdefault(record["normalized_code_hash"], record)
    after_internal_dedup = list(unique_by_normalized_hash.values())
    candidates = [  # 排除与paired数据来自同一项目同一提交的其他函数。
        record
        for record in after_internal_dedup
        if (record.get("project"), record.get("commit_id")) not in excluded_commit_keys
    ]
    if len(candidates) < count:  # 检查良性样本数量。
        raise ValueError(f"排除paired重叠后，普通良性样本不足：需要{count}，实际{len(candidates)}")  # 抛出数量错误。
    stats = {  # 返回每一步排除后的候选规模，便于论文报告数据清洗过程。
        "initial": len(records),
        "after_exact_hash_exclusion": len(after_exact),
        "after_normalized_hash_exclusion": len(after_normalized),
        "after_internal_normalized_deduplication": len(after_internal_dedup),
        "after_project_commit_exclusion": len(candidates),
    }
    return rng.sample(candidates, count), stats  # 使用固定seed随机无放回抽样。


def main():
    """程序入口。"""
    parser = argparse.ArgumentParser(description="构造400个C/C++漏洞—修复对基线实验样本")  # 创建参数解析器。
    parser.add_argument("--config", required=True, help="配置文件路径")  # 添加配置参数。
    parser.add_argument("--inspect-only", action="store_true", help="只检查数量，不写出样本")  # 添加检查模式。
    args = parser.parse_args()  # 解析参数。
    config, _ = load_config(args.config)  # 读取配置，并相对于config位置解析路径。
    prime_files = list(config.get("primevul_files", []))  # 读取普通PrimeVul文件。
    paired_files = list(config.get("paired_files", []))  # 读取成对数据文件。
    patched_files = list(config.get("patched_files", []))  # 读取兼容字段。
    if not prime_files:  # 检查普通数据路径。
        raise SystemExit("请在config.json中填写primevul_files")  # 提示用户。
    if not paired_files:  # 检查成对数据路径。
        raise SystemExit("请在config.json中填写paired_files")  # 提示用户。
    overlap = set(map(str, paired_files)) & set(map(str, patched_files))  # 检查历史错误配置。
    if overlap:
        raise SystemExit(f"paired_files不能同时出现在patched_files中：{sorted(overlap)}")
    if patched_files:
        raise SystemExit("当前精确配对流程不使用独立patched_files，请保持为空数组[]")
    pairs = load_pairs(paired_files)  # 读取全部完整配对。
    benign_records = load_prime_records(prime_files)  # 读取普通良性记录。
    if args.inspect_only:  # 判断是否为检查模式。
        print(f"完整漏洞—修复对：{len(pairs)}")  # 输出配对数量。
        print(f"配对CWE分布：{Counter(pair.get('cwe') for pair in pairs)}")  # 输出配对CWE分布。
        print(f"普通良性记录：{len(benign_records)}")  # 输出普通良性数量。
        return  # 结束检查模式。
    counts = config.get("sample_counts", {"vulnerable": 100, "patched": 100, "benign": 200})  # 读取样本数量配置。
    if int(counts["vulnerable"]) != int(counts["patched"]):  # 检查漏洞和修复数量是否相同。
        raise ValueError("成对抽样要求vulnerable和patched数量相等")  # 抛出配对数量错误。
    if sum(int(value) for value in counts.values()) != 400:  # 当前脚本及下游文件名固定为sample_400.jsonl。
        raise ValueError("当前基线实验固定使用400条样本，请保持100 vulnerable + 100 patched + 200 benign")
    rng = random.Random(int(config.get("sample_seed", 20260916)))  # 创建固定随机数生成器。
    priority_cwes = config.get("priority_cwes", ["CWE-787", "CWE-125", "CWE-416", "CWE-190", "CWE-20"])  # 读取优先CWE。
    selected_pairs = choose_pairs(pairs, int(counts["vulnerable"]), priority_cwes, rng)  # 抽取100个完整配对。
    all_pair_hashes = {side["code_hash"] for pair in pairs for side in (pair["vulnerable"], pair["patched"])}  # 计算所有paired代码哈希。
    all_pair_normalized_hashes = {side["normalized_code_hash"] for pair in pairs for side in (pair["vulnerable"], pair["patched"])}  # 计算忽略空白的哈希。
    all_pair_commit_keys = {  # 收集paired数据的项目+提交，防止同一修复提交泄漏到普通良性样本。
        (side.get("project"), side.get("commit_id"))
        for pair in pairs
        for side in (pair["vulnerable"], pair["patched"])
    }
    selected_benign, benign_filter_stats = choose_benign(  # 抽取200个不重叠普通良性函数。
        benign_records,
        int(counts["benign"]),
        all_pair_hashes,
        all_pair_normalized_hashes,
        all_pair_commit_keys,
        rng,
    )
    selected = []  # 创建最终样本列表。
    for pair in selected_pairs:  # 遍历选中的配对。
        selected.append(pair["vulnerable"])  # 添加漏洞版本。
        selected.append(pair["patched"])  # 添加对应修复版本。
    selected.extend(selected_benign)  # 添加普通良性函数。
    rng.shuffle(selected)  # 打乱最终400个样本顺序。
    selected_normalized_hashes = [record["normalized_code_hash"] for record in selected]
    if len(selected_normalized_hashes) != len(set(selected_normalized_hashes)):
        raise RuntimeError("最终样本存在规范化代码重复，已拒绝写出")
    for index, record in enumerate(selected, 1):  # 遍历最终样本。
        record["sample_index"] = index  # 添加顺序编号。
    pair_ids = Counter(record.get("pair_id") for record in selected if record.get("pair_id"))  # 统计pair_id出现次数。
    selected_pair_checks = []  # 保存每个已选配对的严格验证结果。
    for pair in selected_pairs:  # 逐对检查最终选中的100个漏洞—修复对。
        vulnerable = pair["vulnerable"]  # 读取漏洞版本。
        patched = pair["patched"]  # 读取对应修复版本。
        selected_pair_checks.append(  # 保存当前配对是否同时满足全部条件。
            vulnerable.get("pair_id") == patched.get("pair_id")  # 两侧共享同一个pair_id。
            and vulnerable.get("kind") == "vulnerable"  # 第一侧必须是漏洞版本。
            and patched.get("kind") == "patched"  # 第二侧必须是修复版本。
            and vulnerable.get("gold_label") == 1  # 漏洞版本真实标签必须为1。
            and patched.get("gold_label") == 0  # 修复版本真实标签必须为0。
            and vulnerable.get("project") == patched.get("project")  # 两侧必须来自同一项目。
            and vulnerable.get("commit_id") == patched.get("commit_id")  # 两侧必须来自同一修复提交。
            and vulnerable.get("code_hash") != patched.get("code_hash")  # 修复前后代码必须不同。
        )  # 结束当前配对检查。
    pair_integrity_ok = (  # 汇总最终配对完整性。
        len(pair_ids) == len(selected_pairs)  # pair_id数量必须等于选中的配对数。
        and all(value == 2 for value in pair_ids.values())  # 每个pair_id必须在样本中出现两次。
        and all(selected_pair_checks)  # 每对都必须通过角色、标签、项目、提交和代码差异检查。
    )  # 完成完整性布尔值。
    if not pair_integrity_ok:  # 最终样本若不满足精确配对条件则立即终止。
        raise RuntimeError("生成后的漏洞—修复对完整性检查失败，已拒绝写出不可靠结果")  # 防止继续运行错误实验。
    output_dir = Path(config.get("output_dir", "experiment_workspace"))  # 读取输出目录。
    prepared_dir = output_dir / "prepared"  # 定义prepared目录。
    prepared_dir.mkdir(parents=True, exist_ok=True)  # 创建prepared目录。
    sample_path = prepared_dir / "sample_400.jsonl"  # 定义样本输出路径。
    with sample_path.open("w", encoding="utf-8") as handle:  # 验证通过后才打开样本输出文件。
        for record in selected:  # 遍历最终样本。
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")  # 写入JSONL。
    report = {  # 构造统计报告。
        "experiment_name": config.get("experiment_name"),  # 保存规范中文实验名称。
        "experiment_slug": config.get("experiment_slug"),  # 保存目录和脚本使用的英文标识。
        "seed": config.get("sample_seed", 20260916),  # 保存随机种子。
        "requested_counts": counts,  # 保存请求数量。
        "selected_counts": dict(Counter(record["kind"] for record in selected)),  # 保存实际类型数量。
        "selected_pair_count": len(selected_pairs),  # 保存完整配对数量。
        "pair_integrity_ok": pair_integrity_ok,  # 保存严格配对完整性验证结果。
        "pair_cwe_counts": dict(Counter(pair.get("cwe") for pair in selected_pairs)),  # 保存配对CWE分布。
        "sample_cwe_counts": dict(Counter(record.get("cwe") for record in selected)),  # 保存全部样本CWE分布。
        "cwe_counts_by_kind": {  # 分类别报告CWE，避免把benign的历史CWE与漏洞对混为一谈。
            kind: dict(Counter(record.get("cwe") for record in selected if record["kind"] == kind))
            for kind in ("vulnerable", "patched", "benign")
        },
        "source_cwe_counts_by_kind": {  # 单独报告原始数据携带的CWE，避免与有效gold混淆。
            kind: dict(Counter(record.get("source_cwe") for record in selected if record["kind"] == kind))
            for kind in ("vulnerable", "patched", "benign")
        },
        "selected_pair_cwe_missing_count": sum(pair.get("cwe") is None for pair in selected_pairs),  # 保存配对CWE缺失数。
        "selected_pair_cwe_missing_rate": sum(pair.get("cwe") is None for pair in selected_pairs) / len(selected_pairs),  # 保存CWE缺失率。
        "project_counts": dict(Counter(record.get("project") for record in selected)),  # 保存项目分布。
        "paired_file_count": len(pairs),  # 保存原始完整配对数量。
        "sampling_method": "priority-CWE round-robin + seeded random sampling without replacement",  # 明确真正抽样方法。
        "code_normalization_version": CODE_NORMALIZATION_VERSION,
        "benign_filter_stats": benign_filter_stats,  # 保存良性样本去泄漏统计。
        "benign_unique_project_count": len(
            {record.get("project") for record in selected if record["kind"] == "benign"}
        ),
        "benign_unique_project_commit_count": len(
            {
                (record.get("project"), record.get("commit_id"))
                for record in selected
                if record["kind"] == "benign"
            }
        ),
        "benign_max_functions_per_project_commit": max(
            Counter(
                (record.get("project"), record.get("commit_id"))
                for record in selected
                if record["kind"] == "benign"
            ).values(),
            default=0,
        ),
        "vulnerable_location_label_count": sum(bool(record.get("vul_lines")) for record in selected if record["kind"] == "vulnerable"),  # 有真实漏洞行的漏洞样本数。
        "location_evaluation_available": any(record.get("vul_lines") for record in selected if record["kind"] == "vulnerable"),  # 标记能否做Top-k。
        "pair_diff_evidence_count": sum(bool(pair["vulnerable"].get("diff_evidence_available")) for pair in selected_pairs),  # 有补丁差异证据的配对数。
        "notes": [  # 保存实验边界和语义说明。
            "100个漏洞函数与100个修复函数通过pair_id一一对应。",
            "patched标签仅表示对应已知漏洞的修复版本，不代表绝对安全。",
            "普通良性函数已排除paired数据的精确代码、空白规范化代码及相同项目提交。",
            "普通良性函数的cwe统一设为null；原始字段保存在source_cwe中，仅供数据审计。",
            "pair_changed_*是补丁差异行，不自动视为真实漏洞行gold。",
            "没有vul_lines时Top-k定位必须报告N/A，而不是0%。",
            "旧提示词含CWE-787锚定的预测结果不能与新提示词结果混用。",
        ],
    }  # 结束报告。
    report_path = prepared_dir / "sample_report.json"  # 定义报告输出路径。
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")  # 写入报告。
    print(f"[OK] 已生成精确配对样本：{sample_path}")  # 输出样本路径。
    print(f"[OK] 已生成配对报告：{report_path}")  # 输出报告路径。
    print(f"[OK] 配对完整性：{report['pair_integrity_ok']}")  # 输出配对完整性。


if __name__ == "__main__":  # 判断是否直接执行脚本。
    main()  # 调用程序入口。
