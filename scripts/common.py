#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""C/C++漏洞—修复对直接检测与修复敏感性基线实验的共享函数。"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any


CWE_PATTERN = re.compile(r"^CWE-\d+$", flags=re.I)
REQUIRED_PREDICTION_KEYS = ("vulnerable", "cwe", "location", "confidence", "reason")
CODE_NORMALIZATION_VERSION = "cpp-lexer-v1"
CPP_MULTI_CHAR_OPERATORS = tuple(
    sorted(
        {
            "<<=",
            ">>=",
            "->*",
            "...",
            "##",
            "::",
            ".*",
            "->",
            "++",
            "--",
            "<<",
            ">>",
            "<=",
            ">=",
            "==",
            "!=",
            "&&",
            "||",
            "*=",
            "/=",
            "%=",
            "+=",
            "-=",
            "&=",
            "^=",
            "|=",
        },
        key=len,
        reverse=True,
    )
)
GOLD_SIGNATURE_KEYS = (
    "sample_id",
    "sample_index",
    "kind",
    "gold_vulnerable",
    "gold_label",
    "pair_id",
    "pair_role",
    "code",
    "func_name",
    "cwe",
    "vul_lines",
    "code_lines",
)


def resolve_path(value: str | Path, base_dir: Path) -> Path:
    """把相对路径解释为相对于config.json所在目录，而不是当前终端目录。"""
    path = Path(value).expanduser()
    return path.resolve() if path.is_absolute() else (base_dir / path).resolve()


def load_config(config_path: str | Path) -> tuple[dict[str, Any], Path]:
    """读取配置，并统一解析数据路径与输出路径。"""
    path = Path(config_path).expanduser().resolve()
    config = json.loads(path.read_text(encoding="utf-8-sig"))
    base_dir = path.parent
    for key in ("primevul_files", "paired_files", "patched_files"):
        config[key] = [str(resolve_path(value, base_dir)) for value in config.get(key, [])]
    if config.get("output_dir"):
        config["output_dir"] = str(resolve_path(config["output_dir"], base_dir))
    return config, path


def load_jsonl(path: str | Path) -> list[dict[str, Any]]:
    """严格读取JSONL；非法JSON或非对象记录会立即报错。"""
    file_path = Path(path)
    rows: list[dict[str, Any]] = []
    with file_path.open("r", encoding="utf-8-sig") as handle:
        for line_number, line in enumerate(handle, 1):
            line = line.strip()
            if not line:
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{file_path}:{line_number}不是合法JSON：{exc}") from exc
            if not isinstance(value, dict):
                raise ValueError(f"{file_path}:{line_number}必须是JSON对象")
            rows.append(value)
    return rows


def index_unique(rows: list[dict[str, Any]], key: str, source_name: str) -> dict[Any, dict[str, Any]]:
    """按指定字段建立唯一索引；缺失或重复键都会报错。"""
    index: dict[Any, dict[str, Any]] = {}
    for position, row in enumerate(rows, 1):
        value = row.get(key)
        if value in (None, ""):
            raise ValueError(f"{source_name}第{position}条记录缺少{key}")
        if value in index:
            raise ValueError(f"{source_name}存在重复{key}：{value}")
        index[value] = row
    return index


def file_sha256(path: str | Path) -> str:
    """计算文件SHA256，防止断点续跑时混入不同数据或提示词。"""
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_records_sha256(rows: list[dict[str, Any]]) -> str:
    """计算与路径无关的gold签名，覆盖推理输入、标签、配对和定位字段。"""
    digest = hashlib.sha256()
    for row in rows:
        canonical = {key: row.get(key) for key in GOLD_SIGNATURE_KEYS}
        encoded = json.dumps(
            canonical,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        digest.update(encoded)
        digest.update(b"\n")
    return digest.hexdigest()


def normalize_cpp_for_hash(code: str) -> str:
    """按轻量C/C++词法单元规范化代码，忽略格式和注释但保留字面量内容。"""
    tokens: list[str] = []
    length = len(code)
    position = 0

    def consume_quoted(start: int, quote_position: int, quote: str) -> int:
        cursor = quote_position + 1
        while cursor < length:
            if code[cursor] == "\\":
                cursor += 2
                continue
            if code[cursor] == quote:
                return cursor + 1
            cursor += 1
        return length

    while position < length:
        character = code[position]
        if character.isspace():
            position += 1
            continue
        if code.startswith("//", position):
            newline = code.find("\n", position + 2)
            position = length if newline < 0 else newline + 1
            continue
        if code.startswith("/*", position):
            end = code.find("*/", position + 2)
            position = length if end < 0 else end + 2
            continue

        raw_prefix = next(
            (
                prefix
                for prefix in ("u8R\"", "uR\"", "UR\"", "LR\"", "R\"")
                if code.startswith(prefix, position)
            ),
            None,
        )
        if raw_prefix is not None:
            delimiter_start = position + len(raw_prefix)
            body_start = code.find("(", delimiter_start, delimiter_start + 17)
            if body_start >= 0:
                delimiter = code[delimiter_start:body_start]
                terminator = ")" + delimiter + '"'
                end = code.find(terminator, body_start + 1)
                end = length if end < 0 else end + len(terminator)
                tokens.append(code[position:end])
                position = end
                continue

        quoted_prefix = next(
            (
                prefix
                for prefix in ('u8"', 'u"', 'U"', 'L"', "u8'", "u'", "U'", "L'")
                if code.startswith(prefix, position)
            ),
            None,
        )
        if quoted_prefix is not None:
            quote_position = position + len(quoted_prefix) - 1
            end = consume_quoted(position, quote_position, code[quote_position])
            tokens.append(code[position:end])
            position = end
            continue
        if character in {'"', "'"}:
            end = consume_quoted(position, position, character)
            tokens.append(code[position:end])
            position = end
            continue
        if character.isalpha() or character == "_":
            end = position + 1
            while end < length and (code[end].isalnum() or code[end] == "_"):
                end += 1
            tokens.append(code[position:end])
            position = end
            continue
        if character.isdigit():
            end = position + 1
            while end < length and (
                code[end].isalnum() or code[end] in {"_", ".", "'"}
            ):
                end += 1
            tokens.append(code[position:end])
            position = end
            continue
        operator = next(
            (value for value in CPP_MULTI_CHAR_OPERATORS if code.startswith(value, position)),
            None,
        )
        if operator is not None:
            tokens.append(operator)
            position += len(operator)
            continue
        tokens.append(character)
        position += 1
    return "\x1f".join(tokens)


def parse_strict_json_object(text: str) -> dict[str, Any] | None:
    """仅接受去除首尾空白后完整且唯一的JSON对象，不容忍代码围栏或额外说明。"""
    try:
        value = json.loads(text.strip())
    except (AttributeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def extract_first_json_object(text: str) -> dict[str, Any] | None:
    """从模型输出中提取第一个可解析的JSON对象，避免贪婪正则跨越多个对象。"""
    cleaned = re.sub(r"```(?:json)?", "", text.strip(), flags=re.I).replace("```", "").strip()
    try:
        value = json.loads(cleaned)
        return value if isinstance(value, dict) else None
    except json.JSONDecodeError:
        pass
    decoder = json.JSONDecoder()
    for position, character in enumerate(cleaned):
        if character != "{":
            continue
        try:
            value, _ = decoder.raw_decode(cleaned[position:])
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            return value
    return None


def validate_prediction_schema(value: Any, code_lines: int | None = None) -> tuple[bool, list[str]]:
    """校验原始预测是否满足字段、类型、范围和行号约束。"""
    errors: list[str] = []
    if not isinstance(value, dict):
        return False, ["预测不是JSON对象"]
    missing = [key for key in REQUIRED_PREDICTION_KEYS if key not in value]
    if missing:
        errors.append(f"缺少字段：{','.join(missing)}")
    vulnerable = value.get("vulnerable")
    if type(vulnerable) is not bool:
        errors.append("vulnerable必须是布尔值")
    cwe = value.get("cwe")
    if cwe is not None and (not isinstance(cwe, str) or not CWE_PATTERN.fullmatch(cwe.strip())):
        errors.append("cwe必须是CWE-数字或null")
    location = value.get("location")
    if not isinstance(location, list):
        errors.append("location必须是数组")
    else:
        seen: set[int] = set()
        for line in location:
            if type(line) is not int:
                errors.append("location只能包含整数")
                break
            if line <= 0:
                errors.append("location行号必须从1开始")
                break
            if code_lines is not None and line > code_lines:
                errors.append(f"location行号不能超过函数总行数{code_lines}")
                break
            if line in seen:
                errors.append("location不能包含重复行号")
                break
            seen.add(line)
    confidence = value.get("confidence")
    if type(confidence) not in (int, float) or not 0.0 <= float(confidence) <= 1.0:
        errors.append("confidence必须是0到1之间的数字")
    reason = value.get("reason")
    if not isinstance(reason, str) or not reason.strip():
        errors.append("reason必须是非空字符串")
    return not errors, errors


def prediction_semantic_warnings(value: Any) -> list[str]:
    """记录不影响JSON结构有效性、但需要在分析时注意的语义现象。"""
    if not isinstance(value, dict):
        return []
    warnings: list[str] = []
    if value.get("vulnerable") is False and value.get("location"):
        warnings.append("判定为非漏洞但location非空")
    if value.get("vulnerable") is False and value.get("cwe") is not None:
        warnings.append("判定为非漏洞但cwe非空")
    return warnings
