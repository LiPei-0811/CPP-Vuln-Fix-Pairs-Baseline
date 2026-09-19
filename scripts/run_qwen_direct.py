#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""运行Qwen代码模型的Direct静态漏洞检测，并严格校验结构化输出。"""

from __future__ import annotations

import argparse  # 解析命令行参数。
import hashlib  # 计算系统提示词签名。
import json  # 读取配置并写出JSONL。
import time  # 统计单样本推理耗时。
from pathlib import Path  # 处理跨平台路径。

from common import (  # 复用严格配置、哈希和Schema校验函数。
    canonical_records_sha256,
    extract_first_json_object,
    file_sha256,
    load_config,
    load_jsonl,
    parse_strict_json_object,
    prediction_semantic_warnings,
    resolve_path,
    validate_prediction_schema,
)

SYSTEM_PROMPT = (
    "你是C/C++软件安全审计助手。只输出基于给定代码证据的静态分析结论，"
    "不要提供漏洞利用步骤，不要把任务规则或分析方式当作代码安全性的证据。"
)


def normalize_prediction(value: dict | None) -> dict:
    """把原始模型对象转换为固定字段；该步骤不能替代Schema有效性判断。"""
    if not isinstance(value, dict):  # 原始输出无法解析为对象。
        return {"vulnerable": None, "cwe": None, "location": [], "confidence": None, "reason": ""}
    vulnerable = value.get("vulnerable")  # 读取漏洞判断。
    if isinstance(vulnerable, str):  # 为了保留错误输出用于评估，尝试规范常见字符串。
        lowered = vulnerable.strip().lower()
        vulnerable = True if lowered in {"true", "1", "yes", "是", "存在"} else False if lowered in {"false", "0", "no", "否", "不存在"} else None
    vulnerable = vulnerable if type(vulnerable) is bool else None  # 其他类型视为无效。
    raw_location = value.get("location", value.get("lines", []))  # 兼容少量旧字段。
    if isinstance(raw_location, int) and not isinstance(raw_location, bool):  # 单个整数包装为列表。
        raw_location = [raw_location]
    clean_location: list[int] = []  # 保存可转换的行号，但Schema错误仍会单独记录。
    if isinstance(raw_location, list):
        for line in raw_location:
            try:
                parsed = int(line)
            except (TypeError, ValueError):
                continue
            if parsed > 0 and parsed not in clean_location:
                clean_location.append(parsed)
    confidence = value.get("confidence")  # 读取模型自报置信度。
    try:
        confidence = float(confidence)
        confidence = confidence if 0.0 <= confidence <= 1.0 else None
    except (TypeError, ValueError):
        confidence = None
    cwe = value.get("cwe")  # 读取CWE编号。
    if cwe is not None:
        cwe = str(cwe).strip().upper()
        if cwe in {"", "NULL", "NONE", "UNKNOWN", "N/A"}:
            cwe = None
    reason = value.get("reason")  # 读取解释。
    return {
        "vulnerable": vulnerable,
        "cwe": cwe,
        "location": clean_location,
        "confidence": confidence,
        "reason": reason if isinstance(reason, str) else "",
    }


def build_prompt(template: str, record: dict, max_chars: int) -> tuple[str, bool, int]:
    """构造不包含sample_id、真实标签、真实CWE、kind和pair_id的Direct提示词。"""
    code = str(record.get("code", ""))  # 只读取函数代码。
    truncated = max_chars > 0 and len(code) > max_chars  # 判断是否需要字符级截断。
    visible_code = code[:max_chars] if truncated else code  # 模型只看到截断后的代码。
    metadata = {}  # 默认不提供任何可能与数据划分相关的元数据。
    function_name = record.get("func_name")  # 函数名通常已出现在代码中，但保留为空值检查。
    if function_name:
        metadata["function_name"] = function_name  # 只允许非标签函数名。
    prompt = template.replace("{metadata}", json.dumps(metadata, ensure_ascii=False)).replace("{code}", visible_code)
    return prompt, truncated, visible_code.count("\n") + 1


def build_run_signature(
    model_name: str,
    records: list[dict],
    prompt_path: Path,
    config: dict,
) -> dict:
    """记录本次运行签名，防止断点续跑混入旧提示词、旧数据或不同模型。"""
    return {
        "source": "qwen_direct",
        "experiment_name": config.get("experiment_name"),
        "experiment_slug": config.get("experiment_slug"),
        "model_name": model_name,
        "gold_canonical_sha256": canonical_records_sha256(records),
        "prompt_sha256": file_sha256(prompt_path),
        "system_prompt_sha256": hashlib.sha256(SYSTEM_PROMPT.encode("utf-8")).hexdigest(),
        "prompt_version": config.get("prompt_version", "direct-v2-no-cwe-anchor"),
        "inference_config": {
            "device_map": config.get("device_map", "auto"),
            "max_input_chars": int(config.get("max_input_chars", 24000)),
            "max_new_tokens": int(config.get("max_new_tokens", 384)),
            "temperature": float(config.get("temperature", 0.0)),
            "top_p": float(config.get("top_p", 1.0)),
            "generation_seed": int(config.get("generation_seed", 20260916)),
            "trust_remote_code": bool(config.get("trust_remote_code", False)),
        },
        "schema_version": "1.1",
    }


def main() -> None:
    """程序入口。"""
    parser = argparse.ArgumentParser(description="运行Qwen Direct漏洞检测")
    parser.add_argument("--config", required=True, help="JSON配置文件路径")
    parser.add_argument("--input", required=True, help="待预测样本JSONL路径")
    parser.add_argument("--output", required=True, help="预测JSONL输出路径")
    parser.add_argument(
        "--prompt",
        default=None,
        help="无具体CWE锚定的提示词路径",
    )
    parser.add_argument("--limit", type=int, default=0, help="只运行前N条；0表示全部")
    parser.add_argument(
        "--smoke-pair",
        action="store_true",
        help="只运行一个完整的vulnerable/patched函数对，用于配对Smoke Test",
    )
    parser.add_argument("--resume", action="store_true", help="仅在运行签名一致时按sample_id断点续跑")
    args = parser.parse_args()

    try:  # 延迟导入重量级依赖，便于先运行语法和数据检查。
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer
    except ImportError as exc:
        raise SystemExit("请先安装requirements.txt中的torch、transformers和accelerate") from exc

    config, config_path = load_config(args.config)  # 读取配置并规范配置内路径。
    input_path = Path(args.input).expanduser().resolve()  # 命令行输入路径按当前终端解析。
    default_prompt = Path(__file__).resolve().parents[1] / "prompts" / "direct_detection_zh.txt"
    prompt_value = args.prompt or config.get("prompt_file") or default_prompt
    prompt_path = resolve_path(prompt_value, config_path.parent)  # 配置内相对路径按config目录解析。
    output_path = Path(args.output).expanduser().resolve()  # 解析预测输出路径。
    records = load_jsonl(input_path)  # 严格读取样本。
    signature_records = records  # 运行签名始终覆盖完整输入，Smoke/limit仍可与完整gold核对。
    sample_ids = [row.get("sample_id") for row in records]  # 收集样本ID。
    if any(not value for value in sample_ids):
        raise SystemExit("输入样本存在空sample_id")
    if len(sample_ids) != len(set(sample_ids)):
        raise SystemExit("输入样本存在重复sample_id")
    if args.smoke_pair:
        pair_groups: dict[str, list[dict]] = {}
        for record in records:
            pair_id = record.get("pair_id")
            if pair_id:
                pair_groups.setdefault(str(pair_id), []).append(record)
        smoke_records = []
        for group in pair_groups.values():
            by_kind = {record.get("kind"): record for record in group}
            if set(by_kind) == {"vulnerable", "patched"}:
                smoke_records = [by_kind["vulnerable"], by_kind["patched"]]
                break
        if len(smoke_records) != 2:
            raise SystemExit("输入样本中没有找到完整的vulnerable/patched函数对")
        records = smoke_records
    elif args.limit > 0:
        records = records[: args.limit]  # Smoke Test只截取前N条。

    model_name = str(config.get("model_name", "Qwen/Qwen2.5-Coder-7B-Instruct"))
    prompt_template = prompt_path.read_text(encoding="utf-8")
    signature = build_run_signature(model_name, signature_records, prompt_path, config)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    completed: set[str] = set()
    input_sample_ids = set(sample_ids)
    if args.resume and output_path.exists():
        existing = load_jsonl(output_path)  # 断点续跑前严格检查旧结果。
        for row in existing:
            sample_id = row.get("sample_id")
            if sample_id in completed:
                raise SystemExit(f"旧预测文件存在重复sample_id：{sample_id}")
            completed.add(sample_id)
            if row.get("run_signature") != signature:
                raise SystemExit(
                    "拒绝续跑：旧预测的模型、输入数据、提示词或Schema版本与当前运行不一致。"
                    "请更换输出文件或先归档旧预测。"
                )
            if sample_id not in input_sample_ids:
                raise SystemExit(f"旧预测文件包含不在当前输入中的sample_id：{sample_id}")
    mode = "a" if args.resume else "w"  # 非resume模式必须覆盖，防止重复追加400条。

    trust_remote_code = bool(config.get("trust_remote_code", False))
    tokenizer = AutoTokenizer.from_pretrained(model_name, trust_remote_code=trust_remote_code)
    model = AutoModelForCausalLM.from_pretrained(
        model_name,
        torch_dtype="auto",
        device_map=config.get("device_map", "auto"),
        trust_remote_code=trust_remote_code,
    )
    model.eval()
    max_input_chars = int(config.get("max_input_chars", 24000))

    with output_path.open(mode, encoding="utf-8") as handle:
        for index, record in enumerate(records, 1):
            sample_id = str(record["sample_id"])
            if args.resume and sample_id in completed:
                continue
            prompt, input_truncated, visible_code_lines = build_prompt(prompt_template, record, max_input_chars)
            messages = [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ]
            rendered = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
            inputs = tokenizer([rendered], return_tensors="pt")
            input_device = model.get_input_embeddings().weight.device
            inputs = {key: value.to(input_device) for key, value in inputs.items()}
            generation_kwargs = {
                "max_new_tokens": int(config.get("max_new_tokens", 384)),
                "do_sample": float(config.get("temperature", 0.0)) > 0,
                "pad_token_id": tokenizer.eos_token_id,
            }
            if generation_kwargs["do_sample"]:
                generation_kwargs["temperature"] = float(config.get("temperature", 0.7))
                generation_kwargs["top_p"] = float(config.get("top_p", 0.95))
                base_seed = int(config.get("generation_seed", 20260916))
                sample_seed = base_seed + int(hashlib.sha256(sample_id.encode("utf-8")).hexdigest()[:8], 16)
                torch.manual_seed(sample_seed)
                if torch.cuda.is_available():
                    torch.cuda.manual_seed_all(sample_seed)
            else:
                sample_seed = None
            started = time.perf_counter()
            with torch.no_grad():
                output_ids = model.generate(**inputs, **generation_kwargs)
            latency = time.perf_counter() - started
            generated_text = tokenizer.decode(
                output_ids[0][inputs["input_ids"].shape[1] :],
                skip_special_tokens=True,
            )
            strict_prediction = parse_strict_json_object(generated_text)
            raw_prediction = extract_first_json_object(generated_text)
            strict_json_valid = strict_prediction is not None  # 原始输出必须只有一个JSON对象。
            json_valid = raw_prediction is not None  # 表示至少成功提取到一个JSON对象。
            schema_valid, schema_errors = validate_prediction_schema(raw_prediction, visible_code_lines)
            semantic_warnings = prediction_semantic_warnings(raw_prediction)
            result = {
                "sample_id": sample_id,
                "prediction": normalize_prediction(raw_prediction),
                "json_valid": json_valid,
                "strict_json_applicable": True,
                "strict_json_valid": strict_json_valid,
                "json_recovered": json_valid and not strict_json_valid,
                "schema_valid": schema_valid,
                "schema_errors": schema_errors,
                "semantic_warnings": semantic_warnings,
                "input_truncated": input_truncated,
                "visible_code_lines": visible_code_lines,
                "latency_seconds": latency,
                "generation_seed": sample_seed,
                "raw_output": generated_text,
                "run_signature": signature,
            }
            handle.write(json.dumps(result, ensure_ascii=False) + "\n")
            handle.flush()
            print(
                f"[{index}/{len(records)}] {sample_id} "
                f"json_valid={json_valid} strict_json_valid={strict_json_valid} "
                f"schema_valid={schema_valid} latency={latency:.2f}s"
            )


if __name__ == "__main__":
    main()
