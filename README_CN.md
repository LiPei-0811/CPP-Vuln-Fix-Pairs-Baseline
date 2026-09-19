# 面向真实C/C++漏洞—修复对的直接检测与修复敏感性基线实验

最后检查日期：2026-09-16

规范实验名称：**面向真实C/C++漏洞—修复对的直接检测与修复敏感性基线实验**  
实验目录标识：`cpp_vulnerability_pair_baseline`

本项目用于验证“面向真实C/C++漏洞的证据增强检测与受控执行验证”课题的基础可行性。当前阶段聚焦：

1. 构造100个真实漏洞函数及其一一对应的100个修复函数；
2. 另外抽取200个普通良性函数；
3. 运行Qwen Direct、LineVul或CodeBERT函数级基线；
4. 严格统计分类性能、修复代码误报、配对敏感性、JSON语法有效率和Schema有效率；
5. 为后续补丁RAG、CPG切片和受控执行验证建立可复现数据管线。

本项目只做源代码分析和本地受控实验，不连接真实目标，不生成攻击载荷。

## 一、本次修订解决的问题

- 删除提示词中的具体`CWE-787`示例，避免CWE类别锚定；
- `json_valid`只表示JSON语法有效，新增`schema_valid`验证字段、类型、置信度和行号范围；
- 正式评估默认要求预测完整覆盖全部gold，并拒绝重复、缺失和额外`sample_id`；
- 没有真实漏洞行号时，Top-k结果输出`null/N/A`，不再误写成0%；
- 真实使用`primevul_test_paired.jsonl`构造100个一一对应的漏洞—修复对；
- 抽样采用固定seed、目标CWE轮转和随机无放回补齐，不依赖文件顺序；
- 普通良性样本排除精确代码重复、空白规范化重复和相同项目提交；
- 从漏洞—修复函数对计算`pair_changed_*`补丁差异行，但不把差异行冒充漏洞行gold；
- Qwen非resume模式改为覆盖输出，防止重复追加；resume模式会校验模型、数据和提示词哈希；
- 运行签名同时覆盖gold规范哈希和全部推理参数，正式评估会拒绝旧提示词、旧gold或混合签名；
- 区分“可恢复JSON”和“原始输出严格只含JSON”，避免把Markdown围栏误报为严格JSON合规；
- 增加patched/benign分别误报率及四类配对结果；
- CodeBERT基线不再使用最终测试集选择最佳epoch，支持独立validation并清理验证集代码重叠；
- 一键脚本按传入配置动态解析`output_dir`，不再硬编码默认实验目录；
- 增加8项自动化回归测试，非法JSON、非法标签和重复规范化代码会显式失败，并兼容Windows UTF-8 BOM；
- 代码近重复检查改为轻量C/C++词法规范化，避免删除字符串字面量空白或合并不同词法单元。

## 二、目录结构

```text
项目根目录/
├─ config.json
├─ config.example.json
├─ README_CN.md
├─ requirements.txt
├─ run_cpp_vulnerability_pair_baseline.ps1
├─ check_paired_usage.py
├─ docs/
│  ├─ AI漏洞挖掘方向开源代码清单_20260916.md
│  ├─ 修改与验证报告_20260916.md
│  ├─ 论文文献阅读技巧.txt
│  └─ research_sources/
├─ datasets/
│  ├─ primevul_test.jsonl
│  ├─ primevul_test_paired.jsonl
│  ├─ primevul_train.jsonl
│  ├─ primevul_train_paired.jsonl
│  ├─ primevul_valid.jsonl
│  ├─ primevul_valid_paired.jsonl
│  └─ dataset_manifest.json
├─ prompts/
│  └─ direct_detection_zh.txt
├─ scripts/
│  ├─ common.py
│  ├─ inspect_dataset.py
│  ├─ prepare_sample.py
│  ├─ run_qwen_direct.py
│  ├─ evaluate_predictions.py
│  ├─ normalize_external_predictions.py
│  ├─ build_dataset_manifest.py
│  └─ run_codebert_baseline.py
├─ tests/
│  └─ test_pipeline.py
└─ experiments/
   ├─ cpp_vulnerability_pair_baseline/
   └─ backup_*/
```

## 三、数据角色

### 1. `primevul_test_paired.jsonl`

用于构造：

```text
100 vulnerable + 100 corresponding patched
```

每个函数对必须满足：

- 一条`target=1`，一条`target=0`；
- 项目一致；
- `commit_id`一致；
- 若双方都有`big_vul_idx`，该字段一致；
- 修复前后代码不同；
- 共享同一个`pair_id`。

`patched=0`仅表示对应已知漏洞的修复版本，不代表该函数经过形式化证明且不存在其他漏洞。

### 2. `primevul_test.jsonl`

只用于抽取200个普通良性函数。抽样前排除：

- paired文件中出现过的精确代码；
- 仅空白不同的规范化代码；
- 与paired数据相同的`project + commit_id`。

普通良性函数的`cwe`统一设置为`null`，避免把提交或文件继承的CWE误当成良性函数的gold标签；原始值保存在`source_cwe`中，仅用于数据审计。

### 3. CWE限制

paired数据中大量记录没有CWE。本项目可以用于二分类和漏洞—修复配对分析，但当前不能据此宣称形成了五类CWE均衡数据集。`sample_report.json`会如实记录CWE缺失率。

### 4. 定位限制

当前PrimeVul paired文件没有可靠的`vul_lines`。因此：

```text
location_evaluation_available = false
Top-k localization = N/A
```

`pair_changed_vulnerable_lines`和`pair_changed_patched_lines`只是函数差异行，可用于补丁证据研究，但不能直接当作漏洞行ground truth。

### 5. 数据完整性与许可状态

`datasets/dataset_manifest.json`记录6个本地数据文件的大小、记录数和SHA256。可重新生成：

```powershell
python .\scripts\build_dataset_manifest.py
```

当前只记录了来源仓库提示`DLVulDet/PrimeVul`；准确下载日期、源码Commit和数据许可复核结论仍为空。正式论文复现包或公开分发前必须补齐这些信息。

## 四、配置文件

当前核心配置：

```json
{
  "primevul_files": ["./datasets/primevul_test.jsonl"],
  "paired_files": ["./datasets/primevul_test_paired.jsonl"],
  "patched_files": [],
  "sample_seed": 20260916,
  "model_name": "D:/models/Qwen2.5-Coder-7B-Instruct",
  "generation_seed": 20260916,
  "trust_remote_code": false,
  "prompt_version": "direct-v2-no-cwe-anchor",
  "invalid_prediction_policy": "error",
  "require_complete_predictions": true
}
```

相对路径统一按`config.json`所在目录解析，因此不再依赖终端当前目录。`paired_files`不能同时出现在`patched_files`中；当前流程要求`patched_files`保持空数组。

## 五、安装环境

建议Python 3.10或3.11：

```powershell
conda create -n primevul-exp python=3.11 -y
conda activate primevul-exp
python -m pip install --upgrade pip
pip install -r requirements.txt
```

检查GPU：

```powershell
python -c "import torch; print(torch.__version__); print('CUDA:', torch.cuda.is_available())"
```

使用`device_map=auto`必须安装`accelerate`。

项目的VS Code解释器默认设置为：

```text
${env:USERPROFILE}\anaconda3\envs\primevul-exp\python.exe
```

命令行运行时仍应先执行`conda activate primevul-exp`。当前7B模型在12GB显存设备上会把部分权重卸载到CPU；本轮配对Smoke Test实测单条推理约40秒，完整400条实验预计需要数小时。

## 六、推荐运行顺序

进入项目：

```powershell
Set-Location "D:\日常\C_CPP漏洞修复对直接检测与修复敏感性基线实验_20260916"
conda activate primevul-exp
```

### 1. 语法与数据检查

```powershell
python -m compileall -q .\scripts .\check_paired_usage.py
python .\scripts\inspect_dataset.py --config .\config.json
```

### 2. 重新生成400条样本

```powershell
python .\scripts\prepare_sample.py --config .\config.json
python .\check_paired_usage.py
```

必须确认：

```text
vulnerable = 100
patched = 100
benign = 200
selected_pair_count = 100
pair_integrity_ok = true
```

同时检查：

```text
selected_pair_cwe_missing_rate
location_evaluation_available
pair_diff_evidence_count
benign_filter_stats
benign_unique_project_commit_count
benign_max_functions_per_project_commit
```

### 3. 两条Smoke Test

不要使用旧提示词生成的预测文件。Smoke Test默认覆盖输出：

```powershell
python .\scripts\run_qwen_direct.py `
  --config .\config.json `
  --input .\experiments\cpp_vulnerability_pair_baseline\prepared\sample_400.jsonl `
  --smoke-pair `
  --output .\experiments\cpp_vulnerability_pair_baseline\predictions\qwen_smoke_test.jsonl
```

`--smoke-pair`会选取同一个`pair_id`下的一条vulnerable代码和一条patched代码，避免Smoke Test恰好抽到两个普通非漏洞函数。

检查每条记录：

```json
{
  "json_valid": true,
  "strict_json_valid": false,
  "json_recovered": true,
  "schema_valid": true,
  "schema_errors": []
}
```

`json_valid=true`表示至少成功提取到JSON对象；`strict_json_valid=true`才表示原始输出没有Markdown围栏或额外文字。本轮两条输出均带`json`代码围栏，因此属于“可恢复JSON”，不是严格JSON。

### 4. 完整Qwen Direct

首次运行不要加`--resume`：

```powershell
python .\scripts\run_qwen_direct.py `
  --config .\config.json `
  --input .\experiments\cpp_vulnerability_pair_baseline\prepared\sample_400.jsonl `
  --output .\experiments\cpp_vulnerability_pair_baseline\predictions\qwen_direct.jsonl
```

只有同一次运行中断后才能使用：

```powershell
python .\scripts\run_qwen_direct.py `
  --config .\config.json `
  --input .\experiments\cpp_vulnerability_pair_baseline\prepared\sample_400.jsonl `
  --output .\experiments\cpp_vulnerability_pair_baseline\predictions\qwen_direct.jsonl `
  --resume
```

脚本会核对模型名、gold规范SHA256、提示词SHA256、全部推理参数和Schema版本。任一不一致都会拒绝续跑。

### 5. 正式评估

```powershell
python .\scripts\evaluate_predictions.py `
  --config .\config.json `
  --gold .\experiments\cpp_vulnerability_pair_baseline\prepared\sample_400.jsonl `
  --pred .\experiments\cpp_vulnerability_pair_baseline\predictions\qwen_direct.jsonl `
  --output .\experiments\cpp_vulnerability_pair_baseline\results\qwen_direct_metrics.json `
  --cases-output .\experiments\cpp_vulnerability_pair_baseline\results\qwen_direct_cases.csv
```

正式评估默认要求：

```text
gold_record_count = 400
total_prediction_records = 400
missing_prediction_count = 0
extra_prediction_count = 0
prediction_coverage_rate = 1.0
```

评估两条Smoke Test时必须显式使用`--allow-partial`，该结果不得作为正式指标。

当前配对Smoke Test已经实际通过：

```text
预测记录：2
可恢复JSON率：100%
严格JSON率：0%
Schema有效率：100%
pair结果：vulnerable_0_patched_0
```

这只说明数据、7B模型和评估流程能够运行。漏洞版本在该函数对上被漏检，进一步反映了Direct Baseline对修复差异不够敏感。

### 6. 一键脚本

```powershell
.\run_cpp_vulnerability_pair_baseline.ps1 -Stage inspect
.\run_cpp_vulnerability_pair_baseline.ps1 -Stage prepare
.\run_cpp_vulnerability_pair_baseline.ps1 -Stage smoke
.\run_cpp_vulnerability_pair_baseline.ps1 -Stage full
.\run_cpp_vulnerability_pair_baseline.ps1 -Stage evaluate
```

## 七、评估指标解释

### 1. 分类指标

```text
Precision、Recall、F1、MCC、TP、TN、FP、FN
```

无效JSON或Schema默认按该样本错误预测计入，不允许通过删除无效结果提高指标。

### 2. JSON与Schema

```text
json_valid_rate
```

表示至少从模型输出中成功提取出JSON对象。

```text
strict_json_valid_rate
```

表示原始输出去除首尾空白后就是一个完整JSON对象，不含代码围栏或额外解释。

```text
schema_valid_rate
```

进一步要求：

- 五个字段齐全；
- `vulnerable`为布尔值；
- `cwe`为`CWE-数字`或null；
- `location`为合法、不重复且不越界的正整数数组；
- `confidence`位于0到1；
- `reason`为非空字符串。

### 3. 修复感知指标

```text
patched_false_positive_rate
benign_false_positive_rate
paired_repair_sensitive_success_rate
pair_outcomes
```

配对结果包括：

```text
vulnerable_1_patched_0：正确区分修复前后
vulnerable_1_patched_1：两侧都报漏洞
vulnerable_0_patched_0：两侧都未报漏洞
vulnerable_0_patched_1：反向错误
```

### 4. Top-k定位

只有gold中存在真实`vul_lines`时才计算。没有标注时：

```json
{
  "location_evaluable_count": 0,
  "top_k_location_hit_rate": null,
  "location_status": "not_evaluable_no_ground_truth_lines"
}
```

### 5. CWE结果

只在真实漏洞且gold CWE非空时统计。由于paired数据CWE缺失较多，CWE结果只能作为探索性分析，不能作为主要结论。

### 6. confidence

LLM生成的`confidence`改称`self_reported_confidence`。它没有经过校准，不能直接解释为预测概率，也不参与主要阈值决策。

## 八、CodeBERT和外部基线

### 1. CodeBERT

```powershell
python .\scripts\run_codebert_baseline.py `
  --train-file .\datasets\primevul_train.jsonl `
  --validation-file .\datasets\primevul_valid.jsonl `
  --eval-file .\experiments\cpp_vulnerability_pair_baseline\prepared\sample_400.jsonl `
  --output-dir .\experiments\cpp_vulnerability_pair_baseline\codebert
```

脚本默认阻止训练集与最终评测集的规范化代码重复；独立验证集中与训练集或最终评测集重复的规范化代码会被显式移除并统计。最终`eval-file`只在训练结束后预测，不参与最佳epoch选择。输出：

```text
codebert_metrics.json
codebert_predictions.jsonl
```

然后使用统一评估脚本评估`codebert_predictions.jsonl`。

### 2. LineVul或其他外部模型

CSV至少包含：

```csv
sample_id,predicted_label,probability
abc123,1,0.87
```

转换：

```powershell
python .\scripts\normalize_external_predictions.py `
  --input .\linevul_predictions.csv `
  --gold .\experiments\cpp_vulnerability_pair_baseline\prepared\sample_400.jsonl `
  --output .\experiments\cpp_vulnerability_pair_baseline\predictions\linevul.jsonl
```

转换程序默认要求完整覆盖400个gold样本并拒绝重复ID。

## 九、旧结果说明

旧结果使用了包含具体`CWE-787`示例的提示词，57个正类预测全部输出`CWE-787`，存在明显提示词锚定。旧结果只能作为历史Direct Baseline和问题分析材料，不能继续作为新提示词实验结果，也不能与新样本直接宣称性能提升。

当前规范项目目录未携带早期旧预测和修改前代码备份。若仍需核查旧实验，应从旧项目目录或原始压缩包单独读取，不能放入当前正式结果目录混用。

正式评估会检查`gold_canonical_sha256`、提示词版本和整份预测文件的运行签名；历史文件若缺失签名，只能在审计时显式使用`--allow-signature-mismatch`，不能作为当前正式结果。

## 十、仍需注意的实验边界

- 200个普通良性函数当前只覆盖43个`project + commit_id`组合，单个组合最多贡献41个函数；因此良性误报率是函数级、簇相关的估计，不应解释为200个独立提交上的误报率。
- 当前抽样仍不是project-disjoint或temporal最终评测，应在论文正式结论前补充按项目或时间隔离的评测。
- 400条Qwen完整推理、CodeBERT和LineVul正式运行仍未完成。
- 项目当前没有Git仓库元数据，也没有根目录LICENSE；是否初始化版本控制、是否公开及采用何种许可证需要由项目负责人决定。

## 十一、后续研究落地路线

建议按以下顺序扩展：

```text
PrimeVul精确配对检测
        ↓
Vul-RAG/CVEfixes补丁知识检索
        ↓
Joern + LLMxCPG结构化切片
        ↓
CodeQL/Semgrep证据一致性检查
        ↓
少量ASan/UBSan或SEC-bench式受控执行验证
```

详细开源代码清单见：

```text
docs\AI漏洞挖掘方向开源代码清单_20260916.md
```

不建议当前硕士阶段直接完整复现Cochise、PentestGPT、完整Linux内核PoC系统或大规模OSS-Fuzz集群。

