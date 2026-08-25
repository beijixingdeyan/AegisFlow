# 04 · AI 可解释性与智能降噪

> 对应需求文档 Phase 2 第 6 节 与「软性指导」第 2 点（噪音是安全的敌人）。

---

## 1. 为什么「可解释」是 AegisFlow 的核心卖点

安全分析师不可能信任「黑盒」：如果 AI 说某账号有问题却说不清为什么，分析师既无法判断真伪，
也无法在海量告警中排优先级，更无法通过合规审计。因此 AegisFlow 的每个 AI 决策都强制输出：

1. **特征归因**（类似 SHAP value）：哪些特征、各占多少贡献驱动了这个判定。
2. **自然语言解释**：一句话说明「这个实体为何偏离基线、主要归因于什么」。
3. **ATT&CK 战术路径**：把离散特征映射到攻击链阶段，让分析师看到「攻击者走到哪一步了」。

对应代码：`detection/explain.py`（Explainer）+ `detection/anomaly.py`（contributions）。

---

## 2. 归因机制（SHAP 风格的实现）

- `AnomalyScorer.evaluate` 为每个已训练特征计算 z-score，并按绝对值归一化为**贡献权重**：
  `contribution_i = |z_i| / Σ|z_j|`。这等价于 SHAP 的「该特征对异常的边际贡献」的轻量近似。
- `Explainer` 把贡献最高的前 N 个特征（`top_features=5`）转成分析师可读条目：
  `{feature, contribution, label(中文), tactics(ATT&CK), zscore}`。
- **生产可替换为真实 SHAP/LIME**：接口（返回 `attributed_features`）不变，仅替换后端实现，
  做到「默认安全、透明开放」——检测逻辑可被客户审计。

半透明、可验证的例子（来自 demo）：
```
实体 alice 行为偏离基线：异常分 0.94，
主要归因于「不可能转移(分钟)、新设备、新地理位置、失败登录数(1h)」，
其中「不可能转移(分钟)」贡献最大 (18%)，对应战术阶段 TA0001 Initial Access。
```

---

## 3. 可视化方案（对分析师的呈现）

在管理平面 UI 中（生产实现）：
- **攻击路径图**：将 `attack_path`（战术阶段链）渲染为时间轴/图，展示从 Initial Access →
  Credential Access → ... 的攻击推进。
- **置信度热力图**：每个实体/特征按贡献着色（红=高贡献、绿=正常），一眼定位异常维度。
- **归因瀑布图**：展示各特征对最终分数的增减贡献（类似 SHAP waterfall）。
- **基线对比曲线**：该实体当前值 vs 其历史基线（均值±3σ），直观展示偏离。

本仓库以结构化数据（`DetectionResult.to_dict()` → `explanation`/`reasoning`）输出上述全部
信息，前端可直接消费渲染。

---

## 4. 智能降噪（告警疲劳解药）

**原则**：分析师每天只处理真正重要的少数事件（软性指导：让蓝队觉得「这系统很懂我」）。

`DetectionPipeline._prioritize` 的分级逻辑：
- **none**：综合分低于阈值 —— 不产生任何告警（正常流量绝大多数落在此）。
- **low**：冷启动期（实体样本不足 `min_samples`）的伪异常，专门降级，避免新接入实体的噪音。
- **medium**：AI 检测到偏离但非规则强命中。
- **high**：异常分≥0.7 或规则信号≥0.8。
- **critical**：规则强命中（如提权+可疑命令行，`rule_signal≥0.9`）——强制人工关注。

**多级合并且合并同类**：同一实体在短窗口内的重复异常被合并为一条事件（demo 中 alice 的
30 次攻击事件归并为一条），进一步砍噪音。

**效果验证**（demo，`_synthetic_events`）：
- 输入 831 条遥测（含大量正常登录/执行 + 少量真正的攻击特征）。
- 输出仅 31 条事件，其中绝大多数归并；分析师实际只需看 critical/high 几条。

---

## 5. LLM 推理的降级与可信度

- `intelligence.build_intelligence("mock" | "http")`：生产接远程 LLM 时，失败自动降级到
  mock 启发式推理器（`HttpIntelligence` 内 try/except 回退），**保证检测链在 LLM 后端故障时仍可用**。
- 推理输出 `confidence ∈ [0,1]` 与 `rationale`（依据），供分析师判断 AI 的把握程度，
  也作为自动化响应的「可信度门槛」输入（见 `response/`）。
