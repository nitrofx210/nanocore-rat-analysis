# Explainability — LIME & SHAP

## Why Explainability Matters in Malware Detection

A black-box ML model that flags a file as `NanoCore` with 97% confidence is not enough for:
- **Incident responders** — they need to know *why* to prioritise the alert
- **Legal/compliance** — court admissible evidence needs justification
- **Analyst trust** — unexplained detections get ignored or escalated unnecessarily
- **Model auditing** — ensure the model isn't learning spurious correlations

LIME and SHAP bridge this gap.

---

## SHAP — SHapley Additive exPlanations

### Theory
Based on cooperative game theory. Each feature is a "player" and the prediction is the "payout". Shapley values fairly distribute the payout among all players.

**Property:** SHAP values are the **only** attribution method that satisfies all four axioms simultaneously:
- Efficiency (values sum to prediction)
- Symmetry (equal features get equal credit)
- Dummy (irrelevant features get zero)
- Additivity (consistent across models)

### Implementation
```python
import shap

# TreeExplainer: exact Shapley values for tree-based models (O(TLD))
explainer   = shap.TreeExplainer(rf)
shap_values = explainer.shap_values(X_test[:500])
# shap_values[0] = contributions for NanoCore class (class 0)
```

### Plots Generated

| Plot | What it shows |
|------|--------------|
| **Summary bar** | Mean \|SHAP\| per feature — global importance ranking |
| **Beeswarm** | Direction + magnitude per feature per sample (red=high value, blue=low) |
| **Waterfall** | Single sample: exactly how each feature pushed the prediction |
| **Dependence** | How one feature's SHAP value changes with its actual value |

### Top NanoCore SHAP Features

| Rank | Feature | Mean |SHAP| | Interpretation |
|------|---------|------------|----------------|
| 1 | `TimeDateStamp` | 0.077 | PE compile time — NanoCore compiled Feb 2015 |
| 2 | `rsrc_Misc_VirtualSize` | 0.035 | Resource section size — NanoCore specific |
| 3 | `AddressOfEntryPoint` | 0.034 | EP address pattern |
| 4 | `text_Misc_VirtualSize` | 0.032 | Code section virtual size |
| 5 | `rsrc_PointerToRawData` | 0.031 | Resource data pointer |

---

## LIME — Local Interpretable Model-Agnostic Explanations

### Theory
For a specific prediction, LIME:
1. Takes the sample to explain
2. Perturbs its features randomly 3,000 times
3. Asks the model to predict each perturbed version
4. Fits a **local linear model** to the perturbed predictions
5. The linear model's coefficients = feature contributions for **this sample**

**Key difference from SHAP:** LIME is a local approximation — it's not globally consistent, but it's fast and intuitive for analysts.

### Implementation
```python
import lime.lime_tabular

lime_explainer = lime.lime_tabular.LimeTabularExplainer(
    training_data        = X_train,
    feature_names        = feat_names,
    class_names          = LABEL_LIST,
    mode                 = 'classification',
    random_state         = 42,
    discretize_continuous = True,
    discretizer          = 'quartile'  # quartile binning for continuous features
)

exp = lime_explainer.explain_instance(
    data_row   = X_test[sample_idx],
    predict_fn = rf.predict_proba,
    num_features = 15,
    num_samples  = 3000,
    labels       = (predicted_class,)
)

# Get feature contributions as [(feature_condition, weight), ...]
contributions = exp.as_list(label=predicted_class)
```

### Reading LIME Output
```
Feature condition                    Weight
────────────────────────────────── ────────
TimeDateStamp <= 1.0               +0.042   ← SUPPORTS NanoCore prediction
rsrc_Misc_VirtualSize > 50000      +0.031   ← SUPPORTS NanoCore prediction
api_count <= 100.0                 -0.018   ← OPPOSES NanoCore prediction
SizeOfCode > 10000                 +0.015   ← SUPPORTS NanoCore prediction
```

**Positive weight** = this feature's value supports the predicted class  
**Negative weight** = this feature's value opposes the predicted class

---

## LIME vs SHAP Comparison

| Property | LIME | SHAP |
|----------|------|------|
| **Mathematical foundation** | Local linear approximation | Cooperative game theory |
| **Scope** | One sample at a time | One sample OR dataset-wide |
| **Consistency** | Approximate (local only) | Exact (guaranteed consistent) |
| **Speed** | Fast (3k samples × 1 model call) | Fast (TreeSHAP O(TLD)) |
| **Model agnostic** | Yes (any predict_proba) | TreeExplainer only for trees |
| **Output** | Feature conditions + weights | Feature SHAP values |
| **Best for** | Quick analyst triage | Auditing, reporting, rule-building |
| **Analyst interpretability** | Very high (plain conditions) | High (values need context) |

---

## Usage

```bash
# Run standalone demo
python explainability/shap_lime_demo.py

# Or run in the Jupyter notebook
# Cells 13-15 in detection/malware_classification.ipynb
```

### Prerequisites
```bash
pip install shap>=0.44.0 lime>=0.2.0.1
# Also requires: trained rf_model.joblib and feature_names.npy
# (Generated by running detection/malware_classification.ipynb)
```
