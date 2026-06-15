"""
shap_lime_demo.py
==================
Standalone SHAP + LIME explainability demo for NanoCore RAT detection.

Prerequisites:
    - Run detection/malware_classification.ipynb first to generate:
        rf_model.joblib
        imputer.joblib
        variance_selector.joblib
        feature_names.npy

Usage:
    python explainability/shap_lime_demo.py
"""

import os
import warnings
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use("Agg")
warnings.filterwarnings("ignore")

import joblib
import shap
import lime
import lime.lime_tabular

from pathlib import Path
from sklearn.model_selection import train_test_split

# ── Config ────────────────────────────────────────────────────────────────────
DATA_DIR    = Path("data")
OUTPUT_DIR  = Path("explainability/outputs")
OUTPUT_DIR.mkdir(exist_ok=True)

CLASS_NAMES = {
    0: "NanoCore",
    1: "RedLineStealer",
    2: "Downloader",
    3: "RAT",
    4: "BankingTrojan",
    5: "SnakeKeyLogger",
    6: "Spyware",
}
LABEL_LIST = [CLASS_NAMES[i] for i in range(7)]

THEME = {
    "maroon": "#B51D4B",
    "blue":   "#2980B9",
    "green":  "#27AE60",
    "orange": "#E67E22",
    "purple": "#8E44AD",
    "dark":   "#1A1A1A",
    "gray":   "#7F8C8D",
}


# ── Load models & data ────────────────────────────────────────────────────────

def load_models():
    """Load pre-trained models from joblib files."""
    rf        = joblib.load("rf_model.joblib")
    imp       = joblib.load("imputer.joblib")
    var_sel   = joblib.load("variance_selector.joblib")
    feat_names = np.load("feature_names.npy", allow_pickle=True)
    print(f"Models loaded. Features: {len(feat_names)}")
    return rf, imp, var_sel, feat_names


def load_test_data(imp, var_sel):
    """Reload test split from CSV data."""
    peh = pd.read_csv(DATA_DIR / "PE_Header.csv").fillna(0)
    dll = pd.read_csv(DATA_DIR / "DLLs_Imported.csv").fillna(0)
    pes = pd.read_csv(DATA_DIR / "PE_Section.csv").fillna(0)

    df = peh.merge(dll.drop("Type", axis=1), on="SHA256", how="inner", suffixes=("", "_dll"))
    df = df.merge(pes.drop("Type", axis=1), on="SHA256", how="inner", suffixes=("", "_pes"))
    df = df.fillna(0)

    y = df["Type"].values
    X = df.drop(columns=["SHA256", "Type"])

    X_imp = imp.transform(X)
    X_sel = var_sel.transform(X_imp)

    _, X_test, _, y_test = train_test_split(
        X_sel, y, test_size=0.2, random_state=42, stratify=y
    )
    return X_test, y_test


# ── SHAP Functions ────────────────────────────────────────────────────────────

def run_shap_global(rf, X_test, y_test, feat_names, n_samples=500):
    """
    SHAP global explainability:
      1. Summary bar chart (mean |SHAP| per feature)
      2. Beeswarm plot (direction + magnitude)
      3. Waterfall for best NanoCore sample
    """
    print(f"\n[SHAP] Computing for {n_samples} test samples...")
    X_shap = X_test[:n_samples]
    y_shap = y_test[:n_samples]

    explainer   = shap.TreeExplainer(rf)
    shap_values = explainer.shap_values(X_shap)    # list[7][n × feat]
    sv_nano     = shap_values[0]                   # NanoCore class

    # ── Plot 1: Summary Bar ─────────────────────────────────────────────────
    fig, ax = plt.subplots(figsize=(10, 7))
    mean_abs = np.abs(sv_nano).mean(axis=0)
    top_idx  = np.argsort(mean_abs)[::-1][:20]

    bar_colors = [THEME["maroon"] if i < 5 else
                  THEME["orange"] if i < 10 else
                  THEME["blue"]   for i in range(20)]

    ax.barh(
        [feat_names[i] for i in top_idx[::-1]],
        mean_abs[top_idx[::-1]],
        color=bar_colors[::-1],
        edgecolor="none",
        height=0.65,
    )
    ax.set_xlabel("Mean |SHAP Value| — Contribution to NanoCore Prediction", fontsize=11)
    ax.set_title("SHAP Global Feature Importance — NanoCore Class", fontsize=13, fontweight="bold")
    for spine in ax.spines.values():
        spine.set_visible(False)
    ax.grid(axis="x", alpha=0.3)
    plt.tight_layout()
    out = OUTPUT_DIR / "shap_bar_nanocore.png"
    fig.savefig(out, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  Saved: {out}")

    # ── Plot 2: Beeswarm ────────────────────────────────────────────────────
    plt.figure(figsize=(10, 8))
    shap.summary_plot(
        sv_nano, X_shap,
        feature_names=feat_names,
        max_display=15,
        show=False,
        plot_type="dot",
    )
    plt.title("SHAP Beeswarm — NanoCore vs Rest", fontsize=12, fontweight="bold")
    plt.tight_layout()
    out = OUTPUT_DIR / "shap_beeswarm_nanocore.png"
    plt.savefig(out, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  Saved: {out}")

    # ── Plot 3: Waterfall (single best NanoCore sample) ─────────────────────
    rf_probs    = rf.predict_proba(X_shap)
    nano_idx    = np.where(y_shap == 0)[0]

    if len(nano_idx) > 0:
        best = nano_idx[np.argmax(rf_probs[nano_idx, 0])]
        conf = rf_probs[best, 0]
        print(f"  Waterfall sample: index {best}, confidence {conf*100:.1f}%")

        base = explainer.expected_value
        base_val = base[0] if isinstance(base, (list, np.ndarray)) else float(base)

        shap_exp = shap.Explanation(
            values        = sv_nano[best],
            base_values   = base_val,
            data          = X_shap[best],
            feature_names = feat_names,
        )
        plt.figure(figsize=(10, 7))
        shap.plots.waterfall(shap_exp, max_display=15, show=False)
        plt.title(
            f"SHAP Waterfall — NanoCore Sample (RF confidence: {conf*100:.1f}%)",
            fontsize=11, fontweight="bold"
        )
        plt.tight_layout()
        out = OUTPUT_DIR / "shap_waterfall_nanocore.png"
        plt.savefig(out, dpi=150, bbox_inches="tight")
        plt.close()
        print(f"  Saved: {out}")

    # ── Print top features table ─────────────────────────────────────────────
    shap_series = pd.Series(mean_abs, index=feat_names).nlargest(15)
    print("\n  Top 15 SHAP features for NanoCore:")
    print(f"  {'Feature':<40} {'Mean |SHAP|':>12}")
    print("  " + "-" * 54)
    for fname, val in shap_series.items():
        print(f"  {fname:<40} {val:>12.5f}")

    return sv_nano, explainer


# ── LIME Functions ────────────────────────────────────────────────────────────

def run_lime_samples(rf, X_train, X_test, y_test, feat_names, n_explain=5):
    """
    LIME per-sample explanations for:
      - 3 highest-confidence NanoCore predictions
      - 2 highest-confidence non-NanoCore predictions
    """
    print(f"\n[LIME] Explaining {n_explain} samples (3,000 perturbations each)...")

    explainer = lime.lime_tabular.LimeTabularExplainer(
        training_data        = X_train,
        feature_names        = feat_names.tolist(),
        class_names          = LABEL_LIST,
        mode                 = "classification",
        random_state         = 42,
        discretize_continuous = True,
        discretizer          = "quartile",
    )

    rf_probs = rf.predict_proba(X_test)

    # Select samples
    samples = []
    nano_idx  = np.where(y_test == 0)[0]
    other_idx = np.where(y_test != 0)[0]

    if len(nano_idx) >= 3:
        top3_nano = nano_idx[np.argsort(rf_probs[nano_idx, 0])[::-1][:3]]
        samples.extend([(i, 0, "NanoCore") for i in top3_nano])

    if len(other_idx) >= 2:
        top2_other = other_idx[np.argsort(rf_probs[other_idx, 0])[:2]]
        for i in top2_other:
            samples.append((i, int(y_test[i]), CLASS_NAMES[int(y_test[i])]))

    samples = samples[:n_explain]

    for rank, (idx, true_label, true_name) in enumerate(samples):
        exp = explainer.explain_instance(
            data_row   = X_test[idx],
            predict_fn = rf.predict_proba,
            num_features = 15,
            num_samples  = 3000,
            labels       = (true_label,),
        )

        pred_label = CLASS_NAMES[int(rf.predict(X_test[[idx]])[0])]
        pred_prob  = rf_probs[idx, true_label]
        feats_exp  = exp.as_list(label=true_label)

        names  = [f[0][:52] for f in feats_exp[:12]]
        values = [f[1]       for f in feats_exp[:12]]
        colors = [THEME["maroon"] if v > 0 else THEME["blue"] for v in values]

        fig, ax = plt.subplots(figsize=(10, 5))
        bars = ax.barh(range(len(names)), values, color=colors, edgecolor="none", height=0.65)
        ax.set_yticks(range(len(names)))
        ax.set_yticklabels(names, fontsize=9)
        ax.axvline(0, color=THEME["gray"], linewidth=0.8, linestyle="--")
        ax.set_xlabel("LIME Weight  (→ supports prediction  |  ← opposes)", fontsize=10)
        ax.set_title(
            f"LIME — Sample #{rank+1}  |  True: {true_name}  "
            f"|  Predicted: {pred_label}  |  Confidence: {pred_prob*100:.1f}%",
            fontsize=10, fontweight="bold",
            color=THEME["maroon"] if pred_label == true_name else "#C0392B"
        )

        # Add value labels on bars
        for bar, val in zip(bars, values):
            xpos = val + 0.001 * (1 if val >= 0 else -1)
            ax.text(xpos, bar.get_y() + bar.get_height() / 2,
                    f"{val:+.4f}", va="center", ha="left" if val >= 0 else "right",
                    fontsize=7.5, color=THEME["dark"])

        for spine in ax.spines.values():
            spine.set_visible(False)
        ax.grid(axis="x", alpha=0.2)
        plt.tight_layout()

        out = OUTPUT_DIR / f"lime_sample{rank+1}_{true_name.lower()}.png"
        fig.savefig(out, dpi=150, bbox_inches="tight")
        plt.close(fig)
        print(f"  Sample {rank+1} ({true_name}): top = '{feats_exp[0][0][:40]}' ({feats_exp[0][1]:+.4f})")
        print(f"  Saved: {out}")

    print(f"\n[LIME] Done. All plots in {OUTPUT_DIR}/")


# ── LIME vs SHAP Comparison Plot ──────────────────────────────────────────────

def plot_comparison_table():
    """
    Generate a summary comparison table image of LIME vs SHAP.
    """
    data = {
        "Property":        ["Foundation",  "Scope",           "Consistency", "Speed",           "Best for"],
        "LIME":            ["Local linear\napproximation", "One sample", "Approximate\n(local only)", "Fast\n(3k samples)", "Analyst triage\nAlert investigation"],
        "SHAP":            ["Shapley\ngame theory", "Sample + Dataset", "Exact\n(guaranteed)", "Fast\n(TreeSHAP)", "Auditing\nCompliance & rules"],
    }

    fig, ax = plt.subplots(figsize=(12, 4))
    ax.axis("off")

    col_labels = ["Property", "LIME", "SHAP"]
    rows       = list(zip(data["Property"], data["LIME"], data["SHAP"]))

    table = ax.table(
        cellText  = rows,
        colLabels = col_labels,
        cellLoc   = "center",
        loc       = "center",
    )
    table.auto_set_font_size(False)
    table.set_fontsize(10)
    table.scale(1.2, 2.2)

    for (row, col), cell in table.get_celld().items():
        if row == 0:
            cell.set_facecolor(THEME["maroon"])
            cell.set_text_props(color="white", fontweight="bold")
        elif col == 0:
            cell.set_facecolor("#F2F2F2")
            cell.set_text_props(fontweight="bold")
        elif col == 1:
            cell.set_facecolor("#EBF5FB")
        elif col == 2:
            cell.set_facecolor("#E8F8F5")
        cell.set_edgecolor("#D5D5D5")

    ax.set_title("LIME vs SHAP — Explainability Method Comparison",
                 fontsize=13, fontweight="bold", pad=15, y=1.02)
    plt.tight_layout()
    out = OUTPUT_DIR / "lime_vs_shap_comparison.png"
    fig.savefig(out, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"\n  Saved: {out}")


# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("  NanoCore RAT — SHAP + LIME Explainability Demo")
    print("=" * 60)

    try:
        rf, imp, var_sel, feat_names = load_models()
    except FileNotFoundError as e:
        print(f"\n[ERROR] {e}")
        print("Run detection/malware_classification.ipynb first to generate model files.")
        raise SystemExit(1)

    X_test, y_test = load_test_data(imp, var_sel)
    print(f"Test set loaded: {X_test.shape}")

    # Rebuild X_train for LIME (needed as background reference)
    from sklearn.model_selection import train_test_split
    peh = pd.read_csv(DATA_DIR / "PE_Header.csv").fillna(0)
    dll = pd.read_csv(DATA_DIR / "DLLs_Imported.csv").fillna(0)
    pes = pd.read_csv(DATA_DIR / "PE_Section.csv").fillna(0)
    df  = peh.merge(dll.drop("Type", axis=1), on="SHA256", how="inner", suffixes=("", "_dll"))
    df  = df.merge(pes.drop("Type", axis=1), on="SHA256", how="inner", suffixes=("", "_pes"))
    df  = df.fillna(0)
    y   = df["Type"].values
    X   = df.drop(columns=["SHA256", "Type"])
    X_imp = imp.transform(X)
    X_sel = var_sel.transform(X_imp)
    X_train, _, y_train, _ = train_test_split(X_sel, y, test_size=0.2, random_state=42, stratify=y)

    # Run SHAP
    sv_nano, explainer = run_shap_global(rf, X_test, y_test, feat_names)

    # Run LIME
    run_lime_samples(rf, X_train, X_test, y_test, feat_names, n_explain=5)

    # Comparison table
    plot_comparison_table()

    print("\n" + "=" * 60)
    print(f"  All outputs saved to: {OUTPUT_DIR.resolve()}/")
    print("=" * 60)
    for f in sorted(OUTPUT_DIR.glob("*.png")):
        size = os.path.getsize(f) / 1024
        print(f"    {f.name:<45} {size:>6.1f} KB")
