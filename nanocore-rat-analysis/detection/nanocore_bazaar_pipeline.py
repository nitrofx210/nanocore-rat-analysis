"""
╔══════════════════════════════════════════════════════════════════════════════╗
║         NanoCore RAT — ML Detection with LIME & SHAP Explainability         ║
║         Data Source: MalwareBazaar API (abuse.ch)                           ║
║                                                                              ║
║  Pipeline:                                                                   ║
║  1. Fetch malware samples from MalwareBazaar (NanoCore + benign-like)       ║
║  2. Extract static PE features from API metadata                             ║
║  3. Train Random Forest + XGBoost classifiers                               ║
║  4. Evaluate with classification report + confusion matrix                   ║
║  5. SHAP — global feature importance (dataset-wide)                          ║
║  6. LIME — per-sample local explanation                                      ║
║                                                                              ║
║  Requirements:                                                               ║
║    pip install requests scikit-learn xgboost shap lime pandas               ║
║                numpy matplotlib seaborn                                      ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import os
import sys
import json
import time
import hashlib
import warnings
import requests
import numpy as np
import pandas as pd
import matplotlib
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import seaborn as sns

from datetime import datetime
from collections import Counter

from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import (
    classification_report, confusion_matrix, roc_auc_score,
    roc_curve, precision_recall_curve, average_precision_score
)
from sklearn.pipeline import Pipeline

import xgboost as xgb
import shap
import lime
import lime.lime_tabular

warnings.filterwarnings("ignore")
matplotlib.use("Agg")   # non-interactive backend

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────

OUTPUT_DIR   = "ml_detection_output"
API_BASE     = "https://mb-api.abuse.ch/api/v1/"
MAX_SAMPLES  = 300          # samples per query (API max = 1000)
RANDOM_STATE = 42

# Malware families to treat as MALICIOUS (label=1)
MALICIOUS_TAGS = [
    "NanoCore", "AsyncRAT", "QuasarRAT", "DarkComet",
    "njRAT", "RemcosRAT", "AgentTesla", "FormBook"
]

# Families to treat as BENIGN-LIKE for contrast (label=0)
# These are non-RAT tools often on MalwareBazaar (PUPs, adware)
BENIGN_TAGS = [
    "Adware", "Miner", "Downloader"
]

os.makedirs(OUTPUT_DIR, exist_ok=True)

# ─────────────────────────────────────────────────────────────────────────────
# COLOUR PALETTE  (threat-lab theme)
# ─────────────────────────────────────────────────────────────────────────────

PALETTE = {
    "bg":        "#0A0E1A",
    "panel":     "#111827",
    "card":      "#1F2937",
    "red":       "#EF4444",
    "orange":    "#F97316",
    "green":     "#10B981",
    "blue":      "#3B82F6",
    "purple":    "#8B5CF6",
    "yellow":    "#F59E0B",
    "white":     "#F9FAFB",
    "muted":     "#6B7280",
}

def set_dark_theme():
    plt.rcParams.update({
        "figure.facecolor":  PALETTE["bg"],
        "axes.facecolor":    PALETTE["panel"],
        "axes.edgecolor":    PALETTE["card"],
        "axes.labelcolor":   PALETTE["white"],
        "axes.titlecolor":   PALETTE["white"],
        "xtick.color":       PALETTE["muted"],
        "ytick.color":       PALETTE["muted"],
        "text.color":        PALETTE["white"],
        "grid.color":        PALETTE["card"],
        "grid.linestyle":    "--",
        "grid.alpha":        0.5,
        "legend.facecolor":  PALETTE["panel"],
        "legend.edgecolor":  PALETTE["card"],
        "font.family":       "DejaVu Sans",
        "font.size":         11,
        "axes.titlesize":    13,
        "axes.titleweight":  "bold",
    })

set_dark_theme()


# ─────────────────────────────────────────────────────────────────────────────
# STEP 1 — MalwareBazaar API Client
# ─────────────────────────────────────────────────────────────────────────────

class MalwareBazaarClient:
    """
    Thin wrapper around the MalwareBazaar REST API.
    Docs: https://bazaar.abuse.ch/api/
    No API key required for most endpoints.
    """

    def __init__(self, base_url: str = API_BASE, delay: float = 1.0):
        self.base = base_url
        self.delay = delay          # polite delay between requests
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "MalwareAnalysis-Research/1.0"})

    def _post(self, payload: dict) -> dict:
        """POST to MalwareBazaar API and return JSON."""
        try:
            resp = self.session.post(self.base, data=payload, timeout=30)
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException as e:
            print(f"  [!] API error: {e}")
            return {"query_status": "error", "data": []}

    def query_by_tag(self, tag: str, limit: int = 100) -> list:
        """Fetch samples with a specific tag (e.g. 'NanoCore')."""
        print(f"  → Querying tag: {tag} (limit={limit})")
        result = self._post({"query": "get_taginfo", "tag": tag, "limit": limit})
        time.sleep(self.delay)
        if result.get("query_status") == "ok":
            return result.get("data", [])
        return []

    def query_by_filetype(self, filetype: str = "exe", limit: int = 100) -> list:
        """Fetch recent samples of a filetype."""
        print(f"  → Querying filetype: {filetype} (limit={limit})")
        result = self._post({"query": "get_file_type", "file_type": filetype, "limit": limit})
        time.sleep(self.delay)
        if result.get("query_status") == "ok":
            return result.get("data", [])
        return []

    def query_by_signature(self, signature: str, limit: int = 100) -> list:
        """Fetch samples matching a specific signature string."""
        print(f"  → Querying signature: {signature}")
        result = self._post({"query": "get_siginfo", "signature": signature, "limit": limit})
        time.sleep(self.delay)
        if result.get("query_status") == "ok":
            return result.get("data", [])
        return []

    def get_sample_info(self, sha256: str) -> dict:
        """Get full metadata for a single sample by SHA256."""
        result = self._post({"query": "get_info", "hash": sha256})
        time.sleep(self.delay * 0.5)
        if result.get("query_status") == "ok":
            data = result.get("data", [])
            return data[0] if data else {}
        return {}


# ─────────────────────────────────────────────────────────────────────────────
# STEP 2 — Feature Engineering from API Metadata
# ─────────────────────────────────────────────────────────────────────────────

class FeatureExtractor:
    """
    Extract ML-ready features from MalwareBazaar sample metadata.

    Features are entirely derived from the API JSON — no binary download needed.
    This makes analysis fast and safe (no execution required).

    Feature Groups:
      A. File size / entropy proxy
      B. File type / extension encoding
      C. Signature / detection metadata
      D. Tag-based features (family, capability hints)
      E. Temporal features (age, upload recency)
      F. Reporter / origin features
    """

    # Tags that are strong indicators of malicious capability
    CAPABILITY_TAGS = {
        "rat":           ["rat", "remote-access", "remote_access"],
        "keylogger":     ["keylogger", "keygrab"],
        "stealer":       ["stealer", "infostealer", "credential"],
        "persistence":   ["persistence", "autorun", "startup", "scheduled-task"],
        "c2":            ["c2", "c&c", "command-and-control", "beacon"],
        "obfuscation":   ["obfuscated", "packed", "crypter", "protector"],
        "dropper":       ["dropper", "loader", "downloader"],
        "network":       ["network", "tcp", "http", "dns", "port"],
        "dotnet":        [".net", "dotnet", "csharp", "c#"],
        "vb":            ["vb", "vbscript", "vba", "visualbasic"],
        "powershell":    ["powershell", "ps1", "psh"],
        "office":        ["office", "macro", "doc", "excel", "word"],
    }

    KNOWN_MALICIOUS_FAMILIES = {
        "nanocore", "asyncrat", "quasarrat", "darkcomet", "njrat",
        "remcosrat", "agenttesla", "formbook", "redline", "raccoon",
        "lokibot", "azorult", "emotet", "trickbot", "qbot",
        "cobalt strike", "meterpreter", "mimikatz", "netsupport"
    }

    def __init__(self):
        self.le_ext    = LabelEncoder()
        self.le_mime   = LabelEncoder()
        self._fitted   = False
        self._ext_classes  = []
        self._mime_classes = []

    def _extract_tags_features(self, tags: list) -> dict:
        """Binary features for known capability-indicating tags."""
        tags_lower = [t.lower() for t in (tags or [])]
        feats = {}
        for cap, keywords in self.CAPABILITY_TAGS.items():
            feats[f"tag_{cap}"] = int(
                any(kw in tag for tag in tags_lower for kw in keywords)
            )
        feats["tag_count"]         = len(tags_lower)
        feats["tag_family_known"]  = int(
            any(fam in " ".join(tags_lower) for fam in self.KNOWN_MALICIOUS_FAMILIES)
        )
        return feats

    def _parse_size(self, raw) -> int:
        """Safe integer conversion for file size."""
        try:
            return int(raw) if raw else 0
        except (ValueError, TypeError):
            return 0

    def _days_since(self, date_str: str) -> float:
        """Days elapsed since a date string (YYYY-MM-DD HH:MM:SS)."""
        if not date_str:
            return 0.0
        try:
            dt = datetime.strptime(date_str[:10], "%Y-%m-%d")
            return max(0.0, (datetime.utcnow() - dt).days)
        except ValueError:
            return 0.0

    def extract_one(self, sample: dict) -> dict:
        """
        Extract all features from a single MalwareBazaar sample dict.

        Returns a flat dict of feature_name → numeric_value.
        """
        tags      = sample.get("tags", []) or []
        file_size = self._parse_size(sample.get("file_size"))
        mime      = (sample.get("file_type_mime") or "").lower()
        ext       = (sample.get("file_type") or "").lower()
        sig       = (sample.get("signature") or "").lower()
        reporter  = (sample.get("reporter") or "").lower()
        sha256    = (sample.get("sha256_hash") or "")
        first_seen = sample.get("first_seen", "")
        delivery  = (sample.get("delivery_method") or "").lower()
        origin    = (sample.get("origin_country") or "").lower()

        # ── A. File size features ─────────────────────────────────────────
        size_kb   = file_size / 1024
        size_mb   = size_kb / 1024

        # Size buckets typical of .NET RATs (100–2000 KB)
        is_rat_size = int(100 <= size_kb <= 2000)

        # ── B. File type encoding ─────────────────────────────────────────
        is_exe   = int("exe" in ext or ext in ("exe", "pe32", "pe"))
        is_dll   = int("dll" in ext)
        is_doc   = int(ext in ("doc", "docx", "xls", "xlsx", "rtf", "pdf"))
        is_ps1   = int("ps1" in ext or "powershell" in mime)
        is_dotnet= int(".net" in mime or "csharp" in mime or "mono" in mime or
                       any("dotnet" in t.lower() or ".net" in t.lower() for t in tags))
        is_win   = int("windows" in mime or "win" in mime or is_exe or is_dll)

        # ── C. Hash entropy proxy ─────────────────────────────────────────
        # True entropy requires the binary; use hash digit variance as proxy
        sha_digits = [int(c, 16) for c in sha256[:32] if c in "0123456789abcdef"]
        hash_variance = float(np.var(sha_digits)) if sha_digits else 0.0

        # ── D. Signature / AV detection features ─────────────────────────
        has_sig        = int(bool(sig))
        sig_is_rat     = int("rat" in sig or "trojan" in sig or "remote" in sig)
        sig_is_nano    = int("nano" in sig or "nanocore" in sig)
        sig_is_stealer = int("stealer" in sig or "steal" in sig or "infostealer" in sig)
        sig_is_loader  = int("loader" in sig or "dropper" in sig or "downloader" in sig)

        # ── E. Tag features ───────────────────────────────────────────────
        tag_feats = self._extract_tags_features(tags)

        # ── F. Temporal features ──────────────────────────────────────────
        days_old       = self._days_since(first_seen)
        is_recent      = int(days_old < 90)
        is_old         = int(days_old > 365)

        # ── G. Delivery / origin ─────────────────────────────────────────
        email_delivery = int("email" in delivery or "phish" in delivery)
        web_delivery   = int("web" in delivery or "http" in delivery)

        # ── H. Reporter trust ─────────────────────────────────────────────
        # Automated reporters (abuse.ch systems) vs manual
        auto_reporter  = int(any(r in reporter for r in ("abuse.ch", "urlhaus", "triage", "any.run")))

        feats = {
            # File size
            "file_size_kb":       size_kb,
            "file_size_mb":       size_mb,
            "is_rat_size":        is_rat_size,
            # File type
            "is_exe":             is_exe,
            "is_dll":             is_dll,
            "is_document":        is_doc,
            "is_script":          is_ps1,
            "is_dotnet":          is_dotnet,
            "is_windows":         is_win,
            # Hash proxy
            "hash_digit_variance": hash_variance,
            # Signatures
            "has_av_signature":   has_sig,
            "sig_is_rat":         sig_is_rat,
            "sig_is_nanocore":    sig_is_nano,
            "sig_is_stealer":     sig_is_stealer,
            "sig_is_loader":      sig_is_loader,
            # Temporal
            "days_since_upload":  days_old,
            "is_recent_sample":   is_recent,
            "is_old_sample":      is_old,
            # Delivery
            "email_delivery":     email_delivery,
            "web_delivery":       web_delivery,
            # Reporter
            "auto_reporter":      auto_reporter,
        }
        feats.update(tag_feats)
        return feats

    def extract_many(self, samples: list, label: int) -> pd.DataFrame:
        """Extract features from a list of samples, attaching a label."""
        rows = []
        for s in samples:
            feats = self.extract_one(s)
            feats["label"]  = label
            feats["sha256"] = s.get("sha256_hash", "")
            feats["family"] = s.get("signature", s.get("tags", ["unknown"])[0]
                                    if s.get("tags") else "unknown")
            rows.append(feats)
        return pd.DataFrame(rows)


# ─────────────────────────────────────────────────────────────────────────────
# STEP 3 — Data Fetching & Dataset Assembly
# ─────────────────────────────────────────────────────────────────────────────

def fetch_dataset(client: MalwareBazaarClient, max_per_tag: int = 100) -> pd.DataFrame:
    """
    Fetch malicious and benign-like samples from MalwareBazaar
    and assemble a labeled dataset.

    Labels:
      1 = Malicious (RAT family)
      0 = Benign-like (non-RAT, lower severity)
    """
    extractor = FeatureExtractor()
    all_dfs = []

    print("\n[+] Fetching MALICIOUS samples (RAT families)...")
    mal_samples = []
    for tag in MALICIOUS_TAGS:
        samples = client.query_by_tag(tag, limit=max_per_tag)
        mal_samples.extend(samples)
        print(f"    {tag}: {len(samples)} samples")

    # Deduplicate by SHA256
    seen = set()
    mal_unique = []
    for s in mal_samples:
        h = s.get("sha256_hash", "")
        if h and h not in seen:
            seen.add(h)
            mal_unique.append(s)

    print(f"  Total unique malicious: {len(mal_unique)}")
    df_mal = extractor.extract_many(mal_unique, label=1)
    all_dfs.append(df_mal)

    print("\n[+] Fetching BENIGN-like samples...")
    ben_samples = []
    for tag in BENIGN_TAGS:
        samples = client.query_by_tag(tag, limit=max_per_tag // 2)
        ben_samples.extend(samples)
        print(f"    {tag}: {len(samples)} samples")

    # Also grab some generic exe samples without malicious tags
    generic = client.query_by_filetype("exe", limit=50)
    # Filter: keep only samples without RAT-family tags
    rat_kw = {"nanocore", "asyncrat", "quasarrat", "remcos", "njrat",
               "darkcomet", "agenttesla", "formbook"}
    for s in generic:
        sample_tags = {t.lower() for t in (s.get("tags") or [])}
        if not sample_tags.intersection(rat_kw):
            ben_samples.append(s)

    seen_b = set()
    ben_unique = []
    for s in ben_samples:
        h = s.get("sha256_hash", "")
        if h and h not in seen:   # also exclude any in malicious set
            seen.add(h)
            ben_unique.append(s)

    print(f"  Total unique benign-like: {len(ben_unique)}")
    df_ben = extractor.extract_many(ben_unique, label=0)
    all_dfs.append(df_ben)

    df = pd.concat(all_dfs, ignore_index=True)
    df = df.fillna(0)

    print(f"\n[✓] Dataset: {len(df)} total samples")
    print(f"    Malicious (1): {df['label'].sum()}")
    print(f"    Benign-like (0): {(df['label']==0).sum()}")

    # Save raw dataset
    csv_path = os.path.join(OUTPUT_DIR, "dataset.csv")
    df.to_csv(csv_path, index=False)
    print(f"    Saved → {csv_path}")
    return df


# ─────────────────────────────────────────────────────────────────────────────
# STEP 4 — ML Training & Evaluation
# ─────────────────────────────────────────────────────────────────────────────

def get_feature_columns(df: pd.DataFrame) -> list:
    """Return feature columns (exclude meta columns)."""
    exclude = {"label", "sha256", "family"}
    return [c for c in df.columns if c not in exclude]


def train_and_evaluate(df: pd.DataFrame) -> dict:
    """
    Train Random Forest and XGBoost classifiers.
    Returns dict with models, test data, and evaluation metrics.
    """
    feat_cols = get_feature_columns(df)
    X = df[feat_cols].values.astype(float)
    y = df["label"].values.astype(int)

    print(f"\n[+] Training on {len(feat_cols)} features, {len(X)} samples")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=RANDOM_STATE, stratify=y
    )

    # ── Random Forest ─────────────────────────────────────────────────────
    rf = RandomForestClassifier(
        n_estimators=200,
        max_depth=None,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )
    rf.fit(X_train, y_train)

    # ── XGBoost ──────────────────────────────────────────────────────────
    scale_pos_weight = (y_train == 0).sum() / max((y_train == 1).sum(), 1)
    xgb_clf = xgb.XGBClassifier(
        n_estimators=200,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        scale_pos_weight=scale_pos_weight,
        eval_metric="logloss",
        random_state=RANDOM_STATE,
        verbosity=0,
    )
    xgb_clf.fit(X_train, y_train)

    # ── Evaluate both ────────────────────────────────────────────────────
    results = {}
    for name, model in [("RandomForest", rf), ("XGBoost", xgb_clf)]:
        y_pred  = model.predict(X_test)
        y_prob  = model.predict_proba(X_test)[:, 1]
        auc     = roc_auc_score(y_test, y_prob)
        ap      = average_precision_score(y_test, y_prob)
        cv      = cross_val_score(model, X, y, cv=5, scoring="roc_auc", n_jobs=-1)

        print(f"\n  [{name}]")
        print(f"    AUC-ROC : {auc:.4f}")
        print(f"    Avg Prec: {ap:.4f}")
        print(f"    5-fold CV AUC: {cv.mean():.4f} ± {cv.std():.4f}")
        print(classification_report(y_test, y_pred,
                                    target_names=["Benign-like", "Malicious"],
                                    digits=4))
        results[name] = {
            "model":    model,
            "y_pred":   y_pred,
            "y_prob":   y_prob,
            "auc":      auc,
            "ap":       ap,
            "cv_auc":   cv,
            "cm":       confusion_matrix(y_test, y_pred),
        }

    return {
        "feat_cols":  feat_cols,
        "X_train":    X_train,
        "X_test":     X_test,
        "y_train":    y_train,
        "y_test":     y_test,
        "results":    results,
        "rf":         rf,
        "xgb":        xgb_clf,
    }


# ─────────────────────────────────────────────────────────────────────────────
# STEP 5 — SHAP (Global Explainability)
# ─────────────────────────────────────────────────────────────────────────────

def run_shap(train_data: dict) -> None:
    """
    Compute SHAP values for both models and produce:
      - Summary beeswarm plot (global feature importance)
      - Bar chart of mean |SHAP| values
      - Dependence plot for top feature
      - Waterfall plot for a single high-confidence malicious prediction
    """
    print("\n[+] Computing SHAP values...")

    feat_cols = train_data["feat_cols"]
    X_train   = train_data["X_train"]
    X_test    = train_data["X_test"]
    y_test    = train_data["y_test"]

    for model_name, model_key in [("RandomForest", "rf"), ("XGBoost", "xgb")]:
        model = train_data[model_key]
        print(f"  Computing SHAP for {model_name}...")

        # TreeExplainer is fast and exact for tree-based models
        explainer   = shap.TreeExplainer(model)
        shap_values = explainer.shap_values(X_test)

        # For RF, shap_values is a list [class0, class1]; take class1
        if isinstance(shap_values, list):
            sv = shap_values[1]
        else:
            sv = shap_values

        # ── Plot 1: SHAP Summary Bar ──────────────────────────────────────
        fig, ax = plt.subplots(figsize=(10, 7))
        mean_abs = np.abs(sv).mean(axis=0)
        sorted_idx = np.argsort(mean_abs)[::-1][:20]

        colors = [PALETTE["red"] if i < 5 else
                  PALETTE["orange"] if i < 10 else
                  PALETTE["blue"] for i in range(20)]

        ax.barh(
            [feat_cols[i] for i in sorted_idx[::-1]],
            mean_abs[sorted_idx[::-1]],
            color=colors[::-1],
            edgecolor="none",
            height=0.65,
        )
        ax.set_xlabel("Mean |SHAP value| — Feature Importance", color=PALETTE["white"])
        ax.set_title(f"SHAP Global Feature Importance — {model_name}", pad=12)
        ax.tick_params(axis="y", labelsize=9)
        for spine in ax.spines.values():
            spine.set_visible(False)
        ax.axvline(x=0, color=PALETTE["muted"], lw=0.5)
        fig.tight_layout()
        out = os.path.join(OUTPUT_DIR, f"shap_bar_{model_name}.png")
        fig.savefig(out, dpi=150, bbox_inches="tight", facecolor=PALETTE["bg"])
        plt.close(fig)
        print(f"    Saved → {out}")

        # ── Plot 2: SHAP Beeswarm / Summary ─────────────────────────────
        fig, ax = plt.subplots(figsize=(10, 8))
        shap.summary_plot(
            sv, X_test,
            feature_names=feat_cols,
            max_display=20,
            show=False,
            plot_type="dot",
            color_bar=True,
        )
        plt.gcf().set_facecolor(PALETTE["bg"])
        plt.gcf().axes[0].set_facecolor(PALETTE["panel"])
        out = os.path.join(OUTPUT_DIR, f"shap_beeswarm_{model_name}.png")
        plt.savefig(out, dpi=150, bbox_inches="tight", facecolor=PALETTE["bg"])
        plt.close()
        print(f"    Saved → {out}")

        # ── Plot 3: SHAP Waterfall for a single malicious sample ─────────
        # Pick highest-confidence malicious prediction
        y_prob = model.predict_proba(X_test)[:, 1]
        mal_idx = np.where(y_test == 1)[0]
        if len(mal_idx) > 0:
            best_idx = mal_idx[np.argmax(y_prob[mal_idx])]

            fig, ax = plt.subplots(figsize=(10, 7))
            shap_exp = shap.Explanation(
                values=sv[best_idx],
                base_values=explainer.expected_value[1]
                            if isinstance(explainer.expected_value, list)
                            else explainer.expected_value,
                data=X_test[best_idx],
                feature_names=feat_cols,
            )
            shap.plots.waterfall(shap_exp, max_display=15, show=False)
            plt.gcf().set_facecolor(PALETTE["bg"])
            out = os.path.join(OUTPUT_DIR, f"shap_waterfall_{model_name}.png")
            plt.savefig(out, dpi=150, bbox_inches="tight", facecolor=PALETTE["bg"])
            plt.close()
            print(f"    Saved → {out}")

        # ── Plot 4: Top feature dependence ───────────────────────────────
        top_feat_idx = int(np.argmax(mean_abs))
        fig, ax = plt.subplots(figsize=(8, 5))
        sc = ax.scatter(
            X_test[:, top_feat_idx],
            sv[:, top_feat_idx],
            c=y_test,
            cmap="coolwarm",
            alpha=0.6,
            edgecolors="none",
            s=30,
        )
        ax.set_xlabel(feat_cols[top_feat_idx])
        ax.set_ylabel("SHAP value")
        ax.set_title(f"SHAP Dependence — {feat_cols[top_feat_idx]} ({model_name})")
        cbar = fig.colorbar(sc, ax=ax)
        cbar.set_label("True Label (0=Benign, 1=Malicious)",
                        color=PALETTE["white"], fontsize=9)
        for spine in ax.spines.values():
            spine.set_visible(False)
        fig.tight_layout()
        out = os.path.join(OUTPUT_DIR, f"shap_dependence_{model_name}.png")
        fig.savefig(out, dpi=150, bbox_inches="tight", facecolor=PALETTE["bg"])
        plt.close(fig)
        print(f"    Saved → {out}")

    print("[✓] SHAP complete.")


# ─────────────────────────────────────────────────────────────────────────────
# STEP 6 — LIME (Local Explainability)
# ─────────────────────────────────────────────────────────────────────────────

def run_lime(train_data: dict, n_samples: int = 5) -> None:
    """
    LIME (Local Interpretable Model-Agnostic Explanations).

    For each of `n_samples` test instances, produce a bar chart showing
    which features pushed the model toward / away from 'Malicious'.

    LIME:
      1. Takes a single instance
      2. Perturbs its features (adds noise)
      3. Asks the model to re-predict each perturbed version
      4. Fits a local linear model to explain the boundary
      5. The linear model coefficients = feature contributions
    """
    print(f"\n[+] Running LIME on {n_samples} samples per model...")

    feat_cols = train_data["feat_cols"]
    X_train   = train_data["X_train"]
    X_test    = train_data["X_test"]
    y_test    = train_data["y_test"]

    # Build the LIME explainer once (shared across models)
    explainer = lime.lime_tabular.LimeTabularExplainer(
        training_data=X_train,
        feature_names=feat_cols,
        class_names=["Benign-like", "Malicious"],
        mode="classification",
        random_state=RANDOM_STATE,
        discretize_continuous=True,
        discretizer="quartile",
    )

    for model_name, model_key in [("RandomForest", "rf"), ("XGBoost", "xgb")]:
        model = train_data[model_key]
        y_prob = model.predict_proba(X_test)[:, 1]

        # ── Pick representative samples ──────────────────────────────────
        # 3 high-confidence malicious, 2 high-confidence benign
        mal_idx = np.where(y_test == 1)[0]
        ben_idx = np.where(y_test == 0)[0]

        selected = []
        if len(mal_idx) >= 3:
            top_mal = mal_idx[np.argsort(y_prob[mal_idx])[::-1][:3]]
            selected.extend([(i, "Malicious") for i in top_mal])
        if len(ben_idx) >= 2:
            top_ben = ben_idx[np.argsort(y_prob[ben_idx])[:2]]
            selected.extend([(i, "Benign-like") for i in top_ben])

        selected = selected[:n_samples]

        for rank, (idx, true_label) in enumerate(selected):
            instance  = X_test[idx]
            pred_prob = y_prob[idx]
            pred_label = "Malicious" if pred_prob >= 0.5 else "Benign-like"

            print(f"  [{model_name}] Sample {rank+1}: "
                  f"True={true_label}, Pred={pred_label} ({pred_prob:.3f})")

            # Run LIME explanation (num_features = top 15 contributors)
            exp = explainer.explain_instance(
                data_row=instance,
                predict_fn=model.predict_proba,
                num_features=15,
                num_samples=3000,
                labels=(1,),
            )

            feats_exp = exp.as_list(label=1)   # list of (feature_condition, weight)

            # ── Plot LIME explanation bar chart ──────────────────────────
            fig, ax = plt.subplots(figsize=(10, 6))

            names  = [f[0] for f in feats_exp]
            values = [f[1] for f in feats_exp]
            colors = [PALETTE["red"] if v > 0 else PALETTE["blue"] for v in values]

            bars = ax.barh(
                range(len(names)), values,
                color=colors, edgecolor="none", height=0.65
            )
            ax.set_yticks(range(len(names)))
            ax.set_yticklabels(names, fontsize=8)
            ax.axvline(x=0, color=PALETTE["muted"], lw=1)
            ax.set_xlabel("LIME Weight (positive → Malicious, negative → Benign-like)")

            conf_color = PALETTE["red"] if pred_label == "Malicious" else PALETTE["blue"]
            ax.set_title(
                f"LIME — {model_name}  |  Sample #{rank+1}\n"
                f"True: {true_label}   Predicted: {pred_label} ({pred_prob:.3f})",
                color=conf_color, fontsize=12,
            )
            for spine in ax.spines.values():
                spine.set_visible(False)

            # Add value labels
            for bar, val in zip(bars, values):
                x_pos = val + 0.001 * np.sign(val)
                ax.text(x_pos, bar.get_y() + bar.get_height()/2,
                        f"{val:+.4f}", va="center", fontsize=7.5,
                        color=PALETTE["white"])

            fig.tight_layout()
            out = os.path.join(OUTPUT_DIR,
                               f"lime_{model_name}_sample{rank+1}.png")
            fig.savefig(out, dpi=150, bbox_inches="tight",
                        facecolor=PALETTE["bg"])
            plt.close(fig)
            print(f"    Saved → {out}")

    print("[✓] LIME complete.")


# ─────────────────────────────────────────────────────────────────────────────
# STEP 7 — Evaluation Plots
# ─────────────────────────────────────────────────────────────────────────────

def plot_evaluation(train_data: dict) -> None:
    """
    Produce evaluation visualisations:
      - ROC curves (both models on one plot)
      - Precision-Recall curves
      - Confusion matrices
      - Feature importance comparison
    """
    print("\n[+] Generating evaluation plots...")

    feat_cols = train_data["feat_cols"]
    y_test    = train_data["y_test"]
    results   = train_data["results"]

    # ── ROC Curves ────────────────────────────────────────────────────────
    fig, ax = plt.subplots(figsize=(7, 6))
    colors_roc = [PALETTE["red"], PALETTE["blue"]]
    for (name, res), color in zip(results.items(), colors_roc):
        fpr, tpr, _ = roc_curve(y_test, res["y_prob"])
        ax.plot(fpr, tpr, lw=2, color=color,
                label=f"{name}  (AUC={res['auc']:.4f})")
    ax.plot([0,1],[0,1], "--", color=PALETTE["muted"], lw=1, label="Random")
    ax.set_xlabel("False Positive Rate")
    ax.set_ylabel("True Positive Rate")
    ax.set_title("ROC Curves — NanoCore RAT Detection")
    ax.legend(loc="lower right", fontsize=10)
    ax.grid(True, alpha=0.3)
    for spine in ax.spines.values(): spine.set_visible(False)
    fig.tight_layout()
    out = os.path.join(OUTPUT_DIR, "eval_roc_curves.png")
    fig.savefig(out, dpi=150, bbox_inches="tight", facecolor=PALETTE["bg"])
    plt.close(fig)
    print(f"  Saved → {out}")

    # ── Precision-Recall ──────────────────────────────────────────────────
    fig, ax = plt.subplots(figsize=(7, 6))
    for (name, res), color in zip(results.items(), colors_roc):
        prec, rec, _ = precision_recall_curve(y_test, res["y_prob"])
        ap = res["ap"]
        ax.plot(rec, prec, lw=2, color=color,
                label=f"{name}  (AP={ap:.4f})")
    ax.set_xlabel("Recall")
    ax.set_ylabel("Precision")
    ax.set_title("Precision-Recall Curves")
    ax.legend(loc="upper right", fontsize=10)
    ax.grid(True, alpha=0.3)
    for spine in ax.spines.values(): spine.set_visible(False)
    fig.tight_layout()
    out = os.path.join(OUTPUT_DIR, "eval_pr_curves.png")
    fig.savefig(out, dpi=150, bbox_inches="tight", facecolor=PALETTE["bg"])
    plt.close(fig)
    print(f"  Saved → {out}")

    # ── Confusion Matrices ────────────────────────────────────────────────
    fig, axes = plt.subplots(1, 2, figsize=(12, 5))
    for ax, (name, res) in zip(axes, results.items()):
        cm = res["cm"]
        sns.heatmap(
            cm, annot=True, fmt="d", ax=ax,
            cmap=sns.color_palette(
                [PALETTE["bg"], PALETTE["panel"], PALETTE["card"],
                 PALETTE["blue"], PALETTE["orange"], PALETTE["red"]],
                as_cmap=True),
            linewidths=0.5, linecolor=PALETTE["card"],
            xticklabels=["Benign-like", "Malicious"],
            yticklabels=["Benign-like", "Malicious"],
            cbar=False,
            annot_kws={"size": 14, "weight": "bold", "color": PALETTE["white"]},
        )
        tn, fp, fn, tp = cm.ravel()
        ax.set_title(f"{name}\nTP={tp}  FP={fp}  FN={fn}  TN={tn}", fontsize=11)
        ax.set_xlabel("Predicted Label")
        ax.set_ylabel("True Label")
        for spine in ax.spines.values(): spine.set_visible(False)
    fig.suptitle("Confusion Matrices", fontsize=14, y=1.02)
    fig.tight_layout()
    out = os.path.join(OUTPUT_DIR, "eval_confusion_matrices.png")
    fig.savefig(out, dpi=150, bbox_inches="tight", facecolor=PALETTE["bg"])
    plt.close(fig)
    print(f"  Saved → {out}")

    # ── RF Feature Importance vs SHAP importance comparison ───────────────
    rf  = train_data["rf"]
    imp = rf.feature_importances_
    top_n = 15
    top_idx = np.argsort(imp)[::-1][:top_n]

    fig, ax = plt.subplots(figsize=(10, 6))
    ax.barh(
        [feat_cols[i] for i in top_idx[::-1]],
        imp[top_idx[::-1]],
        color=PALETTE["orange"],
        edgecolor="none",
        height=0.65,
    )
    ax.set_xlabel("Gini Impurity-Based Feature Importance (RandomForest)")
    ax.set_title("Top 15 Features — Random Forest Built-in Importance")
    for spine in ax.spines.values(): spine.set_visible(False)
    fig.tight_layout()
    out = os.path.join(OUTPUT_DIR, "eval_rf_feature_importance.png")
    fig.savefig(out, dpi=150, bbox_inches="tight", facecolor=PALETTE["bg"])
    plt.close(fig)
    print(f"  Saved → {out}")

    print("[✓] Evaluation plots complete.")


# ─────────────────────────────────────────────────────────────────────────────
# STEP 8 — NanoCore-Specific Detection
# ─────────────────────────────────────────────────────────────────────────────

def query_nanocore_specific(client: MalwareBazaarClient,
                             train_data: dict) -> None:
    """
    Fetch NanoCore-specific samples and run inference + LIME
    explanation on each to produce analyst-ready reports.
    """
    print("\n[+] Querying NanoCore-specific samples for targeted analysis...")

    feat_cols = train_data["feat_cols"]
    extractor = FeatureExtractor()

    # Fetch fresh NanoCore samples
    nano_samples = client.query_by_tag("NanoCore", limit=20)
    if not nano_samples:
        nano_samples = client.query_by_signature("NanoCore", limit=20)

    if not nano_samples:
        print("  [!] No NanoCore samples returned. Check API connectivity.")
        return

    print(f"  Found {len(nano_samples)} NanoCore samples")

    # Build LIME explainer from training data
    lime_explainer = lime.lime_tabular.LimeTabularExplainer(
        training_data=train_data["X_train"],
        feature_names=feat_cols,
        class_names=["Benign-like", "Malicious"],
        mode="classification",
        random_state=RANDOM_STATE,
        discretize_continuous=True,
    )

    rf  = train_data["rf"]
    xgb_model = train_data["xgb"]

    report_rows = []

    for i, sample in enumerate(nano_samples[:10]):   # analyse first 10
        feats = extractor.extract_one(sample)
        x = np.array([[feats.get(c, 0.0) for c in feat_cols]], dtype=float)

        rf_prob  = rf.predict_proba(x)[0, 1]
        xgb_prob = xgb_model.predict_proba(x)[0, 1]
        ensemble = (rf_prob + xgb_prob) / 2

        verdict = "🚨 MALICIOUS" if ensemble >= 0.5 else "⚠️ SUSPICIOUS"

        sha = sample.get("sha256_hash", "?")[:16] + "..."
        report_rows.append({
            "Sample": sha,
            "RF_Prob":  round(rf_prob, 4),
            "XGB_Prob": round(xgb_prob, 4),
            "Ensemble": round(ensemble, 4),
            "Verdict":  verdict,
            "File_Size_KB": round(feats.get("file_size_kb", 0), 1),
            "Is_DotNet": int(feats.get("is_dotnet", 0)),
            "Tag_RAT":   int(feats.get("tag_rat", 0)),
            "Sig_RAT":   int(feats.get("sig_is_rat", 0)),
        })

        # LIME explanation for this sample
        exp = lime_explainer.explain_instance(
            data_row=x[0],
            predict_fn=rf.predict_proba,
            num_features=10,
            num_samples=2000,
            labels=(1,),
        )
        feats_exp = exp.as_list(label=1)

        # Save LIME plot
        fig, ax = plt.subplots(figsize=(9, 5))
        names  = [f[0] for f in feats_exp]
        vals   = [f[1] for f in feats_exp]
        colors = [PALETTE["red"] if v > 0 else PALETTE["blue"] for v in vals]
        ax.barh(range(len(names)), vals, color=colors, edgecolor="none", height=0.65)
        ax.set_yticks(range(len(names)))
        ax.set_yticklabels(names, fontsize=8)
        ax.axvline(0, color=PALETTE["muted"], lw=1)
        ax.set_xlabel("LIME Weight")
        ax.set_title(
            f"NanoCore Sample #{i+1}  |  SHA256: ...{sample.get('sha256_hash','')[-12:]}\n"
            f"RF={rf_prob:.3f}  XGB={xgb_prob:.3f}  Ensemble={ensemble:.3f}  →  {verdict}",
            fontsize=10, color=PALETTE["red"] if ensemble >= 0.5 else PALETTE["yellow"],
        )
        for spine in ax.spines.values(): spine.set_visible(False)
        fig.tight_layout()
        out = os.path.join(OUTPUT_DIR, f"nanocore_lime_sample{i+1}.png")
        fig.savefig(out, dpi=150, bbox_inches="tight", facecolor=PALETTE["bg"])
        plt.close(fig)

    # Print report table
    report_df = pd.DataFrame(report_rows)
    print("\n  NanoCore Detection Report:")
    print(report_df.to_string(index=False))

    report_path = os.path.join(OUTPUT_DIR, "nanocore_detection_report.csv")
    report_df.to_csv(report_path, index=False)
    print(f"\n  Report saved → {report_path}")


# ─────────────────────────────────────────────────────────────────────────────
# MAIN PIPELINE
# ─────────────────────────────────────────────────────────────────────────────

def main():
    print("=" * 70)
    print("  NanoCore RAT — ML Detection with LIME & SHAP")
    print("  Data: MalwareBazaar API (abuse.ch)")
    print("=" * 70)

    client = MalwareBazaarClient(delay=1.2)

    # ── 1. Fetch dataset ──────────────────────────────────────────────────
    df = fetch_dataset(client, max_per_tag=MAX_SAMPLES)

    if len(df) < 20:
        print("\n[!] Not enough data to train a model.")
        print("    Check your internet connection to abuse.ch")
        sys.exit(1)

    # ── 2. Train & evaluate ───────────────────────────────────────────────
    train_data = train_and_evaluate(df)

    # ── 3. Evaluation plots ───────────────────────────────────────────────
    plot_evaluation(train_data)

    # ── 4. SHAP global explainability ────────────────────────────────────
    run_shap(train_data)

    # ── 5. LIME local explainability ──────────────────────────────────────
    run_lime(train_data, n_samples=5)

    # ── 6. NanoCore-specific analysis ────────────────────────────────────
    query_nanocore_specific(client, train_data)

    # ── 7. Summary ───────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("  PIPELINE COMPLETE")
    print(f"  Output directory: {os.path.abspath(OUTPUT_DIR)}/")
    print("=" * 70)
    print("\n  Output files:")
    for f in sorted(os.listdir(OUTPUT_DIR)):
        fpath = os.path.join(OUTPUT_DIR, f)
        size  = os.path.getsize(fpath)
        print(f"    {f:<55} {size/1024:>6.1f} KB")


if __name__ == "__main__":
    main()
