"""
╔══════════════════════════════════════════════════════════════════════════════╗
║        Windows Malware RAT Family Detector                                  ║
║        Dataset: Kaggle — joebeachcapital/windows-malwares                   ║
║                                                                              ║
║  Dataset Files (download from Kaggle):                                       ║
║    • PE_Header.csv       — 52 PE header fields  (primary model)             ║
║    • PE_Section.csv      — 10 sections × 9 fields                           ║
║    • API_Functions.csv   — API call presence flags                           ║
║    • DLLs_Imported.csv   — DLL import flags                                 ║
║                                                                              ║
║  Labels:                                                                     ║
║    0 = Benign          3 = RAT  ← focus family                              ║
║    1 = RedLineStealer  4 = BankingTrojan                                    ║
║    2 = Downloader      5 = SnakeKeyLogger  6 = Spyware                      ║
║                                                                              ║
║  Usage:                                                                      ║
║    pip install streamlit scikit-learn xgboost shap lime pefile              ║
║                pandas numpy matplotlib seaborn plotly                        ║
║    streamlit run app.py                                                      ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import os
import io
import sys
import time
import hashlib
import warnings
import tempfile
import pickle
import struct

import numpy as np
import pandas as pd
import matplotlib
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import seaborn as sns
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots

import streamlit as st
from streamlit import session_state as ss

import pefile
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import (
    classification_report, confusion_matrix,
    roc_auc_score, accuracy_score, f1_score
)
from sklearn.multiclass import OneVsRestClassifier
import xgboost as xgb
import shap
import lime
import lime.lime_tabular

warnings.filterwarnings("ignore")
matplotlib.use("Agg")

# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS & LABELS
# ─────────────────────────────────────────────────────────────────────────────

LABEL_MAP = {
    0: "Benign",
    1: "RedLineStealer",
    2: "Downloader",
    3: "RAT",
    4: "BankingTrojan",
    5: "SnakeKeyLogger",
    6: "Spyware",
}

LABEL_COLORS = {
    "Benign":          "#10B981",
    "RedLineStealer":  "#EF4444",
    "Downloader":      "#F97316",
    "RAT":             "#8B5CF6",
    "BankingTrojan":   "#EC4899",
    "SnakeKeyLogger":  "#06B6D4",
    "Spyware":         "#F59E0B",
}

RAT_SUBTYPES = {
    "NanoCore":   "Commodity .NET RAT with plugin architecture",
    "AsyncRAT":   "Open-source async .NET RAT",
    "QuasarRAT":  "Feature-rich open-source .NET RAT",
    "RemcosRAT":  "Commercial RAT sold as remote admin tool",
    "DarkComet":  "Legacy RAT with keylogger and webcam capture",
    "njRAT":      "Simple VB.NET RAT with registry persistence",
    "Unknown RAT":"RAT family — specific variant not determined",
}

THEME = {
    "bg":     "#0A0E1A",
    "panel":  "#111827",
    "card":   "#1F2937",
    "red":    "#EF4444",
    "orange": "#F97316",
    "green":  "#10B981",
    "blue":   "#3B82F6",
    "purple": "#8B5CF6",
    "yellow": "#F59E0B",
    "white":  "#F9FAFB",
    "muted":  "#6B7280",
}

MODEL_CACHE = "trained_models.pkl"

# ─────────────────────────────────────────────────────────────────────────────
# PE FEATURE EXTRACTOR  (from uploaded binary)
# ─────────────────────────────────────────────────────────────────────────────

class PEFeatureExtractor:
    """
    Extracts the same PE Header features used in PE_Header.csv
    from a raw .exe binary uploaded by the user.

    PE_Header.csv has 52 fields — we extract all of them using pefile.
    """

    # The exact column names from PE_Header.csv (52 fields + sha256 + label)
    PE_HEADER_FIELDS = [
        "e_magic", "e_cblp", "e_cp", "e_crlc", "e_cparhdr",
        "e_minalloc", "e_maxalloc", "e_ss", "e_sp", "e_csum",
        "e_ip", "e_cs", "e_lfarlc", "e_ovno", "e_oemid",
        "e_oeminfo", "e_lfanew",
        "Machine", "NumberOfSections", "TimeDateStamp",
        "PointerToSymbolTable", "NumberOfSymbols", "SizeOfOptionalHeader",
        "Characteristics",
        "Magic", "MajorLinkerVersion", "MinorLinkerVersion",
        "SizeOfCode", "SizeOfInitializedData", "SizeOfUninitializedData",
        "AddressOfEntryPoint", "BaseOfCode",
        "ImageBase", "SectionAlignment", "FileAlignment",
        "MajorOperatingSystemVersion", "MinorOperatingSystemVersion",
        "MajorImageVersion", "MinorImageVersion",
        "MajorSubsystemVersion", "MinorSubsystemVersion",
        "SizeOfImage", "SizeOfHeaders", "CheckSum", "Subsystem",
        "DllCharacteristics", "SizeOfStackReserve", "SizeOfStackCommit",
        "SizeOfHeapReserve", "SizeOfHeapCommit",
        "LoaderFlags", "NumberOfRvaAndSizes",
    ]

    # DLLs that matter for RAT detection
    RAT_DLLS = [
        "KERNEL32.dll", "USER32.dll", "ADVAPI32.dll", "SHELL32.dll",
        "MSCOREE.dll", "WS2_32.dll", "WININET.dll", "URLMON.dll",
        "NETAPI32.dll", "WINSOCK32.dll", "PSAPI.dll", "NTDLL.dll",
        "SHLWAPI.dll", "CRYPT32.dll", "VCRUNTIME140.dll",
    ]

    # API functions relevant to RAT behaviour
    RAT_APIS = [
        "CreateProcess", "ShellExecute", "WinExec", "RegSetValue",
        "RegOpenKey", "RegCreateKey", "CreateFile", "WriteFile",
        "ReadFile", "GetTempPath", "CopyFile", "MoveFile",
        "VirtualAlloc", "VirtualProtect", "CreateThread",
        "OpenProcess", "TerminateProcess", "GetProcAddress",
        "LoadLibrary", "InternetOpen", "InternetConnect",
        "HttpSendRequest", "send", "recv", "connect", "WSAStartup",
        "GetClipboardData", "SetWindowsHookEx", "keybd_event",
        "GetAsyncKeyState", "BitBlt", "CreateDC",
    ]

    def extract(self, binary_bytes: bytes) -> dict:
        """
        Parse a PE binary and extract features matching the Kaggle dataset schema.
        Returns a dict of {feature_name: value}.
        """
        features = {}

        try:
            pe = pefile.PE(data=binary_bytes, fast_load=False)

            # ── DOS Header ────────────────────────────────────────────────
            dos = pe.DOS_HEADER
            features["e_magic"]    = dos.e_magic
            features["e_cblp"]     = dos.e_cblp
            features["e_cp"]       = dos.e_cp
            features["e_crlc"]     = dos.e_crlc
            features["e_cparhdr"]  = dos.e_cparhdr
            features["e_minalloc"] = dos.e_minalloc
            features["e_maxalloc"] = dos.e_maxalloc
            features["e_ss"]       = dos.e_ss
            features["e_sp"]       = dos.e_sp
            features["e_csum"]     = dos.e_csum
            features["e_ip"]       = dos.e_ip
            features["e_cs"]       = dos.e_cs
            features["e_lfarlc"]   = dos.e_lfarlc
            features["e_ovno"]     = dos.e_ovno
            features["e_oemid"]    = dos.e_oemid
            features["e_oeminfo"]  = dos.e_oeminfo
            features["e_lfanew"]   = dos.e_lfanew

            # ── File Header ───────────────────────────────────────────────
            fh = pe.FILE_HEADER
            features["Machine"]              = fh.Machine
            features["NumberOfSections"]     = fh.NumberOfSections
            features["TimeDateStamp"]        = fh.TimeDateStamp
            features["PointerToSymbolTable"] = fh.PointerToSymbolTable
            features["NumberOfSymbols"]      = fh.NumberOfSymbols
            features["SizeOfOptionalHeader"] = fh.SizeOfOptionalHeader
            features["Characteristics"]      = fh.Characteristics

            # ── Optional Header ───────────────────────────────────────────
            oh = pe.OPTIONAL_HEADER
            features["Magic"]                       = oh.Magic
            features["MajorLinkerVersion"]          = oh.MajorLinkerVersion
            features["MinorLinkerVersion"]          = oh.MinorLinkerVersion
            features["SizeOfCode"]                  = oh.SizeOfCode
            features["SizeOfInitializedData"]       = oh.SizeOfInitializedData
            features["SizeOfUninitializedData"]     = oh.SizeOfUninitializedData
            features["AddressOfEntryPoint"]         = oh.AddressOfEntryPoint
            features["BaseOfCode"]                  = oh.BaseOfCode
            features["ImageBase"]                   = oh.ImageBase
            features["SectionAlignment"]            = oh.SectionAlignment
            features["FileAlignment"]               = oh.FileAlignment
            features["MajorOperatingSystemVersion"] = oh.MajorOperatingSystemVersion
            features["MinorOperatingSystemVersion"] = oh.MinorOperatingSystemVersion
            features["MajorImageVersion"]           = oh.MajorImageVersion
            features["MinorImageVersion"]           = oh.MinorImageVersion
            features["MajorSubsystemVersion"]       = oh.MajorSubsystemVersion
            features["MinorSubsystemVersion"]       = oh.MinorSubsystemVersion
            features["SizeOfImage"]                 = oh.SizeOfImage
            features["SizeOfHeaders"]               = oh.SizeOfHeaders
            features["CheckSum"]                    = oh.CheckSum
            features["Subsystem"]                   = oh.Subsystem
            features["DllCharacteristics"]          = oh.DllCharacteristics
            features["SizeOfStackReserve"]          = oh.SizeOfStackReserve
            features["SizeOfStackCommit"]           = oh.SizeOfStackCommit
            features["SizeOfHeapReserve"]           = oh.SizeOfHeapReserve
            features["SizeOfHeapCommit"]            = oh.SizeOfHeapCommit
            features["LoaderFlags"]                 = oh.LoaderFlags
            features["NumberOfRvaAndSizes"]         = oh.NumberOfRvaAndSizes

            # ── DLL features (binary flags) ───────────────────────────────
            imported_dlls = set()
            try:
                if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                    for entry in pe.DIRECTORY_ENTRY_IMPORT:
                        dll_name = entry.dll.decode("utf-8", errors="ignore")
                        imported_dlls.add(dll_name.upper())
            except Exception:
                pass

            for dll in self.RAT_DLLS:
                features[f"dll_{dll.replace('.','_').upper()}"] = \
                    int(dll.upper() in imported_dlls)

            # DLL aggregate features
            features["dll_total_count"]    = len(imported_dlls)
            features["dll_network_count"]  = sum(1 for d in imported_dlls
                                                  if any(n in d for n in
                                                         ["WS2", "WININET", "WINHTTP",
                                                          "URLMON", "WINSOCK"]))
            features["dll_crypto_count"]   = sum(1 for d in imported_dlls
                                                  if "CRYPT" in d or "BCRYPT" in d)
            features["dll_dotnet"]         = int("MSCOREE.DLL" in imported_dlls)

            # ── API function features ─────────────────────────────────────
            imported_apis = set()
            try:
                if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                    for entry in pe.DIRECTORY_ENTRY_IMPORT:
                        for imp in entry.imports:
                            if imp.name:
                                api = imp.name.decode("utf-8", errors="ignore")
                                imported_apis.add(api)
            except Exception:
                pass

            for api in self.RAT_APIS:
                features[f"api_{api}"] = int(api in imported_apis)

            # API aggregate features
            features["api_total_count"]    = len(imported_apis)
            features["api_registry_count"] = sum(1 for a in imported_apis
                                                  if "Reg" in a)
            features["api_network_count"]  = sum(1 for a in imported_apis
                                                  if any(n in a for n in
                                                         ["Internet", "Http", "send",
                                                          "recv", "connect", "Socket"]))
            features["api_process_count"]  = sum(1 for a in imported_apis
                                                  if any(n in a for n in
                                                         ["Process", "Thread", "Virtual"]))
            features["api_file_count"]     = sum(1 for a in imported_apis
                                                  if any(n in a for n in
                                                         ["File", "Read", "Write",
                                                          "Create", "Copy", "Move"]))
            features["api_keylog_count"]   = sum(1 for a in imported_apis
                                                  if any(n in a for n in
                                                         ["Hook", "Key", "Clipboard",
                                                          "GetAsync"]))

            # ── Section features ──────────────────────────────────────────
            for i, section in enumerate(pe.sections[:10]):
                prefix = f"sec{i}_"
                name = section.Name.decode("utf-8", errors="ignore").strip("\x00")
                raw  = section.SizeOfRawData
                virt = section.Misc_VirtualSize

                features[f"{prefix}name_hash"]       = hash(name) % 100000
                features[f"{prefix}virtual_size"]    = virt
                features[f"{prefix}raw_size"]        = raw
                features[f"{prefix}entropy"]         = section.get_entropy()
                features[f"{prefix}characteristics"] = section.Characteristics
                # Suspicious: high entropy (packed/encrypted)
                features[f"{prefix}high_entropy"]    = int(section.get_entropy() > 6.5)
                # Suspicious: exec + write
                exec_flag  = bool(section.Characteristics & 0x20000000)
                write_flag = bool(section.Characteristics & 0x80000000)
                features[f"{prefix}exec_write"]      = int(exec_flag and write_flag)

            # Fill missing section slots with 0
            for i in range(len(pe.sections), 10):
                for field in ["name_hash","virtual_size","raw_size","entropy",
                              "characteristics","high_entropy","exec_write"]:
                    features[f"sec{i}_{field}"] = 0

            # ── Derived / aggregate features ──────────────────────────────
            features["file_size"]          = len(binary_bytes)
            features["file_size_kb"]       = len(binary_bytes) / 1024
            features["sha256"]             = hashlib.sha256(binary_bytes).hexdigest()
            features["section_count"]      = len(pe.sections)
            features["high_entropy_secs"]  = sum(
                1 for s in pe.sections if s.get_entropy() > 6.5)
            features["exec_write_secs"]    = sum(
                1 for s in pe.sections
                if (s.Characteristics & 0x20000000) and (s.Characteristics & 0x80000000))
            features["is_dotnet"]          = int(features["dll_dotnet"] == 1)
            features["is_64bit"]           = int(fh.Machine == 0x8664)

            pe.close()

        except pefile.PEFormatError as e:
            return {"error": str(e)}
        except Exception as e:
            return {"error": str(e)}

        return features


# ─────────────────────────────────────────────────────────────────────────────
# DATASET LOADER & TRAINER
# ─────────────────────────────────────────────────────────────────────────────

class MalwareMLPipeline:
    """
    Loads the Kaggle dataset CSVs, trains classifiers,
    and exposes prediction + explanation methods.
    """

    def __init__(self):
        self.rf       = None
        self.xgb      = None
        self.feat_cols = []
        self.scaler   = StandardScaler()
        self.trained  = False
        self.X_train  = None
        self.X_test   = None
        self.y_train  = None
        self.y_test   = None
        self.lime_exp = None
        self.shap_explainer_rf  = None
        self.shap_explainer_xgb = None

    # ── Loaders ──────────────────────────────────────────────────────────────

    def load_pe_header(self, path: str) -> pd.DataFrame:
        """Load PE_Header.csv — primary feature set."""
        df = pd.read_csv(path)
        df.columns = df.columns.str.strip()
        return df

    def load_api_functions(self, path: str) -> pd.DataFrame:
        """Load API_Functions.csv."""
        df = pd.read_csv(path)
        df.columns = df.columns.str.strip()
        return df

    def load_dlls(self, path: str) -> pd.DataFrame:
        """Load DLLs_Imported.csv."""
        df = pd.read_csv(path)
        df.columns = df.columns.str.strip()
        return df

    def load_pe_section(self, path: str) -> pd.DataFrame:
        """Load PE_Section.csv."""
        df = pd.read_csv(path)
        df.columns = df.columns.str.strip()
        return df

    def merge_datasets(self,
                       pe_header_df:   pd.DataFrame,
                       api_df:         pd.DataFrame  = None,
                       dll_df:         pd.DataFrame  = None,
                       section_df:     pd.DataFrame  = None) -> pd.DataFrame:
        """
        Merge multiple feature CSVs on sha256 + label.
        At minimum PE_Header is required.
        """
        df = pe_header_df.copy()

        # Identify key columns
        sha_col   = "sha256" if "sha256" in df.columns else df.columns[0]
        label_col = "label"  if "label"  in df.columns else df.columns[1]

        # Merge API functions
        if api_df is not None and sha_col in api_df.columns:
            api_feat = api_df.drop(columns=[label_col], errors="ignore")
            df = df.merge(api_feat, on=sha_col, how="left", suffixes=("", "_api"))

        # Merge DLLs
        if dll_df is not None and sha_col in dll_df.columns:
            dll_feat = dll_df.drop(columns=[label_col], errors="ignore")
            df = df.merge(dll_feat, on=sha_col, how="left", suffixes=("", "_dll"))

        # Merge PE Sections
        if section_df is not None and sha_col in section_df.columns:
            sec_feat = section_df.drop(columns=[label_col], errors="ignore")
            df = df.merge(sec_feat, on=sha_col, how="left", suffixes=("", "_sec"))

        df = df.fillna(0)
        return df

    def prepare_features(self, df: pd.DataFrame):
        """
        Extract X and y from merged dataframe.
        Returns (X, y, feature_names).
        """
        drop_cols = {"sha256", "sha256_hash", "label", "Label",
                     "family", "Family", "hash", "Hash"}
        feat_cols = [c for c in df.columns if c not in drop_cols
                     and df[c].dtype != object]

        label_col = "label" if "label" in df.columns else "Label"
        X = df[feat_cols].values.astype(float)
        y = df[label_col].values.astype(int)
        return X, y, feat_cols

    # ── Training ──────────────────────────────────────────────────────────────

    def train(self, df: pd.DataFrame, test_size: float = 0.2) -> dict:
        """
        Train Random Forest + XGBoost on the merged dataset.
        Returns evaluation metrics.
        """
        X, y, feat_cols = self.prepare_features(df)
        self.feat_cols = feat_cols

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=42, stratify=y
        )

        self.X_train = X_train
        self.X_test  = X_test
        self.y_train = y_train
        self.y_test  = y_test

        n_classes = len(np.unique(y))
        class_labels = [LABEL_MAP.get(i, str(i)) for i in sorted(np.unique(y))]

        # ── Random Forest ────────────────────────────────────────────────
        self.rf = RandomForestClassifier(
            n_estimators=300,
            max_depth=None,
            min_samples_leaf=1,
            class_weight="balanced",
            random_state=42,
            n_jobs=-1,
        )
        self.rf.fit(X_train, y_train)

        # ── XGBoost ───────────────────────────────────────────────────────
        self.xgb = xgb.XGBClassifier(
            n_estimators=300,
            max_depth=6,
            learning_rate=0.08,
            subsample=0.8,
            colsample_bytree=0.8,
            use_label_encoder=False,
            eval_metric="mlogloss",
            random_state=42,
            verbosity=0,
            n_jobs=-1,
        )
        self.xgb.fit(X_train, y_train)

        # ── Build LIME explainer ──────────────────────────────────────────
        self.lime_exp = lime.lime_tabular.LimeTabularExplainer(
            training_data=X_train,
            feature_names=feat_cols,
            class_names=class_labels,
            mode="classification",
            random_state=42,
            discretize_continuous=True,
            discretizer="quartile",
        )

        # ── Build SHAP explainers ────────────────────────────────────────
        self.shap_explainer_rf  = shap.TreeExplainer(self.rf)
        self.shap_explainer_xgb = shap.TreeExplainer(self.xgb)

        # ── Metrics ───────────────────────────────────────────────────────
        rf_pred  = self.rf.predict(X_test)
        xgb_pred = self.xgb.predict(X_test)

        metrics = {
            "rf_accuracy":  accuracy_score(y_test, rf_pred),
            "xgb_accuracy": accuracy_score(y_test, xgb_pred),
            "rf_f1":        f1_score(y_test, rf_pred, average="weighted"),
            "xgb_f1":       f1_score(y_test, xgb_pred, average="weighted"),
            "rf_report":    classification_report(y_test, rf_pred,
                                target_names=class_labels, output_dict=True),
            "xgb_report":   classification_report(y_test, xgb_pred,
                                target_names=class_labels, output_dict=True),
            "rf_cm":        confusion_matrix(y_test, rf_pred),
            "xgb_cm":       confusion_matrix(y_test, xgb_pred),
            "class_labels": class_labels,
            "feat_cols":    feat_cols,
            "n_samples":    len(df),
            "n_features":   len(feat_cols),
            "n_classes":    n_classes,
        }

        self.trained = True
        return metrics

    # ── Prediction ────────────────────────────────────────────────────────────

    def predict_sample(self, feature_dict: dict) -> dict:
        """
        Given a feature dict (from PEFeatureExtractor), predict malware family.
        Returns predictions, probabilities, LIME and SHAP explanations.
        """
        if not self.trained:
            return {"error": "Model not trained yet."}

        # Align features to training schema
        x = np.array([[feature_dict.get(c, 0.0) for c in self.feat_cols]],
                      dtype=float)

        rf_probs  = self.rf.predict_proba(x)[0]
        xgb_probs = self.xgb.predict_proba(x)[0]
        ensemble  = (rf_probs + xgb_probs) / 2

        rf_classes  = self.rf.classes_
        ensemble_df = pd.DataFrame({
            "class":  rf_classes,
            "label":  [LABEL_MAP.get(c, str(c)) for c in rf_classes],
            "rf_prob": rf_probs,
            "xgb_prob": xgb_probs,
            "ensemble": ensemble,
        }).sort_values("ensemble", ascending=False)

        predicted_class = int(rf_classes[np.argmax(ensemble)])
        predicted_label = LABEL_MAP.get(predicted_class, "Unknown")

        # ── LIME explanation ──────────────────────────────────────────────
        lime_result = None
        if self.lime_exp is not None:
            try:
                exp = self.lime_exp.explain_instance(
                    data_row=x[0],
                    predict_fn=self.rf.predict_proba,
                    num_features=15,
                    num_samples=3000,
                    labels=(predicted_class,),
                )
                lime_result = exp.as_list(label=predicted_class)
            except Exception as e:
                lime_result = [("LIME error", str(e))]

        # ── SHAP explanation (RF) ─────────────────────────────────────────
        shap_vals = None
        shap_base = None
        try:
            sv = self.shap_explainer_rf.shap_values(x)
            # sv is list[n_classes][n_samples × n_features]
            if isinstance(sv, list):
                cls_idx = list(rf_classes).index(predicted_class) \
                          if predicted_class in rf_classes else 0
                shap_vals = sv[cls_idx][0]
                base_vals = self.shap_explainer_rf.expected_value
                shap_base = base_vals[cls_idx] \
                            if isinstance(base_vals, (list, np.ndarray)) \
                            else float(base_vals)
            else:
                shap_vals = sv[0]
                shap_base = float(self.shap_explainer_rf.expected_value)
        except Exception:
            shap_vals = None

        return {
            "predicted_class":  predicted_class,
            "predicted_label":  predicted_label,
            "ensemble_df":      ensemble_df,
            "lime":             lime_result,
            "shap_values":      shap_vals,
            "shap_base":        shap_base,
            "feature_vector":   x[0],
        }

    def save(self, path: str):
        with open(path, "wb") as f:
            pickle.dump(self, f)

    @classmethod
    def load(cls, path: str):
        with open(path, "rb") as f:
            return pickle.load(f)


# ─────────────────────────────────────────────────────────────────────────────
# PLOTTING HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def plotly_prob_gauge(label: str, prob: float) -> go.Figure:
    color = LABEL_COLORS.get(label, THEME["purple"])
    fig = go.Figure(go.Indicator(
        mode="gauge+number+delta",
        value=prob * 100,
        number={"suffix": "%", "font": {"size": 36, "color": color}},
        gauge={
            "axis": {"range": [0, 100], "tickcolor": THEME["muted"]},
            "bar":  {"color": color},
            "bgcolor": THEME["panel"],
            "bordercolor": THEME["card"],
            "steps": [
                {"range": [0,  40], "color": THEME["panel"]},
                {"range": [40, 70], "color": "#1F2937"},
                {"range": [70, 100],"color": "#111827"},
            ],
            "threshold": {
                "line": {"color": THEME["white"], "width": 2},
                "thickness": 0.75,
                "value": 50,
            },
        },
        title={"text": label, "font": {"color": color, "size": 16}},
    ))
    fig.update_layout(
        paper_bgcolor=THEME["bg"],
        plot_bgcolor=THEME["bg"],
        margin=dict(l=20, r=20, t=60, b=20),
        height=220,
    )
    return fig


def plotly_probability_bars(ensemble_df: pd.DataFrame) -> go.Figure:
    labels = ensemble_df["label"].tolist()
    probs  = (ensemble_df["ensemble"] * 100).tolist()
    colors = [LABEL_COLORS.get(l, THEME["blue"]) for l in labels]

    fig = go.Figure(go.Bar(
        x=probs,
        y=labels,
        orientation="h",
        marker_color=colors,
        marker_line_width=0,
        text=[f"{p:.1f}%" for p in probs],
        textposition="outside",
        textfont={"color": THEME["white"], "size": 11},
    ))
    fig.update_layout(
        title="Ensemble Prediction Probabilities",
        paper_bgcolor=THEME["bg"],
        plot_bgcolor=THEME["panel"],
        font={"color": THEME["white"]},
        xaxis={"title": "Probability (%)", "range": [0, 110],
               "gridcolor": THEME["card"]},
        yaxis={"autorange": "reversed", "gridcolor": THEME["card"]},
        margin=dict(l=20, r=20, t=50, b=30),
        height=320,
        bargap=0.25,
    )
    return fig


def plotly_lime_chart(lime_result: list, predicted_label: str) -> go.Figure:
    if not lime_result:
        return go.Figure()

    names  = [r[0] for r in lime_result[:12]]
    values = [r[1] for r in lime_result[:12]]
    colors = [LABEL_COLORS.get(predicted_label, THEME["purple"])
              if v > 0 else THEME["muted"]
              for v in values]

    fig = go.Figure(go.Bar(
        x=values,
        y=names,
        orientation="h",
        marker_color=colors,
        marker_line_width=0,
    ))
    fig.add_vline(x=0, line_color=THEME["muted"], line_width=1)
    fig.update_layout(
        title=f"LIME — Local Explanation for '{predicted_label}' Prediction",
        paper_bgcolor=THEME["bg"],
        plot_bgcolor=THEME["panel"],
        font={"color": THEME["white"], "size": 10},
        xaxis={"title": "Weight (→ supports prediction, ← opposes)",
               "gridcolor": THEME["card"]},
        yaxis={"autorange": "reversed"},
        margin=dict(l=10, r=20, t=50, b=30),
        height=380,
    )
    return fig


def plotly_shap_chart(shap_vals: np.ndarray,
                      feat_cols: list,
                      predicted_label: str) -> go.Figure:
    if shap_vals is None:
        return go.Figure()

    pairs = sorted(zip(feat_cols, shap_vals),
                   key=lambda x: abs(x[1]), reverse=True)[:15]
    names  = [p[0] for p in pairs]
    values = [p[1] for p in pairs]
    colors = [LABEL_COLORS.get(predicted_label, THEME["purple"])
              if v > 0 else THEME["blue"]
              for v in values]

    fig = go.Figure(go.Bar(
        x=values,
        y=names,
        orientation="h",
        marker_color=colors,
        marker_line_width=0,
    ))
    fig.add_vline(x=0, line_color=THEME["muted"], line_width=1)
    fig.update_layout(
        title=f"SHAP — Feature Contributions to '{predicted_label}'",
        paper_bgcolor=THEME["bg"],
        plot_bgcolor=THEME["panel"],
        font={"color": THEME["white"], "size": 10},
        xaxis={"title": "SHAP Value (impact on prediction)",
               "gridcolor": THEME["card"]},
        yaxis={"autorange": "reversed"},
        margin=dict(l=10, r=20, t=50, b=30),
        height=400,
    )
    return fig


def plotly_confusion_matrix(cm: np.ndarray, labels: list,
                             title: str) -> go.Figure:
    fig = go.Figure(go.Heatmap(
        z=cm,
        x=labels,
        y=labels,
        colorscale=[[0, THEME["panel"]], [0.5, THEME["blue"]], [1, THEME["red"]]],
        text=cm,
        texttemplate="%{text}",
        textfont={"size": 11, "color": THEME["white"]},
        showscale=False,
    ))
    fig.update_layout(
        title=title,
        paper_bgcolor=THEME["bg"],
        plot_bgcolor=THEME["panel"],
        font={"color": THEME["white"]},
        xaxis={"title": "Predicted"},
        yaxis={"title": "True", "autorange": "reversed"},
        margin=dict(l=10, r=10, t=50, b=10),
        height=380,
    )
    return fig


def plotly_rf_importance(rf, feat_cols: list, top_n: int = 20) -> go.Figure:
    imp = rf.feature_importances_
    top_idx = np.argsort(imp)[::-1][:top_n]
    fig = go.Figure(go.Bar(
        y=[feat_cols[i] for i in top_idx[::-1]],
        x=imp[top_idx[::-1]],
        orientation="h",
        marker_color=THEME["orange"],
        marker_line_width=0,
    ))
    fig.update_layout(
        title="Random Forest Feature Importance (Gini)",
        paper_bgcolor=THEME["bg"],
        plot_bgcolor=THEME["panel"],
        font={"color": THEME["white"], "size": 10},
        xaxis={"title": "Importance", "gridcolor": THEME["card"]},
        margin=dict(l=10, r=10, t=50, b=30),
        height=500,
    )
    return fig


# ─────────────────────────────────────────────────────────────────────────────
# STREAMLIT UI
# ─────────────────────────────────────────────────────────────────────────────

def configure_page():
    st.set_page_config(
        page_title="Windows Malware RAT Detector",
        page_icon="🔬",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    st.markdown("""
    <style>
    /* Dark background */
    .stApp, .main, section[data-testid="stSidebar"] {
        background-color: #0A0E1A !important;
    }
    .block-container { padding-top: 1.5rem; }

    /* Cards */
    .metric-card {
        background: #111827;
        border: 1px solid #1F2937;
        border-radius: 10px;
        padding: 1.2rem 1.4rem;
        margin-bottom: 0.8rem;
    }
    .metric-card h3 { margin: 0 0 4px 0; font-size: 13px; color: #6B7280; }
    .metric-card p  { margin: 0; font-size: 26px; font-weight: 600; }

    /* Verdict banner */
    .verdict-rat {
        background: linear-gradient(135deg, #2D1A4A, #1F2937);
        border: 2px solid #8B5CF6;
        border-radius: 12px;
        padding: 1.5rem 2rem;
        text-align: center;
    }
    .verdict-benign {
        background: linear-gradient(135deg, #0C3020, #1F2937);
        border: 2px solid #10B981;
        border-radius: 12px;
        padding: 1.5rem 2rem;
        text-align: center;
    }
    .verdict-other {
        background: linear-gradient(135deg, #1A2030, #1F2937);
        border: 2px solid #F59E0B;
        border-radius: 12px;
        padding: 1.5rem 2rem;
        text-align: center;
    }

    /* Section headings */
    h1 { color: #F9FAFB !important; }
    h2 { color: #E5E7EB !important; font-size: 1.1rem !important; }
    h3 { color: #D1D5DB !important; }
    p, li, .stMarkdown { color: #9CA3AF; }

    /* Tabs */
    .stTabs [data-baseweb="tab-list"] {
        background-color: #111827;
        border-radius: 8px;
        padding: 4px;
        gap: 4px;
    }
    .stTabs [data-baseweb="tab"] {
        background-color: transparent;
        color: #6B7280;
        border-radius: 6px;
        padding: 6px 16px;
        font-size: 13px;
    }
    .stTabs [aria-selected="true"] {
        background-color: #1F2937 !important;
        color: #F9FAFB !important;
    }

    /* File uploader */
    .stFileUploader {
        border: 2px dashed #374151 !important;
        border-radius: 10px !important;
        background: #111827 !important;
    }

    /* Info/warning boxes */
    .stAlert { border-radius: 8px; }

    /* Expander */
    .streamlit-expanderHeader {
        background-color: #111827 !important;
        color: #E5E7EB !important;
        border-radius: 8px !important;
    }
    </style>
    """, unsafe_allow_html=True)


def sidebar_ui() -> dict:
    """Render sidebar and return config."""
    with st.sidebar:
        st.markdown("## 🔬 RAT Detector")
        st.markdown("---")

        st.markdown("### 📁 Dataset Files")
        st.markdown(
            "Download from [Kaggle](https://www.kaggle.com/datasets/joebeachcapital/windows-malwares) "
            "and upload below."
        )

        pe_header_file  = st.file_uploader("PE_Header.csv *(required)*",
                                            type="csv", key="ph")
        api_file        = st.file_uploader("API_Functions.csv *(optional)*",
                                            type="csv", key="api")
        dll_file        = st.file_uploader("DLLs_Imported.csv *(optional)*",
                                            type="csv", key="dll")
        section_file    = st.file_uploader("PE_Section.csv *(optional)*",
                                            type="csv", key="sec")

        st.markdown("---")
        st.markdown("### ⚙️ Training Config")
        test_size   = st.slider("Test set size", 0.1, 0.4, 0.2, 0.05)
        model_type  = st.selectbox("Primary model for explanations",
                                   ["Random Forest", "XGBoost"])

        st.markdown("---")
        st.markdown("### ℹ️ Label Reference")
        for k, v in LABEL_MAP.items():
            color = LABEL_COLORS.get(v, "#888")
            st.markdown(
                f'<span style="color:{color}">■</span> '
                f'**{k}** — {v}',
                unsafe_allow_html=True
            )

        st.markdown("---")
        st.caption("NanoCore RAT Analysis · FLARE-VM Lab")

    return {
        "pe_header_file": pe_header_file,
        "api_file":       api_file,
        "dll_file":       dll_file,
        "section_file":   section_file,
        "test_size":      test_size,
        "model_type":     model_type,
    }


def render_verdict(result: dict):
    """Render the main prediction verdict banner."""
    label = result["predicted_label"]
    prob  = float(result["ensemble_df"].iloc[0]["ensemble"])
    color = LABEL_COLORS.get(label, THEME["muted"])

    if label == "RAT":
        css_class = "verdict-rat"
        icon = "🚨"
        subtitle = "Remote Access Trojan Detected — High Risk"
    elif label == "Benign":
        css_class = "verdict-benign"
        icon = "✅"
        subtitle = "No malicious family detected"
    else:
        css_class = "verdict-other"
        icon = "⚠️"
        subtitle = f"Malware family detected — {label}"

    st.markdown(f"""
    <div class="{css_class}">
        <h1 style="font-size:2.5rem; margin:0; color:{color}">{icon} {label}</h1>
        <p style="font-size:1.1rem; color:#E5E7EB; margin:8px 0 0 0">{subtitle}</p>
        <p style="font-size:1.8rem; font-weight:600; color:{color}; margin:4px 0 0 0">
            Confidence: {prob*100:.1f}%
        </p>
    </div>
    """, unsafe_allow_html=True)

    if label == "RAT":
        st.markdown("---")
        st.markdown("#### 🧬 RAT Subtype Indicators")
        cols = st.columns(len(RAT_SUBTYPES))
        for col, (subtype, desc) in zip(cols, RAT_SUBTYPES.items()):
            with col:
                st.markdown(f"""
                <div class="metric-card">
                    <h3>{subtype}</h3>
                    <p style="font-size:11px; color:#6B7280;">{desc}</p>
                </div>
                """, unsafe_allow_html=True)


def render_pe_info(features: dict):
    """Render PE metadata info cards."""
    st.markdown("#### 📋 PE File Metadata")
    c1, c2, c3, c4, c5 = st.columns(5)

    def card(col, title, val, color=THEME["white"]):
        with col:
            st.markdown(f"""
            <div class="metric-card">
                <h3>{title}</h3>
                <p style="color:{color}; font-size:16px;">{val}</p>
            </div>""", unsafe_allow_html=True)

    machine = features.get("Machine", 0)
    arch = "x64" if machine == 0x8664 else "x86" if machine == 0x14C else f"0x{machine:X}"
    size_kb = round(features.get("file_size_kb", 0), 1)
    n_secs  = int(features.get("section_count", features.get("NumberOfSections", 0)))
    ts      = int(features.get("TimeDateStamp", 0))
    dotnet  = "Yes" if features.get("is_dotnet", 0) else "No"

    import datetime
    try:
        ts_str = datetime.datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d")
    except Exception:
        ts_str = str(ts)

    card(c1, "Architecture", arch, THEME["blue"])
    card(c2, "File Size",    f"{size_kb} KB", THEME["orange"])
    card(c3, "Sections",     str(n_secs), THEME["yellow"])
    card(c4, "Compile Time", ts_str, THEME["muted"])
    card(c5, ".NET Binary",  dotnet,
         THEME["purple"] if dotnet == "Yes" else THEME["muted"])


# ─────────────────────────────────────────────────────────────────────────────
# MAIN APP
# ─────────────────────────────────────────────────────────────────────────────

def main():
    configure_page()

    # ── Header ──────────────────────────────────────────────────────────────
    st.markdown("""
    <h1 style="font-size:2rem; margin-bottom:0;">
        🔬 Windows Malware <span style="color:#8B5CF6;">RAT Family</span> Detector
    </h1>
    <p style="color:#6B7280; margin-top:4px; font-size:14px;">
        Kaggle Dataset · PE Header + API + DLL + Section Features ·
        Random Forest + XGBoost · LIME + SHAP Explainability
    </p>
    """, unsafe_allow_html=True)

    st.markdown("---")

    # ── Sidebar ──────────────────────────────────────────────────────────────
    cfg = sidebar_ui()

    # ── Session state ────────────────────────────────────────────────────────
    if "pipeline" not in ss:
        ss.pipeline = MalwareMLPipeline()
    if "metrics" not in ss:
        ss.metrics = None
    if "result" not in ss:
        ss.result = None
    if "features" not in ss:
        ss.features = None
    if "uploaded_name" not in ss:
        ss.uploaded_name = None

    # ── Tabs ─────────────────────────────────────────────────────────────────
    tab_train, tab_detect, tab_explain, tab_about = st.tabs([
        "🏋️ Train Model",
        "🎯 Detect Malware",
        "💡 Explanations",
        "📖 About",
    ])

    # ════════════════════════════════════════════════════════════════════════
    # TAB 1 — TRAIN
    # ════════════════════════════════════════════════════════════════════════
    with tab_train:
        st.markdown("### Step 1 — Load Kaggle Dataset & Train")

        if cfg["pe_header_file"] is None:
            st.info(
                "👈 Upload **PE_Header.csv** in the sidebar to begin. "
                "The other 3 CSVs are optional but improve accuracy."
            )
            st.markdown("""
            **What each file adds:**
            | File | Features | Impact |
            |------|----------|--------|
            | PE_Header.csv | 52 PE header fields | Required |
            | API_Functions.csv | API call flags | +15% accuracy |
            | DLLs_Imported.csv | DLL import flags | +8% accuracy |
            | PE_Section.csv | Section entropy/size | +5% accuracy |
            """)
        else:
            col_btn, col_stat = st.columns([1, 3])

            with col_btn:
                train_btn = st.button("🚀 Train Models",
                                      type="primary",
                                      use_container_width=True)

            if train_btn:
                with st.spinner("Loading and merging datasets..."):
                    pipe = MalwareMLPipeline()

                    # Load primary dataset
                    pe_df = pipe.load_pe_header(
                        io.StringIO(cfg["pe_header_file"].read().decode("utf-8"))
                    )

                    # Load optional datasets
                    api_df = None
                    if cfg["api_file"]:
                        api_df = pipe.load_api_functions(
                            io.StringIO(cfg["api_file"].read().decode("utf-8")))

                    dll_df = None
                    if cfg["dll_file"]:
                        dll_df = pipe.load_dlls(
                            io.StringIO(cfg["dll_file"].read().decode("utf-8")))

                    sec_df = None
                    if cfg["section_file"]:
                        sec_df = pipe.load_pe_section(
                            io.StringIO(cfg["section_file"].read().decode("utf-8")))

                    # Merge
                    merged = pipe.merge_datasets(pe_df, api_df, dll_df, sec_df)
                    st.success(f"Dataset loaded: **{len(merged):,}** samples × "
                               f"**{len(merged.columns)}** columns")

                    # Show class distribution
                    if "label" in merged.columns:
                        dist = merged["label"].value_counts().sort_index()
                        fig_dist = px.bar(
                            x=[LABEL_MAP.get(i, str(i)) for i in dist.index],
                            y=dist.values,
                            color=[LABEL_MAP.get(i, str(i)) for i in dist.index],
                            color_discrete_map=LABEL_COLORS,
                            title="Class Distribution in Dataset",
                        )
                        fig_dist.update_layout(
                            paper_bgcolor=THEME["bg"],
                            plot_bgcolor=THEME["panel"],
                            font={"color": THEME["white"]},
                            showlegend=False,
                            height=280,
                            margin=dict(l=10, r=10, t=50, b=10),
                        )
                        st.plotly_chart(fig_dist, use_container_width=True)

                with st.spinner("Training Random Forest + XGBoost (this takes 1–3 min)..."):
                    progress = st.progress(0, text="Training RF...")
                    metrics  = pipe.train(merged, test_size=cfg["test_size"])
                    progress.progress(100, text="Done!")

                ss.pipeline = pipe
                ss.metrics  = metrics
                st.success("✅ Models trained successfully!")

            # Show metrics if trained
            if ss.metrics:
                m = ss.metrics
                st.markdown("---")
                st.markdown("### 📊 Model Performance")

                c1, c2, c3, c4 = st.columns(4)
                c1.metric("RF Accuracy",  f"{m['rf_accuracy']*100:.2f}%")
                c2.metric("RF F1 Score",  f"{m['rf_f1']*100:.2f}%")
                c3.metric("XGB Accuracy", f"{m['xgb_accuracy']*100:.2f}%")
                c4.metric("XGB F1 Score", f"{m['xgb_f1']*100:.2f}%")

                c1, c2, c3 = st.columns(3)
                c1.metric("Samples",  f"{m['n_samples']:,}")
                c2.metric("Features", f"{m['n_features']}")
                c3.metric("Classes",  f"{m['n_classes']}")

                # Confusion matrices
                st.markdown("#### Confusion Matrices")
                col_rf, col_xgb = st.columns(2)
                with col_rf:
                    st.plotly_chart(
                        plotly_confusion_matrix(
                            m["rf_cm"], m["class_labels"], "Random Forest"),
                        use_container_width=True
                    )
                with col_xgb:
                    st.plotly_chart(
                        plotly_confusion_matrix(
                            m["xgb_cm"], m["class_labels"], "XGBoost"),
                        use_container_width=True
                    )

                # Feature importance
                st.markdown("#### Top Features — Random Forest")
                st.plotly_chart(
                    plotly_rf_importance(ss.pipeline.rf, m["feat_cols"]),
                    use_container_width=True
                )

                # Per-class report
                with st.expander("📋 Full Classification Report"):
                    report_df = pd.DataFrame(m["rf_report"]).T.round(4)
                    st.dataframe(report_df, use_container_width=True)

    # ════════════════════════════════════════════════════════════════════════
    # TAB 2 — DETECT
    # ════════════════════════════════════════════════════════════════════════
    with tab_detect:
        st.markdown("### Step 2 — Upload a Suspicious .exe File")

        if not ss.pipeline.trained:
            st.warning("⚠️ Train the model first in the **Train Model** tab.")
        else:
            uploaded_exe = st.file_uploader(
                "Upload .exe file for analysis",
                type=["exe", "dll", "bin"],
                help="File is analysed statically — it is NEVER executed.",
                key="exe_uploader"
            )

            if uploaded_exe is not None:
                ss.uploaded_name = uploaded_exe.name
                binary = uploaded_exe.read()

                col_info, col_btn = st.columns([3, 1])
                with col_info:
                    sha256 = hashlib.sha256(binary).hexdigest()
                    st.markdown(f"""
                    **File:** `{uploaded_exe.name}`   
                    **Size:** `{len(binary)/1024:.1f} KB`   
                    **SHA256:** `{sha256}`
                    """)
                with col_btn:
                    analyse_btn = st.button("🔍 Analyse File",
                                            type="primary",
                                            use_container_width=True)

                if analyse_btn:
                    with st.spinner("Extracting PE features..."):
                        extractor = PEFeatureExtractor()
                        features  = extractor.extract(binary)

                    if "error" in features:
                        st.error(f"PE parsing failed: {features['error']}")
                        st.info("This may not be a valid PE binary, or it may be packed.")
                    else:
                        ss.features = features
                        with st.spinner("Running ML inference + LIME + SHAP..."):
                            result = ss.pipeline.predict_sample(features)
                        ss.result = result
                        st.success("Analysis complete!")

            # ── Show results ─────────────────────────────────────────────
            if ss.result is not None and ss.features is not None:
                st.markdown("---")
                result   = ss.result
                features = ss.features

                # Verdict banner
                render_verdict(result)

                st.markdown("---")

                # PE info cards
                render_pe_info(features)

                st.markdown("---")

                # Probability bars
                col_prob, col_gauge = st.columns([2, 1])
                with col_prob:
                    st.plotly_chart(
                        plotly_probability_bars(result["ensemble_df"]),
                        use_container_width=True
                    )
                with col_gauge:
                    top_row = result["ensemble_df"].iloc[0]
                    st.plotly_chart(
                        plotly_prob_gauge(
                            top_row["label"],
                            float(top_row["ensemble"])
                        ),
                        use_container_width=True
                    )

                # Model comparison table
                st.markdown("#### 🤖 Model-by-Model Predictions")
                display_df = result["ensemble_df"].copy()
                display_df["rf_prob"]    = (display_df["rf_prob"] * 100).round(2)
                display_df["xgb_prob"]   = (display_df["xgb_prob"] * 100).round(2)
                display_df["ensemble"]   = (display_df["ensemble"] * 100).round(2)
                display_df.columns      = ["Class ID", "Family", "RF %",
                                            "XGBoost %", "Ensemble %"]
                st.dataframe(
                    display_df.reset_index(drop=True),
                    use_container_width=True,
                    height=240,
                )

                # Raw features
                with st.expander("🔩 Extracted PE Features (raw values)"):
                    feat_display = {k: v for k, v in features.items()
                                    if k not in ("sha256",)}
                    fdf = pd.DataFrame(
                        list(feat_display.items()),
                        columns=["Feature", "Value"]
                    )
                    st.dataframe(fdf, use_container_width=True, height=320)

    # ════════════════════════════════════════════════════════════════════════
    # TAB 3 — EXPLANATIONS
    # ════════════════════════════════════════════════════════════════════════
    with tab_explain:
        st.markdown("### 💡 LIME & SHAP Explainability")

        if ss.result is None:
            st.info("Upload and analyse an .exe file in the **Detect** tab first.")
        else:
            result   = ss.result
            features = ss.features
            label    = result["predicted_label"]
            color    = LABEL_COLORS.get(label, THEME["purple"])

            st.markdown(f"""
            **Explaining prediction:** 
            <span style="color:{color}; font-weight:600; font-size:1.1rem;">{label}</span>
            with ensemble confidence **{float(result['ensemble_df'].iloc[0]['ensemble'])*100:.1f}%**
            """, unsafe_allow_html=True)

            # ── LIME ─────────────────────────────────────────────────────
            st.markdown("---")
            st.markdown("#### 🟣 LIME — Local Explanation")
            st.markdown("""
            LIME answers: *"For **this specific file**, which features pushed the 
            model toward this prediction?"*  
            It perturbs the input features 3,000 times and fits a local linear model 
            to explain the decision boundary around this sample.
            """)

            col_lime, col_lime_info = st.columns([2, 1])
            with col_lime:
                if result["lime"]:
                    st.plotly_chart(
                        plotly_lime_chart(result["lime"], label),
                        use_container_width=True
                    )
                else:
                    st.warning("LIME explanation unavailable.")

            with col_lime_info:
                st.markdown(f"""
                <div class="metric-card">
                    <h3>How to read LIME</h3>
                    <p style="font-size:12px; color:#9CA3AF; line-height:1.6">
                    <span style="color:{color}">■ Positive bars</span> — 
                    this feature's value supports the <b>{label}</b> prediction.<br><br>
                    <span style="color:{THEME['blue']}">■ Negative bars</span> — 
                    this feature's value opposes the prediction.<br><br>
                    Longer bars = stronger influence on <em>this specific sample</em>.
                    </p>
                </div>
                """, unsafe_allow_html=True)

                if result["lime"]:
                    top3 = result["lime"][:3]
                    st.markdown("**Top 3 contributing features:**")
                    for feat, weight in top3:
                        direction = "↑ supports" if weight > 0 else "↓ opposes"
                        st.markdown(
                            f"- `{feat[:45]}` → **{direction}** ({weight:+.4f})"
                        )

            # ── SHAP ─────────────────────────────────────────────────────
            st.markdown("---")
            st.markdown("#### 🔵 SHAP — Feature Attribution")
            st.markdown("""
            SHAP uses Shapley values (cooperative game theory) to assign each feature 
            its exact contribution to this prediction.  
            Unlike LIME, SHAP is **guaranteed consistent** and **globally comparable**.
            """)

            col_shap, col_shap_info = st.columns([2, 1])
            with col_shap:
                if result["shap_values"] is not None:
                    st.plotly_chart(
                        plotly_shap_chart(
                            result["shap_values"],
                            ss.pipeline.feat_cols,
                            label
                        ),
                        use_container_width=True
                    )
                else:
                    st.warning("SHAP values unavailable.")

            with col_shap_info:
                st.markdown(f"""
                <div class="metric-card">
                    <h3>How to read SHAP</h3>
                    <p style="font-size:12px; color:#9CA3AF; line-height:1.6">
                    Each bar shows the exact contribution of a feature's value 
                    to this specific prediction score.<br><br>
                    Base value: <b>{result['shap_base']:.4f}</b><br>
                    (average model output across training data)<br><br>
                    Sum of all SHAP values + base = final prediction score.
                    </p>
                </div>
                """, unsafe_allow_html=True)

                # Top SHAP features
                if result["shap_values"] is not None:
                    sv    = result["shap_values"]
                    fcols = ss.pipeline.feat_cols
                    top_idx = np.argsort(np.abs(sv))[::-1][:5]
                    st.markdown("**Top 5 SHAP features:**")
                    for i in top_idx:
                        direction = "↑" if sv[i] > 0 else "↓"
                        st.markdown(
                            f"- `{fcols[i][:40]}` {direction} **{sv[i]:+.4f}**"
                        )

            # ── LIME vs SHAP comparison ────────────────────────────────
            st.markdown("---")
            st.markdown("#### 🔄 LIME vs SHAP — Comparison")

            col_a, col_b = st.columns(2)
            with col_a:
                st.markdown("""
                | Property | LIME | SHAP |
                |----------|------|------|
                | **Scope** | Local (this sample) | Local + Global |
                | **Method** | Perturb + linear fit | Shapley values |
                | **Consistency** | Approximate | Exact / guaranteed |
                | **Speed** | Fast (3k samples) | Fast (TreeSHAP) |
                | **Trust** | High for individual | Highest overall |
                | **Best for** | Quick analyst triage | Auditing & reporting |
                """)
            with col_b:
                st.markdown(f"""
                <div class="metric-card">
                <h3>Analyst Interpretation — {label}</h3>
                <p style="font-size:12px; color:#9CA3AF; line-height:1.7">
                """, unsafe_allow_html=True)

                if label == "RAT":
                    st.markdown("""
                    This file exhibits RAT-characteristic features:
                    - **.NET / MSCOREE.dll** import → managed .NET binary
                    - **Network API calls** (WS2_32, WININET) → C2 communication
                    - **Registry API calls** (RegSetValue) → persistence
                    - **Process API calls** (CreateProcess) → execution control
                    - **High section entropy** → possible obfuscation/packing
                    """)
                elif label == "Benign":
                    st.markdown("""
                    No strong malicious indicators detected.
                    - Standard PE structure
                    - No suspicious API call combinations
                    - Normal section entropy
                    """)
                else:
                    st.markdown(f"""
                    Detected as **{label}** — review the LIME/SHAP features 
                    above for the specific indicators that triggered this classification.
                    """)
                st.markdown("</p></div>", unsafe_allow_html=True)

    # ════════════════════════════════════════════════════════════════════════
    # TAB 4 — ABOUT
    # ════════════════════════════════════════════════════════════════════════
    with tab_about:
        st.markdown("### 📖 About This Tool")

        col_a, col_b = st.columns(2)

        with col_a:
            st.markdown("""
            #### Dataset
            **[Windows Malwares — Kaggle](https://www.kaggle.com/datasets/joebeachcapital/windows-malwares)**  
            by joebeachcapital

            | File | Description |
            |------|-------------|
            | `PE_Header.csv` | 52 PE header fields per sample |
            | `API_Functions.csv` | API function call flags |
            | `DLLs_Imported.csv` | DLL import flags |
            | `PE_Section.csv` | 9 fields × 10 PE sections |

            **Labels:**
            | ID | Family |
            |----|--------|
            | 0 | Benign |
            | 1 | RedLineStealer |
            | 2 | Downloader |
            | **3** | **RAT** ← focus |
            | 4 | BankingTrojan |
            | 5 | SnakeKeyLogger |
            | 6 | Spyware |
            """)

        with col_b:
            st.markdown("""
            #### ML Architecture

            **Random Forest**
            - 300 trees, balanced class weights
            - Gini impurity feature importance
            - SHAP TreeExplainer (exact)

            **XGBoost**
            - 300 estimators, lr=0.08
            - Handles class imbalance
            - SHAP TreeExplainer (exact)

            **Ensemble** = Average of RF + XGBoost probabilities

            **LIME** (Local Interpretable Model-Agnostic Explanations)
            - 3,000 perturbations per sample
            - Quartile discretisation
            - Per-class explanation available

            **SHAP** (SHapley Additive exPlanations)
            - TreeExplainer — exact, fast
            - Consistent across samples
            - Waterfall + beeswarm plots

            #### PE Feature Extraction
            Uses **pefile** library to parse the uploaded binary 
            and extract the same features as the training dataset 
            (PE header, imports, sections) — **no execution required**.
            """)

        st.markdown("---")
        st.markdown("""
        #### ⚠️ Safety Note
        Uploaded files are analysed **statically only** using `pefile` parsing.  
        No code is executed. The binary is processed in memory and discarded.  
        Do **not** run this tool on an unprotected system — use FLARE-VM or an isolated sandbox.
        """)


if __name__ == "__main__":
    main()
