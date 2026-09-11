"""
Stage 6: Train V3 Models (XGBoost & TabNet) with Multi-Split Evaluation.

Trains:
1. XGBoost V3 Classifier (Gradient Boosted Decision Trees)
2. TabNet V3 Classifier (Deep Attentive Neural Network)

Using:
- V3 unified dataset and feature pipeline.
- Preserves V1/V2 model artifacts without overwriting.
- Evaluates across all 3 splits:
    1. Random Split
    2. Time-Based Split
    3. Identity-Holdout Split
- Computes comprehensive security metrics:
    accuracy, precision, recall, f1, roc_auc, pr_auc,
    confusion_matrix, false_positive_rate (FPR), false_negative_rate (FNR).
- Generates publication-ready diagnostic plots:
    - Confusion matrices
    - ROC curves
    - Precision-Recall (PR) curves
    - Feature importance charts
- Compares V2 vs V3 performance.
"""

import os
import sys
import json
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")  # Non-interactive backend
import matplotlib.pyplot as plt
import seaborn as sns

import torch
import xgboost as xgb
from pytorch_tabnet.tab_model import TabNetClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    average_precision_score,
    confusion_matrix,
    roc_curve,
    precision_recall_curve,
)
from tabulate import tabulate

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from src.config import (
    FEATURE_COLUMNS,
    FEATURE_DESCRIPTIONS,
    SEED,
    SPLITS_DIR,
    METRICS_REPORT_PATH,
    PIPELINE_V3_PATH,
    XGBOOST_V3_PATH,
    TABNET_V3_PATH,
    METRICS_V3_REPORT_PATH,
    TRAINING_CONFIG_V3_PATH,
    FEATURE_NAMES_V3_PATH,
    PLOTS_V3_DIR,
)
from src.feature_pipeline import CloudTrailFeaturePipeline

os.makedirs(PLOTS_V3_DIR, exist_ok=True)

def compute_security_metrics(y_true, y_pred, y_prob) -> dict:
    """Computes comprehensive detection metrics with security-critical focus."""
    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel()
    
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0
    acc = float(accuracy_score(y_true, y_pred))
    prec = float(precision_score(y_true, y_pred, zero_division=0))
    rec = float(recall_score(y_true, y_pred, zero_division=0))
    f1 = float(f1_score(y_true, y_pred, zero_division=0))
    auc = float(roc_auc_score(y_true, y_prob))
    pr_auc = float(average_precision_score(y_true, y_prob))
    
    return {
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1": round(f1, 4),
        "roc_auc": round(auc, 4),
        "pr_auc": round(pr_auc, 4),
        "confusion_matrix": cm.tolist(),
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
        "false_positive_rate": round(fpr, 4),
        "false_negative_rate": round(fnr, 4),
    }

def generate_plots(y_true, xgb_prob, tabnet_prob, xgb_pred, tabnet_pred, feature_names, xgb_model, tabnet_model):
    """Generates and saves diagnostic evaluation plots."""
    print("[*] Generating diagnostic visualization plots into models/plots_v3/...")
    
    # 1. Confusion Matrix Plots
    fig, axes = plt.subplots(1, 2, figsize=(12, 5))
    cm_xgb = confusion_matrix(y_true, xgb_pred)
    cm_tab = confusion_matrix(y_true, tabnet_pred)
    
    sns.heatmap(cm_xgb, annot=True, fmt="d", cmap="Blues", ax=axes[0], cbar=False)
    axes[0].set_title("XGBoost V3 Confusion Matrix")
    axes[0].set_xlabel("Predicted Label")
    axes[0].set_ylabel("True Label")
    axes[0].set_xticklabels(["Benign (0)", "Threat (1)"])
    axes[0].set_yticklabels(["Benign (0)", "Threat (1)"])
    
    sns.heatmap(cm_tab, annot=True, fmt="d", cmap="Purples", ax=axes[1], cbar=False)
    axes[1].set_title("TabNet V3 Confusion Matrix")
    axes[1].set_xlabel("Predicted Label")
    axes[1].set_ylabel("True Label")
    axes[1].set_xticklabels(["Benign (0)", "Threat (1)"])
    axes[1].set_yticklabels(["Benign (0)", "Threat (1)"])
    
    plt.tight_layout()
    cm_plot_path = os.path.join(PLOTS_V3_DIR, "confusion_matrices_v3.png")
    plt.savefig(cm_plot_path, dpi=200)
    plt.close()
    
    # 2. ROC Curves Comparison
    fpr_x, tpr_x, _ = roc_curve(y_true, xgb_prob)
    fpr_t, tpr_t, _ = roc_curve(y_true, tabnet_prob)
    auc_x = roc_auc_score(y_true, xgb_prob)
    auc_t = roc_auc_score(y_true, tabnet_prob)
    
    plt.figure(figsize=(7, 6))
    plt.plot(fpr_x, tpr_x, color="#2563eb", lw=2, label=f"XGBoost V3 (AUC = {auc_x:.4f})")
    plt.plot(fpr_t, tpr_t, color="#9333ea", lw=2, label=f"TabNet V3 (AUC = {auc_t:.4f})")
    plt.plot([0, 1], [0, 1], color="gray", linestyle="--", lw=1)
    plt.xlabel("False Positive Rate")
    plt.ylabel("True Positive Rate (Recall)")
    plt.title("ROC Curve: XGBoost vs TabNet (V3)")
    plt.legend(loc="lower right")
    plt.grid(True, alpha=0.3)
    roc_plot_path = os.path.join(PLOTS_V3_DIR, "roc_curve_comparison_v3.png")
    plt.savefig(roc_plot_path, dpi=200)
    plt.close()
    
    # 3. Precision-Recall Curves
    prec_x, rec_x, _ = precision_recall_curve(y_true, xgb_prob)
    prec_t, rec_t, _ = precision_recall_curve(y_true, tabnet_prob)
    pr_auc_x = average_precision_score(y_true, xgb_prob)
    pr_auc_t = average_precision_score(y_true, tabnet_prob)
    
    plt.figure(figsize=(7, 6))
    plt.plot(rec_x, prec_x, color="#2563eb", lw=2, label=f"XGBoost V3 (PR-AUC = {pr_auc_x:.4f})")
    plt.plot(rec_t, prec_t, color="#9333ea", lw=2, label=f"TabNet V3 (PR-AUC = {pr_auc_t:.4f})")
    plt.xlabel("Recall")
    plt.ylabel("Precision")
    plt.title("Precision-Recall Curve: XGBoost vs TabNet (V3)")
    plt.legend(loc="lower left")
    plt.grid(True, alpha=0.3)
    pr_plot_path = os.path.join(PLOTS_V3_DIR, "pr_curve_comparison_v3.png")
    plt.savefig(pr_plot_path, dpi=200)
    plt.close()
    
    # 4. Feature Importance (XGBoost Gain & TabNet Weights)
    xgb_importances = xgb_model.feature_importances_
    tab_importances = tabnet_model.feature_importances_
    
    fig, axes = plt.subplots(1, 2, figsize=(14, 6))
    idx_sorted_x = np.argsort(xgb_importances)
    axes[0].barh(range(len(feature_names)), xgb_importances[idx_sorted_x], color="#3b82f6", align="center")
    axes[0].set_yticks(range(len(feature_names)))
    axes[0].set_yticklabels([feature_names[i] for i in idx_sorted_x])
    axes[0].set_title("XGBoost V3 Feature Importance (Gain)")
    axes[0].set_xlabel("Relative Importance")
    
    idx_sorted_t = np.argsort(tab_importances)
    axes[1].barh(range(len(feature_names)), tab_importances[idx_sorted_t], color="#a855f7", align="center")
    axes[1].set_yticks(range(len(feature_names)))
    axes[1].set_yticklabels([feature_names[i] for i in idx_sorted_t])
    axes[1].set_title("TabNet V3 Feature Importance (Attention Mask)")
    axes[1].set_xlabel("Relative Importance")
    
    plt.tight_layout()
    fi_plot_path = os.path.join(PLOTS_V3_DIR, "feature_importance_comparison_v3.png")
    plt.savefig(fi_plot_path, dpi=200)
    plt.close()
    
    print(f"  [+] Plots saved:\n      - {cm_plot_path}\n      - {roc_plot_path}\n      - {pr_plot_path}\n      - {fi_plot_path}")

def train_and_evaluate_v3():
    print("=" * 82)
    print("      STAGE 6: TRAINING V3 MODELS (XGBOOST & TABNET)")
    print("=" * 82)
    
    # Check splits exist
    random_train_path = os.path.join(SPLITS_DIR, "random_train.csv")
    random_test_path = os.path.join(SPLITS_DIR, "random_test.csv")
    time_train_path = os.path.join(SPLITS_DIR, "time_train.csv")
    time_test_path = os.path.join(SPLITS_DIR, "time_test.csv")
    ident_train_path = os.path.join(SPLITS_DIR, "identity_holdout_train.csv")
    ident_test_path = os.path.join(SPLITS_DIR, "identity_holdout_test.csv")
    
    for p in [random_train_path, random_test_path, time_train_path, time_test_path, ident_train_path, ident_test_path]:
        if not os.path.exists(p):
            raise FileNotFoundError(f"Split file missing at {p}. Run data/build_v3_dataset.py first.")
            
    df_train = pd.read_csv(random_train_path)
    df_test = pd.read_csv(random_test_path)
    
    print(f"[*] Primary Training Data (Random Split): {len(df_train):,} train rows, {len(df_test):,} test rows")
    
    # 1. Fit V3 Feature Pipeline
    print("\n[*] Fitting CloudTrailFeaturePipeline V3 on training set...")
    pipeline_v3 = CloudTrailFeaturePipeline()
    X_train_df = pipeline_v3.fit_transform(df_train)
    X_test_df = pipeline_v3.transform(df_test)
    pipeline_v3.save(PIPELINE_V3_PATH)
    
    X_train = X_train_df.values.astype(np.float32)
    y_train = df_train["is_threat"].values.astype(int)
    X_test = X_test_df.values.astype(np.float32)
    y_test = df_test["is_threat"].values.astype(int)
    
    feature_names = list(X_train_df.columns)
    with open(FEATURE_NAMES_V3_PATH, "w") as f:
        json.dump(feature_names, f, indent=2)
    print(f"  [+] Feature names saved to {FEATURE_NAMES_V3_PATH}")
    
    # 2. Train Model 1: XGBoost V3
    print("\n[*] Training Model 1: XGBoost V3 Classifier...")
    xgb_model = xgb.XGBClassifier(
        n_estimators=160,
        max_depth=5,
        learning_rate=0.07,
        subsample=0.85,
        colsample_bytree=0.85,
        eval_metric="logloss",
        random_state=SEED,
    )
    xgb_model.fit(X_train, y_train)
    xgb_model.save_model(XGBOOST_V3_PATH)
    print(f"  [+] XGBoost V3 trained & saved to: {XGBOOST_V3_PATH}")
    
    # 3. Train Model 2: TabNet V3
    print("\n[*] Training Model 2: PyTorch TabNet V3 Classifier...")
    torch.manual_seed(SEED)
    tabnet_model = TabNetClassifier(
        n_d=16,
        n_a=16,
        n_steps=4,
        gamma=1.3,
        lambda_sparse=1e-3,
        optimizer_fn=torch.optim.Adam,
        optimizer_params=dict(lr=2e-2),
        mask_type="entmax",
        seed=SEED,
        verbose=0,
    )
    tabnet_model.fit(
        X_train=X_train,
        y_train=y_train,
        eval_set=[(X_test, y_test)],
        eval_name=["valid"],
        eval_metric=["auc"],
        max_epochs=20,
        patience=8,
        batch_size=512,
        virtual_batch_size=128,
        drop_last=False,
    )
    tabnet_model.save_model(TABNET_V3_PATH.replace(".zip", ""))
    print(f"  [+] TabNet V3 trained & saved to: {TABNET_V3_PATH}")
    
    # 4. Multi-Split Evaluation
    print("\n" + "=" * 82)
    print("         EVALUATING V3 MODELS ACROSS 3 INDEPENDENT SPLITS")
    print("=" * 82)
    
    splits = [
        ("Random Split (i.i.d)", random_train_path, random_test_path),
        ("Time-Based Split (Temporal)", time_train_path, time_test_path),
        ("Identity-Holdout Split (Generalization)", ident_train_path, ident_test_path),
    ]
    
    all_metrics = {
        "xgboost_v3": {},
        "tabnet_v3": {},
    }
    
    primary_metrics_for_plots = None
    
    for split_name, tr_path, te_path in splits:
        split_key = split_name.split()[0].lower()
        print(f"\n--- Split: {split_name} ---")
        d_tr = pd.read_csv(tr_path)
        d_te = pd.read_csv(te_path)
        
        # Transform using fitted pipeline
        X_te_df = pipeline_v3.transform(d_te)
        X_te = X_te_df.values.astype(np.float32)
        y_te = d_te["is_threat"].values.astype(int)
        
        # XGBoost
        xgb_preds = xgb_model.predict(X_te)
        xgb_probs = xgb_model.predict_proba(X_te)[:, 1]
        xgb_metrics = compute_security_metrics(y_te, xgb_preds, xgb_probs)
        all_metrics["xgboost_v3"][split_key] = xgb_metrics
        
        # TabNet
        tab_preds = tabnet_model.predict(X_te)
        tab_probs = tabnet_model.predict_proba(X_te)[:, 1]
        tab_metrics = compute_security_metrics(y_te, tab_preds, tab_probs)
        all_metrics["tabnet_v3"][split_key] = tab_metrics
        
        if split_key == "random":
            primary_metrics_for_plots = (y_te, xgb_probs, tab_probs, xgb_preds, tab_preds)
            
        rows = [
            ["Metric", "XGBoost V3", "TabNet V3"],
            ["Accuracy", f"{xgb_metrics['accuracy']:.4f}", f"{tab_metrics['accuracy']:.4f}"],
            ["Precision (Security)", f"{xgb_metrics['precision']:.4f}", f"{tab_metrics['precision']:.4f}"],
            ["Recall (Security)", f"{xgb_metrics['recall']:.4f}", f"{tab_metrics['recall']:.4f}"],
            ["F1-Score (Security)", f"{xgb_metrics['f1']:.4f}", f"{tab_metrics['f1']:.4f}"],
            ["ROC-AUC", f"{xgb_metrics['roc_auc']:.4f}", f"{tab_metrics['roc_auc']:.4f}"],
            ["PR-AUC (Security)", f"{xgb_metrics['pr_auc']:.4f}", f"{tab_metrics['pr_auc']:.4f}"],
            ["False Positive Rate (FPR)", f"{xgb_metrics['false_positive_rate']:.4f}", f"{tab_metrics['false_positive_rate']:.4f}"],
            ["False Negative Rate (FNR)", f"{xgb_metrics['false_negative_rate']:.4f}", f"{tab_metrics['false_negative_rate']:.4f}"],
            ["Confusion Matrix (TN, FP, FN, TP)", 
             f"TN={xgb_metrics['tn']}, FP={xgb_metrics['fp']}\nFN={xgb_metrics['fn']}, TP={xgb_metrics['tp']}",
             f"TN={tab_metrics['tn']}, FP={tab_metrics['fp']}\nFN={tab_metrics['fn']}, TP={tab_metrics['tp']}"],
        ]
        print(tabulate(rows, headers="firstrow", tablefmt="grid"))
        
    # 5. Generate Diagnostic Plots
    if primary_metrics_for_plots:
        generate_plots(
            primary_metrics_for_plots[0],
            primary_metrics_for_plots[1],
            primary_metrics_for_plots[2],
            primary_metrics_for_plots[3],
            primary_metrics_for_plots[4],
            feature_names,
            xgb_model,
            tabnet_model,
        )
        
    # 6. Save Training Configuration
    training_config = {
        "version": "v3.0",
        "random_seed": SEED,
        "features": feature_names,
        "xgboost_hyperparameters": {
            "n_estimators": 160,
            "max_depth": 5,
            "learning_rate": 0.07,
            "subsample": 0.85,
            "colsample_bytree": 0.85,
            "eval_metric": "logloss",
        },
        "tabnet_hyperparameters": {
            "n_d": 16,
            "n_a": 16,
            "n_steps": 4,
            "gamma": 1.3,
            "lambda_sparse": 1e-3,
            "optimizer": "Adam",
            "lr": 0.02,
            "mask_type": "entmax",
            "max_epochs": 20,
            "patience": 8,
            "batch_size": 512,
            "virtual_batch_size": 128,
        },
    }
    with open(TRAINING_CONFIG_V3_PATH, "w") as f:
        json.dump(training_config, f, indent=2)
    print(f"\n[+] Training config saved to {TRAINING_CONFIG_V3_PATH}")

    # 7. Compare V2 vs V3
    v2_metrics = {}
    if os.path.exists(METRICS_REPORT_PATH):
        try:
            with open(METRICS_REPORT_PATH, "r") as f:
                v2_metrics = json.load(f)
        except Exception:
            pass
            
    print("\n" + "=" * 82)
    print("                     V2 vs V3 BENCHMARK COMPARISON")
    print("=" * 82)
    
    xgb_v2 = v2_metrics.get("xgboost", {})
    tab_v2 = v2_metrics.get("tabnet", {})
    xgb_v3 = all_metrics["xgboost_v3"]["random"]
    tab_v3 = all_metrics["tabnet_v3"]["random"]
    
    comp_table = [
        ["Model Architecture", "Metric", "V2 Benchmark", "V3 Benchmark", "Delta (V3 - V2)"],
        ["XGBoost", "Accuracy", f"{xgb_v2.get('accuracy', 0):.4f}", f"{xgb_v3['accuracy']:.4f}", f"{xgb_v3['accuracy'] - xgb_v2.get('accuracy', 0):+.4f}"],
        ["XGBoost", "Precision", f"{xgb_v2.get('precision', 0):.4f}", f"{xgb_v3['precision']:.4f}", f"{xgb_v3['precision'] - xgb_v2.get('precision', 0):+.4f}"],
        ["XGBoost", "Recall", f"{xgb_v2.get('recall', 0):.4f}", f"{xgb_v3['recall']:.4f}", f"{xgb_v3['recall'] - xgb_v2.get('recall', 0):+.4f}"],
        ["XGBoost", "F1-Score", f"{xgb_v2.get('f1', 0):.4f}", f"{xgb_v3['f1']:.4f}", f"{xgb_v3['f1'] - xgb_v2.get('f1', 0):+.4f}"],
        ["XGBoost", "ROC-AUC", f"{xgb_v2.get('roc_auc', 0):.4f}", f"{xgb_v3['roc_auc']:.4f}", f"{xgb_v3['roc_auc'] - xgb_v2.get('roc_auc', 0):+.4f}"],
        ["XGBoost", "PR-AUC", "N/A", f"{xgb_v3['pr_auc']:.4f}", "New Metric"],
        ["XGBoost", "FPR", "N/A", f"{xgb_v3['false_positive_rate']:.4f}", "New Metric"],
        ["XGBoost", "FNR", "N/A", f"{xgb_v3['false_negative_rate']:.4f}", "New Metric"],
        ["---", "---", "---", "---", "---"],
        ["TabNet", "Accuracy", f"{tab_v2.get('accuracy', 0):.4f}", f"{tab_v3['accuracy']:.4f}", f"{tab_v3['accuracy'] - tab_v2.get('accuracy', 0):+.4f}"],
        ["TabNet", "Precision", f"{tab_v2.get('precision', 0):.4f}", f"{tab_v3['precision']:.4f}", f"{tab_v3['precision'] - tab_v2.get('precision', 0):+.4f}"],
        ["TabNet", "Recall", f"{tab_v2.get('recall', 0):.4f}", f"{tab_v3['recall']:.4f}", f"{tab_v3['recall'] - tab_v2.get('recall', 0):+.4f}"],
        ["TabNet", "F1-Score", f"{tab_v2.get('f1', 0):.4f}", f"{tab_v3['f1']:.4f}", f"{tab_v3['f1'] - tab_v2.get('f1', 0):+.4f}"],
        ["TabNet", "ROC-AUC", f"{tab_v2.get('roc_auc', 0):.4f}", f"{tab_v3['roc_auc']:.4f}", f"{tab_v3['roc_auc'] - tab_v2.get('roc_auc', 0):+.4f}"],
        ["TabNet", "PR-AUC", "N/A", f"{tab_v3['pr_auc']:.4f}", "New Metric"],
        ["TabNet", "FPR", "N/A", f"{tab_v3['false_positive_rate']:.4f}", "New Metric"],
        ["TabNet", "FNR", "N/A", f"{tab_v3['false_negative_rate']:.4f}", "New Metric"],
    ]
    print(tabulate(comp_table, headers="firstrow", tablefmt="grid"))
    
    # Save combined metrics report
    v3_summary = {
        "evaluation_splits": all_metrics,
        "v2_comparison": {
            "v2_metrics": v2_metrics,
            "v3_random_metrics": {
                "xgboost": xgb_v3,
                "tabnet": tab_v3,
            }
        },
        "feature_columns": feature_names,
    }
    with open(METRICS_V3_REPORT_PATH, "w") as f:
        json.dump(v3_summary, f, indent=2)
    print(f"\n[+] Evaluation Metrics V3 saved to: {METRICS_V3_REPORT_PATH}")
    print("=" * 82 + "\n")
    return v3_summary

if __name__ == "__main__":
    train_and_evaluate_v3()
