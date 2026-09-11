import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
"""
Model training and comparative benchmarking: XGBoost vs TabNet.

Trains:
1. XGBoost Classifier (Primary model, optimized for SHAP TreeExplainer)
2. TabNet Classifier (Secondary deep-learning model with built-in attention)
Reports:
- Accuracy, Precision, Recall, F1-Score, ROC-AUC, and Confusion Matrix for both.
Saves models and metrics for deployment and notebook exploration.
"""

import json
import os
import numpy as np
import pandas as pd
import xgboost as xgb
import torch
from pytorch_tabnet.tab_model import TabNetClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
)
from tabulate import tabulate

from src.config import (
    TRAIN_CSV,
    TEST_CSV,
    PIPELINE_PATH,
    XGBOOST_MODEL_PATH,
    TABNET_MODEL_PATH,
    METRICS_REPORT_PATH,
    FEATURE_COLUMNS,
    SEED,
)
from src.feature_pipeline import CloudTrailFeaturePipeline

def evaluate_predictions(y_true, y_pred, y_prob):
    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred)
    rec = recall_score(y_true, y_pred)
    f1 = f1_score(y_true, y_pred)
    auc = roc_auc_score(y_true, y_prob)
    cm = confusion_matrix(y_true, y_pred).tolist()
    return {
        "accuracy": float(acc),
        "precision": float(prec),
        "recall": float(rec),
        "f1": float(f1),
        "roc_auc": float(auc),
        "confusion_matrix": cm,
    }

def train_and_evaluate():
    print("=" * 78)
    print("      MODEL BENCHMARK: XGBOOST vs TABNET (DEEP TABULAR LEARNING)")
    print("=" * 78)
    
    if not os.path.exists(TRAIN_CSV) or not os.path.exists(TEST_CSV):
        raise FileNotFoundError("Train/Test data not found. Run data/generate_dataset.py first.")
        
    train_df = pd.read_csv(TRAIN_CSV)
    test_df = pd.read_csv(TEST_CSV)
    
    y_train = train_df["is_threat"].values
    y_test = test_df["is_threat"].values
    
    # 1. Feature Engineering
    print("[*] Fitting Feature Pipeline on training dataset...")
    pipeline = CloudTrailFeaturePipeline()
    X_train_df = pipeline.fit_transform(train_df)
    X_test_df = pipeline.transform(test_df)
    pipeline.save(PIPELINE_PATH)
    
    X_train = X_train_df.values.astype(np.float32)
    X_test = X_test_df.values.astype(np.float32)
    
    print(f"  [+] Training set size: {X_train.shape[0]} samples, {X_train.shape[1]} features")
    print(f"  [+] Test set size:     {X_test.shape[0]} samples, {X_test.shape[1]} features")
    
    # -------------------------------------------------------------
    # 2. Model 1: XGBoost (Primary Model)
    # -------------------------------------------------------------
    print("\n[*] Training Model 1: XGBoost Classifier...")
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
    
    xgb_preds = xgb_model.predict(X_test)
    xgb_probs = xgb_model.predict_proba(X_test)[:, 1]
    xgb_metrics = evaluate_predictions(y_test, xgb_preds, xgb_probs)
    
    xgb_model.save_model(XGBOOST_MODEL_PATH)
    print(f"  [+] XGBoost trained & saved to: {XGBOOST_MODEL_PATH}")
    
    # -------------------------------------------------------------
    # 3. Model 2: TabNet (Deep Tabular Neural Network)
    # -------------------------------------------------------------
    print("\n[*] Training Model 2: PyTorch TabNet Classifier...")
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
    
    tabnet_preds = tabnet_model.predict(X_test)
    tabnet_probs = tabnet_model.predict_proba(X_test)[:, 1]
    tabnet_metrics = evaluate_predictions(y_test, tabnet_preds, tabnet_probs)
    
    tabnet_model.save_model(TABNET_MODEL_PATH.replace(".zip", ""))
    print(f"  [+] TabNet trained & saved to: {TABNET_MODEL_PATH}")
    
    # -------------------------------------------------------------
    # 4. Comparative Metrics Presentation
    # -------------------------------------------------------------
    print("\n" + "=" * 78)
    print("                COMPARATIVE MODEL PERFORMANCE")
    print("=" * 78)
    
    comp_rows = [
        ["Model Architecture", "XGBoost (Gradient Boosted Trees)", "TabNet (Deep Attentive Network)"],
        ["Interpretability Mechanism", "Exact Shapley Values (TreeExplainer)", "Sparse Attention Masks (Sequential)"],
        ["Accuracy", f"{xgb_metrics['accuracy']:.4f}", f"{tabnet_metrics['accuracy']:.4f}"],
        ["Precision", f"{xgb_metrics['precision']:.4f}", f"{tabnet_metrics['precision']:.4f}"],
        ["Recall", f"{xgb_metrics['recall']:.4f}", f"{tabnet_metrics['recall']:.4f}"],
        ["F1-Score", f"{xgb_metrics['f1']:.4f}", f"{tabnet_metrics['f1']:.4f}"],
        ["ROC-AUC", f"{xgb_metrics['roc_auc']:.4f}", f"{tabnet_metrics['roc_auc']:.4f}"],
        ["Confusion Matrix (TN, FP, FN, TP)", 
         f"TN={xgb_metrics['confusion_matrix'][0][0]}, FP={xgb_metrics['confusion_matrix'][0][1]}\nFN={xgb_metrics['confusion_matrix'][1][0]}, TP={xgb_metrics['confusion_matrix'][1][1]}",
         f"TN={tabnet_metrics['confusion_matrix'][0][0]}, FP={tabnet_metrics['confusion_matrix'][0][1]}\nFN={tabnet_metrics['confusion_matrix'][1][0]}, TP={tabnet_metrics['confusion_matrix'][1][1]}"],
    ]
    
    print(tabulate(comp_rows, headers="firstrow", tablefmt="grid"))
    
    metrics_summary = {
        "xgboost": xgb_metrics,
        "tabnet": tabnet_metrics,
        "feature_columns": FEATURE_COLUMNS,
    }
    with open(METRICS_REPORT_PATH, "w") as f:
        json.dump(metrics_summary, f, indent=2)
    print(f"\n[+] Detailed evaluation metrics stored at: {METRICS_REPORT_PATH}")
    return metrics_summary

if __name__ == "__main__":
    train_and_evaluate()


