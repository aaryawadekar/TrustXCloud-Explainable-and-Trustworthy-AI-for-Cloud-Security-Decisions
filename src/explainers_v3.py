"""
Stage 8: V3 Explainability Layer (SHAP, LIME, TabNet Attention).

Implements multi-model explainability for V3 architecture:
1. SHAP TreeExplainer for exact Shapley feature attributions (XGBoost V3).
2. TabNet Sequential Attention Masks for neural feature attributions (TabNet V3).
3. LIME TabularExplainer for perturbation-based local surrogate explanations.

Strict Terminology:
- Uses 'feature contribution', 'model attribution', and 'perturbation-based explanation'.
- Strictly avoids calling explanations 'causal'.

Covers:
- True Benign
- True Threat
- False Positive
- False Negative
- All major privilege escalation attack types
- Global SHAP feature importance & local attribution plots
- XGBoost vs TabNet comparative explanations
- Saves explanations_v3.json and plots in models/plots_v3/
"""

import os
import sys
import json
from typing import Dict, List, Any, Optional
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns

import shap
import lime
import lime.lime_tabular
import xgboost as xgb
import torch
from pytorch_tabnet.tab_model import TabNetClassifier
from tabulate import tabulate

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from src.config import (
    MODELS_DIR,
    PROCESSED_DATA_DIR,
    SPLITS_DIR,
    PIPELINE_V3_PATH,
    XGBOOST_V3_PATH,
    TABNET_V3_PATH,
    FEATURE_NAMES_V3_PATH,
    FEATURE_DESCRIPTIONS,
    PLOTS_V3_DIR,
    SEED,
)
from src.feature_pipeline import CloudTrailFeaturePipeline

EXPLANATIONS_V3_JSON = os.path.join(MODELS_DIR, "explanations_v3.json")
os.makedirs(PLOTS_V3_DIR, exist_ok=True)

class V3SecurityExplainer:
    def __init__(self):
        if not os.path.exists(XGBOOST_V3_PATH) or not os.path.exists(TABNET_V3_PATH):
            raise FileNotFoundError("Trained V3 models not found. Run src/train_v3.py first.")
            
        print("[*] Initializing V3 Explainability Pipeline...")
        self.pipeline = CloudTrailFeaturePipeline.load(PIPELINE_V3_PATH)
        
        # Load XGBoost V3
        self.xgb_model = xgb.XGBClassifier()
        self.xgb_model.load_model(XGBOOST_V3_PATH)
        
        # Load TabNet V3
        self.tabnet_model = TabNetClassifier()
        self.tabnet_model.load_model(TABNET_V3_PATH)
        
        with open(FEATURE_NAMES_V3_PATH, "r") as f:
            self.feature_names = json.load(f)
            
        # Background data from random training split
        train_path = os.path.join(SPLITS_DIR, "random_train.csv")
        self.train_df = pd.read_csv(train_path)
        self.X_train = self.pipeline.transform(self.train_df).values.astype(np.float32)
        
        # Test data from random test split
        test_path = os.path.join(SPLITS_DIR, "random_test.csv")
        self.test_df = pd.read_csv(test_path)
        self.X_test = self.pipeline.transform(self.test_df).values.astype(np.float32)
        self.y_test = self.test_df["is_threat"].values.astype(int)
        
        # 1. SHAP TreeExplainer for XGBoost
        print("  [+] Initializing SHAP TreeExplainer for XGBoost V3...")
        self.tree_explainer = shap.TreeExplainer(self.xgb_model)
        
        # 2. LIME TabularExplainer
        print("  [+] Initializing LIME TabularExplainer (perturbation-based surrogate)...")
        self.lime_explainer = lime.lime_tabular.LimeTabularExplainer(
            training_data=self.X_train,
            feature_names=self.feature_names,
            class_names=["Benign", "Threat"],
            mode="classification",
            random_state=SEED,
        )

    def explain_instance(self, X_sample: np.ndarray, num_top_features: int = 6) -> dict:
        """
        Computes multi-model attributions (SHAP, TabNet attention, LIME) for a single instance.
        """
        if X_sample.ndim == 1:
            X_sample = X_sample.reshape(1, -1)
            
        # Model predictions
        p_xgb = float(self.xgb_model.predict_proba(X_sample)[0, 1])
        p_tab = float(self.tabnet_model.predict_proba(X_sample)[0, 1])
        
        dec_xgb = "THREAT" if p_xgb >= 0.50 else "BENIGN"
        dec_tab = "THREAT" if p_tab >= 0.50 else "BENIGN"
        
        # 1. SHAP Feature Attribution (TreeExplainer)
        shap_vals = self.tree_explainer.shap_values(X_sample)[0]
        base_val = float(self.tree_explainer.expected_value)
        
        shap_ranking = np.argsort(np.abs(shap_vals))[::-1]
        shap_attributions = []
        for rank, idx in enumerate(shap_ranking[:num_top_features], start=1):
            fname = self.feature_names[idx]
            val = float(X_sample[0, idx])
            s_val = float(shap_vals[idx])
            direction = "Positive (Increases Threat Attribution)" if s_val > 0 else "Negative (Supports Benign Attribution)"
            
            shap_attributions.append({
                "ranking": rank,
                "feature": fname,
                "feature_value": val,
                "contribution": round(s_val, 4),
                "direction": direction,
                "description": FEATURE_DESCRIPTIONS.get(fname, "CloudTrail behavioral telemetry signal"),
            })
            
        # 2. TabNet Sequential Attention Attribution
        M_explain, masks = self.tabnet_model.explain(X_sample)
        tab_weights = M_explain[0]
        # Normalize weights
        sum_weights = np.sum(tab_weights)
        if sum_weights > 0:
            tab_norm_weights = tab_weights / sum_weights
        else:
            tab_norm_weights = tab_weights
            
        tab_ranking = np.argsort(tab_norm_weights)[::-1]
        tabnet_attributions = []
        for rank, idx in enumerate(tab_ranking[:num_top_features], start=1):
            fname = self.feature_names[idx]
            val = float(X_sample[0, idx])
            w_val = float(tab_norm_weights[idx])
            direction = "Attentive Focus (Active Step Saliency)"
            tabnet_attributions.append({
                "ranking": rank,
                "feature": fname,
                "feature_value": val,
                "contribution": round(w_val, 4),
                "direction": direction,
                "description": FEATURE_DESCRIPTIONS.get(fname, "CloudTrail behavioral telemetry signal"),
            })
            
        # 3. LIME Perturbation-Based Surrogate Explanation
        lime_exp = self.lime_explainer.explain_instance(
            data_row=X_sample[0],
            predict_fn=self.xgb_model.predict_proba,
            num_features=num_top_features,
        )
        lime_attributions = []
        for rank, (rule, weight) in enumerate(lime_exp.as_list(), start=1):
            direction = "Positive (Surrogate Threat Attribution)" if weight > 0 else "Negative (Surrogate Benign Attribution)"
            lime_attributions.append({
                "ranking": rank,
                "feature_rule": rule,
                "contribution": round(weight, 4),
                "direction": direction,
            })
            
        return {
            "xgboost_inference": {
                "decision": dec_xgb,
                "threat_probability": round(p_xgb, 4),
                "base_expected_value": round(base_val, 4),
                "shap_attributions": shap_attributions,
            },
            "tabnet_inference": {
                "decision": dec_tab,
                "threat_probability": round(p_tab, 4),
                "tabnet_attributions": tabnet_attributions,
            },
            "lime_perturbation_surrogate": {
                "lime_attributions": lime_attributions,
            },
        }

    def generate_global_shap_plot(self):
        """Generates global mean absolute SHAP feature importance plot across test set."""
        print("[*] Generating Global SHAP Feature Importance Plot...")
        shap_matrix = self.tree_explainer.shap_values(self.X_test)
        mean_abs_shap = np.mean(np.abs(shap_matrix), axis=0)
        
        idx_sorted = np.argsort(mean_abs_shap)
        plt.figure(figsize=(9, 6))
        plt.barh(range(len(self.feature_names)), mean_abs_shap[idx_sorted], color="#2563eb", align="center")
        plt.yticks(range(len(self.feature_names)), [self.feature_names[i] for i in idx_sorted])
        plt.xlabel("Mean |SHAP Value| (Average Model Impact)")
        plt.title("Global SHAP Feature Attribution (XGBoost V3)")
        plt.grid(True, alpha=0.3)
        plt.tight_layout()
        
        out_path = os.path.join(PLOTS_V3_DIR, "shap_global_importance_v3.png")
        plt.savefig(out_path, dpi=200)
        plt.close()
        print(f"  [+] Saved: {out_path}")
        return out_path

    def plot_local_shap_attribution(self, explanation: dict, title: str, filename: str):
        """Plots local horizontal bar chart of feature contributions for an instance."""
        shap_items = explanation["xgboost_inference"]["shap_attributions"]
        features = [item["feature"] for item in shap_items][::-1]
        values = [item["contribution"] for item in shap_items][::-1]
        colors = ["#ef4444" if v > 0 else "#10b981" for v in values]
        
        plt.figure(figsize=(8, 4.5))
        plt.barh(features, values, color=colors, align="center")
        plt.axvline(0, color="gray", linestyle="--", lw=0.8)
        plt.xlabel("SHAP Feature Attribution (Contribution to Log-Odds)")
        plt.title(f"Local Model Attribution: {title}")
        plt.grid(True, alpha=0.3)
        plt.tight_layout()
        
        out_path = os.path.join(PLOTS_V3_DIR, filename)
        plt.savefig(out_path, dpi=200)
        plt.close()
        return out_path

def run_explainability_suite():
    print("=" * 82)
    print("      STAGE 8: EXPLAINABILITY SUITE (SHAP + LIME + TABNET V3)")
    print("=" * 82)
    
    explainer = V3SecurityExplainer()
    test_df = explainer.test_df.copy()
    X_test = explainer.X_test
    y_test = explainer.y_test
    
    # Pre-calculate predictions
    xgb_probs = explainer.xgb_model.predict_proba(X_test)[:, 1]
    xgb_preds = (xgb_probs >= 0.50).astype(int)
    
    # 1. Global SHAP
    explainer.generate_global_shap_plot()
    
    # 2. Select instances for targeted explanations
    # Find indices for True Benign (TN), True Threat (TP), False Positive (FP), False Negative (FN)
    tn_idx = np.where((y_test == 0) & (xgb_preds == 0))[0][0]
    tp_idx = np.where((y_test == 1) & (xgb_preds == 1))[0][0]
    
    fp_indices = np.where((y_test == 0) & (xgb_preds == 1))[0]
    fp_idx = fp_indices[0] if len(fp_indices) > 0 else None
    
    fn_indices = np.where((y_test == 1) & (xgb_preds == 0))[0]
    fn_idx = fn_indices[0] if len(fn_indices) > 0 else None
    
    explanation_suite = {}
    
    # Helper to explain and print an instance
    def process_case(case_name: str, idx: int, plot_filename: str):
        row = test_df.iloc[idx]
        X_inst = X_test[idx]
        exp = explainer.explain_instance(X_inst)
        
        print(f"\n" + "-" * 78)
        print(f"CASE: {case_name}")
        print(f"Event: {row.get('event_name')} | Source: {row.get('event_source')} | Identity: {row.get('user_name', row.get('identity_session_id'))}")
        print(f"Ground Truth: {'Threat (1)' if row.get('is_threat')==1 else 'Benign (0)'} | XGBoost Probability: {exp['xgboost_inference']['threat_probability']:.4f} | TabNet Probability: {exp['tabnet_inference']['threat_probability']:.4f}")
        print("-" * 78)
        
        # Display table of SHAP attributions
        rows = []
        for a in exp["xgboost_inference"]["shap_attributions"]:
            rows.append([a["ranking"], a["feature"], a["feature_value"], f"{a['contribution']:+.4f}", a["direction"]])
        print(tabulate(rows, headers=["Rank", "Feature", "Value", "SHAP Contribution", "Direction"], tablefmt="grid"))
        
        explainer.plot_local_shap_attribution(exp, case_name, plot_filename)
        
        explanation_suite[case_name] = {
            "metadata": {
                "event_name": str(row.get("event_name")),
                "event_source": str(row.get("event_source")),
                "identity": str(row.get("user_name", row.get("identity_session_id"))),
                "ground_truth": int(row.get("is_threat")),
                "data_source": str(row.get("data_source")),
                "attack_type": str(row.get("attack_type")),
            },
            "explanation": exp,
            "plot_saved": os.path.join(PLOTS_V3_DIR, plot_filename),
        }
        
    process_case("1. True Benign (Normal Baseline)", tn_idx, "shap_local_true_benign.png")
    process_case("2. True Threat (Confirmed Intrusion)", tp_idx, "shap_local_true_threat.png")
    if fp_idx is not None:
        process_case("3. False Positive (Benign Flagged as Threat)", fp_idx, "shap_local_false_positive.png")
    if fn_idx is not None:
        process_case("4. False Negative (Stealth Threat Missed)", fn_idx, "shap_local_false_negative.png")
        
    # 3. One example for each major attack type
    print("\n" + "=" * 82)
    print("         EXPLANATIONS FOR EACH MAJOR IAM PRIVILEGE ESCALATION TYPE")
    print("=" * 82)
    
    major_attacks = [
        ("privilege_escalation_user_policy", "shap_attack_user_policy.png"),
        ("inline_policy_injection", "shap_attack_inline_user_policy.png"),
        ("privilege_escalation_role_policy", "shap_attack_role_policy.png"),
        ("role_inline_policy_backdoor", "shap_attack_role_inline.png"),
        ("rogue_credential_creation", "shap_attack_create_key.png"),
        ("credential_activation_abuse", "shap_attack_update_key.png"),
        ("unauthorized_role_assumption", "shap_attack_assume_role.png"),
        ("pass_role_privilege_escalation", "shap_attack_pass_role.png"),
    ]
    
    for att_type, plot_name in major_attacks:
        sub_indices = np.where((test_df["attack_type"] == att_type) & (y_test == 1))[0]
        if len(sub_indices) > 0:
            target_idx = sub_indices[0]
            process_case(f"Attack Scenario: {att_type}", target_idx, plot_name)

    # 4. Save Explanations JSON
    with open(EXPLANATIONS_V3_JSON, "w") as f:
        json.dump(explanation_suite, f, indent=2)
    print(f"\n[+] Full V3 Explanation Suite Saved to: {EXPLANATIONS_V3_JSON}")
    print("=" * 82 + "\n")
    return explanation_suite

if __name__ == "__main__":
    run_explainability_suite()
