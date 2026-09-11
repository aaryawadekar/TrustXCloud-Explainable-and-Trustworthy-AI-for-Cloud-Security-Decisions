"""
Explainability Layer: SHAP TreeExplainer and LIME Tabular Explainer.

Provides:
- Exact Shapley values via TreeExplainer for XGBoost.
- Local linear surrogate cross-check via LIME.
- Global feature importance aggregation across test data.
"""

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np
import pandas as pd
import shap
import lime
import lime.lime_tabular
import xgboost as xgb

from src.config import (
    XGBOOST_MODEL_PATH,
    TRAIN_CSV,
    TEST_CSV,
    PIPELINE_PATH,
    FEATURE_COLUMNS,
    FEATURE_DESCRIPTIONS,
)
from src.feature_pipeline import CloudTrailFeaturePipeline

class CloudSecurityExplainer:
    def __init__(self):
        if not os.path.exists(XGBOOST_MODEL_PATH):
            raise FileNotFoundError(f"Model not found at {XGBOOST_MODEL_PATH}. Run src/train.py first.")
            
        self.model = xgb.XGBClassifier()
        self.model.load_model(XGBOOST_MODEL_PATH)
        
        self.pipeline = CloudTrailFeaturePipeline.load(PIPELINE_PATH)
        self.feature_names = FEATURE_COLUMNS
        
        # Load training and test background data
        train_df = pd.read_csv(TRAIN_CSV)
        self.X_train = self.pipeline.transform(train_df).values.astype(np.float32)
        
        test_df = pd.read_csv(TEST_CSV)
        self.X_test = self.pipeline.transform(test_df).values.astype(np.float32)
        self.y_test = test_df["is_threat"].values
        
        # Initialize SHAP TreeExplainer
        print("[*] Initializing SHAP TreeExplainer...")
        self.tree_explainer = shap.TreeExplainer(self.model)
        
        # Initialize LIME Tabular Explainer
        print("[*] Initializing LIME TabularExplainer...")
        self.lime_explainer = lime.lime_tabular.LimeTabularExplainer(
            training_data=self.X_train,
            feature_names=self.feature_names,
            class_names=["Benign", "Threat"],
            mode="classification",
            random_state=42,
        )

    def explain_instance(self, X_sample: np.ndarray, num_top_features: int = 5) -> dict:
        """
        Computes SHAP and LIME explanations for a single 1D feature vector.
        """
        if X_sample.ndim == 1:
            X_sample = X_sample.reshape(1, -1)
            
        # 1. Model inference
        prob_threat = float(self.model.predict_proba(X_sample)[0, 1])
        decision = "THREAT" if prob_threat >= 0.50 else "BENIGN"
        confidence = prob_threat if decision == "THREAT" else (1.0 - prob_threat)
        
        # 2. SHAP exact TreeExplainer attribution
        shap_values = self.tree_explainer.shap_values(X_sample)[0]
        base_value = float(self.tree_explainer.expected_value)
        
        # Rank features by absolute SHAP magnitude
        indices = np.argsort(np.abs(shap_values))[::-1]
        shap_top = []
        for idx in indices[:num_top_features]:
            feat_name = self.feature_names[idx]
            val = float(X_sample[0, idx])
            s_val = float(shap_values[idx])
            impact = "Increases Threat Risk" if s_val > 0 else "Supports Benign Decision"
            desc = FEATURE_DESCRIPTIONS.get(feat_name, "CloudTrail contextual signal")
            
            shap_top.append({
                "feature": feat_name,
                "value": val,
                "shap_value": round(s_val, 4),
                "impact": impact,
                "description": desc,
            })
            
        # 3. LIME surrogate cross-check
        lime_exp = self.lime_explainer.explain_instance(
            data_row=X_sample[0],
            predict_fn=self.model.predict_proba,
            num_features=num_top_features,
        )
        lime_list = []
        for rule, weight in lime_exp.as_list():
            lime_list.append({
                "rule": rule,
                "weight": round(weight, 4),
                "direction": "Pro-Threat" if weight > 0 else "Pro-Benign"
            })
            
        return {
            "decision": decision,
            "confidence": round(confidence, 4),
            "threat_probability": round(prob_threat, 4),
            "base_value": round(base_value, 4),
            "shap_top_features": shap_top,
            "lime_explanation": lime_list,
            "raw_shap_values": shap_values.tolist(),
        }

    def get_global_importance(self) -> pd.DataFrame:
        """
        Computes mean absolute SHAP values across test dataset.
        """
        shap_matrix = self.tree_explainer.shap_values(self.X_test)
        mean_abs_shap = np.mean(np.abs(shap_matrix), axis=0)
        
        importance_df = pd.DataFrame({
            "feature": self.feature_names,
            "mean_abs_shap": mean_abs_shap,
            "description": [FEATURE_DESCRIPTIONS.get(f, "") for f in self.feature_names]
        }).sort_values(by="mean_abs_shap", ascending=False).reset_index(drop=True)
        
        return importance_df
