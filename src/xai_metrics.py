"""
Quantitative Explainability Evaluation: Faithfulness and Stability (V3).

Implements real XAI evaluation metrics using V3 models:
1. Faithfulness: Feature ablation test measuring model output delta (Delta P)
   when perturbing top-SHAP features vs. random features.
2. Stability: Input perturbation test measuring Spearman rank correlation
   and Top-k Jaccard similarity of SHAP attributions under controlled noise.

Model Version: v3.0
"""

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
import numpy as np
import pandas as pd
from scipy.stats import spearmanr
from tabulate import tabulate

import shap
import xgboost as xgb

from src.config import (
    XGBOOST_V3_PATH,
    PIPELINE_V3_PATH,
    FEATURE_NAMES_V3_PATH,
    SPLITS_DIR,
    SEED,
)
from src.feature_pipeline import CloudTrailFeaturePipeline


class V3XAIEvaluator:
    """Loads V3 XGBoost and SHAP for quantitative XAI evaluation."""

    def __init__(self):
        print("[*] Initializing V3 XAI Evaluator...")

        self.pipeline = CloudTrailFeaturePipeline.load(PIPELINE_V3_PATH)

        self.model = xgb.XGBClassifier()
        self.model.load_model(XGBOOST_V3_PATH)

        with open(FEATURE_NAMES_V3_PATH, "r") as f:
            self.feature_names = json.load(f)

        # Load V3 training/test splits
        train_path = os.path.join(SPLITS_DIR, "random_train.csv")
        test_path = os.path.join(SPLITS_DIR, "random_test.csv")

        train_df = pd.read_csv(train_path)
        self.X_train = self.pipeline.transform(train_df).values.astype(np.float32)

        test_df = pd.read_csv(test_path)
        self.X_test = self.pipeline.transform(test_df).values.astype(np.float32)
        self.y_test = test_df["is_threat"].values.astype(int)

        self.tree_explainer = shap.TreeExplainer(self.model)
        print("[+] V3 XAI Evaluator initialized.\n")


def evaluate_faithfulness(evaluator: V3XAIEvaluator, num_samples: int = 250):
    """
    Evaluates explanation Faithfulness via Feature Ablation:
    Does removing/masking top SHAP features degrade model probability significantly
    more than removing random features?
    """
    print(f"[*] Evaluating Explanation Faithfulness across {num_samples} test samples...")
    X_test = evaluator.X_test[:num_samples]
    background_median = np.median(evaluator.X_train, axis=0)

    delta_p_top1 = []
    delta_p_top3 = []
    delta_p_random = []

    num_features = X_test.shape[1]

    for i in range(num_samples):
        x = X_test[i:i+1]
        base_prob = evaluator.model.predict_proba(x)[0, 1]
        shap_vals = evaluator.tree_explainer.shap_values(x)[0]

        # Rank features by absolute SHAP attribution
        ranked_indices = np.argsort(np.abs(shap_vals))[::-1]
        top1_idx = ranked_indices[0]
        top3_indices = ranked_indices[:3]

        # 1. Ablate Top-1 feature
        x_ablate_top1 = x.copy()
        x_ablate_top1[0, top1_idx] = background_median[top1_idx]
        prob_top1 = evaluator.model.predict_proba(x_ablate_top1)[0, 1]
        delta_p_top1.append(abs(base_prob - prob_top1))

        # 2. Ablate Top-3 features
        x_ablate_top3 = x.copy()
        for idx in top3_indices:
            x_ablate_top3[0, idx] = background_median[idx]
        prob_top3 = evaluator.model.predict_proba(x_ablate_top3)[0, 1]
        delta_p_top3.append(abs(base_prob - prob_top3))

        # 3. Ablate Random 3 features (Control Baseline)
        non_top_indices = [idx for idx in range(num_features) if idx not in top3_indices]
        np.random.seed(42)
        random_indices = np.random.choice(non_top_indices, size=min(3, len(non_top_indices)), replace=False)
        x_ablate_rand = x.copy()
        for idx in random_indices:
            x_ablate_rand[0, idx] = background_median[idx]
        prob_rand = evaluator.model.predict_proba(x_ablate_rand)[0, 1]
        delta_p_random.append(abs(base_prob - prob_rand))

    avg_delta_top1 = float(np.mean(delta_p_top1))
    avg_delta_top3 = float(np.mean(delta_p_top3))
    avg_delta_random = float(np.mean(delta_p_random))
    faithfulness_ratio = avg_delta_top3 / (avg_delta_random + 1e-6)

    return {
        "avg_delta_p_top1": round(avg_delta_top1, 4),
        "avg_delta_p_top3": round(avg_delta_top3, 4),
        "avg_delta_p_random": round(avg_delta_random, 4),
        "faithfulness_ratio": round(faithfulness_ratio, 2),
    }

def evaluate_stability(evaluator: V3XAIEvaluator, num_samples: int = 150, noise_std: float = 0.05):
    """
    Evaluates Explanation Stability under small input perturbations:
    Are SHAP attributions robust and consistent when small noise is added?
    Computes:
    - Spearman Rank Correlation of feature importance ranks.
    - Top-3 Jaccard Similarity (set overlap of top-3 features).
    """
    print(f"[*] Evaluating Explanation Stability across {num_samples} test samples (noise std={noise_std})...")
    X_test = evaluator.X_test[:num_samples]
    feature_stds = np.std(evaluator.X_train, axis=0) + 1e-4

    rank_correlations = []
    jaccard_scores = []

    for i in range(num_samples):
        x = X_test[i:i+1]
        shap_orig = evaluator.tree_explainer.shap_values(x)[0]

        # Apply slight perturbation to continuous/frequency features
        noise = np.random.normal(0, noise_std, size=x.shape) * feature_stds
        # Keep binary categorical features unchanged
        binary_mask = np.isin(np.arange(x.shape[1]), [5, 6, 8, 10, 11, 12, 13])
        noise[0, binary_mask] = 0.0

        x_perturbed = x + noise
        shap_perturbed = evaluator.tree_explainer.shap_values(x_perturbed)[0]

        # 1. Spearman Rank Correlation
        corr, _ = spearmanr(np.abs(shap_orig), np.abs(shap_perturbed))
        if not np.isnan(corr):
            rank_correlations.append(corr)

        # 2. Top-3 Jaccard Similarity
        top3_orig = set(np.argsort(np.abs(shap_orig))[-3:])
        top3_pert = set(np.argsort(np.abs(shap_perturbed))[-3:])
        jaccard = len(top3_orig.intersection(top3_pert)) / len(top3_orig.union(top3_pert))
        jaccard_scores.append(jaccard)

    avg_rank_corr = float(np.mean(rank_correlations))
    avg_jaccard = float(np.mean(jaccard_scores))

    return {
        "mean_spearman_rank_correlation": round(avg_rank_corr, 4),
        "mean_top3_jaccard_similarity": round(avg_jaccard, 4),
        "stability_status": "STABLE" if avg_rank_corr >= 0.85 else "MODERATE",
    }

def run_xai_metrics():
    print("=" * 78)
    print("       SCIENTIFIC XAI EVALUATION: FAITHFULNESS & STABILITY (V3)")
    print("=" * 78)

    evaluator = V3XAIEvaluator()

    # 1. Faithfulness
    f_res = evaluate_faithfulness(evaluator)

    # 2. Stability
    s_res = evaluate_stability(evaluator)

    print("\n" + "=" * 78)
    print("                     XAI EVALUATION RESULTS (V3)")
    print("=" * 78)

    table = [
        ["Metric Category", "Evaluation Metric", "Measured Value", "Study-Defined Benchmark", "Assessment"],
        ["Faithfulness", "Delta P (Ablating Top-1 SHAP)", f"{f_res['avg_delta_p_top1']:.4f}", "> 0.02", "---"],
        ["Faithfulness", "Delta P (Ablating Top-3 SHAP)", f"{f_res['avg_delta_p_top3']:.4f}", "> 0.05", "---"],
        ["Faithfulness", "Delta P (Ablating Random-3 Control)", f"{f_res['avg_delta_p_random']:.4f}", "< Delta Top-3", "Baseline"],
        ["Faithfulness", "Faithfulness Impact Ratio", f"{f_res['faithfulness_ratio']:.2f}x", "> 1.50x", "---"],
        ["Stability", "Spearman Rank Correlation", f"{s_res['mean_spearman_rank_correlation']:.4f}", "> 0.70", "---"],
        ["Stability", "Top-3 Jaccard Similarity", f"{s_res['mean_top3_jaccard_similarity']:.4f}", "> 0.50", "---"],
    ]

    # Compute assessments
    table[1][4] = "Passed" if f_res["avg_delta_p_top1"] > 0.02 else "Below Benchmark"
    table[2][4] = "Passed" if f_res["avg_delta_p_top3"] > 0.05 else "Below Benchmark"
    table[3][4] = "Passed" if f_res["avg_delta_p_random"] < f_res["avg_delta_p_top3"] else "Unexpected"
    table[4][4] = "High Faithfulness" if f_res["faithfulness_ratio"] > 1.5 else "Low Faithfulness"
    table[5][4] = s_res["stability_status"]
    table[6][4] = "High Rank Invariance" if s_res["mean_top3_jaccard_similarity"] > 0.50 else "Moderate"

    print(tabulate(table, headers="firstrow", tablefmt="grid"))

    print(f"\n[+] Interpretation (study-defined criteria, not universal thresholds):")
    print(f"  * Perturbing the top-3 SHAP features causes a {f_res['faithfulness_ratio']:.1f}x larger change in prediction than perturbing random features.")
    print(f"  * Spearman rank correlation of {s_res['mean_spearman_rank_correlation']:.2%} indicates {'strong' if s_res['mean_spearman_rank_correlation'] >= 0.85 else 'moderate'} explanation stability under input perturbations.\n")

    return {"faithfulness": f_res, "stability": s_res}

if __name__ == "__main__":
    run_xai_metrics()
