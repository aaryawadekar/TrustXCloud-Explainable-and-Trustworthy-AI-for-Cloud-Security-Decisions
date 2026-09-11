"""
Notebook 3: Explainability Benchmark (SHAP, LIME, Faithfulness, Stability & LLM Audit).
Evaluates explanation quality and demonstrates the LLM narration layer.
"""

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.explainers import CloudSecurityExplainer
from src.xai_metrics import run_xai_metrics
from src.predict_and_explain import CloudSecurityAnalyzer
from run_demo import SCENARIOS

def main():
    print("[*] Running Notebook 3: Explainability Benchmark...")
    explainer = CloudSecurityExplainer()
    
    print("\n--- Global SHAP Feature Importance ---")
    global_imp = explainer.get_global_importance()
    print(global_imp.to_string(index=False))
    
    print("\n--- Running Quantitative XAI Metrics ---")
    run_xai_metrics()
    
    print("\n--- Testing Single-Decision LLM Narration & Faithfulness Audit ---")
    analyzer = CloudSecurityAnalyzer()
    res = analyzer.analyze_event(SCENARIOS[1]["event"])
    analyzer.print_decision_report(res)
    print("[+] Notebook 3 complete.")

if __name__ == "__main__":
    main()
