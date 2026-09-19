"""
FastAPI Backend Bridge for TrustXCloud V3 Research Prototype.
Connects the Next.js Frontend Dashboard to the Python XAI & ML Inference Engine.

Usage:
    uvicorn api:app --host 0.0.0.0 --port 8000 --reload
"""

import os
import sys
import json
from typing import Dict, Any, Optional
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

app = FastAPI(
    title="TrustXCloud V3 API Bridge",
    description="REST API bridging the Next.js SOC Panel UI to the V3 dual ML & multi-level XAI pipeline.",
    version="3.0.0",
)

# Enable CORS for Next.js frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Lazy initialization of analyzer
analyzer = None

def get_analyzer():
    global analyzer
    if analyzer is None:
        try:
            from src.predict_and_explain import CloudSecurityAnalyzer
            analyzer = CloudSecurityAnalyzer()
        except Exception as e:
            print(f"[!] Error initializing CloudSecurityAnalyzer: {e}")
    return analyzer


@app.get("/health")
def health_check():
    return {
        "status": "online",
        "service": "TrustXCloud API Bridge",
        "model_version": "v3.0",
        "models": ["xgboost_v3", "tabnet_v3"],
        "explainers": ["shap_tree_explainer", "lime_surrogate", "llm_faithfulness_audit"],
    }


@app.get("/api/v1/metrics")
def get_metrics():
    """Serves real evaluation metrics from models/final_metrics_v3.json and xai_metrics_v3.json."""
    metrics_path = os.path.join(os.path.dirname(__file__), "models", "final_metrics_v3.json")
    xai_path = os.path.join(os.path.dirname(__file__), "models", "xai_metrics_v3.json")
    
    result = {}
    if os.path.exists(metrics_path):
        with open(metrics_path, "r") as f:
            result["model_metrics"] = json.load(f)
    if os.path.exists(xai_path):
        with open(xai_path, "r") as f:
            result["xai_metrics"] = json.load(f)
            
    return result


@app.get("/api/v1/scenarios")
def get_scenarios():
    """Returns the 5 canonical evaluation scenarios from run_demo.py."""
    try:
        import run_demo
        scenarios = getattr(run_demo, "SCENARIOS", [])
        return {"scenarios": scenarios}
    except Exception as e:
        return {"error": str(e)}


class EventPayload(BaseModel):
    event: Dict[str, Any]


@app.post("/api/v1/analyze")
def analyze_cloudtrail_event(payload: EventPayload):
    """
    Analyzes an incoming AWS CloudTrail event through the full V3 pipeline:
    Baseline -> V3 Features -> XGBoost + TabNet -> SHAP + LIME -> Narrative -> Faithfulness
    """
    engine = get_analyzer()
    if engine is None:
        raise HTTPException(
            status_code=503,
            detail="CloudSecurityAnalyzer engine is not available in current environment.",
        )
    
    try:
        analysis = engine.analyze_event(payload.event)
        return analysis
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api:app", host="0.0.0.0", port="8000", reload=True)
