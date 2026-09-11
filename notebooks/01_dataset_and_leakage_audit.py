"""
Notebook 1: Dataset Profiling & Zero Label Leakage Verification.
Explores the generated CloudTrail corpus, plots class distributions,
and runs the statistical leakage audit.
"""

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

from src.config import DATASET_CSV
from data.verify_no_leakage import PRIVILEGE_EVENTS
from data.verify_no_leakage import run_leakage_audit

def main():
    print("[*] Running Notebook 1: Dataset Profiling & Zero Leakage Audit...")
    df = pd.read_csv(DATASET_CSV)
    
    print("\n--- Dataset Head (First 5 records) ---")
    print(df[["event_time", "identity_arn", "event_name", "aws_region", "call_frequency_10m", "is_threat"]].head())
    
    print("\n--- Class Distribution ---")
    print(df["is_threat"].value_counts(normalize=True).rename({0: "Benign", 1: "Threat"}))
    
    print("\n--- Running Rigorous Leakage Audit ---")
    run_leakage_audit()
    print("[+] Notebook 1 complete.")

if __name__ == "__main__":
    main()

