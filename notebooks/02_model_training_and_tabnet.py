"""
Notebook 2: Model Training & Deep Learning Comparison (XGBoost vs TabNet).
Trains both models, logs metrics, and demonstrates model inference.
"""

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.train import train_and_evaluate

def main():
    print("[*] Running Notebook 2: Model Training & Benchmark...")
    metrics = train_and_evaluate()
    print("[+] Model benchmarking complete.")

if __name__ == "__main__":
    main()
