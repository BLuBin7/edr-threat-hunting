#!/usr/bin/env python3
"""
Train Isolation Forest model for anomaly detection on EDR telemetry data
"""

import argparse
import os
import pickle
from datetime import datetime

import mlflow
import mlflow.sklearn
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from sklearn.model_selection import train_test_split
import matplotlib.pyplot as plt
import seaborn as sns


def generate_synthetic_data(n_normal=5000, n_anomaly=500):
    """
    Generate synthetic EDR telemetry data for training
    In production, this would come from real telemetry stored in DVC

    Features (15 total):
    0-2: Process features (lineage depth, rare parent-child, privilege escalation)
    3-5: Commandline features (length, entropy, encoded)
    6-8: File activity (modifications, sensitive access, mass activity rate)
    9-11: Network activity (connections, suspicious DNS, beaconing)
    12-14: Persistence (has mechanism, cron count, service count)
    """

    print(f"Generating synthetic training data: {n_normal} normal + {n_anomaly} anomaly samples...")

    # Normal behavior
    normal_data = []
    for _ in range(n_normal):
        sample = [
            np.random.randint(1, 4),        # 0: lineage depth (1-3)
            0.0,                             # 1: rare parent-child (false)
            0.0,                             # 2: privilege escalation (false)
            np.random.randint(10, 200),     # 3: cmdline length (short)
            np.random.uniform(2.0, 4.0),    # 4: cmdline entropy (low)
            0.0,                             # 5: encoded cmd (false)
            np.random.randint(0, 5),        # 6: file modifications (few)
            0.0,                             # 7: sensitive file access (none)
            np.random.uniform(0, 10),       # 8: mass file activity rate (low)
            np.random.randint(0, 3),        # 9: network connections (few)
            0.0,                             # 10: suspicious DNS (false)
            np.random.uniform(0, 0.3),      # 11: beaconing score (low)
            0.0,                             # 12: persistence mechanism (false)
            0.0,                             # 13: cron count (none)
            0.0,                             # 14: service count (none)
        ]
        normal_data.append(sample)

    # Anomalous behavior (attack patterns)
    anomaly_data = []
    for _ in range(n_anomaly):
        attack_type = np.random.choice(['encoded_powershell', 'credential_dump', 'beaconing', 'ransomware'])

        if attack_type == 'encoded_powershell':
            sample = [
                np.random.randint(3, 6),        # Deep lineage
                1.0,                             # Rare parent-child
                np.random.choice([0.0, 1.0]),   # Maybe privilege escalation
                np.random.randint(500, 2000),   # Long cmdline
                np.random.uniform(5.0, 7.0),    # High entropy
                1.0,                             # Encoded cmd
                np.random.randint(0, 5),
                0.0,
                np.random.uniform(0, 10),
                np.random.randint(1, 5),        # Some network
                np.random.choice([0.0, 1.0]),
                np.random.uniform(0, 0.5),
                0.0,
                0.0,
                0.0,
            ]
        elif attack_type == 'credential_dump':
            sample = [
                np.random.randint(2, 5),
                1.0,
                1.0,                             # Privilege escalation
                np.random.randint(100, 500),
                np.random.uniform(3.0, 5.0),
                0.0,
                np.random.randint(0, 3),
                np.random.randint(3, 10),       # Sensitive file access
                np.random.uniform(0, 5),
                np.random.randint(0, 2),
                0.0,
                0.0,
                0.0,
                0.0,
                0.0,
            ]
        elif attack_type == 'beaconing':
            sample = [
                np.random.randint(2, 4),
                np.random.choice([0.0, 1.0]),
                0.0,
                np.random.randint(50, 300),
                np.random.uniform(3.0, 5.0),
                0.0,
                np.random.randint(0, 3),
                0.0,
                np.random.uniform(0, 5),
                np.random.randint(10, 50),      # Many connections
                1.0,                             # Suspicious DNS
                np.random.uniform(0.8, 1.0),    # High beaconing score
                np.random.choice([0.0, 1.0]),
                0.0,
                0.0,
            ]
        else:  # ransomware
            sample = [
                np.random.randint(2, 4),
                np.random.choice([0.0, 1.0]),
                0.0,
                np.random.randint(100, 400),
                np.random.uniform(3.5, 5.5),
                0.0,
                np.random.randint(100, 500),    # Many file mods
                np.random.randint(0, 5),
                np.random.uniform(200, 500),    # High mass activity
                np.random.randint(1, 5),
                0.0,
                0.0,
                0.0,
                0.0,
                0.0,
            ]

        anomaly_data.append(sample)

    # Combine and create labels
    X = np.array(normal_data + anomaly_data, dtype=np.float32)
    y = np.array([1] * n_normal + [-1] * n_anomaly)  # 1=normal, -1=anomaly

    # Shuffle
    indices = np.random.permutation(len(X))
    X = X[indices]
    y = y[indices]

    return X, y


def train_model(X_train, contamination=0.1):
    """Train Isolation Forest model"""

    print(f"\nTraining Isolation Forest (contamination={contamination})...")

    model = IsolationForest(
        n_estimators=100,
        max_samples='auto',
        contamination=contamination,
        random_state=42,
        n_jobs=-1
    )

    model.fit(X_train)

    print("Training completed!")
    return model


def evaluate_model(model, X_test, y_test):
    """Evaluate model performance"""

    print("\nEvaluating model...")

    # Predict
    y_pred = model.predict(X_test)

    # Decision scores (lower = more anomalous)
    scores = model.decision_function(X_test)

    # Convert to binary (1=normal, 0=anomaly)
    y_test_binary = (y_test == 1).astype(int)
    y_pred_binary = (y_pred == 1).astype(int)

    # Metrics
    print("\nClassification Report:")
    print(classification_report(y_test_binary, y_pred_binary, target_names=['Anomaly', 'Normal']))

    print("\nConfusion Matrix:")
    cm = confusion_matrix(y_test_binary, y_pred_binary)
    print(cm)

    # ROC AUC
    try:
        roc_auc = roc_auc_score(y_test_binary, -scores)  # Negative scores for anomaly
        print(f"\nROC AUC Score: {roc_auc:.4f}")
    except:
        roc_auc = 0.0

    # Calculate metrics
    tn, fp, fn, tp = cm.ravel()
    accuracy = (tp + tn) / (tp + tn + fp + fn)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

    metrics = {
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1_score': f1,
        'roc_auc': roc_auc,
        'true_positives': int(tp),
        'false_positives': int(fp),
        'true_negatives': int(tn),
        'false_negatives': int(fn),
    }

    return metrics, y_pred, scores


def plot_results(scores, y_test, output_dir):
    """Generate visualization plots"""

    print("\nGenerating plots...")

    os.makedirs(output_dir, exist_ok=True)

    # Anomaly score distribution
    plt.figure(figsize=(10, 6))

    normal_scores = scores[y_test == 1]
    anomaly_scores = scores[y_test == -1]

    plt.hist(normal_scores, bins=50, alpha=0.5, label='Normal', color='blue')
    plt.hist(anomaly_scores, bins=50, alpha=0.5, label='Anomaly', color='red')
    plt.xlabel('Anomaly Score')
    plt.ylabel('Frequency')
    plt.title('Anomaly Score Distribution')
    plt.legend()
    plt.grid(True, alpha=0.3)

    plot_path = os.path.join(output_dir, 'anomaly_score_distribution.png')
    plt.savefig(plot_path, dpi=150, bbox_inches='tight')
    plt.close()

    print(f"Plot saved: {plot_path}")


def main():
    parser = argparse.ArgumentParser(description='Train Isolation Forest for EDR threat detection')
    parser.add_argument('--output-dir', type=str, default='../models', help='Output directory for models')
    parser.add_argument('--n-normal', type=int, default=5000, help='Number of normal samples')
    parser.add_argument('--n-anomaly', type=int, default=500, help='Number of anomaly samples')
    parser.add_argument('--contamination', type=float, default=0.1, help='Contamination parameter')
    parser.add_argument('--mlflow-tracking-uri', type=str, default='http://localhost:5000', help='MLflow tracking URI')

    args = parser.parse_args()

    # Setup MLflow
    mlflow.set_tracking_uri(args.mlflow_tracking_uri)
    mlflow.set_experiment("edr-threat-hunting")

    with mlflow.start_run():
        # Log parameters
        mlflow.log_param("n_normal", args.n_normal)
        mlflow.log_param("n_anomaly", args.n_anomaly)
        mlflow.log_param("contamination", args.contamination)
        mlflow.log_param("n_estimators", 100)

        # Generate data
        X, y = generate_synthetic_data(args.n_normal, args.n_anomaly)

        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )

        print(f"\nDataset split:")
        print(f"  Train: {len(X_train)} samples")
        print(f"  Test:  {len(X_test)} samples")

        # Train model
        model = train_model(X_train, contamination=args.contamination)

        # Evaluate
        metrics, y_pred, scores = evaluate_model(model, X_test, y_test)

        # Log metrics to MLflow
        for key, value in metrics.items():
            mlflow.log_metric(key, value)

        # Plot results
        plot_results(scores, y_test, args.output_dir)
        mlflow.log_artifact(os.path.join(args.output_dir, 'anomaly_score_distribution.png'))

        # Save model
        os.makedirs(args.output_dir, exist_ok=True)
        model_path = os.path.join(args.output_dir, 'isolation_forest.pkl')

        with open(model_path, 'wb') as f:
            pickle.dump(model, f)

        print(f"\nModel saved: {model_path}")

        # Log model to MLflow
        mlflow.sklearn.log_model(model, "model")

        print(f"\n✅ Training completed successfully!")
        print(f"   F1 Score: {metrics['f1_score']:.4f}")
        print(f"   ROC AUC:  {metrics['roc_auc']:.4f}")


if __name__ == '__main__':
    main()
