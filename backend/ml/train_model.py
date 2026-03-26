"""
AEGIS Scanner — Model Training Script
Trains a Random Forest classifier on synthetic vulnerability data
and saves the trained model to disk.

Pipeline:
1. Generate (or load) synthetic training data
2. Split into train/test sets (80/20)
3. Train a Random Forest classifier
4. Evaluate accuracy, precision, recall, F1
5. Save the trained model + label encoder via joblib

Usage:
    python -m backend.ml.train_model

Output:
    backend/ml/model/risk_model.pkl        — trained Random Forest
    backend/ml/model/label_encoder.pkl     — label encoder (risk level ↔ int)
    backend/ml/model/training_metrics.json — accuracy, classification report
"""

import os
import json
import logging
import joblib
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import (
    classification_report,
    accuracy_score,
    confusion_matrix,
)

from backend.ml.synthetic_data import (
    generate_dataset,
    save_dataset,
    FEATURE_COLUMNS,
    LABEL_COLUMN,
    OUTPUT_FILE,
)
from backend.config import MODEL_PATH, RISK_LEVELS

logger = logging.getLogger(__name__)

# Output directory for model artifacts
MODEL_DIR = os.path.dirname(MODEL_PATH)
LABEL_ENCODER_PATH = os.path.join(MODEL_DIR, "label_encoder.pkl")
METRICS_PATH = os.path.join(MODEL_DIR, "training_metrics.json")


def train(num_samples=2000, seed=42, test_size=0.2):
    """
    Full training pipeline: generate data → train → evaluate → save.

    Args:
        num_samples: number of synthetic training samples
        seed: random seed for reproducibility
        test_size: fraction of data reserved for testing

    Returns:
        dict with training metrics
    """
    logger.info("=" * 60)
    logger.info("AEGIS Scanner — Model Training Pipeline")
    logger.info("=" * 60)

    # ------------------------------------------------------------------
    # Step 1: Generate synthetic data
    # ------------------------------------------------------------------
    logger.info("\nStep 1: Generating synthetic training data...")

    # Check if data already exists
    if os.path.exists(OUTPUT_FILE):
        logger.info(f"  Loading existing data from {OUTPUT_FILE}")
        df = pd.read_csv(OUTPUT_FILE)
    else:
        logger.info(f"  Generating {num_samples} new samples...")
        samples = generate_dataset(num_samples=num_samples, seed=seed)
        save_dataset(samples)
        df = pd.read_csv(OUTPUT_FILE)

    logger.info(f"  Dataset shape: {df.shape}")
    logger.info(f"  Label distribution:\n{df[LABEL_COLUMN].value_counts().to_string()}")

    # ------------------------------------------------------------------
    # Step 2: Prepare features and labels
    # ------------------------------------------------------------------
    logger.info("\nStep 2: Preparing features and labels...")

    X = df[FEATURE_COLUMNS].values
    y_raw = df[LABEL_COLUMN].values

    # Encode risk level labels as integers
    label_encoder = LabelEncoder()
    # Fit with the defined order so encoding is consistent
    label_encoder.fit(RISK_LEVELS)
    y = label_encoder.transform(y_raw)

    logger.info(f"  Features: {X.shape[1]} columns")
    logger.info(f"  Labels: {label_encoder.classes_.tolist()}")
    logger.info(f"  Encoding: {dict(zip(label_encoder.classes_, label_encoder.transform(label_encoder.classes_)))}")

    # ------------------------------------------------------------------
    # Step 3: Train/test split
    # ------------------------------------------------------------------
    logger.info(f"\nStep 3: Splitting data ({int((1-test_size)*100)}/{int(test_size*100)})...")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=test_size,
        random_state=seed,
        stratify=y,  # maintain class balance in both sets
    )

    logger.info(f"  Training set: {X_train.shape[0]} samples")
    logger.info(f"  Test set: {X_test.shape[0]} samples")

    # ------------------------------------------------------------------
    # Step 4: Train Random Forest
    # ------------------------------------------------------------------
    logger.info("\nStep 4: Training Random Forest classifier...")

    model = RandomForestClassifier(
        n_estimators=200,          # 200 trees in the forest
        max_depth=15,              # limit depth to prevent overfitting
        min_samples_split=5,       # minimum samples to split a node
        min_samples_leaf=2,        # minimum samples in a leaf
        class_weight="balanced",   # handle any class imbalance
        random_state=seed,
        n_jobs=-1,                 # use all CPU cores
    )

    model.fit(X_train, y_train)
    logger.info("  Model trained successfully.")

    # ------------------------------------------------------------------
    # Step 5: Evaluate
    # ------------------------------------------------------------------
    logger.info("\nStep 5: Evaluating model performance...")

    y_pred = model.predict(X_test)

    accuracy = accuracy_score(y_test, y_pred)
    report = classification_report(
        y_test, y_pred,
        target_names=label_encoder.classes_,
        output_dict=True,
    )
    report_text = classification_report(
        y_test, y_pred,
        target_names=label_encoder.classes_,
    )
    conf_matrix = confusion_matrix(y_test, y_pred)

    # Cross-validation for more robust accuracy estimate
    cv_scores = cross_val_score(model, X, y, cv=5, scoring="accuracy")

    logger.info(f"\n  Test Accuracy: {accuracy:.4f}")
    logger.info(f"  Cross-Val Accuracy: {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")
    logger.info(f"\n  Classification Report:\n{report_text}")
    logger.info(f"\n  Confusion Matrix:\n{conf_matrix}")

    # Feature importance
    importances = model.feature_importances_
    feature_ranking = sorted(
        zip(FEATURE_COLUMNS, importances),
        key=lambda x: x[1],
        reverse=True,
    )
    logger.info("\n  Top 10 Feature Importances:")
    for fname, imp in feature_ranking[:10]:
        logger.info(f"    {fname}: {imp:.4f}")

    # ------------------------------------------------------------------
    # Step 6: Save model artifacts
    # ------------------------------------------------------------------
    logger.info(f"\nStep 6: Saving model to {MODEL_DIR}/...")

    os.makedirs(MODEL_DIR, exist_ok=True)

    # Save trained model
    joblib.dump(model, MODEL_PATH)
    logger.info(f"  Saved model: {MODEL_PATH}")

    # Save label encoder
    joblib.dump(label_encoder, LABEL_ENCODER_PATH)
    logger.info(f"  Saved label encoder: {LABEL_ENCODER_PATH}")

    # Save metrics
    metrics = {
        "accuracy": round(accuracy, 4),
        "cross_val_accuracy_mean": round(cv_scores.mean(), 4),
        "cross_val_accuracy_std": round(cv_scores.std(), 4),
        "classification_report": report,
        "feature_importances": {
            name: round(float(imp), 4) for name, imp in feature_ranking
        },
        "confusion_matrix": conf_matrix.tolist(),
        "model_params": {
            "n_estimators": 200,
            "max_depth": 15,
            "min_samples_split": 5,
            "min_samples_leaf": 2,
            "class_weight": "balanced",
        },
        "training_samples": int(X_train.shape[0]),
        "test_samples": int(X_test.shape[0]),
        "num_features": int(X.shape[1]),
    }

    with open(METRICS_PATH, "w") as f:
        json.dump(metrics, f, indent=2)
    logger.info(f"  Saved metrics: {METRICS_PATH}")

    logger.info("\n" + "=" * 60)
    logger.info(f"Training complete! Accuracy: {accuracy:.4f}")
    logger.info("=" * 60)

    return metrics


# ------------------------------------------------------------------
# CLI entry point
# ------------------------------------------------------------------
if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",
    )
    metrics = train()

    print("\n--- Summary ---")
    print(f"Accuracy:   {metrics['accuracy']:.4f}")
    print(f"Cross-Val:  {metrics['cross_val_accuracy_mean']:.4f} "
          f"± {metrics['cross_val_accuracy_std']:.4f}")
    print(f"\nTop 5 features:")
    for name, imp in sorted(
        metrics["feature_importances"].items(),
        key=lambda x: x[1],
        reverse=True,
    )[:5]:
        print(f"  {name}: {imp:.4f}")