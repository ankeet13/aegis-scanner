# Author: Aayush — Risk Predictor Module
"""
AEGIS Scanner — Risk Predictor
Loads the trained Random Forest model and predicts an overall risk level
for a scanned application based on its findings.

This is the final step in the ML pipeline:
    Real scan findings
        → feature_extractor.extract_features()
            → feature_extractor.features_to_dataframe_row()
                → risk_predictor.predict()
                    → { risk_level: "High", confidence: 0.87, ... }

Usage:
    from backend.ml.risk_predictor import RiskPredictor

    predictor = RiskPredictor()
    result = predictor.predict(findings)
    # result = {
    #     "risk_level": "High",
    #     "confidence": 0.87,
    #     "probabilities": {"Safe": 0.01, "Low": 0.03, ...},
    #     "features_summary": { ... }
    # }
"""

import os
import logging
import joblib
import numpy as np

from backend.config import MODEL_PATH, RISK_LEVELS
from backend.ml.feature_extractor import (
    extract_features,
    features_to_dataframe_row,
    summarise_features,
    FEATURE_COLUMNS,
)

logger = logging.getLogger(__name__)

# Path to label encoder (saved alongside the model)
LABEL_ENCODER_PATH = os.path.join(os.path.dirname(MODEL_PATH), "label_encoder.pkl")
METRICS_PATH = os.path.join(os.path.dirname(MODEL_PATH), "training_metrics.json")


class RiskPredictor:
    """
    Loads a trained Random Forest model and predicts risk level
    from scan findings.

    The model and label encoder are loaded once at init time and
    reused for all predictions.
    """

    def __init__(self, model_path=None, encoder_path=None):
        self.model_path = model_path or MODEL_PATH
        self.encoder_path = encoder_path or LABEL_ENCODER_PATH
        self.model = None
        self.label_encoder = None
        self._loaded = False

        self._load_model()

    def _load_model(self):
        """Load the trained model and label encoder from disk."""
        if not os.path.exists(self.model_path):
            logger.warning(
                f"Model not found at {self.model_path}. "
                f"Run 'python -m backend.ml.train_model' first."
            )
            return

        if not os.path.exists(self.encoder_path):
            logger.warning(
                f"Label encoder not found at {self.encoder_path}. "
                f"Run 'python -m backend.ml.train_model' first."
            )
            return

        try:
            self.model = joblib.load(self.model_path)
            self.label_encoder = joblib.load(self.encoder_path)
            self._loaded = True
            logger.info(
                f"Risk predictor loaded: model={self.model_path}, "
                f"classes={self.label_encoder.classes_.tolist()}"
            )
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            self._loaded = False

    def predict(self, findings):
        """
        Predict overall risk level from a list of scan findings.

        Args:
            findings: list of Finding dicts (from Finding.to_dict())
                      across all four scanners

        Returns:
            dict with:
                risk_level: str ("Safe", "Low", "Medium", "High", "Critical")
                confidence: float (0.0–1.0, probability of predicted class)
                probabilities: dict mapping each risk level to its probability
                features_summary: dict with human-readable feature breakdown
                features_raw: dict with raw feature values
        """
        # Step 1: Extract features from findings
        features = extract_features(findings)

        # Step 2: If model isn't loaded, fall back to rule-based prediction
        if not self._loaded:
            logger.warning("Model not loaded — using rule-based fallback.")
            return self._rule_based_prediction(features, findings)

        # Step 3: Convert to DataFrame row for sklearn
        X = features_to_dataframe_row(features)

        # Step 4: Predict
        prediction_encoded = self.model.predict(X)[0]
        risk_level = self.label_encoder.inverse_transform([prediction_encoded])[0]

        # Step 5: Get probability distribution across all classes
        probabilities_array = self.model.predict_proba(X)[0]
        probabilities = {
            level: round(float(prob), 4)
            for level, prob in zip(self.label_encoder.classes_, probabilities_array)
        }

        # Confidence is the probability of the predicted class
        confidence = float(probabilities.get(risk_level, 0.0))

        result = {
            "risk_level": risk_level,
            "confidence": round(confidence, 4),
            "probabilities": probabilities,
            "features_summary": summarise_features(features),
            "features_raw": features,
        }

        logger.info(
            f"Risk prediction: {risk_level} "
            f"(confidence={confidence:.2f}, "
            f"findings={features['total_findings']})"
        )

        return result

    def _rule_based_prediction(self, features, findings):
        """
        Fallback prediction using hand-crafted rules when the ML model
        is not available (e.g., before training).

        This provides a reasonable prediction based on domain expertise
        and ensures the scanner still works without a trained model.
        """
        score = features["weighted_risk_score"]
        total = features["total_findings"]
        has_sqli = features["has_confirmed_sqli"]
        has_bac = features["has_unauth_access"]
        has_weak_creds = features["has_weak_credentials"]
        num_critical = features["num_critical"]

        # Rule-based decision tree
        if total == 0:
            risk_level = "Safe"
            confidence = 0.95
        elif num_critical >= 2 or (has_sqli and has_weak_creds):
            risk_level = "Critical"
            confidence = 0.85
        elif num_critical >= 1 or (has_sqli or (has_bac and has_weak_creds)):
            risk_level = "High"
            confidence = 0.80
        elif score > 15 or features["num_high"] >= 2:
            risk_level = "Medium"
            confidence = 0.75
        elif score > 5 or total > 3:
            risk_level = "Low"
            confidence = 0.70
        else:
            risk_level = "Safe"
            confidence = 0.65

        # Build probability distribution centered on predicted level
        probabilities = self._build_fallback_probabilities(
            risk_level, confidence
        )

        return {
            "risk_level": risk_level,
            "confidence": round(confidence, 4),
            "probabilities": probabilities,
            "features_summary": summarise_features(features),
            "features_raw": features,
            "note": "Prediction from rule-based fallback (model not trained yet)",
        }

    @staticmethod
    def _build_fallback_probabilities(predicted_level, confidence):
        """
        Build a plausible probability distribution for the fallback predictor.
        Centers most probability mass on the predicted level with some spread
        to adjacent levels.
        """
        probabilities = {level: 0.0 for level in RISK_LEVELS}
        probabilities[predicted_level] = confidence

        # Distribute remaining probability to adjacent levels
        remaining = 1.0 - confidence
        idx = RISK_LEVELS.index(predicted_level)

        adjacent = []
        if idx > 0:
            adjacent.append(RISK_LEVELS[idx - 1])
        if idx < len(RISK_LEVELS) - 1:
            adjacent.append(RISK_LEVELS[idx + 1])

        if adjacent:
            per_adjacent = remaining / (len(adjacent) + 1)
            for adj in adjacent:
                probabilities[adj] = round(per_adjacent, 4)
            # Any leftover goes to the furthest levels
            leftover = remaining - sum(
                probabilities[a] for a in adjacent
            )
            # Spread leftover evenly across all non-predicted levels
            non_predicted = [l for l in RISK_LEVELS if l != predicted_level]
            for level in non_predicted:
                if probabilities[level] == 0.0:
                    probabilities[level] = round(
                        leftover / len(non_predicted), 4
                    )

        return probabilities

    def is_loaded(self):
        """Check if the model was loaded successfully."""
        return self._loaded

    def get_model_info(self):
        """Return info about the loaded model for the API."""
        info = {
            "model_loaded": self._loaded,
            "model_path": self.model_path,
            "risk_levels": RISK_LEVELS,
        }

        if self._loaded:
            info["model_type"] = type(self.model).__name__
            info["n_estimators"] = getattr(self.model, "n_estimators", None)
            info["n_features"] = getattr(self.model, "n_features_in_", None)
            info["classes"] = self.label_encoder.classes_.tolist()

            # Load training metrics if available
            if os.path.exists(METRICS_PATH):
                import json
                with open(METRICS_PATH, "r") as f:
                    metrics = json.load(f)
                info["training_accuracy"] = metrics.get("accuracy")
                info["cross_val_accuracy"] = metrics.get(
                    "cross_val_accuracy_mean"
                )

        return info