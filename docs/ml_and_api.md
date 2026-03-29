# Authentication Scanner, ML Pipeline, API & Frontend

## Author: Aayush Das

## Authentication Scanner (auth_scanner.py)
Detects A07:2021 Authentication Failures:
- Weak credentials: tests 20 common pairs from common_creds.txt
- Missing rate limiting: 10 rapid failed logins
- Missing CSRF protection: checks forms for hidden CSRF tokens
- Session cookie security: checks HttpOnly, Secure, SameSite flags

Login success uses multi-signal scoring:
redirect (+2), success keywords (+2), no failure keywords (+1), 
body length change (+1), new Set-Cookie (+1). Score >= 3 = success.

## ML Risk Prediction Pipeline
- synthetic_data.py: generates 2,000 training samples
- feature_extractor.py: converts findings to 23-element vector
- train_model.py: Random Forest, 200 trees, max depth 15
- risk_predictor.py: predicts Safe/Low/Medium/High/Critical + confidence

Performance: 97% test accuracy, 95.85% cross-validation

## Flask API (app.py)
POST /api/scan orchestrates: crawl → 4 parallel scanners → ML 
prediction → policy engine → PDF report → JSON response

## React Frontend
Dashboard with URL input, severity cards, risk gauge, OWASP chart, 
severity distribution, filterable findings table, PDF download