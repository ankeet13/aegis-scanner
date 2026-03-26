"""
AEGIS Scanner — Flask REST API
Main entry point that orchestrates the full scan pipeline:

1. Receive target URL from the frontend
2. Crawl the target to discover endpoints
3. Run all 4 scanners in parallel (ThreadPoolExecutor)
4. Combine findings and extract ML features
5. Predict risk level via the trained Random Forest
6. Generate remediation recommendations via the policy engine
7. Return structured JSON (and optionally generate a PDF report)

Endpoints:
    POST /api/scan         — run a full scan
    GET  /api/model-info   — return ML model metadata
    GET  /api/health       — health check
    GET  /api/report/<id>  — download a generated PDF report

Usage:
    python -m backend.app
"""

import os
import time
import logging
import traceback
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from flask import Flask, request, jsonify, send_file
from flask_cors import CORS

from backend.config import FLASK_HOST, FLASK_PORT, FLASK_DEBUG
from backend.utils.http_client import HTTPClient
from backend.scanners.crawler import Crawler
from backend.scanners.sqli_scanner import SQLiScanner
from backend.scanners.bac_scanner import BACScanner
from backend.scanners.auth_scanner import AuthScanner
from backend.scanners.misconfig_scanner import MisconfigScanner
from backend.ml.risk_predictor import RiskPredictor
from backend.utils.policy_engine import PolicyEngine
from backend.utils.report_generator import ReportGenerator

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------
app = Flask(__name__)
CORS(app)  # allow React frontend on a different port

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

# Initialise shared components (loaded once at startup)
risk_predictor = RiskPredictor()
policy_engine = PolicyEngine()
report_generator = ReportGenerator()

# Store generated report paths for download
generated_reports = {}


# ---------------------------------------------------------------------------
# POST /api/scan — Run a full scan
# ---------------------------------------------------------------------------
@app.route("/api/scan", methods=["POST"])
def run_scan():
    """
    Run a full vulnerability scan against the target URL.

    Request JSON:
        {
            "target_url": "http://localhost:8080",
            "auth_cookie": {"session": "abc123"},   // optional
            "max_depth": 3,                          // optional
            "max_urls": 100,                         // optional
            "generate_report": true                  // optional
        }

    Response JSON:
        {
            "target_url": "...",
            "scan_duration": 45.2,
            "crawl_stats": { ... },
            "findings": [ ... ],
            "risk_prediction": { ... },
            "recommendations": { ... },
            "model_info": { ... },
            "report_url": "/api/report/abc123"  // if generate_report=true
        }
    """
    try:
        data = request.get_json()
        if not data or "target_url" not in data:
            return jsonify({"error": "target_url is required"}), 400

        target_url = data["target_url"].strip()
        auth_cookie = data.get("auth_cookie")
        max_depth = data.get("max_depth")
        max_urls = data.get("max_urls")
        generate_report = data.get("generate_report", True)

        # Validate URL
        if not target_url.startswith(("http://", "https://")):
            return jsonify({"error": "target_url must start with http:// or https://"}), 400

        logger.info("=" * 60)
        logger.info(f"SCAN STARTED: {target_url}")
        logger.info("=" * 60)

        scan_start = time.time()

        # ------------------------------------------------------------------
        # Phase 1: Crawl the target
        # ------------------------------------------------------------------
        logger.info("\n--- Phase 1: Crawling ---")
        http_client = HTTPClient(
            auth_cookie=auth_cookie if auth_cookie else None
        )
        crawler = Crawler(http_client=http_client)
        endpoints = crawler.crawl(
            target_url,
            max_depth=max_depth,
            max_urls=max_urls,
        )
        crawl_stats = crawler.get_stats()
        logger.info(f"Crawl complete: {crawl_stats}")

        # ------------------------------------------------------------------
        # Phase 2: Run all 4 scanners in parallel
        # ------------------------------------------------------------------
        logger.info("\n--- Phase 2: Scanning (parallel) ---")

        sqli_scanner = SQLiScanner(http_client=http_client)
        bac_scanner = BACScanner(http_client=http_client)
        auth_scanner = AuthScanner(http_client=http_client)
        misconfig_scanner = MisconfigScanner(http_client=http_client)

        all_findings = []

        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = {
                executor.submit(sqli_scanner.scan, endpoints): "sqli",
                executor.submit(bac_scanner.scan, endpoints): "bac",
                executor.submit(auth_scanner.scan, endpoints): "auth",
                executor.submit(
                    misconfig_scanner.scan, endpoints, target_url
                ): "misconfig",
            }

            for future in as_completed(futures):
                scanner_name = futures[future]
                try:
                    findings = future.result()
                    logger.info(
                        f"  {scanner_name} scanner: "
                        f"{len(findings)} finding(s)"
                    )
                    all_findings.extend(findings)
                except Exception as e:
                    logger.error(
                        f"  {scanner_name} scanner FAILED: {e}\n"
                        f"{traceback.format_exc()}"
                    )

        # Convert Finding objects to dicts
        findings_dicts = []
        for f in all_findings:
            if hasattr(f, "to_dict"):
                findings_dicts.append(f.to_dict())
            elif isinstance(f, dict):
                findings_dicts.append(f)

        logger.info(f"\nTotal findings: {len(findings_dicts)}")

        # ------------------------------------------------------------------
        # Phase 3: ML risk prediction
        # ------------------------------------------------------------------
        logger.info("\n--- Phase 3: Risk Prediction ---")
        risk_prediction = risk_predictor.predict(findings_dicts)
        logger.info(
            f"Risk level: {risk_prediction['risk_level']} "
            f"(confidence: {risk_prediction['confidence']:.2%})"
        )

        # ------------------------------------------------------------------
        # Phase 4: Remediation recommendations
        # ------------------------------------------------------------------
        logger.info("\n--- Phase 4: Recommendations ---")
        recommendations = policy_engine.generate_recommendations(
            findings_dicts, risk_prediction["risk_level"]
        )
        logger.info(
            f"Generated {recommendations['total_recommendations']} "
            f"recommendations"
        )

        # ------------------------------------------------------------------
        # Phase 5: Generate PDF report (optional)
        # ------------------------------------------------------------------
        report_url = None
        if generate_report:
            logger.info("\n--- Phase 5: PDF Report ---")
            try:
                scan_results = {
                    "target_url": target_url,
                    "scan_duration": round(time.time() - scan_start, 2),
                    "crawl_stats": crawl_stats,
                    "findings": findings_dicts,
                    "risk_prediction": risk_prediction,
                    "recommendations": recommendations,
                    "model_info": risk_predictor.get_model_info(),
                }
                report_path = report_generator.generate(scan_results)
                report_id = os.path.basename(report_path).replace(".pdf", "")
                generated_reports[report_id] = report_path
                report_url = f"/api/report/{report_id}"
                logger.info(f"Report generated: {report_path}")
            except Exception as e:
                logger.error(f"Report generation failed: {e}")
                report_url = None

        scan_duration = round(time.time() - scan_start, 2)

        # ------------------------------------------------------------------
        # Build response
        # ------------------------------------------------------------------
        response = {
            "target_url": target_url,
            "scan_timestamp": datetime.now().isoformat(),
            "scan_duration": scan_duration,
            "crawl_stats": crawl_stats,
            "findings": findings_dicts,
            "risk_prediction": {
                "risk_level": risk_prediction["risk_level"],
                "confidence": risk_prediction["confidence"],
                "probabilities": risk_prediction["probabilities"],
                "features_summary": risk_prediction.get("features_summary", {}),
            },
            "recommendations": recommendations,
            "model_info": risk_predictor.get_model_info(),
            "report_url": report_url,
            "scanner_stats": {
                "sqli": sqli_scanner.get_stats(),
                "bac": bac_scanner.get_stats(),
                "auth": auth_scanner.get_stats(),
                "misconfig": misconfig_scanner.get_stats(),
            },
        }

        logger.info(f"\nSCAN COMPLETE in {scan_duration}s")
        logger.info(f"Risk: {risk_prediction['risk_level']}")
        logger.info(f"Findings: {len(findings_dicts)}")
        logger.info("=" * 60)

        return jsonify(response), 200

    except Exception as e:
        logger.error(f"Scan failed: {e}\n{traceback.format_exc()}")
        return jsonify({
            "error": "Scan failed",
            "message": str(e),
        }), 500


# ---------------------------------------------------------------------------
# GET /api/report/<report_id> — Download a PDF report
# ---------------------------------------------------------------------------
@app.route("/api/report/<report_id>", methods=["GET"])
def download_report(report_id):
    """Download a previously generated PDF report."""
    report_path = generated_reports.get(report_id)

    if not report_path or not os.path.exists(report_path):
        return jsonify({"error": "Report not found"}), 404

    return send_file(
        report_path,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"{report_id}.pdf",
    )


# ---------------------------------------------------------------------------
# GET /api/model-info — ML model metadata
# ---------------------------------------------------------------------------
@app.route("/api/model-info", methods=["GET"])
def model_info():
    """Return information about the loaded ML model."""
    return jsonify(risk_predictor.get_model_info()), 200


# ---------------------------------------------------------------------------
# GET /api/health — Health check
# ---------------------------------------------------------------------------
@app.route("/api/health", methods=["GET"])
def health_check():
    """Health check endpoint."""
    return jsonify({
        "status": "ok",
        "model_loaded": risk_predictor.is_loaded(),
        "timestamp": datetime.now().isoformat(),
    }), 200


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    logger.info("Starting AEGIS Scanner API...")
    logger.info(f"Model loaded: {risk_predictor.is_loaded()}")
    logger.info(f"Listening on {FLASK_HOST}:{FLASK_PORT}")

    app.run(
        host=FLASK_HOST,
        port=FLASK_PORT,
        debug=FLASK_DEBUG,
    )