# Author: Aayush — Synthetic Data Generator
"""
AEGIS Scanner — Synthetic Training Data Generator
Generates realistic synthetic scan results to train the Random Forest
risk classifier. Since we don't have thousands of real scanned applications,
we simulate scan outcomes based on heuristic rules that model how real-world
vulnerabilities cluster together.

Concept:
- A "Safe" app has zero or very few low-severity findings
- A "Critical" app has confirmed SQLi, exposed credentials, and missing headers
- Real apps tend to cluster: a poorly secured app usually has MULTIPLE issues
- We encode this domain knowledge into generation rules

Usage:
    python -m backend.ml.synthetic_data
    → Generates backend/ml/data/synthetic_training_data.csv
"""

import os
import random
import csv
import logging

logger = logging.getLogger(__name__)

# Output path for generated data
DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
OUTPUT_FILE = os.path.join(DATA_DIR, "synthetic_training_data.csv")

# Feature columns — these match what feature_extractor.py produces
FEATURE_COLUMNS = [
    "num_sqli_findings",
    "num_bac_findings",
    "num_auth_findings",
    "num_misconfig_findings",
    "num_critical",
    "num_high",
    "num_medium",
    "num_low",
    "has_confirmed_sqli",           # bool → 1/0
    "has_blind_sqli",               # bool → 1/0
    "has_time_based_sqli",          # bool → 1/0
    "has_unauth_access",            # bool → 1/0
    "has_idor",                     # bool → 1/0
    "has_weak_credentials",         # bool → 1/0
    "has_missing_rate_limit",       # bool → 1/0
    "missing_headers_count",        # int 0–7
    "exposed_files_count",          # int 0–N
    "has_info_disclosure",          # bool → 1/0
    "has_verbose_errors",           # bool → 1/0
    "has_exposed_env",              # bool → 1/0
    "has_exposed_git",              # bool → 1/0
    "total_findings",               # int
    "weighted_risk_score",          # float — sum of severity weights
]

LABEL_COLUMN = "risk_level"

# Risk levels (matching config.RISK_LEVELS)
RISK_LEVELS = ["Safe", "Low", "Medium", "High", "Critical"]


def generate_dataset(num_samples=2000, seed=42):
    """
    Generate a synthetic dataset of scan results with risk labels.

    Strategy:
    - For each risk level, generate samples that reflect realistic
      vulnerability distributions for that risk tier
    - Add controlled noise so the model learns to generalise
    - Balance the dataset across risk levels

    Args:
        num_samples: total number of samples to generate
        seed: random seed for reproducibility

    Returns:
        list of dicts, each representing one training sample
    """
    random.seed(seed)
    samples = []

    samples_per_level = num_samples // len(RISK_LEVELS)

    for level in RISK_LEVELS:
        for _ in range(samples_per_level):
            sample = _generate_sample(level)
            samples.append(sample)

    # Shuffle to avoid ordering bias
    random.shuffle(samples)

    logger.info(
        f"Generated {len(samples)} synthetic training samples "
        f"({samples_per_level} per risk level)"
    )
    return samples


def _generate_sample(risk_level):
    """
    Generate a single training sample for the given risk level.

    Each risk level has characteristic vulnerability patterns:
    - Safe: minimal or no findings
    - Low: a few misconfig issues, maybe info disclosure
    - Medium: some misconfig + possible auth issues, no confirmed SQLi
    - High: confirmed vulnerabilities in 1-2 categories, multiple severities
    - Critical: confirmed SQLi + BAC or auth failures + heavy misconfig
    """
    sample = {}

    if risk_level == "Safe":
        sample = _gen_safe()
    elif risk_level == "Low":
        sample = _gen_low()
    elif risk_level == "Medium":
        sample = _gen_medium()
    elif risk_level == "High":
        sample = _gen_high()
    elif risk_level == "Critical":
        sample = _gen_critical()

    # Compute derived features
    sample["total_findings"] = (
        sample["num_sqli_findings"]
        + sample["num_bac_findings"]
        + sample["num_auth_findings"]
        + sample["num_misconfig_findings"]
    )

    sample["weighted_risk_score"] = (
        sample["num_critical"] * 10
        + sample["num_high"] * 7
        + sample["num_medium"] * 4
        + sample["num_low"] * 2
    )

    sample[LABEL_COLUMN] = risk_level

    return sample


# ------------------------------------------------------------------
# Risk Level Generators
# ------------------------------------------------------------------

def _gen_safe():
    """Safe app: zero or near-zero findings."""
    missing_headers = random.choice([0, 0, 0, 1])
    info_disc = random.choice([0, 0, 1])

    num_low = missing_headers + info_disc
    num_misconfig = missing_headers + info_disc

    return {
        "num_sqli_findings": 0,
        "num_bac_findings": 0,
        "num_auth_findings": 0,
        "num_misconfig_findings": num_misconfig,
        "num_critical": 0,
        "num_high": 0,
        "num_medium": 0,
        "num_low": num_low,
        "has_confirmed_sqli": 0,
        "has_blind_sqli": 0,
        "has_time_based_sqli": 0,
        "has_unauth_access": 0,
        "has_idor": 0,
        "has_weak_credentials": 0,
        "has_missing_rate_limit": 0,
        "missing_headers_count": missing_headers,
        "exposed_files_count": 0,
        "has_info_disclosure": info_disc,
        "has_verbose_errors": 0,
        "has_exposed_env": 0,
        "has_exposed_git": 0,
    }


def _gen_low():
    """Low risk: minor misconfig, maybe a few info-level issues."""
    missing_headers = random.randint(1, 3)
    info_disc = random.choice([0, 1, 1])
    verbose_err = random.choice([0, 0, 1])
    exposed_files = random.choice([0, 0, 1])

    num_low = missing_headers + info_disc
    num_medium = verbose_err + (1 if exposed_files else 0)
    num_misconfig = missing_headers + info_disc + verbose_err + exposed_files

    return {
        "num_sqli_findings": 0,
        "num_bac_findings": 0,
        "num_auth_findings": 0,
        "num_misconfig_findings": num_misconfig,
        "num_critical": 0,
        "num_high": 0,
        "num_medium": num_medium,
        "num_low": num_low,
        "has_confirmed_sqli": 0,
        "has_blind_sqli": 0,
        "has_time_based_sqli": 0,
        "has_unauth_access": 0,
        "has_idor": 0,
        "has_weak_credentials": 0,
        "has_missing_rate_limit": random.choice([0, 0, 1]),
        "missing_headers_count": missing_headers,
        "exposed_files_count": exposed_files,
        "has_info_disclosure": info_disc,
        "has_verbose_errors": verbose_err,
        "has_exposed_env": 0,
        "has_exposed_git": 0,
    }


def _gen_medium():
    """Medium risk: misconfig + possible auth issues or tentative findings."""
    missing_headers = random.randint(2, 5)
    info_disc = random.choice([0, 1])
    verbose_err = random.choice([0, 1])
    exposed_files = random.randint(0, 2)
    exposed_env = random.choice([0, 0, 1])
    exposed_git = random.choice([0, 0, 1])

    # Possible auth issues
    missing_rate_limit = random.choice([0, 1, 1])
    weak_creds = random.choice([0, 0, 1])

    # Tentative SQLi (not confirmed)
    tentative_sqli = random.choice([0, 0, 1])

    num_sqli = tentative_sqli
    num_auth = missing_rate_limit + weak_creds
    num_misconfig = (
        missing_headers + info_disc + verbose_err
        + exposed_files + exposed_env + exposed_git
    )

    num_critical = 1 if (weak_creds and exposed_env) else 0
    num_high = (1 if exposed_env else 0) + (1 if exposed_git else 0)
    num_medium = (
        verbose_err + missing_rate_limit + tentative_sqli
        + min(exposed_files, 1)
    )
    num_low = missing_headers + info_disc

    return {
        "num_sqli_findings": num_sqli,
        "num_bac_findings": 0,
        "num_auth_findings": num_auth,
        "num_misconfig_findings": num_misconfig,
        "num_critical": num_critical,
        "num_high": num_high,
        "num_medium": num_medium,
        "num_low": num_low,
        "has_confirmed_sqli": 0,
        "has_blind_sqli": 0,
        "has_time_based_sqli": 0,
        "has_unauth_access": 0,
        "has_idor": 0,
        "has_weak_credentials": weak_creds,
        "has_missing_rate_limit": missing_rate_limit,
        "missing_headers_count": missing_headers,
        "exposed_files_count": exposed_files + exposed_env + exposed_git,
        "has_info_disclosure": info_disc,
        "has_verbose_errors": verbose_err,
        "has_exposed_env": exposed_env,
        "has_exposed_git": exposed_git,
    }


def _gen_high():
    """High risk: confirmed vulns in 1-2 categories, multiple severities."""
    missing_headers = random.randint(3, 6)
    info_disc = random.choice([1, 1, 0])
    verbose_err = random.choice([0, 1, 1])
    exposed_files = random.randint(1, 3)
    exposed_env = random.choice([0, 1, 1])
    exposed_git = random.choice([0, 1])

    # Confirmed vulnerabilities in at least one major category
    has_sqli = random.choice([0, 1, 1])
    has_blind = random.choice([0, 1]) if has_sqli else 0
    has_time = random.choice([0, 1]) if has_sqli else 0
    has_bac = random.choice([0, 1, 1])
    has_unauth = has_bac
    has_idor = random.choice([0, 1]) if has_bac else 0

    weak_creds = random.choice([0, 1])
    missing_rate_limit = random.choice([1, 1, 0])

    num_sqli = has_sqli + has_blind + has_time
    num_bac = has_unauth + has_idor
    num_auth = weak_creds + missing_rate_limit
    num_misconfig = (
        missing_headers + info_disc + verbose_err
        + exposed_files + exposed_env + exposed_git
    )

    num_critical = (1 if has_sqli else 0) + (1 if (has_bac and weak_creds) else 0)
    num_high = (
        (1 if has_blind else 0) + (1 if has_unauth else 0)
        + (1 if exposed_env else 0)
    )
    num_medium = (
        (1 if has_time else 0) + verbose_err + missing_rate_limit
        + (1 if has_idor else 0)
    )
    num_low = missing_headers + info_disc

    return {
        "num_sqli_findings": num_sqli,
        "num_bac_findings": num_bac,
        "num_auth_findings": num_auth,
        "num_misconfig_findings": num_misconfig,
        "num_critical": num_critical,
        "num_high": num_high,
        "num_medium": num_medium,
        "num_low": num_low,
        "has_confirmed_sqli": has_sqli,
        "has_blind_sqli": has_blind,
        "has_time_based_sqli": has_time,
        "has_unauth_access": has_unauth,
        "has_idor": has_idor,
        "has_weak_credentials": weak_creds,
        "has_missing_rate_limit": missing_rate_limit,
        "missing_headers_count": missing_headers,
        "exposed_files_count": exposed_files + exposed_env + exposed_git,
        "has_info_disclosure": info_disc,
        "has_verbose_errors": verbose_err,
        "has_exposed_env": exposed_env,
        "has_exposed_git": exposed_git,
    }


def _gen_critical():
    """Critical risk: confirmed SQLi + BAC/auth failures + heavy misconfig."""
    missing_headers = random.randint(4, 7)
    info_disc = 1
    verbose_err = random.choice([1, 1, 0])
    exposed_files = random.randint(2, 5)
    exposed_env = random.choice([1, 1, 0])
    exposed_git = random.choice([1, 1, 0])

    # Critical apps almost always have confirmed SQLi
    has_sqli = 1
    has_blind = random.choice([0, 1, 1])
    has_time = random.choice([0, 1, 1])

    # BAC issues very common in critical apps
    has_bac = random.choice([1, 1, 0])
    has_unauth = has_bac
    has_idor = random.choice([0, 1]) if has_bac else 0

    # Auth failures
    weak_creds = random.choice([1, 1, 0])
    missing_rate_limit = 1

    num_sqli = has_sqli + has_blind + has_time + random.randint(0, 2)
    num_bac = has_unauth + has_idor + random.randint(0, 1)
    num_auth = weak_creds + missing_rate_limit
    num_misconfig = (
        missing_headers + info_disc + verbose_err
        + exposed_files + exposed_env + exposed_git
    )

    num_critical = (
        has_sqli + (1 if weak_creds else 0)
        + (1 if (has_unauth and exposed_env) else 0)
    )
    num_high = (
        has_blind + has_unauth
        + (1 if exposed_env else 0) + (1 if exposed_git else 0)
    )
    num_medium = (
        has_time + verbose_err + missing_rate_limit
        + has_idor + min(exposed_files, 2)
    )
    num_low = missing_headers + info_disc

    return {
        "num_sqli_findings": num_sqli,
        "num_bac_findings": num_bac,
        "num_auth_findings": num_auth,
        "num_misconfig_findings": num_misconfig,
        "num_critical": num_critical,
        "num_high": num_high,
        "num_medium": num_medium,
        "num_low": num_low,
        "has_confirmed_sqli": has_sqli,
        "has_blind_sqli": has_blind,
        "has_time_based_sqli": has_time,
        "has_unauth_access": has_unauth,
        "has_idor": has_idor,
        "has_weak_credentials": weak_creds,
        "has_missing_rate_limit": missing_rate_limit,
        "missing_headers_count": missing_headers,
        "exposed_files_count": exposed_files + exposed_env + exposed_git,
        "has_info_disclosure": info_disc,
        "has_verbose_errors": verbose_err,
        "has_exposed_env": exposed_env,
        "has_exposed_git": exposed_git,
    }


# ------------------------------------------------------------------
# Save to CSV
# ------------------------------------------------------------------
def save_dataset(samples, output_path=None):
    """Save generated samples to CSV."""
    output_path = output_path or OUTPUT_FILE

    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    columns = FEATURE_COLUMNS + [LABEL_COLUMN]

    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()
        for sample in samples:
            writer.writerow({col: sample.get(col, 0) for col in columns})

    logger.info(f"Saved {len(samples)} samples to {output_path}")
    return output_path


# ------------------------------------------------------------------
# CLI entry point
# ------------------------------------------------------------------
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    print("Generating synthetic training data...")
    samples = generate_dataset(num_samples=2000, seed=42)
    path = save_dataset(samples)
    print(f"Done! Saved {len(samples)} samples to {path}")

    # Print distribution summary
    from collections import Counter
    labels = [s[LABEL_COLUMN] for s in samples]
    print("\nDistribution:")
    for level, count in sorted(Counter(labels).items()):
        print(f"  {level}: {count}")