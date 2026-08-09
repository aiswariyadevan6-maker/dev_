# System Architecture — Zero Day Hunter

## Overview
Hybrid AI-Based Network Intrusion Detection System combining:
- Random Forest (supervised) — detects known attack patterns
- Autoencoder (unsupervised) — detects zero-day anomalies

## Models
| Model | Type | Purpose |
|---|---|---|
| RandomForestClassifier 100 trees | Supervised | Known attack detection |
| Autoencoder 42-32-42 | Unsupervised | Zero-day anomaly detection |
| StandardScaler | Preprocessing | Feature normalization |

## Decision Logic
- RF=1 AND AE anomaly: CONFIRMED ATTACK (CRITICAL)
- RF=1 only: KNOWN ATTACK (HIGH)
- AE anomaly only: ZERO-DAY (MEDIUM)
- Neither: BENIGN (LOW)

## Dataset
UNSW-NB15 — 257,673 records, 42 features, sampled to 50,000 for training.
