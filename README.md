# Zero Day Hunter — AI-Based Hybrid Network Intrusion Detection System

Student: Aiswariya Akhil (E4318387) | Course: CIS4055 | Supervisor: Nauman Issar

## Overview
Hybrid ML NIDS combining Random Forest (supervised, 99% accuracy)
and Autoencoder (unsupervised, zero-day detection) with real-time SOC dashboard.

## Results
| Model              | Accuracy | Precision | Recall | AUC    |
|--------------------|----------|-----------|--------|--------|
| Random Forest      | 99.03%   | 99.31%    | 99.17% | 0.9926 |
| Hybrid RF+AE       | 97.44%   | 96.84%    | 99.23% | 0.9611 |
| Decision Tree      | 92.82%   | 94.47%    | 94.29% | —      |
| Logistic Regression| 89.55%   | 87.74%    | 97.23% | —      |
| KNN                | 90.63%   | 91.99%    | 93.48% | —      |
| Naive Bayes        | 81.62%   | 86.81%    | 84.01% | —      |

## Quick Start
See SETUP.md for full instructions.

    git clone https://github.com/aiswariyadevan6-maker/dev_.git
    cd dev_
    python3 -m venv venv && source venv/bin/activate
    pip install -r requirements.txt
    python main.py build-dataset
    python main.py train
    ./run.sh

## Dashboard Features
- Live Detection Panel with real-time AI predictions
- Confusion Matrix and ROC Curve visualizations
- Algorithm Accuracy Comparison (6 models side-by-side)
- Alert Management with direct block/unblock IP
- CVE Threat Intelligence panel
- Decision Explanation per detection
- CSV and PDF export
- Role-based access control

## Dataset
UNSW-NB15 (Moustafa & Slay, 2015) — 50,000 network records, 42 features.

## Reference
Moustafa, N. & Slay, J. (2015). UNSW-NB15: A comprehensive data set for
network intrusion detection systems. MilCIS, IEEE.
