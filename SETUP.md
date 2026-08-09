# Zero Day Hunter - Setup Guide

Student: Aiswariya Akhil (E4318387)
Course: CIS4055 Computing Masters Project
Supervisor: Nauman Issar

## Requirements
- Python 3.10+
- 4GB RAM minimum

## Quick Start

### 1. Clone and install
    git clone https://github.com/aiswariyadevan6-maker/dev_.git
    cd dev_
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt

### 2. Build dataset and train models
    python main.py build-dataset
    python main.py train
    python main.py evaluate

### 3. Run the dashboard
    ./run.sh
    Visit: http://127.0.0.1:8000/

### 4. First-time setup
    cd nids_dashboard
    python manage.py createsuperuser
    python manage.py seed_metrics

### 5. Generate demo files
    python main.py demo

## Running Tests
    pip install pytest
    python -m pytest tests/ -v
