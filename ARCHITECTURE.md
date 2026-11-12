# Cyber Shield AI - System Architecture

AI-powered suspicious URL detection and blocking system.

## Detection Pipeline

User URL -> Flask Web Application -> URL Feature Extraction -> Machine Learning + Heuristic Analysis -> Risk Score Engine -> Threat Intelligence -> Final Classification -> SAFE / SUSPICIOUS -> BLOCK -> Scan History

## Machine Learning

Model: Random Forest Classifier
Estimators: 200
Train-test split: 80/20 stratified
Dataset: PhiUSIIL Phishing URL Dataset

## Model Metrics

Accuracy: 99.54%
Precision: 99.82%
Recall: 99.10%
F1 Score: 99.46%

## Technology Stack

Python
Flask
Scikit-learn
Pandas
NumPy
Joblib
Python-dotenv
Requests
HTML
CSS
JSON
VirusTotal API

## Security

API keys are stored in .env and excluded using .gitignore.

## Purpose

The project demonstrates Machine Learning, Cybersecurity, URL threat detection, heuristic security analysis, threat intelligence, web application development, and security logging.
