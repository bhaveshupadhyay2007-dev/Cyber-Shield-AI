# Cyber Shield AI

AI-Powered Suspicious URL Detection and Blocking System

Cyber Shield AI is a machine-learning-based cybersecurity application designed to detect suspicious and potentially phishing URLs.

## Features

- Machine Learning based URL classification
- Suspicious URL detection
- Heuristic security analysis
- Threat intelligence integration
- Risk scoring
- Automatic suspicious URL blocking
- Scan history
- Security statistics
- Flask web interface

## Machine Learning Model

Cyber Shield AI uses a Random Forest Classifier trained using the PhiUSIIL Phishing URL Dataset.

Dataset size: **235,795 URLs**

Training configuration:

- Algorithm: Random Forest Classifier
- Number of Trees: 200
- Train/Test Split: 80/20
- Random State: 42
- Class Weight: Balanced

## Model Performance

| Metric | Score |
|---|---|
| Accuracy | 99.54% |
| Precision | 99.82% |
| Recall | 99.10% |
| F1 Score | 99.46% |

These results are based on the held-out test set from the project training pipeline.

## Risk Scoring

The system combines multiple security signals:

- Machine Learning: 45%
- Heuristic Analysis: 40%
- Threat Intelligence: 15%

| Risk Score | Classification | Action |
|---|---|---|
| 0-39 | SAFE | ALLOW |
| 40-69 | WARNING | CHECK |
| 70-100 | SUSPICIOUS | BLOCK |

## Technologies Used

- Python
- Flask
- Scikit-learn
- Random Forest
- Pandas
- NumPy
- Joblib
- HTML
- CSS
- JavaScript
- VirusTotal API

## Project Structure

`	ext
cyber shield ai/
|-- app.py
|-- run_app.py
|-- scan_history.py
|-- requirements.txt
|-- README.md
|-- .gitignore
|
|-- dataset/
|   -- PhiUSIIL_Phishing_URL_Dataset.csv
|
|-- models/
|   |-- url_model.pkl
|   -- url_model_backup_before_retraining.pkl
|
|-- src/
|   |-- predict.py
|   |-- feature_extraction.py
|   |-- threat_intelligence.py
|   |-- train_model.py
|   -- evaluate_model.py
|
|-- templates/
|   |-- index.html
|   |-- blocked.html
|   -- history.html
|
-- static/
    -- style.css
` 

## Running the Application

`ash
python run_app.py
` 

Then open:

http://127.0.0.1:5000

## Model Training

`ash
python src/train_model.py
` 

## Model Evaluation

`ash
python src/evaluate_model.py
` 

## Security

The VirusTotal API key is stored in the .env file. The .env file must never be uploaded to GitHub.

## Future Improvements

- Browser extension integration
- Real-time URL scanning
- Additional threat intelligence sources
- WHOIS analysis
- DNS analysis
- SSL certificate analysis
- Explainable AI
- Advanced dashboard
- REST API
- Real-time monitoring

## Resume Description

**Cyber Shield AI — AI-Powered Suspicious URL Detection and Blocking System**

Developed a machine-learning-based phishing URL detection system using Random Forest and URL-based feature engineering. Trained the model on 235,795 URLs using an 80/20 stratified split, achieving 99.54% accuracy, 99.82% precision, 99.10% recall, and 99.46% F1-score on the held-out test set. Combined machine learning, heuristic security analysis, and threat intelligence into a unified risk-scoring and URL-blocking pipeline.

