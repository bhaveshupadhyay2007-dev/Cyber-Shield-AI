import os
import sys
import joblib

from sklearn.ensemble import RandomForestClassifier

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from feature_extraction import extract_features


# Training data
# 0 = SAFE
# 1 = SUSPICIOUS

data = [
    ("https://www.google.com", 0),
    ("https://www.microsoft.com", 0),
    ("https://www.github.com", 0),
    ("https://www.wikipedia.org", 0),
    ("https://www.amazon.com", 0),
    ("https://www.apple.com", 0),
    ("https://www.linkedin.com", 0),
    ("https://www.microsoft.com/en-in", 0),
    ("https://www.python.org", 0),
    ("https://www.netflix.com", 0),

    ("http://paypal-login-security.com", 1),
    ("http://google-login-verify-account.com", 1),
    ("http://free-money-prize.xyz", 1),
    ("http://account-verify-security.tk", 1),
    ("http://192.168.1.10/login", 1),
    ("http://secure-login-paypal.xyz", 1),
    ("http://bank-account-confirmation.ml", 1),
    ("http://win-free-iphone-prize.com", 1),
    ("http://login-verification-account123.com", 1),
    ("http://update-password-security.xyz", 1),
    ("http://free-gift-card-now.xyz", 1),
    ("http://paypal.com@evil-site.com/login", 1),
    ("http://google.com@malicious-site.xyz", 1),
    ("http://account-reset-password-now.com", 1),
]


X = [extract_features(url) for url, label in data]
y = [label for url, label in data]

model = RandomForestClassifier(
    n_estimators=100,
    random_state=42
)

model.fit(X, y)

# Create models folder
base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
model_path = os.path.join(base_dir, "models", "url_model.pkl")

joblib.dump(model, model_path)

print("===================================")
print(" Cyber Shield AI Model Trained!")
print("===================================")
print(f"Model saved at: {model_path}")
print(f"Training URLs: {len(data)}")