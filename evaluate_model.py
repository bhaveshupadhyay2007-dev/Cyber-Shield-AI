import os
import joblib

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)

from src.feature_extraction import extract_features


MODEL_PATH = os.path.join("models", "url_model.pkl")


# ============================================================
# TEST DATA
# Dataset mapping:
# 1 = SAFE
# 0 = PHISHING
#
# Cyber Shield AI mapping:
# 0 = SAFE
# 1 = SUSPICIOUS
# ============================================================

TEST_DATA = [

    # SAFE = 0 for Cyber Shield AI
    ("https://www.google.com", 0),
    ("https://github.com", 0),
    ("https://www.microsoft.com", 0),
    ("https://www.apple.com", 0),
    ("https://www.amazon.com", 0),
    ("https://www.linkedin.com", 0),
    ("https://www.wikipedia.org", 0),
    ("https://www.python.org", 0),
    ("https://www.mozilla.org", 0),
    ("https://www.cloudflare.com", 0),

    # SUSPICIOUS = 1 for Cyber Shield AI
    ("http://paypal-login-security.com", 1),
    ("http://secure-login-verify-account.tk/login?password=verify", 1),
    ("http://paypal-security-verify-account.tk/login?confirm=password", 1),
    ("http://192.168.1.100/login/verify-account?password=123456", 1),
    ("http://192.168.1.50/login", 1),
    ("http://secure-account-verification.ml/login", 1),
    ("http://bank-login-security.ga/verify", 1),
    ("http://account-password-reset.tk/login", 1),
    ("http://paypal-confirm-payment.cf/login", 1),
    ("http://verify-user-account.top/password", 1)
]


print("=" * 60)
print("CYBER SHIELD AI - NEW MODEL EVALUATION")
print("=" * 60)


# ============================================================
# CHECK MODEL
# ============================================================

if not os.path.exists(MODEL_PATH):

    print("\nERROR: Model file not found.")
    print(MODEL_PATH)

    raise SystemExit


model = joblib.load(MODEL_PATH)


print("\nModel:", type(model).__name__)
print("Classes:", model.classes_)
print("Features:", model.n_features_in_)


# ============================================================
# FEATURE EXTRACTION
# ============================================================

X = []
y_true = []


for url, label in TEST_DATA:

    features = extract_features(url)

    X.append(features)
    y_true.append(label)


# ============================================================
# PREDICTION
# ============================================================

y_pred = model.predict(X)


# ============================================================
# PERFORMANCE
# ============================================================

accuracy = accuracy_score(
    y_true,
    y_pred
)

precision = precision_score(
    y_true,
    y_pred,
    zero_division=0
)

recall = recall_score(
    y_true,
    y_pred,
    zero_division=0
)

f1 = f1_score(
    y_true,
    y_pred,
    zero_division=0
)


cm = confusion_matrix(
    y_true,
    y_pred
)


print("\n" + "=" * 60)
print("PERFORMANCE")
print("=" * 60)

print(
    f"\nAccuracy  : {accuracy * 100:.2f}%"
)

print(
    f"Precision : {precision * 100:.2f}%"
)

print(
    f"Recall    : {recall * 100:.2f}%"
)

print(
    f"F1 Score  : {f1 * 100:.2f}%"
)


# ============================================================
# CONFUSION MATRIX
# ============================================================

print("\n" + "=" * 60)
print("CONFUSION MATRIX")
print("=" * 60)

print("\n                 Predicted")
print("              SAFE  SUSPICIOUS")

print(
    f"Actual SAFE     {cm[0][0]:<5} {cm[0][1]}"
)

print(
    f"Actual SUSP     {cm[1][0]:<5} {cm[1][1]}"
)


# ============================================================
# CLASSIFICATION REPORT
# ============================================================

print("\n" + "=" * 60)
print("CLASSIFICATION REPORT")
print("=" * 60)

print(
    classification_report(
        y_true,
        y_pred,
        target_names=[
            "SAFE",
            "SUSPICIOUS"
        ],
        zero_division=0
    )
)


# ============================================================
# URL BY URL
# ============================================================

print("\n" + "=" * 60)
print("URL-BY-URL RESULTS")
print("=" * 60)


for (url, actual), predicted in zip(
    TEST_DATA,
    y_pred
):

    actual_text = (
        "SAFE"
        if actual == 0
        else "SUSPICIOUS"
    )

    predicted_text = (
        "SAFE"
        if predicted == 0
        else "SUSPICIOUS"
    )

    status = (
        "PASS"
        if actual == predicted
        else "MISS"
    )

    print("\n[" + status + "]")

    print(
        "URL       :",
        url
    )

    print(
        "Expected  :",
        actual_text
    )

    print(
        "Predicted :",
        predicted_text
    )


print("\n" + "=" * 60)
print("EVALUATION COMPLETE")
print("=" * 60)