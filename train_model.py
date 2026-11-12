import os
import sys
import time
import joblib
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)

sys.path.insert(0, os.path.abspath("."))

from src.feature_extraction import extract_features


# ============================================================
# PATHS
# ============================================================

DATASET_PATH = os.path.join(
    "dataset",
    "PhiUSIIL_Phishing_URL_Dataset.csv"
)

MODEL_PATH = os.path.join(
    "models",
    "url_model.pkl"
)


print("=" * 70)
print("CYBER SHIELD AI - MODEL TRAINING")
print("=" * 70)


# ============================================================
# CHECK DATASET
# ============================================================

if not os.path.exists(DATASET_PATH):

    print("\nERROR: Dataset not found.")
    print(DATASET_PATH)

    raise SystemExit


print("\nDataset found:")
print(DATASET_PATH)


# ============================================================
# LOAD DATASET
# ============================================================

print("\nLoading dataset...")

start_time = time.time()

df = pd.read_csv(DATASET_PATH)

print("\nDataset loaded successfully.")

print("Rows    :", len(df))
print("Columns :", len(df.columns))


# ============================================================
# SELECT REQUIRED COLUMNS
# ============================================================

df = df[["URL", "label"]]

print("\nUsing columns:")
print("URL")
print("label")


# ============================================================
# CLEAN DATA
# ============================================================

print("\nCleaning dataset...")

df = df.dropna(
    subset=["URL", "label"]
)

df["URL"] = df["URL"].astype(str)

df = df.drop_duplicates(
    subset=["URL"]
)

df = df[
    df["label"].isin([0, 1])
]

df = df.reset_index(
    drop=True
)


print("\nRows after cleaning:")
print(len(df))


print("\nOriginal dataset labels:")

print(
    df["label"].value_counts()
)


# ============================================================
# FEATURE EXTRACTION
# ============================================================

print("\n" + "=" * 70)
print("EXTRACTING URL FEATURES")
print("=" * 70)

print("\nUsing existing 15-feature extraction system.")

X = []
y = []

total = len(df)

for index, row in df.iterrows():

    url = row["URL"]

    # IMPORTANT:
    # PhiUSIIL dataset:
    # 1 = SAFE
    # 0 = PHISHING
    #
    # Cyber Shield AI:
    # 0 = SAFE
    # 1 = SUSPICIOUS
    #
    # Therefore we invert the label.

    label = 1 - int(row["label"])

    try:

        features = extract_features(url)

        if len(features) == 15:

            X.append(features)
            y.append(label)

    except Exception:

        continue


    if (index + 1) % 10000 == 0:

        print(
            f"Processed {index + 1}/{total} URLs..."
        )


print("\nFeature extraction complete.")

print(
    "Usable samples:",
    len(X)
)

print(
    "Number of features:",
    len(X[0])
)


# ============================================================
# FINAL LABEL DISTRIBUTION
# ============================================================

print("\nCyber Shield AI labels:")

print(
    "0 = SAFE"
)

print(
    "1 = SUSPICIOUS"
)

print("\nDistribution:")

print(
    pd.Series(y).value_counts()
)


# ============================================================
# TRAIN / TEST SPLIT
# ============================================================

print("\n" + "=" * 70)
print("CREATING TRAIN / TEST SPLIT")
print("=" * 70)

X_train, X_test, y_train, y_test = train_test_split(

    X,
    y,

    test_size=0.20,

    random_state=42,

    stratify=y
)


print(
    "\nTraining samples:",
    len(X_train)
)

print(
    "Testing samples :",
    len(X_test)
)


# ============================================================
# RANDOM FOREST
# ============================================================

print("\n" + "=" * 70)
print("TRAINING RANDOM FOREST")
print("=" * 70)

print("\nPlease wait...")


model = RandomForestClassifier(

    n_estimators=200,

    random_state=42,

    n_jobs=-1,

    class_weight="balanced"
)


model.fit(
    X_train,
    y_train
)


print("\nModel training complete.")


# ============================================================
# PREDICTION
# ============================================================

print("\nEvaluating model...")

y_pred = model.predict(
    X_test
)


# ============================================================
# METRICS
# ============================================================

accuracy = accuracy_score(
    y_test,
    y_pred
)

precision = precision_score(
    y_test,
    y_pred,
    zero_division=0
)

recall = recall_score(
    y_test,
    y_pred,
    zero_division=0
)

f1 = f1_score(
    y_test,
    y_pred,
    zero_division=0
)

cm = confusion_matrix(
    y_test,
    y_pred
)


# ============================================================
# PERFORMANCE
# ============================================================

print("\n" + "=" * 70)
print("MODEL PERFORMANCE")
print("=" * 70)

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

print("\n" + "=" * 70)
print("CONFUSION MATRIX")
print("=" * 70)

print("\n                 Predicted")

print(
    "              SAFE  SUSPICIOUS"
)

print(
    f"Actual SAFE     {cm[0][0]:<5} {cm[0][1]}"
)

print(
    f"Actual SUSP     {cm[1][0]:<5} {cm[1][1]}"
)


# ============================================================
# CLASSIFICATION REPORT
# ============================================================

print("\n" + "=" * 70)
print("CLASSIFICATION REPORT")
print("=" * 70)

print(
    classification_report(

        y_test,

        y_pred,

        target_names=[
            "SAFE",
            "SUSPICIOUS"
        ],

        zero_division=0
    )
)


# ============================================================
# SAVE MODEL
# ============================================================

print("\n" + "=" * 70)
print("SAVING MODEL")
print("=" * 70)


os.makedirs(
    "models",
    exist_ok=True
)


joblib.dump(
    model,
    MODEL_PATH
)


print("\nNew model saved successfully:")

print(
    MODEL_PATH
)


# ============================================================
# FINAL SUMMARY
# ============================================================

elapsed_time = time.time() - start_time


print("\n" + "=" * 70)
print("TRAINING COMPLETE")
print("=" * 70)

print(
    f"\nTotal time: {elapsed_time:.2f} seconds"
)

print(
    "\nDataset samples:",
    len(X)
)

print(
    "Training samples:",
    len(X_train)
)

print(
    "Testing samples:",
    len(X_test)
)

print(
    "Features:",
    len(X[0])
)

print(
    "\nModel: RandomForestClassifier"
)

print(
    "\nCyber Shield AI label mapping:"
)

print(
    "0 = SAFE"
)

print(
    "1 = SUSPICIOUS"
)

print("\nNew model is ready.")

print("=" * 70)