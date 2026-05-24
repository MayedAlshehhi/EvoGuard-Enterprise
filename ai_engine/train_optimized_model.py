import json
import os
from datetime import datetime

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, precision_recall_fscore_support
from sklearn.model_selection import train_test_split


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.abspath(os.path.join(BASE_DIR, ".."))
DATASET_PATH = os.path.join(PROJECT_DIR, "data", "raw", "nsl_kdd_train.txt")
ENCODER_PATH = os.path.join(BASE_DIR, "label_encoders.pkl")
FEATURE_PATH = os.path.join(BASE_DIR, "selected_features.pkl")
MODEL_PATH = os.path.join(BASE_DIR, "evoguard_optimized_model.pkl")
METRICS_PATH = os.path.join(BASE_DIR, "model_metrics.json")


columns = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins",
    "logged_in", "num_compromised", "root_shell", "su_attempted",
    "num_root", "num_file_creations", "num_shells", "num_access_files",
    "num_outbound_cmds", "is_host_login", "is_guest_login", "count",
    "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate",
    "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
    "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
    "label", "difficulty_level",
]


def format_percent(value):
    return f"{value * 100:.2f}%"


df = pd.read_csv(DATASET_PATH, names=columns)
df = df.drop("difficulty_level", axis=1)

label_encoders = joblib.load(ENCODER_PATH)
selected_features = joblib.load(FEATURE_PATH)

for col in ["protocol_type", "service", "flag", "label"]:
    df[col] = label_encoders[col].transform(df[col])

X = df[selected_features]
y = df["label"]

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y,
)

model = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    n_jobs=-1,
)

model.fit(X_train, y_train)

y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
precision, recall, f1_score, _ = precision_recall_fscore_support(
    y_test,
    y_pred,
    average="weighted",
    zero_division=0,
)

report = classification_report(y_test, y_pred, zero_division=0, output_dict=True)

metrics = {
    "accuracy": accuracy,
    "accuracy_display": format_percent(accuracy),
    "precision": precision,
    "precision_display": format_percent(precision),
    "recall": recall,
    "recall_display": format_percent(recall),
    "f1_score": f1_score,
    "f1_score_display": format_percent(f1_score),
    "dataset": "NSL-KDD",
    "model": "RandomForestClassifier",
    "last_trained": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    "selected_features_count": len(selected_features),
    "train_samples": int(len(X_train)),
    "test_samples": int(len(X_test)),
    "metric_source": "validation_split",
    "classification_report": report,
}

joblib.dump(model, MODEL_PATH)

with open(METRICS_PATH, "w", encoding="utf-8") as file:
    json.dump(metrics, file, indent=2)

print("\nOptimized EvoGuard Model Trained Successfully!")
print(f"Selected Features Used: {len(selected_features)}")
print(f"Optimized Model Accuracy: {metrics['accuracy_display']}")
print(f"Precision: {metrics['precision_display']}")
print(f"Recall: {metrics['recall_display']}")
print(f"F1 Score: {metrics['f1_score_display']}")
print("\nOptimized model saved as evoguard_optimized_model.pkl")
print("Model metrics saved as model_metrics.json")
