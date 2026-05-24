from agentic_ai import agentic_analysis
from attack_mapper import map_attack_category
import pandas as pd
import joblib

model = joblib.load("evoguard_model.pkl")
label_encoders = joblib.load("label_encoders.pkl")

file_path = r"C:\Users\M\Desktop\EvoGuard-Enterprise\data\raw\nsl_kdd_train.txt"

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
    "label", "difficulty_level"
]

df = pd.read_csv(file_path, names=columns)
df = df.drop("difficulty_level", axis=1)

# Test one real sample from each available attack label
labels_to_test = ["normal", "neptune", "satan", "guess_passwd", "buffer_overflow"]

for label in labels_to_test:
    sample = df[df["label"] == label].head(1)

    if sample.empty:
        print(f"No sample found for: {label}")
        continue

    actual_label = sample["label"].values[0]
    X = sample.drop("label", axis=1)

    for col in ["protocol_type", "service", "flag"]:
        X[col] = label_encoders[col].transform(X[col])

    prediction = model.predict(X)
    predicted_label = label_encoders["label"].inverse_transform(prediction)[0]

    category = map_attack_category(predicted_label)

    analysis = agentic_analysis(predicted_label)

    print(f"Actual Attack: {actual_label}")
    print(f"EvoGuard Prediction: {analysis['attack_label']}")
    print(f"Attack Category: {analysis['attack_category']}")
    print(f"Risk Score: {analysis['risk_score']}/100")
    print(f"Risk Level: {analysis['risk_level']}")
    print(f"Explanation: {analysis['explanation']}")
    print("Recommended Actions:")
    for action in analysis["recommended_actions"]:
        print(f"- {action}")
    print("-" * 40)