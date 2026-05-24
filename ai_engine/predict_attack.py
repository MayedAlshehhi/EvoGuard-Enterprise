import pandas as pd
import joblib

# =========================
# Load Saved Model
# =========================

model = joblib.load("evoguard_model.pkl")
label_encoders = joblib.load("label_encoders.pkl")

print("EvoGuard AI Model Loaded Successfully!")

# =========================
# Example Attack Data
# =========================

sample_data = {
    "duration": [0],
    "protocol_type": ["tcp"],
    "service": ["http"],
    "flag": ["SF"],
    "src_bytes": [181],
    "dst_bytes": [5450],
    "land": [0],
    "wrong_fragment": [0],
    "urgent": [0],
    "hot": [0],
    "num_failed_logins": [0],
    "logged_in": [1],
    "num_compromised": [0],
    "root_shell": [0],
    "su_attempted": [0],
    "num_root": [0],
    "num_file_creations": [0],
    "num_shells": [0],
    "num_access_files": [0],
    "num_outbound_cmds": [0],
    "is_host_login": [0],
    "is_guest_login": [0],
    "count": [9],
    "srv_count": [9],
    "serror_rate": [0.0],
    "srv_serror_rate": [0.0],
    "rerror_rate": [0.0],
    "srv_rerror_rate": [0.0],
    "same_srv_rate": [1.0],
    "diff_srv_rate": [0.0],
    "srv_diff_host_rate": [0.0],
    "dst_host_count": [9],
    "dst_host_srv_count": [9],
    "dst_host_same_srv_rate": [1.0],
    "dst_host_diff_srv_rate": [0.0],
    "dst_host_same_src_port_rate": [0.11],
    "dst_host_srv_diff_host_rate": [0.0],
    "dst_host_serror_rate": [0.0],
    "dst_host_srv_serror_rate": [0.0],
    "dst_host_rerror_rate": [0.0],
    "dst_host_srv_rerror_rate": [0.0]
}

df = pd.DataFrame(sample_data)

# =========================
# Encode Categorical Data
# =========================

df["protocol_type"] = label_encoders["protocol_type"].transform(df["protocol_type"])
df["service"] = label_encoders["service"].transform(df["service"])
df["flag"] = label_encoders["flag"].transform(df["flag"])

# =========================
# Predict Attack
# =========================

prediction = model.predict(df)

attack_label = label_encoders["label"].inverse_transform(prediction)

print("\nPredicted Attack Type:")
print(attack_label[0])