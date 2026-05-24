import pandas as pd
import joblib

model = joblib.load("evoguard_model.pkl")
label_encoders = joblib.load("label_encoders.pkl")

print("EvoGuard Attack Simulation Started!\n")

# Same column order used during training
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
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate"
]

attack_samples = {
    "Normal Traffic": [0, "tcp", "http", "SF", 181, 5450, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9, 9, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 9, 9, 1.0, 0.0, 0.11, 0.0, 0.0, 0.0, 0.0, 0.0],
    "DoS Style Traffic": [0, "tcp", "private", "S0", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 300, 300, 1.0, 1.0, 0.0, 0.0, 0.01, 0.06, 0.0, 255, 10, 0.04, 0.06, 0.0, 0.0, 1.0, 1.0, 0.0, 0.0],
    "Probe Scan Traffic": [0, "tcp", "private", "REJ", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 100, 1, 0.0, 0.0, 1.0, 1.0, 0.01, 0.07, 0.0, 255, 1, 0.0, 0.07, 0.0, 0.0, 0.0, 0.0, 1.0, 1.0],
    "Brute Force Style Traffic": [0, "tcp", "ftp", "SF", 100, 200, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 20, 20, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 100, 20, 0.2, 0.1, 0.05, 0.0, 0.0, 0.0, 0.0, 0.0],
    "Privilege Escalation Style Traffic": [10, "tcp", "telnet", "SF", 500, 1000, 0, 0, 0, 5, 2, 1, 3, 1, 1, 5, 3, 1, 2, 0, 0, 1, 5, 5, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 50, 5, 0.1, 0.1, 0.02, 0.0, 0.0, 0.0, 0.0, 0.0]
}

for name, values in attack_samples.items():
    df = pd.DataFrame([values], columns=columns)

    for col in ["protocol_type", "service", "flag"]:
        df[col] = label_encoders[col].transform(df[col])

    prediction = model.predict(df)
    attack_label = label_encoders["label"].inverse_transform(prediction)[0]

    print(f"Scenario: {name}")
    print(f"Prediction: {attack_label}")
    print("-" * 40)