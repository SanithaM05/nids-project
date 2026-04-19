import pandas as pd
import joblib
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import (
    confusion_matrix,
    classification_report,
    accuracy_score,
    precision_score,
    recall_score,
    f1_score
)
import matplotlib.pyplot as plt
import seaborn as sns

# -------- LOAD MODEL --------
model = joblib.load("model.pkl")

# -------- LOAD DATA --------
columns = [
    "duration","protocol_type","service","flag","src_bytes","dst_bytes","land",
    "wrong_fragment","urgent","hot","num_failed_logins","logged_in","num_compromised",
    "root_shell","su_attempted","num_root","num_file_creations","num_shells",
    "num_access_files","num_outbound_cmds","is_host_login","is_guest_login",
    "count","srv_count","serror_rate","srv_serror_rate","rerror_rate",
    "srv_rerror_rate","same_srv_rate","diff_srv_rate","srv_diff_host_rate",
    "dst_host_count","dst_host_srv_count","dst_host_same_srv_rate",
    "dst_host_diff_srv_rate","dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate","dst_host_serror_rate",
    "dst_host_srv_serror_rate","dst_host_rerror_rate",
    "dst_host_srv_rerror_rate","label","difficulty"
]

df = pd.read_csv("KDDTest+.txt", names=columns)

# -------- PREPROCESS --------
df["label"] = df["label"].apply(lambda x: "normal" if x == "normal" else "attack")

le = LabelEncoder()
for col in ["protocol_type","service","flag"]:
    df[col] = le.fit_transform(df[col])

X = df.drop(["label","difficulty"], axis=1)
y = df["label"]

# -------- PREDICT --------
y_pred = model.predict(X)

# -------- METRICS --------
accuracy = accuracy_score(y, y_pred)
precision = precision_score(y, y_pred, pos_label="attack")
recall = recall_score(y, y_pred, pos_label="attack")
f1 = f1_score(y, y_pred, pos_label="attack")

print("\n📊 Evaluation Metrics:")
print(f"Accuracy  : {accuracy:.4f}")
print(f"Precision : {precision:.4f}")
print(f"Recall    : {recall:.4f}")
print(f"F1 Score  : {f1:.4f}")

print("\n📄 Classification Report:")
print(classification_report(y, y_pred))

# -------- CONFUSION MATRIX --------
cm = confusion_matrix(y, y_pred)

plt.figure(figsize=(6,5))
sns.heatmap(cm, annot=True, fmt='d')
plt.title("Confusion Matrix")
plt.xlabel("Predicted")
plt.ylabel("Actual")
plt.savefig("confusion_matrix.png")
plt.close()

# -------- BAR GRAPH --------
metrics = ["Accuracy", "Precision", "Recall", "F1 Score"]
values = [accuracy, precision, recall, f1]

plt.figure(figsize=(6,5))
plt.bar(metrics, values)
plt.title("Model Evaluation Metrics")
plt.ylabel("Score")
plt.ylim(0,1)
plt.savefig("metrics_bar.png")
plt.close()

# -------- PIE CHART --------
plt.figure(figsize=(6,5))
plt.pie(values, labels=metrics, autopct='%1.2f%%')
plt.title("Metrics Distribution")
plt.savefig("metrics_pie.png")
plt.close()

# -------- EXTRA GRAPH (ACCURACY vs ERROR) --------
error = 1 - accuracy

plt.figure(figsize=(6,5))
plt.bar(["Accuracy", "Error"], [accuracy, error])
plt.title("Accuracy vs Error")
plt.savefig("accuracy_error.png")
plt.close()

print("\n✅ Graphs saved successfully!")