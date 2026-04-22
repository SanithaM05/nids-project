from fastapi import FastAPI
from pydantic import BaseModel
import joblib
import numpy as np

app = FastAPI(
    title="Network Intrusion Detection API",
    description="Detects malicious network traffic",
    version="1.0"
)

# Load model
model = joblib.load("model.pkl")

# Define input format
class InputData(BaseModel):
    features: list

# Home
@app.get("/")
def home():
    return {"message": "NIDS API Running 🚀"}

# Prediction
@app.post("/predict")
def predict(data: InputData):
    try:
        arr = np.array(data.features).reshape(1, -1)
        pred = model.predict(arr)[0]

        return {
            "prediction": str(pred),
            "result": "Attack 🚨" if pred == 1 else "Normal ✅"
        }

    except Exception as e:
        return {"error": str(e)}