import joblib
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from google import genai
from google.colab import userdata
import os

# Initialize FastAPI app
app = FastAPI(title="Phishing and Scam Detection API")

# Global placeholders for models
model_ml = None
vectorizer = None
client = None
MODEL_NAME = "gemini-2.5-flash-lite" # Using a stable, fast model

class MessageRequest(BaseModel):
    message: str

@app.on_event("startup")
def load_resources():
    global model_ml, vectorizer, client
    # Load classical ML models
    try:
        model_ml = joblib.load("message_classifier_logreg.joblib")
        vectorizer = joblib.load("tfidf_vectorizer.joblib")
    except Exception as e:
        print(f"Error loading ML models: {e}")

    # Initialize Gemini Client
    try:
        api_key = os.environ.get("GOOGLE_API_KEY")
        if api_key:
            client = genai.Client(api_key=api_key)
    except Exception as e:
        print(f"Error initializing Gemini client: {e}")

SYSTEM_PROMPT = """You are a phishing/scam detection assistant. Given a message, analyze it for signs of
phishing, scam, or social engineering intent. Look specifically for:
- Urgency or pressure tactics
- Requests for sensitive info (OTP, password, PIN, bank details)
- Impersonation of a trusted entity (bank, government, delivery company, relative)
- Suspicious links or unrealistic offers

Respond ONLY in this exact format:
Risk: <Low/Medium/High>
Signals: <comma-separated list of triggered signals, or "None">
Explanation: <one sentence explaining the verdict>
"""

@app.post("/analyze")
def analyze_message(payload: MessageRequest):
    if model_ml is None or vectorizer is None:
        raise HTTPException(status_code=500, detail="ML models are not loaded.")

    # 1. Get classical ML model prediction
    vec = vectorizer.transform([payload.message])
    prediction = model_ml.predict(vec)[0]
    probs = model_ml.predict_proba(vec)[0]
    confidence = dict(zip(model_ml.classes_, [float(p) for p in probs]))

    # 2. Get LLM feedback if Gemini client is available
    llm_verdict = "LLM analysis unavailable"
    if client:
        try:
            full_prompt = f"{SYSTEM_PROMPT}\n\nMessage to analyze:\n{payload.message}"
            response = client.models.generate_content(
                model=MODEL_NAME,
                contents=full_prompt,
            )
            llm_verdict = response.text.strip()
        except Exception as e:
            llm_verdict = f"Error calling LLM: {str(e)}"

    return {
        "message": payload.message,
        "ml_model": {
            "prediction": prediction,
            "confidence_scores": confidence
        },
        "llm_analysis": llm_verdict
    }
