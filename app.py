from flask import Flask, request, jsonify
from flask_cors import CORS
from cryptography.fernet import Fernet, InvalidToken
import os
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("encryption-api")

app = Flask(__name__)
CORS(app)

def get_cipher():
    key = os.environ.get("FERNET_KEY")
    if not key:
        return None, "FERNET_KEY is not set"
    try:
        return Fernet(key.encode() if not key.startswith("gAAAA") else key), None
    except Exception as e:
        return None, f"Invalid FERNET_KEY: {e}"

@app.get("/")
def root():
    return jsonify({"name": "encryption-api", "status": "ok"})

@app.get("/health")
def health():
    return jsonify({"status": "healthy"})

@app.post("/encrypt")
def encrypt():
    cipher, err = get_cipher()
    if err:
        return jsonify({"error": err}), 500
    data = request.get_json(silent=True) or {}
    raw = data.get("RawID")
    if not raw:
        return jsonify({"error": "RawID is required"}), 400
    token = cipher.encrypt(raw.encode()).decode()
    return jsonify({"SurveyID": token, "status": "success"})

@app.post("/decrypt")
def decrypt():
    cipher, err = get_cipher()
    if err:
        return jsonify({"error": err}), 500
    data = request.get_json(silent=True) or {}
    survey = data.get("SurveyID")
    if not survey:
        return jsonify({"error": "SurveyID is required"}), 400
    try:
        raw = cipher.decrypt(survey.encode()).decode()
    except InvalidToken:
        return jsonify({"error": "Invalid or corrupted SurveyID"}), 400
    return jsonify({"RawID": raw, "status": "success"})

@app.get("/generate-key")
def generate_key():
    return jsonify({"FERNET_KEY": Fernet.generate_key().decode()})

# ローカル実行用（Render では gunicorn が使われます）
if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=True)
