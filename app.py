from flask import Flask, request, jsonify, redirect
from flask_cors import CORS
from cryptography.fernet import Fernet, InvalidToken
import os
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("encryption-api")

app = Flask(__name__)
CORS(app)


def get_cipher():
    """環境変数から鍵を取得して Fernet インスタンスを返す。"""
    key = os.environ.get("FERNET_KEY")
    if not key:
        return None, "FERNET_KEY is not set"
    try:
        # Render の Environment には str を入れる想定
        return Fernet(key.encode()), None
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
    """
    入力: {"RawID": "<平文ID>"} -> 出力: {"SurveyID": "<暗号トークン>", "status": "success"}
    """
    cipher, err = get_cipher()
    if err:
        return jsonify({"error": err}), 500

    data = request.get_json(silent=True) or {}
    raw = data.get("RawID")
    if not raw:
        return jsonify({"error": "RawID is required"}), 400
    if not isinstance(raw, str):
        return jsonify({"error": "RawID must be a string"}), 400
    if len(raw) > 256:
        return jsonify({"error": "RawID too long"}), 400

    token = cipher.encrypt(raw.encode()).decode()
    logger.info("Encrypted RawID (len=%d) -> token (len=%d)", len(raw), len(token))
    return jsonify({"SurveyID": token, "status": "success"})


@app.post("/decrypt")
def decrypt():
    """
    入力: {"SurveyID": "<暗号トークン>"} -> 出力: {"RawID": "<平文ID>", "status": "success"}
    """
    cipher, err = get_cipher()
    if err:
        return jsonify({"error": err}), 500

    data = request.get_json(silent=True) or {}
    survey = data.get("SurveyID")
    if not survey:
        return jsonify({"error": "SurveyID is required"}), 400
    if not isinstance(survey, str):
        return jsonify({"error": "SurveyID must be a string"}), 400

    try:
        raw = cipher.decrypt(survey.encode()).decode()
    except InvalidToken:
        return jsonify({"error": "Invalid or corrupted SurveyID"}), 400

    logger.info("Decrypted token (len=%d) -> RawID (len=%d)", len(survey), len(raw))
    return jsonify({"RawID": raw, "status": "success"})


@app.get("/generate-key")
def generate_key():
    """開発用途: Fernet 鍵を生成（本番では使わず、Environment で管理）"""
    return jsonify({"FERNET_KEY": Fernet.generate_key().decode()})


@app.get("/prefill")
def prefill():
    """
    Power Apps からの起動用。
    例:
      GET /prefill?raw=TEST-RAW-001&template=<URLエンコード済みテンプレート>&tx=...
    - raw: 暗号化する元のID（必須）
    - template: "ID" というプレースホルダを含む MS Forms の事前入力URL（必須）
    - tx: 任意のトレーサ（ログ用途）
    処理:
      raw を暗号化 → template の "ID" をトークンに置換 → 302 Redirect
    """
    raw = request.args.get("raw", "")
    template = request.args.get("template", "")
    tx = request.args.get("tx")  # 任意（ログ用）

    if not raw or not template:
        return jsonify({"error": "raw and template are required"}), 400
    if len(raw) > 256:
        return jsonify({"error": "raw too long"}), 400

    cipher, err = get_cipher()
    if err:
        return jsonify({"error": err}), 500

    token = cipher.encrypt(raw.encode()).decode()

    # Power Apps 側で EncodeUrl 済みの template に対して "ID" を文字列置換
    filled = template.replace("ID", token)

    logger.info("prefill tx=%s raw_len=%d token_len=%d", tx, len(raw), len(token))
    return redirect(filled, code=302)


# ローカル実行用（Render では gunicorn が使われます）
if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=True)
