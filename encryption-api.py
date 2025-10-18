# app.py
from flask import Flask, request, jsonify
from flask_cors import CORS
from cryptography.fernet import Fernet
import os
import logging
from datetime import datetime

# ロギングの設定
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)  # CORS対応（必要に応じて設定を調整）

# 暗号化キーの初期化
def initialize_cipher():
    """暗号化キーを環境変数から取得し、Fernetオブジェクトを初期化"""
    key = os.environ.get("FERNET_KEY")
    
    if not key:
        # 本番環境では必ず環境変数を設定すること
        logger.error("FERNET_KEY not found in environment variables!")
        logger.info("Generate a key using: python3 -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\"")
        return None
    
    try:
        # キーの形式を検証
        cipher = Fernet(key.encode())
        logger.info("Cipher initialized successfully")
        return cipher
    except Exception as e:
        logger.error(f"Invalid FERNET_KEY format: {e}")
        return None

# グローバル変数として暗号化オブジェクトを初期化
cipher = initialize_cipher()

@app.route('/', methods=['GET'])
def home():
    """ホームページ - API情報を表示"""
    return jsonify({
        'service': 'Encryption API',
        'version': '1.0.0',
        'status': 'active' if cipher else 'error',
        'timestamp': datetime.utcnow().isoformat(),
        'endpoints': {
            'encrypt': '/encrypt (POST)',
            'decrypt': '/decrypt (POST)',
            'health': '/health (GET)',
            'generate_key': '/generate-key (GET)'
        }
    }), 200 if cipher else 503

@app.route('/health', methods=['GET'])
def health_check():
    """ヘルスチェックエンドポイント"""
    if cipher is None:
        return jsonify({
            'status': 'unhealthy',
            'message': 'Cipher not initialized. Check FERNET_KEY environment variable.',
            'timestamp': datetime.utcnow().isoformat()
        }), 503
    
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat()
    }), 200

@app.route('/encrypt', methods=['POST'])
def encrypt():
    """RawIDを暗号化してSurveyIDを返す"""
    try:
        # cipherが初期化されているかチェック
        if cipher is None:
            return jsonify({
                'error': 'Encryption service unavailable',
                'message': 'FERNET_KEY not configured'
            }), 503
        
        # リクエストデータの取得
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
        
        raw_id = data.get('RawID')
        if not raw_id:
            return jsonify({'error': 'RawID is required'}), 400
        
        # 文字列型であることを確認
        if not isinstance(raw_id, str):
            raw_id = str(raw_id)
        
        # 空文字列チェック
        if not raw_id.strip():
            return jsonify({'error': 'RawID cannot be empty'}), 400
        
        # 暗号化
        encrypted_bytes = cipher.encrypt(raw_id.encode('utf-8'))
        encrypted_str = encrypted_bytes.decode('utf-8')
        
        logger.info(f"Successfully encrypted RawID (length: {len(raw_id)})")
        return jsonify({
            'SurveyID': encrypted_str,
            'status': 'success'
        }), 200
        
    except Exception as e:
        logger.error(f"Encryption error: {e}")
        return jsonify({
            'error': 'Encryption failed',
            'message': str(e)
        }), 500

@app.route('/decrypt', methods=['POST'])
def decrypt():
    """SurveyIDを復号化してRawIDを返す"""
    try:
        # cipherが初期化されているかチェック
        if cipher is None:
            return jsonify({
                'error': 'Decryption service unavailable',
                'message': 'FERNET_KEY not configured'
            }), 503
        
        # リクエストデータの取得
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
        
        survey_id = data.get('SurveyID')
        if not survey_id:
            return jsonify({'error': 'SurveyID is required'}), 400
        
        # 空文字列チェック
        if not survey_id.strip():
            return jsonify({'error': 'SurveyID cannot be empty'}), 400
        
        # 復号化
        decrypted_bytes = cipher.decrypt(survey_id.encode('utf-8'))
        decrypted_str = decrypted_bytes.decode('utf-8')
        
        logger.info("Successfully decrypted SurveyID")
        return jsonify({
            'RawID': decrypted_str,
            'status': 'success'
        }), 200
        
    except Exception as e:
        logger.error(f"Decryption error: {e}")
        # より具体的なエラーメッセージ
        if "Invalid token" in str(e) or "decrypt" in str(e).lower():
            return jsonify({
                'error': 'Invalid or corrupted SurveyID',
                'message': 'The provided SurveyID could not be decrypted'
            }), 400
        return jsonify({
            'error': 'Decryption failed',
            'message': str(e)
        }), 500

@app.route('/generate-key', methods=['GET'])
def generate_key():
    """新しい暗号化キーを生成（開発用）"""
    new_key = Fernet.generate_key().decode()
    return jsonify({
        'key': new_key,
        'message': 'Save this key as FERNET_KEY environment variable in Render',
        'warning': 'Keep this key secret and secure!'
    }), 200

@app.errorhandler(404)
def not_found(e):
    return jsonify({
        'error': 'Endpoint not found',
        'message': 'Please check the API documentation'
    }), 404

@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({
        'error': 'Method not allowed',
        'message': 'Please check the allowed HTTP methods for this endpoint'
    }), 405

@app.errorhandler(500)
def internal_error(e):
    logger.error(f"Internal server error: {e}")
    return jsonify({
        'error': 'Internal server error',
        'message': 'An unexpected error occurred'
    }), 500

# Renderでの実行用
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port)