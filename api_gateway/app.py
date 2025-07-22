from flask import Flask, request, jsonify
import requests

app = Flask(__name__)

# ENCRYPTION_URL = 'http://encryption_service:5011/encrypt'
# DECRYPTION_URL = 'http://decryption_service:5012/decrypt'

ENCRYPTION_URL = 'http://localhost:5011/encrypt'
DECRYPTION_URL = 'http://localhost:5012/decrypt'

@app.route('/')
def index():
    return {"status": "API Gateway Online"}

@app.route('/encrypt', methods=['POST'])
def encrypt():
    resp = requests.post(ENCRYPTION_URL, data=request.form, headers=request.headers)
    return jsonify(resp.json())

@app.route('/decrypt', methods=['POST'])
def decrypt():
    resp = requests.post(DECRYPTION_URL, data=request.form, headers=request.headers)
    return jsonify(resp.json())

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5050)