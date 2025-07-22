import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../shared')))
from crypto_utils import encrypt_core

from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.form.to_dict()
    result = encrypt_core(data, request.headers)
    return jsonify(result)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5011)