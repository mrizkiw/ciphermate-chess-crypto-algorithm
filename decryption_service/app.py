import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../shared')))
from crypto_utils import decrypt_core

from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/decrypt', methods=['POST'])
def decrypt():
    data = request.form.to_dict()
    result = decrypt_core(data, request.headers)
    return jsonify(result)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5012)