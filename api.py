from flask import Flask, request, jsonify
import json
import requests
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64

app = Flask(__name__)

AES_KEY = b"RTO@N@1V@$U2024#"
VALID_KEY = "SALAAR"

def encrypt(text):
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(text.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(AES_KEY), modes.ECB(), default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(ct).decode()

def decrypt(ciphertext):
    try:
        ct = base64.b64decode(ciphertext.encode())
        cipher = Cipher(algorithms.AES(AES_KEY), modes.ECB(), default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ct) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()
        return data.decode()
    except:
        return None

@app.route('/')
def home():
    return "Vehicle API - Use /api/vehicle?vehicle_number=XXX&key=SALAAR"

@app.route('/robots.txt')
def robots():
    return "User-agent: *\nAllow: /"

@app.route('/api/vehicle', methods=['GET'])
def vehicle_info():
    try:
        vehicle = request.args.get('vehicle_number', '').strip()
        key = request.args.get('key', '').strip()
        
        if not vehicle:
            return jsonify({"error": "vehicle_number required"}), 400
        
        if key != VALID_KEY:
            return jsonify({"error": "Invalid key"}), 403
        
        encrypted = encrypt(vehicle)
        body = {"4svShi1T5ftaZPNNHhJzig=== ": encrypted}
        
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "Mozilla/5.0"
        }
        
        resp = requests.post(
            "https://rcdetailsapi.vehicleinfo.app/api/vasu_rc_doc_details",
            data=body,
            headers=headers,
            timeout=10
        )
        
        decrypted = decrypt(resp.text)
        
        if not decrypted:
            return jsonify({"error": "Decryption failed"}), 500
        
        data = json.loads(decrypted)
        mobile = None
        
        # Search in data array
        if "data" in data and data["data"] and isinstance(data["data"], list):
            item = data["data"][0]
            for k in ['mobile_no', 'mobileNo', 'mobileNumber', 'mobile', 'phone']:
                if k in item:
                    mobile = str(item[k])
                    break
        
        # Search in rc_data
        if not mobile and "rc_data" in data and isinstance(data["rc_data"], dict):
            rc = data["rc_data"]
            for k in ['mobile_no', 'mobileNo', 'mobileNumber', 'mobile', 'phone']:
                if k in rc:
                    mobile = str(rc[k])
                    break
        
        if mobile:
            return jsonify({
                "success": True,
                "vehicle_number": vehicle,
                "mobile_number": mobile
            })
        else:
            return jsonify({
                "success": False,
                "vehicle_number": vehicle,
                "error": "Mobile not found"
            }), 404
            
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Vercel specific
def handler(event, context):
    return app(event, context)

if __name__ == "__main__":
    app.run()