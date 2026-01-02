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
        # Debug: Check if ciphertext is valid base64
        ct = base64.b64decode(ciphertext.encode())
        
        cipher = Cipher(algorithms.AES(AES_KEY), modes.ECB(), default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ct) + decryptor.finalize()
        
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()
        
        return data.decode()
    except Exception as e:
        print(f"Decryption error: {str(e)}")  # Vercel logs mein dikhega
        return None

@app.route('/robots.txt')
def robots():
    return "User-agent: *\nAllow: /", 200, {'Content-Type': 'text/plain'}

@app.route('/')
def home():
    return "<h1>Vehicle API</h1><p>Use: /api/vehicle?vehicle_number=WB24BL7374&key=SALAAR</p>"

@app.route('/api/vehicle', methods=['GET'])
def vehicle_info():
    try:
        vehicle = request.args.get('vehicle_number', '').strip()
        key = request.args.get('key', '').strip()
        
        if not vehicle:
            return jsonify({"success": False, "error": "Missing vehicle_number"}), 400
        
        if key != VALID_KEY:
            return jsonify({"success": False, "error": "Invalid API key"}), 403
        
        # Encrypt
        encrypted = encrypt(vehicle)
        print(f"Encrypted: {encrypted}")  # Debug log
        
        # Call external API
        body = {"4svShi1T5ftaZPNNHhJzig=== ": encrypted}
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        
        response = requests.post(
            "https://rcdetailsapi.vehicleinfo.app/api/vasu_rc_doc_details",
            data=body,
            headers=headers,
            timeout=10
        )
        
        print(f"Response status: {response.status_code}")  # Debug
        print(f"Response text (first 100 chars): {response.text[:100]}")  # Debug
        
        # Try to decrypt
        decrypted = decrypt(response.text)
        
        if decrypted:
            print(f"Decrypted (first 200 chars): {decrypted[:200]}")  # Debug
            
            data = json.loads(decrypted)
            mobile = None
            
            # Search for mobile number
            if "data" in data and data["data"]:
                item = data["data"][0]
                for k in ['mobile_no', 'mobileNo', 'mobileNumber', 'mobile', 'phone']:
                    if k in item:
                        mobile = str(item[k])
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
                    "error": "Mobile number not found"
                }), 404
        else:
            # Agar decrypt nahi ho raha, try direct JSON parse
            try:
                data = json.loads(response.text)
                return jsonify({
                    "success": False,
                    "error": "Response already in plain text",
                    "raw_response": data
                })
            except:
                return jsonify({
                    "success": False,
                    "error": "Decryption failed",
                    "debug_info": {
                        "response_length": len(response.text),
                        "response_preview": response.text[:100] if response.text else "empty"
                    }
                }), 500
            
    except Exception as e:
        print(f"API error: {str(e)}")  # Debug
        return jsonify({"success": False, "error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
else:
    application = app