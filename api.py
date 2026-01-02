from flask import Flask, request, jsonify
import json
import requests
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import random

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
    except Exception as e:
        print(f"Decrypt error: {e}")
        return None

# Random User-Agents list
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1"
]

def get_random_user_agent():
    return random.choice(USER_AGENTS)

@app.route('/robots.txt')
def robots():
    return "User-agent: *\nAllow: /", 200, {'Content-Type': 'text/plain'}

@app.route('/')
def home():
    return "<h1>🚗 Vehicle Info API</h1><p>Use: /api/vehicle?vehicle_number=WB24BL7374&key=SALAAR</p>"

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
        
        # Prepare request with better headers
        body = {"4svShi1T5ftaZPNNHhJzig=== ": encrypted}
        
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": get_random_user_agent(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Cache-Control": "max-age=0"
        }
        
        # Try multiple attempts if needed
        for attempt in range(3):
            try:
                response = requests.post(
                    "https://rcdetailsapi.vehicleinfo.app/api/vasu_rc_doc_details",
                    data=body,
                    headers=headers,
                    timeout=15,
                    allow_redirects=True
                )
                
                print(f"Attempt {attempt+1}: Status {response.status_code}")
                
                if response.status_code == 200:
                    break
                    
                # Change User-Agent for next attempt
                headers["User-Agent"] = get_random_user_agent()
                
            except Exception as e:
                print(f"Attempt {attempt+1} failed: {e}")
                continue
        
        if response.status_code != 200:
            return jsonify({
                "success": False,
                "error": f"External API returned {response.status_code}",
                "response_preview": response.text[:200] if response.text else "empty"
            }), 502
        
        # Decrypt response
        decrypted = decrypt(response.text)
        
        if not decrypted:
            return jsonify({
                "success": False,
                "error": "Decryption failed",
                "debug": "Check if API response format changed"
            }), 500
        
        # Parse and extract mobile number
        data = json.loads(decrypted)
        mobile = None
        
        # Search in data array
        if "data" in data and isinstance(data["data"], list) and len(data["data"]) > 0:
            item = data["data"][0]
            for k in ['mobile_no', 'mobileNo', 'mobileNumber', 'mobile', 'phone', 'phone_no', 'contact']:
                if k in item:
                    mobile = str(item[k])
                    break
        
        # Search in rc_data
        if not mobile and "rc_data" in data and isinstance(data["rc_data"], dict):
            rc_item = data["rc_data"]
            for k in ['mobile_no', 'mobileNo', 'mobileNumber', 'mobile', 'phone', 'phone_no', 'contact']:
                if k in rc_item:
                    mobile = str(rc_item[k])
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
                "error": "Mobile number not found in response",
                "available_keys": list(data.keys()) if isinstance(data, dict) else "N/A"
            }), 404
            
    except json.JSONDecodeError as e:
        return jsonify({"success": False, "error": f"JSON parse error: {str(e)}"}), 500
    except Exception as e:
        return jsonify({"success": False, "error": f"Internal error: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(debug=True)
else:
    application = app