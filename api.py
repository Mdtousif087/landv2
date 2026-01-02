from flask import Flask, request, jsonify
import json
import requests
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64

# Flask app create karo
app = Flask(__name__)

# Configuration
AES_KEY = b"RTO@N@1V@$U2024#"
VALID_KEY = "SALAAR"

def encrypt(text):
    """Encrypt vehicle number"""
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(text.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(AES_KEY), modes.ECB(), default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(ct).decode()

def decrypt(ciphertext):
    """Decrypt response"""
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

@app.route('/robots.txt')
def robots():
    return "User-agent: *\nAllow: /", 200, {'Content-Type': 'text/plain'}

@app.route('/favicon.ico')
def favicon():
    return '', 204

@app.route('/')
def home():
    return "<h1>🚗 Vehicle Info API</h1><p>Use: /api/vehicle?vehicle_number=WB24BL7374&key=SALAAR</p>"

@app.route('/api/vehicle', methods=['GET'])
def vehicle_info():
    """Main API endpoint"""
    try:
        # Get parameters
        vehicle = request.args.get('vehicle_number', '').strip()
        key = request.args.get('key', '').strip()
        
        # Validation
        if not vehicle:
            return jsonify({"success": False, "error": "Missing vehicle_number"}), 400
        
        if not key:
            return jsonify({"success": False, "error": "Missing API key"}), 401
        
        if key != VALID_KEY:
            return jsonify({"success": False, "error": "Invalid API key"}), 403
        
        # Encrypt vehicle number
        encrypted = encrypt(vehicle)
        
        # Prepare request to external API
        body = {"4svShi1T5ftaZPNNHhJzig=== ": encrypted}
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "Mozilla/5.0"
        }
        
        # Call external API
        response = requests.post(
            "https://rcdetailsapi.vehicleinfo.app/api/vasu_rc_doc_details",
            data=body,
            headers=headers,
            timeout=20
        )
        
        # Decrypt response
        decrypted = decrypt(response.text)
        
        if not decrypted:
            return jsonify({"success": False, "error": "Failed to decrypt response"}), 500
        
        # Parse JSON
        data = json.loads(decrypted)
        mobile = None
        
        # Search for mobile number in data array
        if "data" in data and isinstance(data["data"], list) and len(data["data"]) > 0:
            item = data["data"][0]
            
            # Try different mobile number keys
            mobile_keys = ['mobile_no', 'mobileNo', 'mobileNumber', 'mobile', 'phone']
            for k in mobile_keys:
                if k in item:
                    mobile = str(item[k])
                    break
        
        # If not found, check rc_data
        if not mobile and "rc_data" in data and isinstance(data["rc_data"], dict):
            rc_item = data["rc_data"]
            mobile_keys = ['mobile_no', 'mobileNo', 'mobileNumber', 'mobile', 'phone']
            for k in mobile_keys:
                if k in rc_item:
                    mobile = str(rc_item[k])
                    break
        
        # Return response
        if mobile:
            return jsonify({
                "success": True,
                "vehicle_number": vehicle,
                "mobile_number": mobile,
                "message": "Success"
            })
        else:
            return jsonify({
                "success": False,
                "vehicle_number": vehicle,
                "error": "Mobile number not found in database"
            }), 404
            
    except requests.exceptions.RequestException as e:
        return jsonify({"success": False, "error": f"API request failed: {str(e)}"}), 500
    except json.JSONDecodeError as e:
        return jsonify({"success": False, "error": f"Invalid JSON response: {str(e)}"}), 500
    except Exception as e:
        return jsonify({"success": False, "error": f"Internal error: {str(e)}"}), 500

# Vercel requires this
if __name__ == '__main__':
    app.run(debug=True)
else:
    # For Vercel serverless
    application = app