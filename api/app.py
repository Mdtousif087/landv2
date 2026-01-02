# app.py
from flask import Flask, request, jsonify
import json
import requests
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64

app = Flask(__name__)

# Configuration
AES_KEY = b"RTO@N@1V@$U2024#"
AES_ALGORITHM = algorithms.AES(AES_KEY)
VALID_KEY = "SALAAR"  # Your API key

def encrypt(text):
    """Encrypt text using AES"""
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(text.encode('utf-8')) + padder.finalize()
    cipher = Cipher(AES_ALGORITHM, modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(ct).decode('utf-8')

def decrypt(ciphertext):
    """Decrypt text using AES"""
    try:
        ct = base64.b64decode(ciphertext.encode('utf-8'))
        cipher = Cipher(AES_ALGORITHM, modes.ECB(), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ct) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()
        return data.decode('utf-8')
    except Exception:
        return None

def get_mobile_number(vehicle_number):
    """Fetch mobile number for given vehicle number"""
    try:
        encrypted = encrypt(vehicle_number)

        body = {
            "4svShi1T5ftaZPNNHhJzig=== ": encrypted
        }

        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }

        response = requests.post(
            "https://rcdetailsapi.vehicleinfo.app/api/vasu_rc_doc_details",
            data=body,
            headers=headers,
            timeout=20
        )

        response.raise_for_status()
        raw_response = response.text
        decrypted = decrypt(raw_response)

        if decrypted:
            json_data = json.loads(decrypted)
            
            # Search for mobile number in data
            mobile_number = None
            
            # First check in 'data' array
            if "data" in json_data and isinstance(json_data["data"], list) and len(json_data["data"]) > 0:
                data_item = json_data["data"][0]
                
                # Check all possible mobile number keys
                mobile_keys = ['mobile_no', 'mobileNo', 'mobileNumber', 'mobile', 'phone', 'phone_no', 'contact']
                
                for key in mobile_keys:
                    if key in data_item:
                        mobile_number = str(data_item[key])
                        break
            
            # If not found in data, check in rc_data
            if not mobile_number and "rc_data" in json_data and isinstance(json_data["rc_data"], dict):
                rc_data = json_data["rc_data"]
                mobile_keys = ['mobile_no', 'mobileNo', 'mobileNumber', 'mobile', 'phone', 'phone_no', 'contact']
                
                for key in mobile_keys:
                    if key in rc_data:
                        mobile_number = str(rc_data[key])
                        break
            
            return mobile_number
        
    except Exception as e:
        print(f"Error fetching data: {e}")
    
    return None

@app.route('/api/vehicle', methods=['GET'])
def vehicle_info():
    """API endpoint to get vehicle mobile number"""
    # Get parameters
    vehicle_number = request.args.get('vehicle_number', '').strip()
    api_key = request.args.get('key', '').strip()
    
    # Validation
    if not vehicle_number:
        return jsonify({
            "success": False,
            "error": "Missing vehicle_number parameter"
        }), 400
    
    if not api_key:
        return jsonify({
            "success": False,
            "error": "Missing API key"
        }), 401
    
    if api_key != VALID_KEY:
        return jsonify({
            "success": False,
            "error": "Invalid API key"
        }), 403
    
    # Fetch mobile number
    mobile_number = get_mobile_number(vehicle_number)
    
    if mobile_number:
        return jsonify({
            "success": True,
            "vehicle_number": vehicle_number,
            "mobile_number": mobile_number,
            "message": "Data retrieved successfully"
        })
    else:
        return jsonify({
            "success": False,
            "vehicle_number": vehicle_number,
            "error": "Mobile number not found or vehicle not in database"
        }), 404

@app.route('/')
def home():
    """Home page with API documentation"""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Vehicle Information API</title>
        <style>
            body { font-family: Arial, sans-serif; max-width: 800px; margin: 40px auto; padding: 20px; }
            code { background: #f4f4f4; padding: 2px 6px; border-radius: 4px; }
            pre { background: #f4f4f4; padding: 15px; border-radius: 5px; overflow-x: auto; }
        </style>
    </head>
    <body>
        <h1>🚗 Vehicle Information API</h1>
        
        <h2>API Endpoint:</h2>
        <pre>GET /api/vehicle?vehicle_number=WB24BL7374&key=SALAAR</pre>
        
        <h2>Parameters:</h2>
        <ul>
            <li><code>vehicle_number</code> - Vehicle registration number (required)</li>
            <li><code>key</code> - API key (required)</li>
        </ul>
        
        <h2>Success Response:</h2>
        <pre>{
    "success": true,
    "vehicle_number": "WB24BL7374",
    "mobile_number": "6289550995",
    "message": "Data retrieved successfully"
}</pre>
        
        <h2>Error Responses:</h2>
        <pre>{
    "success": false,
    "error": "Missing vehicle_number parameter"
}</pre>
        
        <pre>{
    "success": false,
    "error": "Invalid API key"
}</pre>
        
        <pre>{
    "success": false,
    "vehicle_number": "WB24BL7374",
    "error": "Mobile number not found or vehicle not in database"
}</pre>
    </body>
    </html>
    """

# For Vercel serverless
def handler(event, context):
    return app(event, context)

if __name__ == '__main__':
    app.run(debug=True)
