import json
import base64
import requests
from flask import Flask, jsonify
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)

# === AES CONFIG ===
AES_KEY = b"RTO@N@1V@$U2024#"
AES_ALGORITHM = algorithms.AES(AES_KEY)

# === ENCRYPT ===
def encrypt(text):
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(text.encode("utf-8")) + padder.finalize()
    cipher = Cipher(AES_ALGORITHM, modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(ct).decode("utf-8")

# === DECRYPT ===
def decrypt(ciphertext):
    try:
        ct = base64.b64decode(ciphertext.encode("utf-8"))
        cipher = Cipher(AES_ALGORITHM, modes.ECB(), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ct) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()
        return data.decode("utf-8")
    except Exception:
        return None

# === API ROUTE ===
@app.route("/Vehicle/<vehicle_number>", methods=["GET"])
def get_vehicle(vehicle_number):
    try:
        encrypted = encrypt(vehicle_number)

        body = {
            "4svShi1T5ftaZPNNHhJzig=== ": encrypted
        }

        response = requests.post(
            "https://rcdetailsapi.vehicleinfo.app/api/vasu_rc_doc_details",
            data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=20
        )

        response.raise_for_status()
        raw_response = response.text

        decrypted = decrypt(raw_response)

        if decrypted:
            data = json.loads(decrypted)
        else:
            data = json.loads(raw_response)

        # ✅ CORRECT MOBILE NUMBER EXTRACTION
        mobile_no = None
        records = data.get("data")

        if isinstance(records, list) and len(records) > 0:
            mobile_no = records[0].get("mobile_no")

        return jsonify({
            "vehicle_number": vehicle_number,
            "mobile_no": mobile_no
        })

    except requests.exceptions.RequestException as err:
        return jsonify({
            "error": "Upstream API failed",
            "details": str(err)
        }), 502

    except Exception as err:
        return jsonify({
            "error": "Internal error",
            "details": str(err)
        }), 500

# === START SERVER ===
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)