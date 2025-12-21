import axios from "axios";
import crypto from "crypto";


const AES_KEY = process.env.AES_KEY;
const API_ENDPOINT = process.env.API_ENDPOINT;
const API_KEY_PARAM = process.env.API_KEY_PARAM;
const API_ACCESS_KEY = process.env.API_ACCESS_KEY;

const AES_ALGORITHM = "aes-128-ecb";

function encrypt(text) {
  const cipher = crypto.createCipheriv(
    AES_ALGORITHM,
    Buffer.from(AES_KEY, "utf8"),
    null
  );
  let encrypted = cipher.update(text, "utf8", "base64");
  encrypted += cipher.final("base64");
  return encrypted;
}

function decrypt(ciphertext) {
  try {
    const decipher = crypto.createDecipheriv(
      AES_ALGORITHM,
      Buffer.from(AES_KEY, "utf8"),
      null
    );
    let decrypted = decipher.update(ciphertext, "base64", "utf8");
    decrypted += decipher.final("utf8");
    return decrypted;
  } catch {
    return null;
  }
}

export default async function handler(req, res) {
  res.setHeader("Content-Type", "application/json");
  res.setHeader("Access-Control-Allow-Origin", "*");

  const vehicle_number = req.query.vehicle_number;
  const key = req.query.key; // ✅ Key parameter

  // ✅ Check API key authentication
  if (!key || key !== API_ACCESS_KEY) {
    return res.status(401).json({
      error: "Unauthorized",
      message: "Valid API key required"
    });
  }

  if (!vehicle_number) {
    return res.status(400).json({
      error: "Missing vehicle_number parameter"
    });
  }

  try {
    const encrypted = encrypt(vehicle_number);

    const body = new URLSearchParams();
    body.append(API_KEY_PARAM, encrypted);

    const response = await axios.post(
      API_ENDPOINT,
      body.toString(),
      {
        headers: {
          "Content-Type": "application/x-www-form-urlencoded"
        },
        timeout: 20000
      }
    );

    let data = response.data;

    if (typeof data === "string") {
      const dec = decrypt(data);
      if (dec) data = JSON.parse(dec);
    }

    const mobile = data?.data?.[0]?.mobile_no;

    if (!mobile) {
      return res.json({ error: "Details not found" });
    }

    return res.json({
      vehicleNumber: vehicle_number.toUpperCase(),
      mobileNo: String(mobile)
    });

  } catch (err) {
    console.error("UPSTREAM ERROR:", err.message);
    return res.status(500).json({
      error: "API not working",
      hint: "Upstream rejected request"
    });
  }
}