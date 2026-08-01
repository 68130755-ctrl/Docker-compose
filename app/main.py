from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import joblib
import numpy as np
import os
from feature_extractor import extract_features

app = FastAPI(title="Phishing URL Detector", version="1.0.0")

MODEL_PATH = "phishing_model.pkl"
model = joblib.load(MODEL_PATH) if os.path.exists(MODEL_PATH) else None

class URLRequest(BaseModel):
    url: str

@app.get("/", response_class=HTMLResponse)
def get_ui():
    return """
    <!DOCTYPE html>
    <html lang="th">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Phishing URL Detector</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <style>
            body { background-color: #f4f6f9; font-family: sans-serif; }
            .main-card { max-width: 650px; margin: 60px auto; border-radius: 15px; box-shadow: 0 8px 20px rgba(0,0,0,0.08); }
            .card-header { background: linear-gradient(135deg, #0d6efd, #0d47a1); color: white; border-radius: 15px 15px 0 0 !important; padding: 25px; }
            .result-box { display: none; border-radius: 10px; padding: 20px; margin-top: 25px; }
            .example-btn { cursor: pointer; text-decoration: underline; color: #0d6efd; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="card main-card">
                <div class="card-header text-center">
                    <h3 class="mb-1">🛡️ Phishing URL Detector</h3>
                    <p class="mb-0 opacity-75">ระบบตรวจจับ URL หลอกลวงด้วย Machine Learning</p>
                </div>
                <div class="card-body p-4">
                    <form id="urlForm">
                        <div class="mb-3">
                            <label for="urlInput" class="form-label fw-bold">กรอก URL ที่ต้องการตรวจสอบ:</label>
                            <input type="text" class="form-control form-control-lg" id="urlInput" placeholder="https://example.com" required>
                        </div>
                        <button type="submit" class="btn btn-primary btn-lg w-100" id="submitBtn">🔍 ตรวจสอบความปลอดภัย</button>
                    </form>

                    <div class="mt-3 text-muted small">
                        <span>ตัวอย่างทดสอบ: </span>
                        <span class="example-btn me-2" onclick="setExample('https://github.com/68130755-ctrl/Docker-compose')">เว็บปกติ</span> |
                        <span class="example-btn ms-2" onclick="setExample('http://192.168.1.1/login-verify-account?user=test@paypal.com')">เว็บ Phishing</span>
                    </div>

                    <div id="resultBox" class="result-box text-center">
                        <h4 id="resultTitle" class="fw-bold mb-2"></h4>
                        <p id="resultConfidence" class="mb-3"></p>
                        <hr>
                        <div class="text-start small text-secondary">
                            <strong>ผลการวิเคราะห์ฟีเจอร์:</strong>
                            <ul id="featureList" class="mt-2 mb-0"></ul>
                        </div>
                    </div>
                </div>
                <div class="card-footer text-center text-muted py-3 bg-white border-0">
                    <small>ผู้พัฒนา: พัชรพร ตาอินทร์ (68130755)</small>
                </div>
            </div>
        </div>

        <script>
            function setExample(url) { document.getElementById('urlInput').value = url; }

            document.getElementById('urlForm').addEventListener('submit', async function(e) {
                e.preventDefault();
                const url = document.getElementById('urlInput').value.trim();
                const submitBtn = document.getElementById('submitBtn');
                const resultBox = document.getElementById('resultBox');

                submitBtn.disabled = true;
                submitBtn.innerHTML = '⏳ กำลังประมวลผล...';
                resultBox.style.display = 'none';

                try {
                    const response = await fetch('/predict', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ url: url })
                    });
                    const data = await response.json();
                    submitBtn.disabled = false;
                    submitBtn.innerHTML = '🔍 ตรวจสอบความปลอดภัย';

                    if (response.ok) {
                        resultBox.style.display = 'block';
                        resultBox.className = data.is_phishing ? 'result-box alert alert-danger' : 'result-box alert alert-success';
                        document.getElementById('resultTitle').innerText = (data.is_phishing ? '🚨 ' : '✅ ') + data.prediction;
                        document.getElementById('resultConfidence').innerText = 'ความเชื่อมั่นของโมเดล: ' + data.confidence;

                        const feats = data.extracted_features;
                        document.getElementById('featureList').innerHTML = `
                            <li>โปรโตคอล HTTPS: ${feats.is_https ? '✔️ มีการใช้' : '❌ ไม่ได้ใช้'}</li>
                            <li>การใช้ IP Address แทน Domain: ${feats.is_ip_address ? '⚠️ พบการใช้งาน' : '✔️ ไม่พบ'}</li>
                            <li>คำสุ่มเสี่ยงหลอกลวง: ${feats.has_suspicious_keyword ? '⚠️ พบคำสุ่มเสี่ยง' : '✔️ ไม่พบ'}</li>
                            <li>ความยาว URL / จำนวนจุด (.): ${feats.url_length} ตัวอักษร / ${feats.dot_count} จุด</li>
                        `;
                    }
                } catch (err) {
                    submitBtn.disabled = false;
                    submitBtn.innerHTML = '🔍 ตรวจสอบความปลอดภัย';
                    alert('ไม่สามารถเชื่อมต่อเซิร์ฟเวอร์ได้');
                }
            });
        </script>
    </body>
    </html>
    """

@app.post("/predict")
def predict_url(payload: URLRequest):
    if not model:
        raise HTTPException(status_code=500, detail="Model file not found!")
    
    url = payload.url.strip()
    features = extract_features(url)
    features_array = np.array([features])
    
    prediction = model.predict(features_array)[0]
    probabilities = model.predict_proba(features_array)[0]
    
    result_label = "Phishing URL (อันตราย)" if prediction == 1 else "Legitimate URL (ปลอดภัย)"
    confidence = round(float(np.max(probabilities)) * 100, 2)
    
    return {
        "input_url": url,
        "prediction": result_label,
        "is_phishing": bool(prediction == 1),
        "confidence": f"{confidence}%",
        "extracted_features": {
            "url_length": features[0],
            "dot_count": features[1],
            "is_https": bool(features[6]),
            "is_ip_address": bool(features[7]),
            "has_suspicious_keyword": bool(features[8])
        }
    }