import numpy as np
from sklearn.ensemble import RandomForestClassifier
import joblib
from feature_extractor import extract_features

# 1. รายการ URL ตัวอย่างสำหรับเทรนโมเดล
urls_safe = [
    "https://google.com",
    "www.google.com",
    "https://www.google.com",
    "https://github.com",
    "https://github.com/68130755-ctrl/Docker-compose",
    "https://aws.amazon.com",
    "https://facebook.com",
    "www.facebook.com"
]

urls_phishing = [
    "www.g00gle.com",
    "https://paypa1.com",
    "http://192.168.1.1/login-verify-account?user=test@paypal.com",
    "http://10.0.0.1/ebay-account-update?verify=true@check",
    "http://login-secure-bank-update.xyz/account",
    "http://secure-update-banking-paypal.com/signin/verify",
    "http://192.168.1.50/account/login",
    "http://verify-your-account-now.com/login"
]

# 2. แปลง URL เป็น Features โดยใช้ feature_extractor ตรงๆ
X_safe = [extract_features(url) for url in urls_safe]
X_phishing = [extract_features(url) for url in urls_phishing]

X_train = np.array(X_safe + X_phishing)
y_train = np.array([0] * len(urls_safe) + [1] * len(urls_phishing))

# 3. เทรนโมเดล Random Forest
model = RandomForestClassifier(n_estimators=30, random_state=42)
model.fit(X_train, y_train)

# 4. บันทึกโมเดล
joblib.dump(model, 'phishing_model.pkl')
print("✅ บันทึกโมเดลฉบับปรับปรุงสมบูรณ์เรียบร้อยแล้ว!")