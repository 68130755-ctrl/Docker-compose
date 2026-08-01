import re
from urllib.parse import urlparse

def extract_features(url: str) -> list:
    features = []
    features.append(len(url))                                # 1. ความยาว URL
    features.append(url.count('.'))                           # 2. จำนวนจุด
    features.append(url.count('-'))                           # 3. จำนวนขีด
    features.append(url.count('@'))                           # 4. จำนวน @
    features.append(url.count('?'))                           # 5. จำนวน ?
    features.append(url.count('='))                           # 6. จำนวน =
    features.append(1 if url.startswith('https://') else 0)   # 7. เช็ก HTTPS
    
    # 8. เช็ก IP Address
    ip_pattern = r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.){3}([01]?\d\d?|2[0-4]\d|25[0-5])'
    features.append(1 if re.search(ip_pattern, url) else 0)
    
    # 9. เช็กคำสุ่มเสี่ยง
    suspicious_keywords = ['login', 'verify', 'account', 'update', 'banking', 'secure', 'paypal', 'signin', 'ebay']
    has_keyword = 1 if any(kw in url.lower() for kw in suspicious_keywords) else 0
    features.append(has_keyword)
    
    # 10. ความยาว Domain Name
    try:
        domain = urlparse(url).netloc
        features.append(len(domain))
    except:
        features.append(0)
        
    return features