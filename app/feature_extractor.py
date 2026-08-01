import re
from urllib.parse import urlparse

def extract_features(url: str) -> list:
    features = []
    
    # เติม http:// ชั่วคราวกรณีผู้ใช้พิมพ์แค่ www. หรือชื่อโดเมนลอยๆ
    full_url = url if '://' in url else 'http://' + url
    
    try:
        domain = urlparse(full_url).netloc.lower()
    except:
        domain = ""

    features.append(len(url))                                # 1. ความยาว URL
    features.append(url.count('.'))                           # 2. จำนวนจุด
    features.append(url.count('-'))                           # 3. จำนวนขีด
    features.append(url.count('@'))                           # 4. จำนวน @
    features.append(url.count('?'))                           # 5. จำนวน ?
    features.append(url.count('='))                           # 6. จำนวน =
    features.append(1 if url.startswith('https://') else 0)   # 7. เช็ก HTTPS
    
    # 8. เช็กการใช้ IP Address
    ip_pattern = r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.){3}([01]?\d\d?|2[0-4]\d|25[0-5])'
    features.append(1 if re.search(ip_pattern, url) else 0)
    
    # 9. เช็กคำสุ่มเสี่ยง
    suspicious_keywords = ['login', 'verify', 'account', 'update', 'banking', 'secure', 'paypal', 'signin', 'ebay']
    has_keyword = 1 if any(kw in url.lower() for kw in suspicious_keywords) else 0
    features.append(has_keyword)
    
    # 10. ความยาว Domain Name
    features.append(len(domain))

    # 11. ตรวจจับการใช้เลข 0 หรือ 1 ปนในชื่อโดเมน (เช่น g00gle, paypa1)
    has_typo_num = 1 if re.search(r'[a-zA-Z]+[01]+[a-zA-Z]+', domain) else 0
    features.append(has_typo_num)
    
    # 12. ตรวจจับแบรนด์ปลอม
    legit_domains = ['google.com', 'paypal.com', 'facebook.com', 'amazon.com', 'microsoft.com', 'github.com']
    is_legit_domain = any(domain == legit or domain.endswith('.' + legit) for legit in legit_domains)
    
    fake_brand_pattern = r'(g[0o]{2}gl|payp[a1]l|f[a4]cebo[0o]k|am[a4]z[0o]n|m[i1]cr[0o]s[0o]ft)'
    has_fake_brand = 1 if (re.search(fake_brand_pattern, domain) and not is_legit_domain) else 0
    features.append(has_fake_brand)

    return features