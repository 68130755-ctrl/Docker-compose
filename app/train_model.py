import numpy as np
from sklearn.ensemble import RandomForestClassifier
import joblib

X_train = np.array([
    # เว็บปกติ (Label 0)
    [22, 1, 0, 0, 0, 0, 1, 0, 0, 10],
    [25, 2, 0, 0, 0, 0, 1, 0, 0, 13],
    [32, 2, 1, 0, 0, 0, 1, 0, 0, 18],
    [28, 1, 0, 0, 0, 0, 1, 0, 0, 15],
    
    # เว็บ Phishing (Label 1)
    [85, 4, 3, 1, 2, 3, 0, 1, 1, 25],
    [95, 5, 4, 0, 1, 2, 0, 0, 1, 35],
    [110, 6, 5, 1, 3, 4, 0, 1, 1, 40],
    [78, 3, 2, 0, 1, 2, 0, 0, 1, 28]
])

y_train = np.array([0, 0, 0, 0, 1, 1, 1, 1])

model = RandomForestClassifier(n_estimators=10, random_state=42)
model.fit(X_train, y_train)

joblib.dump(model, 'phishing_model.pkl')
print("✅ บันทึกโมเดลสำเร็จ: phishing_model.pkl")