from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="NSL-KDD Detection API via Compose")

# กำหนด Input Schema จำลองฟีเจอร์หลักบางส่วนจากชุดข้อมูล NSL-KDD
class TrafficData(BaseModel):
    duration: int
    protocol_type: str
    service: str
    src_bytes: int

@app.get("/")
def read_root():
    return {"message": "Welcome to Network Intrusion Detection API Container!"}

@app.post("/predict")
def predict(data: TrafficData):
    # จำลองการตัดสินใจของโมเดล Random Forest (อ้างอิงพฤติกรรมการตรวจจับ DoS Attack ที่ส่ง Byte สูง)
    if data.src_bytes > 5000 or data.protocol_type == "icmp":
        return {
            "prediction": "Attack", 
            "confidence": "99.87%",
            "model_used": "Random Forest Classifier"
        }
    return {
        "prediction": "Normal", 
        "confidence": "100.00%",
        "model_used": "Random Forest Classifier"
    }