import numpy as np
import joblib
import pandas as pd

# Load models
#rf_model = joblib.load(r"D:\AI_Based_Cybersecurity_Threat_Detection\jupyter_models\rf_model1.pkl")
if_model = joblib.load(r"D:\AI_Based_Cybersecurity_Threat_Detection\jupyter_models\if_model_end1.pkl")
rf_model = joblib.load(r"D:\AI_Based_Cybersecurity_Threat_Detection\jupyter_models\rf_model_smote.pkl")
#rf_model = joblib.load(r"D:\AI_Based_Cybersecurity_Threat_Detection\jupyter_models\xgb.pkl")
#rf_model = joblib.load(r"D:\AI Based Cybersecurity threat detection\rf_model.pkl")
#if_model = joblib.load(r"D:\AI Based Cybersecurity threat detection\if_model.pkl")
#rf_model = joblib.load(r"D:\AI_Based_Cybersecurity_Threat_Detection\jupyter_models\rf_final_try1.pkl")
def predict_intrusion(data):
    

    # Predictions
    rf_preds = rf_model.predict(data)
 
    if_preds = if_model.predict(data)

    # Map predictions to numeric values
    """rf_mapping = {'BENIGN': 0, 'MALICIOUS': 1}
    rf_preds = np.array([rf_mapping[i] for i in rf_preds])"""

    # Final prediction using ensemble voting
    final_pred = rf_preds  # By default, rely on RF
    if rf_preds[0] == 0 and if_preds[0] == 1:  # If RF says "Benign" but IF says "Malicious"
        final_pred = 0


    # Feature Importance
    feature_importances = rf_model.feature_importances_
    important_features = sorted(zip(data.columns, feature_importances), key=lambda x: x[1], reverse=True)[:3]
    reason = [f"{feature} contributed significantly" for feature, _ in important_features]
    return rf_preds, if_preds, final_pred, reason
    # Threat Level Determination
    threat_level = "High" if sum(if_preds) > 0 else "Low"
    
    return "Malicious" if final_pred[0] == 1 else "Benign", reason, threat_level

# Example: Input data
malicious_sample = [[23,43,	53,	56,	7687,	76,	45
]]

feature_names = [" Flow Duration", "Flow Bytes/s", " Packet Length Variance", 
                 " Bwd Packet Length Mean", " Fwd IAT Mean", "Init_Win_bytes_forward", 
                 "Subflow Fwd Packets"]
3
input_df = pd.DataFrame(malicious_sample, columns=feature_names)

# Run the prediction
result = predict_intrusion(input_df)
print(result)

# Check probability scores and anomaly detection
print(rf_model.predict_proba(input_df))  # Convert to NumPy before passing
print(if_model.predict(input_df))  # Convert to NumPy before passing



'''
benign_test_cases = [
    [2500000, 5000, 20000, 1400, 30000, 8192, 20],  # Web Browsing
    [4500000, 12000, 25000, 1550, 45000, 16384, 40], # Secure File Transfer
    [6000000, 20000, 30000, 1700, 50000, 32768, 60], # Video Streaming
    [1500000, 4500, 18000, 1100, 25000, 8192, 15],   # Email Exchange
    [3500000, 11000, 22000, 1400, 40000, 16384, 35]  # Cloud Sync
]

# Define test cases for Malicious traffic
malicious_test_cases = [
    [500000, 100000, 50000, 180, 500, 0, 500],   # DDoS Attack
    [1200000, 75000, 40000, 550, 1500, 0, 300],  # Brute Force Attack
    [800000, 25000, 35000, 900, 10000, 4096, 50], # SQL Injection
    [2000000, 30000, 45000, 1200, 20000, 8192, 80], # MITM Attack
    [1000000, 50000, 32000, 850, 5000, 4096, 150]  # C2 Malware
    [1293792
, 8991.398927
, 3435230.673
,1658.142857
, 373.5
,8192
, 3]
]

'''
'''
test_cases = [
    [125376, 8852.12, 34612.45, 245.18, 276.5, 8192, 3, "Benign"],
    [302482, 12342.98, 14567.89, 175.92, 652.4, 10240, 5, "Benign"],
    [558274, 6798.35, 22598.12, 210.67, 432.1, 5120, 4, "Benign"],
    [754632, 9532.76, 37864.50, 320.34, 189.8, 16384, 6, "Benign"],
    [998712, 13456.21, 12986.75, 205.45, 523.7, 20480, 2, "Benign"],
    [1834927, 28912.45, 543876.89, 1658.14, 373.5, 8192, 3, "Malicious"],
    [2057321, 24792.33, 689234.23, 1456.78, 512.9, 1024, 5, "Malicious"],
    [1456790, 19872.56, 467982.67, 1375.45, 486.3, 4096, 4, "Malicious"],
    [2345672, 31987.42, 782345.12, 1876.32, 290.4, 512, 6, "Malicious"],
    [1923876, 27543.98, 563482.78, 1532.87, 628.5, 2048, 2, "Malicious"]
]
'''