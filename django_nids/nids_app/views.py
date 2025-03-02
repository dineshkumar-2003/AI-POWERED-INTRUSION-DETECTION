from django.shortcuts import render
from django.http import JsonResponse
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
import pandas as pd
import joblib
import numpy as np
import os
import time
from django.http import JsonResponse
from scapy.all import sniff,TCP

def capture_packet():
    packet = sniff(count=1)[0]
    flow_start_time = packet.time if hasattr(packet, 'time') else 0
    flow_end_time = time.time()
    flow_duration = flow_end_time - flow_start_time
    return {
        "flow_duration": flow_duration,  
        "flow_bytes": len(packet) / (packet.time if hasattr(packet, 'time') else 1), 
        "packet_length": np.var([len(packet)]),
        "bwd_packet": np.mean([len(packet)]), 
        "fwd_iat": packet.time if hasattr(packet, 'time') else 0, 
        "init_win": packet[TCP].window if packet.haslayer(TCP) else 0,  
        "subflow_fwd": 1  
    }
    return features

def get_packet_data(request):
    data = capture_packet()
    return JsonResponse(data)


rf_model = joblib.load(r"D:\AI_Based_Cybersecurity_Threat_Detection\jupyter_models\rf_model_smote.pkl")
if_model = joblib.load(r"D:\AI_Based_Cybersecurity_Threat_Detection\jupyter_models\if_model_end1.pkl")

def index(request):
    return render(request, 'index.html')

@api_view(['POST'])
def detect_intrusion(request):
    try:
        print("Received request for intrusion detection.")
        data = request.data
        print(f"Input data: {data}")
        df = pd.DataFrame([data])  # Convert JSON input to DataFrame
        print(f"Converted DataFrame: {df}")

        rf_prediction = rf_model.predict(df)[0]
        if_prediction = if_model.predict(df)[0]

        threat_percentage = (rf_prediction * 0.7 + (if_prediction == -1) * 0.3) * 100

        feature_importances = rf_model.feature_importances_
        important_features = sorted(zip(df.columns, feature_importances), key=lambda x: x[1], reverse=True)[:3]
        reason = [f"{feature} contributed significantly" for feature, _ in important_features]

        if rf_prediction == 1 or if_prediction == -1:
            verdict = "Malicious"
            recommendations = [
                "Enable Intrusion Prevention System (IPS).",
                "Regularly update firewall rules.",
                "Implement network segmentation to isolate threats.",
                "Use anomaly detection with real-time monitoring.",
                "Conduct regular security audits and penetration testing."
            ]
        else:
            verdict = "Safe"
            recommendations = [
                "Ensure up-to-date antivirus and firewall settings.",
                "Use strong encryption for sensitive data.",
                "Monitor unusual network activity even if benign.",
                "Educate employees on cybersecurity best practices.",
                "Keep software and security patches updated."
            ]

        result = {
            "Random Forest Prediction": "Attack" if rf_prediction == 1 else "Normal",
            "Isolation Forest Prediction": "Anomaly" if if_prediction == -1 else "Normal",
            "Threat Percentage": f"{threat_percentage:.2f}%",
            "Final Verdict": verdict,
            "Important Features": reason,
            "Recommendations": recommendations
        }

        print(f"Detection result: {result}")
        return Response(result, status=status.HTTP_200_OK)
    except Exception as e:
        print(f"Error occurred: {str(e)}")
        return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
