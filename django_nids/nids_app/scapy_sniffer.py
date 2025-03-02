from scapy.all import sniff
import pandas as pd

# Define callback function to process packets
def process_packet(packet):
    features = {
        "Flow Duration": len(packet),  
        "Flow Bytes/s": len(packet) / (packet.time if hasattr(packet, 'time') else 1), 
        "Packet Length Variance": len(packet),
        "Bwd Packet Length Mean": len(packet), 
        "Fwd IAT Mean": packet.time if hasattr(packet, 'time') else 0, 
        "Init_Win_bytes_forward": 0,  
        "Subflow Fwd Packets": 1  
    }
    return features

def capture_traffic(count=1):
    packets = sniff(count=count)
    features_list = [process_packet(pkt) for pkt in packets]
    return pd.DataFrame(features_list)

if __name__ == "__main__":
    df = capture_traffic()
    print(df)
