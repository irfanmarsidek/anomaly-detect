import os
import joblib
from scapy.all import *

# Function to extract features from a PCAP file
def extract_features_from_pcap(file_path):
    # Load the pcap file
    pcap = rdpcap(file_path)

    # Example feature extraction (you may need to extract more meaningful features)
    num_packets = len(pcap)
    total_bytes = sum([len(packet) for packet in pcap])

    return [num_packets, total_bytes]

# Function to classify PCAP files in a folder using a trained model
def classify_pcaps(folder_path, model_path):
    # Load the trained model
    clf = joblib.load(model_path)

    # Classify each PCAP file in the folder
    for file_name in os.listdir(folder_path):
        if file_name.endswith('.pcap'):
            file_path = os.path.join(folder_path, file_name)
            features = extract_features_from_pcap(file_path)
            # Reshape features for single sample prediction
            features = [features]
            prediction = clf.predict(features)[0]
            print(f"File: {file_name}, Predicted Class: {prediction}")

# Folder containing PCAP files to classify
pcap_folder = "temporary_pcap"

# Path to the trained model file
model_path = "trained_model.pkl"

# Classify PCAP files in the folder using the trained model
classify_pcaps(pcap_folder, model_path)
