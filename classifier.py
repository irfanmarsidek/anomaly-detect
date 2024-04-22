import os
import joblib
from scapy.all import *
import feature_extract

# Function to classify PCAP files in a folder using a trained model
def classify_pcaps(folder_path, model_path):
    # Load the trained model
    clf = joblib.load(model_path)

    # Classify each PCAP file in the folder
    for file_name in os.listdir(folder_path):
        if file_name.endswith('.pcap'):
            file_path = os.path.join(folder_path, file_name)
            parameters = feature_extract.process_pcap(file_path)
            features = feature_extract.synthesize_features(parameters)
            features2 = [features]
            prediction = clf.predict(features2)
            print(f"File: {file_name}, Predicted Class: {prediction}")

# Folder containing PCAP files to classify
pcap_folder = "temporary_pcap"

# Path to the trained model file
model_path = "trained_model.pkl"

# Classify PCAP files in the folder using the trained model
classify_pcaps(pcap_folder, model_path)
