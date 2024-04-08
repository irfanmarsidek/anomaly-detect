import os
import numpy as np
from scapy.all import *
from scapy.layers.inet import TCP
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report
import joblib
import lime.lime_tabular
from collections import Counter

# Function to extract features from a PCAP file
def extract_features(packet):
    
    # Extract features from the packet
    src_ip = packet['IP'].src
    dst_ip = packet['IP'].dst
    protocol = packet['IP'].proto
    length = len(packet)
    info = packet.summary()
    ports = extract_ports(packet)

    return src_ip, dst_ip, protocol, length, info, ports

def extract_ports(packet):
    if 'TCP' in packet:
        src_port = packet['TCP'].sport
        dst_port = packet['TCP'].dport
        return src_port, dst_port
    elif 'UDP' in packet:
        src_port = packet['UDP'].sport
        dst_port = packet['UDP'].dport
        return src_port, dst_port
    else:
        return None, None
    
# Function to process a single pcap file
def process_pcap(file_path):
    packets = rdpcap(file_path)
    features = []

    # Initialize LabelEncoder
    label_encoders = {}

    for packet in packets:
        if 'IP' in packet:  # Check if packet contains IP layer
            src_ip, dst_ip, protocol, length, info, ports = extract_features(packet)

            # Encode categorical features
            if isinstance(info, str):
                info = [info]  # Convert info to list for consistent processing
            for i, feature in enumerate([src_ip, dst_ip, protocol] + list(info)):
                if isinstance(feature, str):
                    if i not in label_encoders:
                        label_encoders[i] = LabelEncoder()
                    feature_encoded = label_encoders[i].fit_transform([feature])[0]
                else:
                    feature_encoded = feature
                features.append(feature_encoded)

            # Add numerical features
            features.extend([length, ports[0], ports[1]])

    # Export Label Encoder
    joblib.dump(label_encoders,'label_encoder.pkl')
    return features

# Function to process a folder of pcap files
def process_folder(folder_path, label=None):
    features = []
    labels = []

    for file_name in os.listdir(folder_path):
        if file_name.endswith('.pcap'):
            file_path = os.path.join(folder_path, file_name)
            features.append(process_pcap(file_path))
            labels.append(label)

    return features, labels

# Main function
def main():
    normal_folder = "normal_pcap"
    anomalous_folder = "anomalous_pcap"

    # Process normal traffic
    normal_features, normal_labels = process_folder(normal_folder, "normal")

    # Process anomalous traffic
    anomalous_features = []
    anomalous_labels = []
    anomaly_types = []

    for anomaly_type in os.listdir(anomalous_folder):
        if os.path.isdir(os.path.join(anomalous_folder, anomaly_type)):
            anomaly_types.append(anomaly_type)
            features, labels = process_folder(os.path.join(anomalous_folder, anomaly_type), anomaly_type)
            anomalous_features.extend(features)
            anomalous_labels.extend(labels)

    # Combine features and labels
    features = normal_features + anomalous_features
    labels = normal_labels + anomalous_labels

    # Split data into train and test sets
    X_train, X_test, y_train, y_test = train_test_split(features, labels, test_size=0.2, random_state=42)

    # Train a classifier
    clf = RandomForestClassifier()
    clf.fit(X_train, y_train)

    # Evaluate the model
    y_pred = clf.predict(X_test)
    print(classification_report(y_test, y_pred))

    # Explain model predictions using LIME
    explainer = lime.lime_tabular.LimeTabularExplainer(np.array(X_train), feature_names=['num_packets', 'total_bytes'])
    exp = explainer.explain_instance(np.array(X_test[0]), clf.predict_proba)
    print("Explanation using LIME:")
    print(exp.as_list())

    # Save the trained model
    joblib.dump(clf, 'trained_model.pkl')


if __name__ == "__main__":
    main()
