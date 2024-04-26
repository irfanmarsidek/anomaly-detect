import os
import numpy as np
from scapy.all import *
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
import joblib
import feature_extract

# Function to process a folder of pcap files
def process_folder(folder_path, label=None):
    features = []
    labels = []

    for file_name in os.listdir(folder_path):
        if file_name.endswith('.pcap'):
            file_path = os.path.join(folder_path, file_name)
            parameters = feature_extract.process_pcap(file_path)
            features.append(feature_extract.synthesize_features(parameters))
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

    # Save the trained model
    joblib.dump(clf, 'trained_model.pkl')


if __name__ == "__main__":
    main()
