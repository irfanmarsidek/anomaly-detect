from scapy.all import rdpcap
from sklearn.preprocessing import LabelEncoder
from tabulate import tabulate

def extract_features(packet):
    # Extract features from the packet
    src_ip = packet['IP'].src
    dst_ip = packet['IP'].dst
    protocol = packet['IP'].proto
    length = len(packet)
    info = packet.summary()
    ports = extract_ports(packet)
    packet_seq = packet.sniffed_on

    return src_ip, dst_ip, protocol, length, info, ports, packet_seq

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

def process_pcap(file_path):
    packets = rdpcap(file_path)
    features = []

    # Initialize LabelEncoder
    label_encoders = {}

    for packet in packets:
        if 'IP' in packet:  # Check if packet contains IP layer
            src_ip, dst_ip, protocol, length, info, ports, packet_seq = extract_features(packet)

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
            features.extend([length, ports[0], ports[1], packet_seq])

    return features

if __name__ == "__main__":
    pcap_file = "anomalous_pcap\Probe\capture_30-03-2024--22-12-46.pcap"
    extracted_features = process_pcap(pcap_file)

    # Reshape features into a table format
    table_data = []
    headers = ["Source IP", "Destination IP", "Protocol", "Length", "Info", "Source Port", "Destination Port", "Packet Sequence"]
    num_columns = len(headers)
    for i in range(0, len(extracted_features), num_columns):
        table_data.append(extracted_features[i:i+num_columns])

    # Print the table
    #print(tabulate(table_data, headers=headers))
    print(extracted_features)

