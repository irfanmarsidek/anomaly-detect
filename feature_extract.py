from scapy.all import rdpcap
import csv

# Function to extract parameters from a PCAP file
def extract_parameters(packet):
    # Extract parameters from the packet
    if 'ARP' in packet:
        src_ip = packet['ARP'].psrc
        dst_ip = packet['ARP'].pdst
        protocol = packet['ARP'].ptype
    else:
        src_ip = packet['IP'].src if 'IP' in packet else '0.0.0.0'
        dst_ip = packet['IP'].dst if 'IP' in packet else '0.0.0.0'
        protocol = packet['IP'].proto if 'IP' in packet else 0
        
    src_port, dst_port = extract_ports(packet)
    length = len(packet)
    return src_ip, dst_ip, protocol, length, src_port, dst_port

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
        return 0, 0
    
def process_pcap(file_path):
    packets = rdpcap(file_path)
    parameters = []

    for packet in packets:
        src_ip, dst_ip, protocol, length, src_port, dst_port = extract_parameters(packet)
        parameters.append([src_ip, dst_ip, protocol, length, src_port, dst_port])

    return parameters

def synthesize_features(parameters):

    total_length = 0  # Total length of all packets
    total_packets = len(parameters)  # Total number of packets

    unique_src_ports = set()  # Set to store unique source ports
    unique_dst_ports = set()  # Set to store unique destination ports

    for param in parameters:
        # Extracting individual parameters from the parameter tuple
        src_ip, dst_ip, protocol, length, src_port, dst_port = param
        
        total_length += length

        if src_port != 0:
            unique_src_ports.add(src_port)
        if dst_port != 0:
            unique_dst_ports.add(dst_port)
        
    length_packet_ratio = round(total_length / total_packets,0)

    total_unique_src_ports = len(unique_src_ports)
    total_unique_dst_ports = len(unique_dst_ports)

    features = [total_unique_dst_ports,total_unique_src_ports,length_packet_ratio]
    return features


def save_to_csv(data, file_path):
    with open(file_path, 'w', newline='') as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(["src_ip", "dst_ip", "protocol", "length", "src_port", "dst_port"])
        writer.writerows(data)


# Example usage:
file_path = "anomalous_pcap/Probe/capture_30-03-2024--22-12-46.pcap"
output_file = "features.csv"
parameters = process_pcap(file_path)
features = synthesize_features(parameters)
save_to_csv(parameters, output_file)
print(features)


