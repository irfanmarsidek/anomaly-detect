import subprocess
import time
import os
import random

def capture_packets(output_dir):
    try:
        os.makedirs(output_dir, exist_ok=True)
        
        while True:
            timestamp = time.strftime("%d-%m-%Y--%H-%M-%S")
            output_file = os.path.join(output_dir, f"capture_{timestamp}.pcap")
            print(f"Capturing packets. Output file: {output_file}")

            # Generate a random number of packets between 2000 and 5000
            num_packets = random.randint(2000, 5000)
            
            # Run tshark to capture packets
            subprocess.run(["tshark", "-i", "wlp2s0", "-w", output_file, "-c", str(num_packets)], check=True)

            print("Capture complete.")

    except KeyboardInterrupt:
        print("\nPacket capture stopped by user.")

if __name__ == "__main__":
    output_directory = "temporary_pcap"
    capture_packets(output_directory)
