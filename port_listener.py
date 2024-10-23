from scapy.all import sniff, conf
from scapy.layers.inet import IP, TCP
import binascii
import datetime
import sys
import logging
from scapy.arch import get_windows_if_list
import os

# Set up logging
logging.basicConfig(
    filename='port_sniffer.log',
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)

def get_interface_by_index(index):
    """Get interface by index from available interfaces"""
    interfaces = get_windows_if_list()
    if 0 <= index < len(interfaces):
        return interfaces[index]['name']
    return None

def packet_callback(packet):
    try:
        if TCP in packet and packet.haslayer('Raw'):
            # Check if the packet is using our target port
            if packet[TCP].sport == 14580 or packet[TCP].dport == 14580:
                # Get the raw data
                raw_data = bytes(packet['Raw'].load)
                
                # Create log message
                log_message = f"""
=== Captured Packet ===
From: {packet[IP].src}:{packet[TCP].sport}
To: {packet[IP].dst}:{packet[TCP].dport}
Length: {len(raw_data)} bytes
Raw data (hex): {binascii.hexlify(raw_data).decode()}
"""
                # Try to decode as text
                try:
                    log_message += f"Attempted decode: {raw_data.decode('utf-8')}\n"
                except:
                    log_message += "Attempted decode: [Failed - Encrypted data]\n"
                
                log_message += "====================="
                
                # Print to console and log file
                print(log_message)
                logging.info(log_message)
                
    except Exception as e:
        logging.error(f"Error processing packet: {str(e)}")

def start_capture():
    try:
        # Get available interfaces
        interfaces = get_windows_if_list()
        
        print("Available interfaces:")
        for idx, iface in enumerate(interfaces):
            print(f"{idx}: {iface['name']} ({iface['description']})")
        
        # Let user select interface
        while True:
            try:
                choice = int(input("\nEnter the number of the interface to use (5 for Ethernet, 6 for Loopback): "))
                if 0 <= choice < len(interfaces):
                    selected_interface = interfaces[choice]['name']
                    break
                else:
                    print("Invalid choice. Please try again.")
            except ValueError:
                print("Please enter a valid number.")
        
        print(f"\nStarting packet capture on port 14580...")
        print(f"Using interface: {selected_interface}")
        print("Listening for encrypted communications...")
        
        # Start capture with basic filter
        sniff(
            iface=selected_interface,
            filter="tcp port 14580",
            prn=packet_callback,
            store=0
        )
        
    except Exception as e:
        logging.error(f"Capture error: {str(e)}")
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    try:
        # Ensure running with admin privileges
        if sys.platform.startswith('win'):
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                print("Please run this script as Administrator")
                sys.exit(1)
                
        # Start the capture
        start_capture()
        
    except KeyboardInterrupt:
        print("\nCapture stopped by user")
    except Exception as e:
        print(f"Fatal error: {str(e)}")
        logging.error(f"Fatal error: {str(e)}")