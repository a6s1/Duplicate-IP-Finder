import tkinter as tk
from tkinter import messagebox
from scapy.all import ARP, Ether, srp
from tabulate import tabulate
import socket

def get_local_ip():
    return socket.gethostbyname(socket.gethostname())

def scan_network(ip_range):
    arp_request = ARP(pdst=ip_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    clients = []
    for sent, received in answered_list:
        clients.append({'ip': received.psrc, 'mac': received.hwsrc})
    
    return clients

def find_duplicates(clients):
    ip_dict = {}
    duplicates = []

    for client in clients:
        if client['ip'] in ip_dict:
            ip_dict[client['ip']].append(client['mac'])
        else:
            ip_dict[client['ip']] = [client['mac']]
    
    for ip, macs in ip_dict.items():
        if len(macs) > 1:
            duplicates.append({'ip': ip, 'macs': macs})
    
    return duplicates

def scan_network_gui():
    ip_range = entry.get()
    if not ip_range:
        messagebox.showwarning("Input Error", "Please enter a network range.")
        return

    try:
        print(f"Scanning network: {ip_range}")
        clients = scan_network(ip_range)
        print(f"Found {len(clients)} devices on the network.")
        duplicates = find_duplicates(clients)
        
        if duplicates:
            result_text = "Duplicate IP addresses found:\n"
            result_text += tabulate(duplicates, headers="keys")
        else:
            result_text = "No duplicate IP addresses found."

        result_label.config(text=result_text)
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {str(e)}")

# Create the main window
root = tk.Tk()
root.title("Duplicate IP Finder")

# Create and place the widgets
tk.Label(root, text="Enter the network range (e.g., 192.168.1.0/24):").pack(pady=10)
entry = tk.Entry(root, width=30)
entry.pack(pady=5)
scan_button = tk.Button(root, text="Scan Network", command=scan_network_gui)
scan_button.pack(pady=10)
result_label = tk.Label(root, text="", justify=tk.LEFT)
result_label.pack(pady=10)

# Run the application
root.mainloop()
