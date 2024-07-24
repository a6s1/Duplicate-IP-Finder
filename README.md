```markdown
# Duplicate IP Finder

This is a Python-based GUI application that scans a specified network range for duplicate IP addresses. The application uses `tkinter` for the GUI and `scapy` for network scanning.

## Features

- Scan a network range to detect duplicate IP addresses.
- Simple and user-friendly GUI interface.
- Display results in a tabular format.

## Requirements

- Python 3.x
- `scapy` library
- `tabulate` library
- `tkinter` (comes pre-installed with Python)

## Installation

1. **Install Python:** Ensure that Python 3.x is installed on your system. You can download it from [python.org](https://www.python.org/downloads/).

2. **Install required libraries:**
   Open your command prompt or terminal and run the following commands to install the necessary libraries:
   ```bash
   pip install scapy tabulate
   ```

## Usage

1. **Running the Application:**
   - Save the script `app.py` to a directory of your choice.
   - Open your command prompt or terminal and navigate to the directory where `app.py` is saved.
   - Run the script using Python:
     ```bash
     python app.py
     ```

2. **Using the GUI:**
   - Enter the network range you want to scan (e.g., `192.168.1.0/24`) in the input field.
   - Click the "Scan Network" button.
   - The application will scan the specified network range and display any duplicate IP addresses found.

## Creating an Executable (Optional)

If you want to create a standalone executable for this application, you can use `pyinstaller`:

1. **Install PyInstaller:**
   ```bash
   pip install pyinstaller
   ```

2. **Create the Executable:**
   - Open your command prompt or terminal and navigate to the directory where `app.py` is saved.
   - Run PyInstaller with the following command:
     ```bash
     pyinstaller --onefile --windowed app.py
     ```

3. **Locate the Executable:**
   - The executable file will be located in the `dist` folder within your project directory.
   - Run the executable to use the application without needing a Python interpreter.

## Example Script

Here’s the complete `app.py` script:

```python
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
```


## Acknowledgments

- The `scapy` library for network packet manipulation.
- The `tabulate` library for easy table creation.
- The `tkinter` library for creating the GUI.
```
