from scapy.all import sniff, conf
from scapy.layers.inet import IP, TCP, UDP
import tkinter as tk
from tkinter import scrolledtext
from threading import Thread
import time


class PacketSnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Sniffer")

        self.start_button = tk.Button(root, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.pack()

        self.stop_button = tk.Button(root, text="Stop Sniffing", command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_button.pack()

        self.text_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=100, height=30)
        self.text_area.pack()

        self.sniffing = False

    def start_sniffing(self):
        self.sniffing = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.text_area.insert(tk.END, "Started packet sniffing...\n\n")

        # Run sniffing in a separate thread to avoid blocking the main thread
        self.sniff_thread = Thread(target=self.sniff_packets)
        self.sniff_thread.start()

    def stop_sniffing(self):
        self.sniffing = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.text_area.insert(tk.END, "\nStopped packet sniffing.\n")

    def sniff_packets(self):
        sniff(prn=self.process_packet, stop_filter=self.stop_sniffer, iface=conf.iface)

    def stop_sniffer(self, packet):
        return not self.sniffing

    def process_packet(self, packet):
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            protocol = "Unknown"
            if packet.haslayer(TCP):
                protocol = "TCP"
            elif packet.haslayer(UDP):
                protocol = "UDP"
            payload = packet[IP].payload

            # Format the packet information
            packet_info = (
                f"Source IP      : {ip_src}\n"
                f"Destination IP : {ip_dst}\n"
                f"Protocol       : {protocol}\n"
                f"Payload        : {payload}\n"
                f"{'-' * 40}\n"
            )

            # Display the packet information in the text area
            self.text_area.insert(tk.END, packet_info)
            self.text_area.see(tk.END)

            # Introduce a delay to slow down packet processing
            time.sleep(0.5)  # 500 milliseconds delay


if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()

# from scapy.all import sniff, conf
# from scapy.layers.inet import IP, TCP, UDP
# import tkinter as tk
# from tkinter import scrolledtext
# from threading import Thread
# import time
#
#
# class PacketSnifferApp:
#     def __init__(self, root):
#         self.root = root
#         self.root.title("Packet Sniffer")
#
#         self.filter_frame = tk.Frame(root)
#         self.filter_frame.pack(pady=10)
#
#         tk.Label(self.filter_frame, text="Source IP:").grid(row=0, column=0, padx=5)
#         self.src_ip_entry = tk.Entry(self.filter_frame)
#         self.src_ip_entry.grid(row=0, column=1, padx=5)
#
#         tk.Label(self.filter_frame, text="Destination IP:").grid(row=1, column=0, padx=5)
#         self.dst_ip_entry = tk.Entry(self.filter_frame)
#         self.dst_ip_entry.grid(row=1, column=1, padx=5)
#
#         tk.Label(self.filter_frame, text="Protocol:").grid(row=2, column=0, padx=5)
#         self.protocol_entry = tk.Entry(self.filter_frame)
#         self.protocol_entry.grid(row=2, column=1, padx=5)
#
#         self.start_button = tk.Button(root, text="Start Sniffing", command=self.start_sniffing)
#         self.start_button.pack(pady=5)
#
#         self.stop_button = tk.Button(root, text="Stop Sniffing", command=self.stop_sniffing, state=tk.DISABLED)
#         self.stop_button.pack(pady=5)
#
#         self.text_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=100, height=30)
#         self.text_area.pack(pady=10)
#
#         self.sniffing = False
#
#     def start_sniffing(self):
#         self.sniffing = True
#         self.start_button.config(state=tk.DISABLED)
#         self.stop_button.config(state=tk.NORMAL)
#         self.text_area.insert(tk.END, "Started packet sniffing...\n\n")
#
#         self.filter_criteria = {
#             "src_ip": self.src_ip_entry.get(),
#             "dst_ip": self.dst_ip_entry.get(),
#             "protocol": self.protocol_entry.get().upper()
#         }
#
#         # Run sniffing in a separate thread to avoid blocking the main thread
#         self.sniff_thread = Thread(target=self.sniff_packets)
#         self.sniff_thread.start()
#
#     def stop_sniffing(self):
#         self.sniffing = False
#         self.start_button.config(state=tk.NORMAL)
#         self.stop_button.config(state=tk.DISABLED)
#         self.text_area.insert(tk.END, "\nStopped packet sniffing.\n")
#
#     def sniff_packets(self):
#         sniff(prn=self.process_packet, stop_filter=self.stop_sniffer, iface=conf.iface)
#
#     def stop_sniffer(self, packet):
#         return not self.sniffing
#
#     def process_packet(self, packet):
#         if IP in packet:
#             ip_src = packet[IP].src
#             ip_dst = packet[IP].dst
#             protocol = "Unknown"
#             if packet.haslayer(TCP):
#                 protocol = "TCP"
#             elif packet.haslayer(UDP):
#                 protocol = "UDP"
#             payload = packet[IP].payload
#
#             # Apply filters
#             if self.filter_criteria["src_ip"] and self.filter_criteria["src_ip"] != ip_src:
#                 return
#             if self.filter_criteria["dst_ip"] and self.filter_criteria["dst_ip"] != ip_dst:
#                 return
#             if self.filter_criteria["protocol"] and self.filter_criteria["protocol"] != protocol:
#                 return
#
#             # Format the packet information
#             packet_info = (
#                 f"Source IP      : {ip_src}\n"
#                 f"Destination IP : {ip_dst}\n"
#                 f"Protocol       : {protocol}\n"
#                 f"Payload        : {payload}\n"
#                 f"{'-' * 40}\n"
#             )
#
#             # Display the packet information in the text area
#             self.text_area.insert(tk.END, packet_info)
#             self.text_area.see(tk.END)
#
#             # Introduce a delay to slow down packet processing
#             time.sleep(0.5)  # 500 milliseconds delay
#
#
# if __name__ == "__main__":
#     root = tk.Tk()
#     app = PacketSnifferApp(root)
#     root.mainloop()
