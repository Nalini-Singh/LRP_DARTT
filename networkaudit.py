# networkaudit.py (amended for graphical host listing and streamlined discovery)
import csv
import os
import sys
import time
import webbrowser
import tkinter
from tkinter import ttk, messagebox
import customtkinter
from PIL import ImageTk, Image
import vulscanner as sc
import searchexploits as msfc
import msfexploit as msfe
import networkx as nx
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

customtkinter.set_appearance_mode("System")
customtkinter.set_default_color_theme("blue")

class App(customtkinter.CTk):
    WIDTH = 800
    HEIGHT = 600

    def __init__(self):
        super().__init__()
        self.title("DARTT: Dynamic Automated Red Team Tool")
        self.geometry(f"{App.WIDTH}x{App.HEIGHT}")
        self.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.Host = {}

        # layout frames
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self.frame_left = customtkinter.CTkFrame(master=self, width=200)
        self.frame_left.grid(row=0, column=0, sticky="nswe")
        self.frame_right = customtkinter.CTkFrame(master=self)
        self.frame_right.grid(row=0, column=1, sticky="nswe", padx=10, pady=10)

        # Host discovery UI
        self.build_discovery_panel()
        # Scan & exploit UI
        self.build_scan_panel()
        # Results display panels
        self.build_result_panels()

    def build_discovery_panel(self):
        lbl = customtkinter.CTkLabel(master=self.frame_left, text="Network Discovery", text_font=(None, 14))
        lbl.pack(pady=(20, 5))
        self.entry_net = customtkinter.CTkEntry(master=self.frame_left, placeholder_text="Target Subnet (e.g. 192.168.1.0/24)")
        self.entry_net.pack(padx=20, pady=5)
        btn = customtkinter.CTkButton(master=self.frame_left, text="Discover Hosts", command=self.discover)
        btn.pack(pady=10)
        self.host_menu = None

    def build_scan_panel(self):
        lbl = customtkinter.CTkLabel(master=self.frame_left, text="Target Scan", text_font=(None, 14))
        lbl.pack(pady=(30, 5))
        self.entry_tgtip = customtkinter.CTkEntry(master=self.frame_left, placeholder_text="Target IP")
        self.entry_tgtip.pack(padx=20, pady=5)
        self.entry_port = customtkinter.CTkEntry(master=self.frame_left, width=80, placeholder_text="Port (opt)")
        self.entry_port.pack(padx=20, pady=5)
        btn = customtkinter.CTkButton(master=self.frame_left, text="Scan Port/CVEs", command=self.scan_tgt)
        btn.pack(pady=10)
        self.attack_menu = None

    def build_result_panels(self):
        # Nmap results
        self.tree_services = ttk.Treeview(self.frame_right,
                                          columns=("Port", "Service", "Version", "CVEs"),
                                          show='headings', height=6)
        for col in ("Port", "Service", "Version", "CVEs"):
            self.tree_services.heading(col, text=col)
            self.tree_services.column(col, width=100)
        self.tree_services.bind('<Double-1>', self.select_service)
        self.tree_services.pack(fill="x", pady=(0,10))

        # Exploits results
        self.tree_exploits = ttk.Treeview(self.frame_right,
                                          columns=("#", "Name", "Date", "Rank", "Desc"),
                                          show='headings', height=6)
        for col, width in zip(("#","Name","Date","Rank","Desc"),(40,150,80,80,200)):
            self.tree_exploits.heading(col, text=col)
            self.tree_exploits.column(col, width=width)
        self.tree_exploits.bind('<Double-1>', self.launch_exploit)
        self.tree_exploits.pack(fill="x")

    def discover(self):
        subnet = self.entry_net.get().strip()
        if not subnet:
            messagebox.showwarning("Input Required", "Please enter a subnet to scan.")
            return
        hosts = sc.discover(subnet)  # now returns list of live hosts
        # update OptionMenu
        if self.host_menu:
            self.host_menu.destroy()
        self.host_menu = customtkinter.CTkOptionMenu(master=self.frame_left,
                                                     values=hosts,
                                                     command=self.set_host)
        self.host_menu.pack(pady=5)
        # show network graph
        self.display_network_graph(hosts)

    def display_network_graph(self, hosts):
        win = customtkinter.CTkToplevel(self)
        win.title("Network Topology")
        fig = plt.Figure(figsize=(4,3))
        G = nx.Graph()
        G.add_node("You")
        for h in hosts:
            G.add_edge("You", h)
        ax = fig.add_subplot(111)
        nx.draw(G, with_labels=True, ax=ax, node_size=600, font_size=8)
        canvas = FigureCanvasTkAgg(fig, master=win)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tkinter.BOTH, expand=True)

    def set_host(self, host):
        self.entry_tgtip.delete(0, tkinter.END)
        self.entry_tgtip.insert(0, host)

    def scan_tgt(self):
        ip = self.entry_tgtip.get().strip()
        port = self.entry_port.get().strip()
        if not ip:
            messagebox.showwarning("Input Required", "Please select or enter a target IP.")
            return
        self.Host = {'IP': ip, 'Port': port}
        xml_file = sc.vulscan(self.Host)
        self.show_scan_results(xml_file)

    def show_scan_results(self, xml_csv_base):
        # clear tree
        for i in self.tree_services.get_children():
            self.tree_services.delete(i)
        # load CSV
        with open(xml_csv_base + '.csv') as f:
            reader = csv.DictReader(f)
            for row in reader:
                self.tree_services.insert('', 'end', values=(row['Port'], row['Service'],
                                                            row['Version'], row['CVE'] if 'CVE' in row else ''))

    def select_service(self, event):
        item = self.tree_services.focus()
        vals = self.tree_services.item(item, 'values')
        port, svc = vals[0], vals[1]
        exploits = msfc.search(self.Host, vals)
        time.sleep(2)
        self.show_exploits()

    def show_exploits(self):
        for i in self.tree_exploits.get_children():
            self.tree_exploits.delete(i)
        with open('outputs/exploits.csv') as f:
            reader = csv.DictReader(f)
            for row in reader:
                self.tree_exploits.insert('', 'end', values=(row['#'], row['Name'], row['Disclosure Date'],
                                                            row['Rank'], row['Desc']))

    def launch_exploit(self, event):
        item = self.tree_exploits.focus()
        vals = self.tree_exploits.item(item, 'values')
        msfe.exploit(self.Host, vals)

    def on_closing(self, *args):
        self.destroy()
        sys.exit(0)

if __name__ == "__main__":
    app = App()
    app.mainloop()

