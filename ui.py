# ui.py - Prototype 2
# Improvement on Prototype 1 - full dark colour scheme matching design mockups
# All core logic is the same as prototype 1
# Changes: dark background, colour coded severity rows, teal header box on login,
# styled treeview tables, colour coded threat level text, red classification footer,
# dark sidebar with highlight on active page, scrollable alerts panel on dashboard

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading  # runs simulation in background so UI doesnt freeze
import time
import random
from datetime import datetime
import threat_log as tl
import alerts as al

#Login credentials
VALID_USERS = {"Isaac": "Password123", "User2": "Password321"}

#this tries to import AI model module - only works if model.py has been run first
try:
    import model as md
    MODEL_AVAILABLE = True
except ImportError:
    MODEL_AVAILABLE = False

#Colour palette
C = {
    "bg":"#232323",
    "sidebar": "#1A1A1A",
    "header": "#141414", 
    "card": "#2D2D2D",  
    "card2": "#333333",  
    "border": "#3A3A3A", 
    "teal": "#1D5C6E",
    "text": "#E0E0E0", 
    "dim": "#9E9E9E",
    "sidebar_txt": "#BDBDBD",
    "high": "#E61610", 
    "medium":"#D68227", 
    "normal":"#00C853", 
    "blue": "#1565C0",
    "red_banner": "#CC0000", 
    "green_panel": "#1A3D1A", 
    "red_panel": "#3D0A0A",}

#Fonts
F_TITLE = ("Arial", 15,"bold")
F_BODY = ("Arial", 10)
F_SMALL = ("Arial", 9)
F_TINY = ("Arial", 8)
F_MONO = ("Courier New",9)
F_BIG = ("Arial", 22, "bold")


#applies the dark colour scheme to ttk Treeview tables
#ttk widgets have their own separate styling system from regular tkinter widgets
#so they need to be configured through ttk.Style() rather than just setting bg=
def apply_tree_style(tree, tag_colours=None):
    style = ttk.Style()
    style.theme_use("clam")
    style.configure("Treeview", background=C["card"], foreground=C["text"], fieldbackground=C["card"], rowheight=22, font=F_MONO)
    style.configure("Treeview.Heading", background=C["header"], foreground=C["text"], font=("Arial", 8, "bold"))
    style.map("Treeview", background=[("selected", C["blue"])], foreground=[("selected", "#ffffff")])
    if tag_colours:
        for tag, bg in tag_colours.items():
            tree.tag_configure(tag, background=bg)



def scrolled_tree(parent, columns, col_cfg, height=18, tag_colours=None):
    frame = tk.Frame(parent, bg=C["bg"])
    tree = ttk.Treeview(frame, columns=columns, show="headings", height=height, selectmode="browse")
    for col, (heading, width) in col_cfg.items():
        tree.heading(col, text=heading)
        tree.column(col, width=width, anchor="center", minwidth=40)
    scroll= ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
    tree.configure(yscrollcommand=scroll.set)
    tree.pack(side="left",fill="both", expand=True)
    scroll.pack(side="right", fill="y")
    apply_tree_style(tree, tag_colours)
    return frame,tree


class IDSApplication:
    def __init__(self, root):
        self.root = root
        self.root.title("AI-IDS | Defence Intrusion Detection System")
        self.root.geometry("1280x800")
        self.root.configure(bg=C["bg"])
        self.root.resizable(True, True)
        #state
        self.current_user = None
        self.session_start= None
        self.model = None
        self.scaler_params = None
        self.model_metrics = None
        self.sim_running =False
        #live traffic counters
        self._total_events =0
        self._src_ips_seen =set()
        self._destination_ips_seen =set()
        self._protocol_counts = {"TCP": 0, "UDP": 0, "ICMP":0}
        tl.load_threat_log()
        self.show_login()

    #returns the display colour for a severity string
    def severity_colour(self, sev):
        return {"High": C["high"], "Medium": C["medium"], "Normal": C["normal"]}.get(sev, C["dim"])

    #loads model from disk after login
    def load_model(self):
        if not MODEL_AVAILABLE:
            return
        try:
            self.model = md.load_model()
            self.scaler_params = md.load_scaler_params()
        except FileNotFoundError:
            self.model = None

    #LOGIN PAGE
    def show_login(self):
        for w in self.root.winfo_children():
            w.destroy()

        outer= tk.Frame(self.root,bg=C["bg"])
        outer.place(relx=0.5, rely=0.5, anchor="center")

        #teal header box
        hdr =tk.Frame(outer, bg=C["teal"], padx=30, pady=20)
        hdr.pack(pady=(0, 25))
        tk.Label(hdr, text="Defense Network IDS Portal",
                 font=("Arial", 18, "bold"), bg=C["teal"], fg="white").pack()
        tk.Label(hdr, text="Authorised Personnel Only",
                 font=("Arial", 12, "bold"), bg=C["teal"], fg="white").pack()

        #login form
        form =tk.Frame(outer, bg=C["bg"])
        form.pack()
        tk.Label(form, text="SECURE LOGIN", font=("Arial", 10, "bold"), bg=C["bg"], fg=C["dim"]).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 8))
        #username field with a person icon
        user_variable = tk.StringVar()
        user_login = tk.Entry(form, textvariable=user_variable, font=F_BODY, width=30,bg="#4A4A4A", fg=C["text"], insertbackground=C["text"],relief="flat", bd=6)
        user_login.insert(0, "USER:")
        user_login.bind("<FocusIn>", lambda e: user_login.delete(0, "end") if user_login.get() == "USER:" else None)
        user_login.grid(row=1, column=0, pady=6, ipady=8)
        tk.Label(form, text="👤", font=("Arial", 18), bg=C["bg"], fg=C["text"]).grid(row=1, column=1, padx=10)
        user_login.focus()

        #password field with a key icon
        pass_variable = tk.StringVar()
        pass_login = tk.Entry(form, textvariable=pass_variable, show="•", font=F_BODY, width=30,
                              bg="#4A4A4A", fg=C["text"], insertbackground=C["text"],
                              relief="flat", bd=6)
        pass_login.grid(row=2, column=0, pady=6, ipady=8)
        tk.Label(form, text="🔑", font=("Arial", 18), bg=C["bg"], fg=C["text"]).grid(row=2, column=1, padx=10)

        #warning message
        warn_row = tk.Frame(form, bg=C["bg"])
        warn_row.grid(row=3, column=0, columnspan=2, sticky="w", pady=(0, 12))
        tk.Label(warn_row, text="FORGOT PASSWORD   ", font=("Arial", 8, "underline"), bg=C["bg"], fg=C["dim"]).pack(side="left")
        tk.Label(warn_row, text="(WARNING: Unauthorised access is monitored and logged)", font=("Arial", 8), bg=C["bg"], fg=C["high"]).pack(side="left")
        err_var = tk.StringVar()
        tk.Label(form, textvariable=err_var, font=F_SMALL, bg=C["bg"], fg=C["high"]).grid(row=4, column=0, columnspan=2)

        def attempt_login(event=None):
            #checks credentials against VALID_USERS dictionary
            uv = user_variable.get().strip()
            pv = pass_variable.get().strip()
            if uv in VALID_USERS and VALID_USERS[uv]==pv:
                self.current_user =uv
                self.session_start =datetime.now()
                self.load_model()
                self.build_main_ui()
            else:
                err_var.set("Invalid username or password. Access denied.")
                pass_variable.set("")
        tk.Button(form, text="  LOGIN  ", command=attempt_login, bg=C["border"], fg=C["text"], font=("Arial", 10, "bold"),relief="flat", cursor="hand2", pady=10, padx=20).grid(row=5, column=0, columnspan=2, pady=10)
        self.root.bind("<Return>", attempt_login)
        #red classification footer- pinned to bottom of window using .place()
        footer = tk.Frame(self.root, bg=C["red_banner"],height=50)
        footer.place(relx=0, rely=1.0, anchor="sw", relwidth=1.0)
        tk.Label(footer, text="CLASSIFICATION: CONFIDENTIAL", font=("Arial", 13, "bold"), bg=C["red_banner"], fg="white").pack(expand=True)


    #Main interface- sidebar and content area
    def build_main_ui(self):
        for w in self.root.winfo_children():
            w.destroy()
        self.root.unbind("<Return>")
        #dark sidebar on the left
        sidebar= tk.Frame(self.root, bg=C["sidebar"], width=210)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)
        self.content = tk.Frame(self.root, bg=C["bg"])
        self.content.pack(side="left", fill="both", expand=True)
        #navigation header button
        navigation_hdr = tk.Frame(sidebar, bg="#2A5F72", padx=10, pady=8)
        navigation_hdr.pack(fill="x", pady=(10, 15), padx=8)
        tk.Label(navigation_hdr, text="Menu Navigation", font=("Arial", 9, "bold"), bg="#2A5F72", fg="white").pack()
        navigation_items = [("Dashboard", "Dashboard"),
            ("Alerts & Events", "Alerts"),
            ("Live Network Traffic", "LiveTraffic"),
            ("Threat Logs", "ThreatLogs"),
            ("Model Performance", "Performance"),
            ("Settings", "Settings"),
            ("Logout", "Logout"),]
        self.navigation_buttons = {}
        self.current_page = tk.StringVar(value="Dashboard")
        for label, key in navigation_items:
            button = tk.Button(sidebar, text=f"  ● {label}", font=F_BODY, anchor="w", relief="flat", cursor="hand2", padx=8, pady=10, bg=C["sidebar"],
                            fg=C["sidebar_txt"], activebackground=C["border"], command=lambda k=key: self.show_page(k))
            button.pack(fill="x")
            self.navigation_buttons[key] =button
        #creates all pages and stores them in dictionary
        self.pages = {}
        self.pages["Dashboard"] = self.create_dashboard()
        self.pages["Alerts"] = self.create_alerts()
        self.pages["LiveTraffic"] = self.generate_live_traffic()
        self.pages["ThreatLogs"] = self.generate_threat_logs()
        self.pages["Performance"] = self.generate_performance()
        self.pages["Settings"] = self.create_settings()
        self.pages["Logout"] = self.create_logout()
        self.show_page("Dashboard")
        #start the background simulation thread
        self.start_simulation()


    def show_page(self,key):
        #hides all pages apart from requested one
        for p in self.pages.values():
            p.pack_forget()
        self.pages[key].pack(fill="both", expand=True)
        self.current_page.set(key)
        #update sidebar highlight- selected page shows white and bold
        for k, button in self.navigation_buttons.items():
            if k== key:
                button.configure(fg="#ffffff", bg=C["border"], font=("Arial", 10, "bold"))
            else:
                button.configure(fg=C["sidebar_txt"], bg=C["sidebar"], font=F_BODY)
        #refreshs data on pages that show live data
        if key== "Dashboard": self.refresh_dashboard()
        if key == "Alerts": self.refresh_alerts()
        if key== "ThreatLogs": self.refresh_threat_logs()
        if key== "Performance": self.refresh_performance()
        if key == "Logout": self.refresh_logout()
        
        
    #builds the page header bar with title on left and user and status on right
    def page_header(self, page, title):
        hdr = tk.Frame(page, bg=C["header"],height=52)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        tk.Label(hdr, text=f"  {title}", font=("Arial", 14, "bold"), bg=C["header"], fg=C["text"]).pack(side="left", padx=10)
        #teal user and status box on the right
        user_box = tk.Frame(hdr, bg=C["teal"], padx=14, pady=6)
        user_box.pack(side="right", padx=15, pady=6)
        tk.Label(user_box, text=f"CURRENT USER: {(self.current_user or '').upper()}", font=("Arial", 8, "bold"), bg=C["teal"], fg=C["text"]).pack(anchor="e")
        sr = tk.Frame(user_box, bg=C["teal"])
        sr.pack(anchor="e")
        tk.Label(sr, text="SYSTEM STATUS  ", font=F_TINY, bg=C["teal"], fg=C["dim"]).pack(side="left")
        tk.Label(sr, text="●", font=F_TINY, bg=C["teal"], fg=C["medium"]).pack(side="left")
        
        
    #red classification footer at the bottom of each page
    def red_footer(self, page):
        footer = tk.Frame(page, bg=C["red_banner"], height=36)
        footer.pack(fill="x", side="bottom")
        footer.pack_propagate(False)
        tk.Label(footer, text="CLASSIFICATION: CONFIDENTIAL",
                 font=("Arial", 11, "bold"), bg=C["red_banner"], fg="white").pack(expand=True)



    #PAGE 1 Dashbaord
    def create_dashboard(self):
        page = tk.Frame(self.content, bg=C["bg"])
        self.page_header(page, "AI INTRUSION DETECTION DASHBOARD")

        body =tk.Frame(page, bg=C["bg"])
        body.pack(fill="both", expand=True, padx=15, pady=10)
        left = tk.Frame(body, bg=C["bg"])
        left.pack(side="left", fill="both", expand=True, padx=(0, 10))
        right = tk.Frame(body, bg=C["bg"], width=290)
        right.pack(side="right", fill="y")
        right.pack_propagate(False)
        #threat level card
        tl_box = tk.Frame(left, bg=C["card"], padx=15, pady=12)
        tl_box.pack(fill="x", pady=(0, 8))
        tk.Label(tl_box, text="THREAT LEVEL :", font=("Arial", 10, "bold"),
                 bg=C["card"], fg=C["dim"]).pack(side="left")
        self.dash_threat_lbl = tk.Label(tl_box, text="SAFE",
                                        font=("Arial", 20, "bold"), bg=C["card"], fg=C["normal"])
        self.dash_threat_lbl.pack(side="left", padx=8)
        #AI detection summary card
        ai_box = tk.Frame(left, bg=C["card"], padx=15, pady=12)
        ai_box.pack(fill="x", pady=(0, 8))
        tk.Label(ai_box, text="AI DETECTION SUMMARY", font=("Arial", 9, "bold"), bg=C["card"], fg=C["text"], anchor="w").pack(fill="x", pady=(0, 5))
        self.dash_24h_lbl = self.dash_row(ai_box, "Last 24hr anomalies:")
        self.dash_sig_lbl = self.dash_row(ai_box, "Signature matches:")
        self.dash_fp_lbl  =self.dash_row(ai_box, "False positives:")
        #system info card
        sys_box = tk.Frame(left, bg=C["card"], padx=15, pady=12)
        sys_box.pack(fill="x")
        tk.Label(sys_box, text="SYSTEM INFORMATION", font=("Arial", 9, "bold"),
                 bg=C["card"], fg=C["text"], anchor="w").pack(fill="x", pady=(0, 5))
        self.dash_cpu_lbl  = self.dash_row(sys_box, "CPU usage:")
        self.dash_mem_lbl  = self.dash_row(sys_box, "Memory usage:")
        self.dash_eng_lbl  = self.dash_row(sys_box,"IDS engine status:")
        self.dash_conf_lbl = self.dash_row(sys_box, "Model confidence score:")
        #live alerts log - right panel with scrollable canvas
        tk.Label(right, text="LIVE ALERTS LOG", font=("Arial", 9,"bold"),
                 bg=C["bg"], fg=C["text"], anchor="w").pack(fill="x", pady=(0, 4))
        #canvas + scrollbar for a scrollable list of alert rows
        alerts_frame = tk.Frame(right, bg=C["card"])
        alerts_frame.pack(fill="both", expand=True)
        canvas= tk.Canvas(alerts_frame, bg=C["card"], highlightthickness=0)
        scroll = ttk.Scrollbar(alerts_frame, orient="vertical", command=canvas.yview)
        self.dash_alerts_inner = tk.Frame(canvas, bg=C["card"])
        self.dash_alerts_inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=self.dash_alerts_inner, anchor="nw")
        canvas.configure(yscrollcommand=scroll.set)
        canvas.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self.red_footer(page)
        return page


    def dash_row(self, parent, label):
        #creates a key - value info row and returns reference to value label for updating
        row = tk.Frame(parent,bg=C["card"])
        row.pack(fill="x", pady=1)
        tk.Label(row, text=label, font=F_SMALL, bg=C["card"], fg=C["dim"], width=22, anchor="w").pack(side="left")
        val = tk.Label(row,text="—", font=F_SMALL, bg=C["card"], fg=C["text"], anchor="w")
        val.pack(side="left")
        return val


    def refresh_dashboard(self):
        threats = tl.get_all_threats()
        last_24h = tl.get_threats_last_24h()
        fp = tl.count_false_positives()
        high = sum(1 for t in last_24h if t["severity"] == "High")
        med = sum(1 for t in last_24h if t["severity"] =="Medium")
        #update threat level text with appropriate colour
        if high:
            self.dash_threat_lbl.configure(text="CRITICAL", fg=C["high"])
        elif med:
            self.dash_threat_lbl.configure(text="ELEVATED", fg=C["medium"])
        else:
            self.dash_threat_lbl.configure(text="SAFE", fg=C["normal"])
        self.dash_24h_lbl.configure(text=str(len(last_24h)))
        self.dash_sig_lbl.configure(text=str(sum(1 for t in last_24h if "Signature" in t.get("detection_method", ""))))
        self.dash_fp_lbl.configure(text=str(fp))
        #CPU and memory are simulated - psutil was attempted but couldnt be installed
        self.dash_cpu_lbl.configure(text=f"{random.randint(15, 45)}%")
        self.dash_mem_lbl.configure(text=f"{random.randint(30, 65)}%")
        self.dash_eng_lbl.configure(text="ACTIVE", fg=C["normal"])
        avg_conf = sum(float(t["confidence"]) for t in last_24h) / len(last_24h) if last_24h else 0
        self.dash_conf_lbl.configure(text=f"{avg_conf:.0%}" if last_24h else "N/A")
        #rebuilds scrollable alerts log
        for w in self.dash_alerts_inner.winfo_children():
            w.destroy()
        recent = list(reversed(threats))[:15]
        if not recent:
            tk.Label(self.dash_alerts_inner, text="No alerts yet.",
                     font=F_SMALL, bg=C["card"], fg=C["dim"]).pack(pady=10)
        else:
            for t in recent:
                col = self.severity_colour(t["severity"])
                row =tk.Frame(self.dash_alerts_inner, bg=C["card"], pady=2)
                row.pack(fill="x", padx=4)
                tk.Label(row, text="●", font=F_TINY, bg=C["card"], fg=col).pack(side="left")
                summary = f"[{t['severity']}] {t['source_ip']} → {t['destination_ip']}\n  {t['attack_type']}"
                tk.Label(row, text=summary, font=F_TINY, bg=C["card"], fg=C["text"], anchor="w", justify="left", wraplength=255).pack(side="left", padx=3)


 
    #PAGE 2 Alerts and evenyts
    def create_alerts(self):
        page = tk.Frame(self.content, bg=C["bg"])
        self.page_header(page, "ALERTS & EVENTS")
        #threat level indicator banner
        self.alerts_threat_lbl = tk.Label(page, text="THREAT LEVEL : SAFE", font=("Arial", 13, "bold"), bg=C["bg"], fg=C["normal"])
        self.alerts_threat_lbl.pack(anchor="w", padx=15, pady=(8, 4))
        #filter bar
        fbar = tk.Frame(page, bg=C["card"], padx=12, pady=6)
        fbar.pack(fill="x", padx=15, pady=(0, 6))
        tk.Label(fbar, text="Filter By:", font=F_SMALL, bg=C["card"], fg=C["dim"]).pack(side="left")
        self.alert_sev_var =tk.StringVar(value="All")
        sev_cb = ttk.Combobox(fbar,textvariable=self.alert_sev_var, values=["All", "High", "Medium", "Normal"], state="readonly", width=9)
        sev_cb.pack(side="left", padx=4)
        sev_cb.bind("<<ComboboxSelected>>", lambda e: self.refresh_alerts())
        tk.Label(fbar, text="Attack Type:", font=F_SMALL, bg=C["card"], fg=C["dim"]).pack(side="left", padx=(8, 0))
        self.alert_type_var= tk.StringVar(value="All")
        type_cb = ttk.Combobox(fbar, textvariable=self.alert_type_var,
                               values=["All","DoS / DDoS Attack", "Brute Force / Credential Attack", "Network Reconnaissance / Port Scan", "Probe / Network Sweep",
                                       "Advanced Persistent Threat (APT)", "Anomalous Traffic (Unknown Type)"],state="readonly", width=28)
        type_cb.pack(side="left", padx=4)
        type_cb.bind("<<ComboboxSelected>>",lambda e: self.refresh_alerts())
        tk.Label(fbar, text="Search:", font=F_SMALL, bg=C["card"], fg=C["dim"]).pack(side="left", padx=(8, 0))
        self.alert_search_var = tk.StringVar()
        tk.Entry(fbar, textvariable=self.alert_search_var, width=18, bg=C["border"], fg=C["text"], insertbackground=C["text"], relief="flat").pack(side="left", padx=4, ipady=3)
        tk.Button(fbar, text="Search", command=self.refresh_alerts, bg=C["blue"], fg="white", relief="flat", padx=8, pady=3).pack(side="left", padx=4)
        #table left, detail panel right
        split = tk.Frame(page, bg=C["bg"])
        split.pack(fill="both", expand=True, padx=15, pady=(0, 4))
        table_frame = tk.Frame(split,bg=C["bg"])
        table_frame.pack(side="left", fill="both", expand=True, padx=(0, 8))
        cols = ("ts", "src", "destination", "type", "conf", "sev")
        col_cfg = {
            "ts":   ("Timestamp", 130), "src": ("Source IP", 115),
            "destination":  ("Destination IP", 115), "type": ("Attack type", 170),
            "conf": ("AI confidence", 85), "sev": ("Severity", 70),
        }
        #colour coded rows- high=dark red, medium=dark orange, normal=default card colour
        tree_frame, self.alert_tree = scrolled_tree(table_frame, cols, col_cfg, height=18, tag_colours={"high": "#3D0000", "medium": "#3D2200", "normal": C["card"]})
        tree_frame.pack(fill="both", expand=True)
        self.alert_tree.bind("<<TreeviewSelect>>", self.on_alert_select)
        self.alert_page_lbl = tk.Label(table_frame, text="0 records", font=F_SMALL, bg=C["bg"], fg=C["dim"])
        self.alert_page_lbl.pack(pady=2, anchor="w")
        button_row = tk.Frame(table_frame, bg=C["bg"])
        button_row.pack(pady=4, anchor="w")
        for txt, cmd, bg in [
            ("Acknowledge Alert", lambda: self.alert_action("Investigating"), C["border"]),
            ("Mark False Positive", lambda: self.alert_action("False Positive"), "#4A3000"),
            ("Escalate Incident", lambda: self.alert_action("Resolved"), C["blue"]),
            ("Export selected", self.export_selected_alert,"#1A3D1A"),
        ]:
            tk.Button(button_row, text=txt, command=cmd, bg=bg, fg="white",font=F_SMALL, relief="flat", cursor="hand2", padx=10, pady=5).pack(side="left", padx=(0,4))
        #detail panel on right- scrolled text with state= "disabled" to make it read-only
        #state temporarily set to "normal" when inserting text then back to "disabled"
        detail= tk.Frame(split, bg=C["card"], width=280, padx=10, pady=10)
        detail.pack(side="right", fill="y")
        detail.pack_propagate(False)
        tk.Label(detail, text="Alerts Details (From selected)", font=("Arial", 9, "bold"), bg=C["card"], fg=C["text"]).pack(anchor="w", pady=(0, 6))
        self.alert_detail_txt = scrolledtext.ScrolledText(detail, font=F_SMALL, wrap="word", bg=C["bg"], fg=C["text"], insertbackground=C["text"], relief="flat", height=30, width=32, state="disabled")
        self.alert_detail_txt.pack(fill="both", expand=True)
        self.red_footer(page)
        return page


    def refresh_alerts(self):
        threats = tl.get_all_threats()
        sev =self.alert_sev_var.get()
        if sev != "All":
            threats = [t for t in threats if t["severity"] ==sev]
        atype = self.alert_type_var.get()
        if atype != "All":
            threats = [t for t in threats if t["attack_type"] == atype]
        q = self.alert_search_var.get().strip()
        if q:
            threats = tl.search_threats(q)
        #update threat level icon colour
        last_24h = tl.get_threats_last_24h()
        high = sum(1 for t in last_24h if t["severity"] == "High")
        med  = sum(1 for t in last_24h if t["severity"] == "Medium")
        if high:
            self.alerts_threat_lbl.configure(text="THREAT LEVEL : CRITICAL",fg=C["high"])
        elif med:
            self.alerts_threat_lbl.configure(text="THREAT LEVEL : ELEVATED",fg=C["medium"])
        else:
            self.alerts_threat_lbl.configure(text="THREAT LEVEL : SAFE", fg=C["normal"])
        for row in self.alert_tree.get_children():
            self.alert_tree.delete(row)
        for t in reversed(threats):
            sev_val = t["severity"]
            tag= sev_val.lower() if sev_val in ("High", "Medium") else "normal"
            self.alert_tree.insert("", "end", iid=t["threat_id"],
                values=(t["timestamp"], t["source_ip"], t["destination_ip"], t["attack_type"], f"{float(t['confidence']):.0%}", t["severity"]), tags=(tag,))
        self.alert_page_lbl.configure(text=f"{len(threats)} records")


    def on_alert_select(self, event=None):
        sel =self.alert_tree.selection()
        if not sel:
            return
        t = tl.get_threat_by_id(sel[0])
        if not t:
            return
        action = al.generate_recommended_action(t["severity"], t["attack_type"])
        detail = (f"Alert ID: {t['threat_id']}\n"
                  f"Timestamp: {t['timestamp']}\n"
                  f"Source IP: {t['source_ip']}\n"
                  f"Destination IP: {t['destination_ip']}\n"
                  f"Attack type: {t['attack_type']}\n"
                  f"Confidence: {float(t['confidence']):.0%}\n"
                  f"Severity: {t['severity']}\n"
                  f"Detection: {t['detection_method']}\n"
                  f"System: {t['affected_system']}\n"
                  f"Priority: {t['response_priority']}\n"
                  f"Status:{t['status']}\n\n"
                  f"Recommended action:\n{action}")
        #temporarily enable to insert text then lock it again
        self.alert_detail_txt.configure(state="normal")
        self.alert_detail_txt.delete("1.0", "end")
        self.alert_detail_txt.insert("1.0",detail)
        self.alert_detail_txt.configure(state="disabled")


    def alert_action(self, new_status):
        sel = self.alert_tree.selection()
        if not sel:
            messagebox.showinfo("No selection","Please select an alert first.")
            return
        tl.update_threat_status(sel[0], new_status)
        self.refresh_alerts()


    def export_selected_alert(self):
        sel =self.alert_tree.selection()
        if not sel:
            messagebox.showinfo("No selection", "Please select an alert first.")
            return
        t = tl.get_threat_by_id(sel[0])
        fname = f"alert_{sel[0]}.txt"
        try:
            with open(fname, "w") as f:
                for k, v in t.items():
                    f.write(f"{k}: {v}\n")
            messagebox.showinfo("Exported", f"Saved to {fname}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

 
    #PAGE 3 Live network traffic
    def generate_live_traffic(self):
        page = tk.Frame(self.content, bg=C["bg"])
        self.page_header(page, "LIVE NETWORK TRAFFIC")
        #threat level banner
        banner = tk.Frame(page, bg=C["card"], padx=15, pady=8)
        banner.pack(fill="x", padx=15, pady=(8, 0))
        self.lt_threat_lbl = tk.Label(banner, text="THREAT LEVEL : SAFE", font=("Arial", 13, "bold"), bg=C["card"], fg=C["normal"])
        self.lt_threat_lbl.pack(anchor="w")
        body = tk.Frame(page, bg=C["bg"])
        body.pack(fill="both", expand=True, padx=15, pady=8)
        #stat panel on the left
        stats = tk.Frame(body, bg=C["card"], padx=12,pady=10, width=200)
        stats.pack(side="left", fill="y", padx=(0, 8))
        stats.pack_propagate(False)
        tk.Label(stats, text="Live Traffic Overview", font=("Arial", 9, "bold"), bg=C["card"], fg=C["text"], anchor="w").pack(fill="x", pady=(0, 6))
        self.lt_pps_lbl = self.lt_stat(stats, "Packets per second:")
        self.lt_conn_lbl = self.lt_stat(stats, "Active connections:")
        self.lt_src_lbl = self.lt_stat(stats, "Unique source IPs:")
        self.lt_destination_lbl = self.lt_stat(stats, "Unique dest IPs:")
        self.lt_tcp_lbl = self.lt_stat(stats, "TCP traffic:")
        self.lt_udp_lbl = self.lt_stat(stats, "UDP traffic:")
        self.lt_icmp_lbl = self.lt_stat(stats,"ICMP traffic:")
        #packet stream table in centre
        table_area = tk.Frame(body, bg=C["bg"])
        table_area.pack(side="left", fill="both", expand=True, padx=(0, 8))
        tk.Label(table_area, text="Real Time Packet Stream", font=("Arial", 9, "bold"), bg=C["bg"], fg=C["text"], anchor="w").pack(fill="x", pady=(0, 4))
        cols = ("ts", "src", "destination", "proto", "size", "status")
        col_cfg = {"ts": ("Time", 80), "src": ("Source IP", 120), "destination": ("Dest IP", 120),
            "proto": ("Protocol", 65), "size": ("Packet size", 80), "status": ("Status", 90),}
        tf, self.lt_tree = scrolled_tree(table_area, cols, col_cfg, height=20, tag_colours={"high": "#3D0000", "medium": "#3D2200", "normal": C["card"]})
        tf.pack(fill="both", expand=True)
        #filters panel on right
        filters = tk.Frame(body,bg=C["card2"], width=190, padx=10, pady=10)
        filters.pack(side="right", fill="y")
        filters.pack_propagate(False)
        tk.Label(filters, text="Filters", font=("Arial", 10, "bold"),
                 bg=C["card2"], fg=C["text"]).pack(anchor="w", pady=(0, 8))
        tk.Label(filters, text="Protocol:", font=F_TINY, bg=C["card2"], fg=C["text"], anchor="w").pack(fill="x")
        self.lt_proto_var = tk.StringVar(value="All")
        ttk.Combobox(filters, textvariable=self.lt_proto_var, values=["All", "TCP", "UDP", "ICMP"],
                     state="readonly",width=14).pack(fill="x", pady=(2, 8))
        tk.Label(filters, text="Traffic type:", font=F_TINY, bg=C["card2"], fg=C["text"], anchor="w").pack(fill="x")
        self.lt_sus_var = tk.StringVar(value="All")
        ttk.Combobox(filters, textvariable=self.lt_sus_var,
                     values=["All", "Suspicious only", "Normal only"],
                     state="readonly", width=14).pack(fill="x", pady=(2, 8))
        tk.Label(filters, text="Source IP:", font=F_TINY, bg=C["card2"], fg=C["text"], anchor="w").pack(fill="x")
        self.lt_src_filter =tk.StringVar()
        tk.Entry(filters, textvariable=self.lt_src_filter, bg=C["border"],
                 fg=C["text"], insertbackground=C["text"], relief="flat", width=16).pack(fill="x", pady=(2, 8))
        tk.Label(filters,text="Dest IP:", font=F_TINY, bg=C["card2"], fg=C["text"], anchor="w").pack(fill="x")
        self.lt_destination_filter = tk.StringVar()
        tk.Entry(filters, textvariable=self.lt_destination_filter, bg=C["border"],
                 fg=C["text"], insertbackground=C["text"], relief="flat", width=16).pack(fill="x",pady=(2, 12))
        tk.Button(filters, text="Clear filters", command=self.clear_lt_filters,
                  bg=C["blue"], fg="white", relief="flat",pady=4).pack(fill="x")
        self.red_footer(page)
        return page



    def lt_stat(self, parent, label):
        tk.Label(parent, text=label, font=F_TINY, bg=C["card"], fg=C["dim"], anchor="w").pack(fill="x")
        val = tk.Label(parent, text="0", font=("Arial", 10, "bold"), bg=C["card"], fg=C["text"], anchor="w")
        val.pack(fill="x",pady=(0,4))
        return val

    def clear_lt_filters(self):
        self.lt_proto_var.set("All")
        self.lt_sus_var.set("All")
        self.lt_src_filter.set("")
        self.lt_destination_filter.set("")

    def add_lt_row(self, event, src, destination, confidence, severity):
        proto = event.get("protocol", "TCP")
        pkt_size = event.get("packet_size_bytes", 0)
        if severity == "High":
            tag, status = "high", "THREAT - HIGH"
        elif severity == "Medium":
            tag, status = "medium","SUSPICIOUS"
        else:
            tag, status = "normal", "Normal"
        ts= datetime.now().strftime("%H:%M:%S")
        self.lt_tree.insert("", 0, values=(ts, src, destination, proto, f"{pkt_size:,}", status), tags=(tag,))
        #cap at 300 rows so table doesnt grow infinitly
        kids = self.lt_tree.get_children()
        if len(kids) > 300:
            self.lt_tree.delete(kids[-1])
        #update overview stats
        self._total_events += 1
        self._src_ips_seen.add(src)
        self._destination_ips_seen.add(destination)
        self._protocol_counts[proto] = self._protocol_counts.get(proto, 0) + 1
        total_proto = sum(self._protocol_counts.values()) or 1
        #update threat level banner on live traffic page
        last_24h = tl.get_threats_last_24h()
        high = sum(1 for t in last_24h if t["severity"] == "High")
        med= sum(1 for t in last_24h if t["severity"] == "Medium")
        try:
            if high:
                self.lt_threat_lbl.configure(text="THREAT LEVEL : CRITICAL", fg=C["high"])
            elif med:
                self.lt_threat_lbl.configure(text="THREAT LEVEL : ELEVATED", fg=C["medium"])
            else:
                self.lt_threat_lbl.configure(text="THREAT LEVEL : SAFE", fg=C["normal"])
            self.lt_pps_lbl.configure(text=str(random.randint(800, 1500)))
            self.lt_conn_lbl.configure(text=str(random.randint(50,150)))
            self.lt_src_lbl.configure(text=str(len(self._src_ips_seen)))
            self.lt_destination_lbl.configure(text=str(len(self._destination_ips_seen)))
            self.lt_tcp_lbl.configure(text=f"{self._protocol_counts.get('TCP',0) / total_proto:.0%}")
            self.lt_udp_lbl.configure(text=f"{self._protocol_counts.get('UDP', 0) / total_proto:.0%}")
            self.lt_icmp_lbl.configure(text=f"{self._protocol_counts.get('ICMP', 0) / total_proto:.0%}")
        except tk.TclError:
            pass


    #PAGE 4 Threat logs
    def generate_threat_logs(self):
        page = tk.Frame(self.content,bg=C["bg"])
        self.page_header(page, "THREAT LOGS")
        title_row = tk.Frame(page, bg=C["bg"])
        title_row.pack(fill="x", padx=15, pady=(8, 0))
        tk.Label(title_row, text="Threat Summary", font=("Arial", 14, "bold"), bg=C["bg"], fg=C["text"]).pack(side="left")
        tk.Button(title_row, text="Export selected", command=self.export_threat_log, bg=C["blue"], fg="white", relief="flat", padx=8, pady=4).pack(side="right")
        #create filter bar
        fbar = tk.Frame(page, bg=C["card"], padx=10, pady=6)
        fbar.pack(fill="x", padx=15, pady=4)
        tk.Label(fbar, text="Filter by:", font=F_SMALL, bg=C["card"], fg=C["dim"]).pack(side="left")
        self.tl_sev_var = tk.StringVar(value="All")
        ttk.Combobox(fbar, textvariable=self.tl_sev_var, values=["All", "High", "Medium", "Normal"], state="readonly", width=10).pack(side="left", padx=4)
        self.tl_status_var = tk.StringVar(value="All")
        ttk.Combobox(fbar, textvariable=self.tl_status_var, values=["All", "Open", "Investigating", "Resolved", "False Positive"], state="readonly", width=14).pack(side="left", padx=4)
        tk.Button(fbar, text="Apply", command=self.refresh_threat_logs, bg=C["blue"], fg="white", relief="flat", padx=8, pady=3).pack(side="left", padx=6)
        #create main table
        cols = ("tid", "src", "destination", "conf", "method", "system", "priority", "ts", "type", "sev", "status")
        col_cfg = {"tid": ("Threat ID", 105), "src": ("Source IP", 105), "destination": ("Dest IP", 105), "conf": ("Confidence", 75), "method": ("Detection", 110), "system": ("System", 110),
            "priority": ("Priority", 100), "ts": ("Timestamp", 130), "type": ("Attack type", 155), "sev": ("Severity", 65), "status": ("Status", 100),}
        tf, self.tl_tree = scrolled_tree(page, cols, col_cfg, height=12, tag_colours={"high": "#3D0000", "medium": "#3D2200", "normal": C["card"]})
        tf.pack(fill="x", padx=15)
        self.tl_tree.bind("<<TreeviewSelect>>", self.on_t1_select)
        #create bottom three panels
        bottom =tk.Frame(page, bg=C["bg"])
        bottom.pack(fill="both", expand=True, padx=15, pady=(4, 4))
        #create stats panel
        stats_panel = tk.Frame(bottom, bg=C["card"], padx=12, pady=10)
        stats_panel.pack(side="left", fill="y", padx=(0, 6))
        self.tl_stat_labels = {}
        for key, label in [
            ("total", "Total threats:"), ("alerts", "Alerts:"), ("traffic_logs", "Traffic logs:"),
            ("system_logs", "System logs:"), ("unresolved", "Unresolved:"), ("acknowledged", "Acknowledged:"),
            ("resolved", "Resolved:"), ("false_positives", "False positives:"),
        ]:
            row = tk.Frame(stats_panel, bg=C["card"])
            row.pack(fill="x", pady=1)
            tk.Label(row, text=label, font=F_SMALL, bg=C["card"], fg=C["dim"], width=16, anchor="w").pack(side="left")
            lbl = tk.Label(row, text="0", font=F_SMALL, bg=C["card"], fg=C["text"])
            lbl.pack(side="left")
            self.tl_stat_labels[key] = lbl
        #createlogs detail panel
        detail_panel = tk.Frame(bottom, bg=C["card"], padx=10, pady=10)
        detail_panel.pack(side="left", fill="both", expand=True, padx=(0, 6))
        tk.Label(detail_panel, text="Log Details (From Selected)", font=("Arial", 9, "bold"),
                 bg=C["card"],fg=C["text"]).pack(anchor="w", pady=(0, 6))
        self.tl_detail_labels = {}
        for label, key in [("Log ID:", "id"), ("Timestamp:", "ts"), ("Source IP:", "src"),("Dest IP:","destination"), ("Event:", "event"), ("Confidence:", "conf"), ("Detection:", "method"), ("Status:","status")]:
            r = tk.Frame(detail_panel, bg=C["card"])
            r.pack(fill="x", pady=1)
            tk.Label(r, text=label, font=F_TINY, bg=C["card"], fg=C["dim"], width=12, anchor="w").pack(side="left")
            lbl = tk.Label(r, text="—", font=F_TINY, bg=C["card"], fg=C["text"], anchor="w")
            lbl.pack(side="left")
            self.tl_detail_labels[key] = lbl
        #create notes panel
        notes_panel = tk.Frame(bottom, bg=C["card"], padx=10, pady=10)
        notes_panel.pack(side="right", fill="both", expand=True)
        tk.Label(notes_panel, text="Notes / Actions taken:", font=("Arial", 9, "bold"), bg=C["card"], fg=C["text"]).pack(anchor="w", pady=(0, 6))
        self.tl_notes_txt = scrolledtext.ScrolledText(notes_panel, font=F_TINY, bg=C["bg"],fg=C["text"], relief="flat", height=8)
        self.tl_notes_txt.pack(fill="both", expand=True)
        self.tl_notes_txt.insert("1.0", "Select a log entry above to view notes.")
        self.red_footer(page)
        return page



    def refresh_threat_logs(self):
        threats = tl.get_all_threats()
        sev =self.tl_sev_var.get()
        if sev != "All":
            threats = [t for t in threats if t["severity"] == sev]
        status = self.tl_status_var.get()
        if status != "All":
            threats = [t for t in threats if t["status"] == status]
        for row in self.tl_tree.get_children():
            self.tl_tree.delete(row)
        for t in threats:
            sev_val = t["severity"]
            tag = sev_val.lower() if sev_val in ("High", "Medium") else "normal"
            self.tl_tree.insert("", "end", iid=t["threat_id"],
                values=(t["threat_id"], t["source_ip"], t["destination_ip"], f"{float(t['confidence']):.0%}", t["detection_method"],
                        t["affected_system"], t["response_priority"], t["timestamp"], t["attack_type"], t["severity"], t["status"]), tags=(tag,))
        stats = tl.get_log_stats()
        for key, lbl in self.tl_stat_labels.items():
            lbl.configure(text=str(stats.get(key, 0)))



    def on_t1_select(self, event=None):
        sel = self.tl_tree.selection()
        if not sel:
            return
        t = tl.get_threat_by_id(sel[0])
        if not t:
            return
        self.tl_detail_labels["id"].configure(text=t["threat_id"])
        self.tl_detail_labels["ts"].configure(text=t["timestamp"])
        self.tl_detail_labels["src"].configure(text=t["source_ip"])
        self.tl_detail_labels["destination"].configure(text=t["destination_ip"])
        self.tl_detail_labels["event"].configure(text=t["attack_type"])
        self.tl_detail_labels["conf"].configure(text=f"{float(t['confidence']):.0%}")
        self.tl_detail_labels["method"].configure(text=t["detection_method"])
        self.tl_detail_labels["status"].configure(text=t["status"])
        action = al.generate_recommended_action(t["severity"],t["attack_type"])
        self.tl_notes_txt.delete("1.0", "end")
        self.tl_notes_txt.insert("1.0", action)



    def export_threat_log(self):
        import shutil
        try:
            dest= f"threat_log_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            shutil.copy("data/threat_log.csv", dest)
            messagebox.showinfo("Exported", f"Saved to {dest}")
        except Exception as e:
            messagebox.showerror("Export failed", str(e))


    #PAGE 5- Model perforamce


    def generate_performance(self):
        page = tk.Frame(self.content, bg=C["bg"])
        self.page_header(page, "MODEL PERFORMANCE")
        banner = tk.Frame(page, bg=C["card"], padx=15, pady=8)
        banner.pack(fill="x", padx=15, pady=(8, 6))
        self.perf_threat_lbl = tk.Label(banner, text="THREAT LEVEL : ELEVATED", font=("Arial", 13, "bold"), bg=C["card"], fg=C["medium"])
        self.perf_threat_lbl.pack(anchor="w")
        self.perf_body = tk.Frame(page, bg=C["bg"])
        self.perf_body.pack(fill="both", expand=True, padx=15)
        self.red_footer(page)
        return page

    def refresh_performance(self):
        for w in self.perf_body.winfo_children():
            w.destroy()
        if not self.model:
            tk.Label(self.perf_body, text="Model not loaded. Run model.py first.", font=F_BODY, bg=C["bg"], fg=C["dim"]).pack(pady=30)
            return
        if self.model_metrics is None:
            try:
                X_test, y_test = md.load_test_data()
                self.model_metrics = md.evaluate_model(self.model, X_test, y_test)
            except Exception as e:
                tk.Label(self.perf_body, text=f"Could not evaluate: {e}", font=F_BODY, bg=C["bg"], fg=C["high"]).pack(pady=30)
                return
        m =self.model_metrics
        #4 metric cards in a row
        metrics_row = tk.Frame(self.perf_body, bg=C["bg"])
        metrics_row.pack(fill="x", pady=(0, 12))
        for label, val in [("Accuracy", f"{m['accuracy']:.1%}"), ("Precision", f"{m['precision']:.1%}"), ("Recall", f"{m['recall']:.1%}"), ("F1 Score", f"{m['f1']:.1%}")]:
            col = C["normal"] if label == "Recall" and m["recall"] >= 0.9 else (C["high"] if label == "Recall" else C["text"])
            box = tk.Frame(metrics_row, bg=C["card"], padx=16, pady=12)
            box.pack(side="left", expand=True, fill="x", padx=4)
            tk.Label(box, text=val, font=("Arial", 22, "bold"), bg=C["card"], fg=col).pack()
            tk.Label(box, text=label, font=F_SMALL, bg=C["card"], fg=C["dim"]).pack()
        lower = tk.Frame(self.perf_body,bg=C["bg"])
        lower.pack(fill="both", expand=True)
        #confusion matrix
        cm_box = tk.Frame(lower, bg=C["card"], padx=14, pady=12)
        cm_box.pack(side="left", fill="both", expand=True, padx=(0, 8))
        tk.Label(cm_box, text="Confusion Matrix", font=("Arial", 10, "bold"),
                 bg=C["card"], fg=C["text"], anchor="w").pack(fill="x", pady=(0, 8))
        grid = tk.Frame(cm_box, bg=C["card"])
        grid.pack()
        for col_i, txt in enumerate(["", "Pred: Normal", "Pred: Attack"]):
            tk.Label(grid, text=txt, font=("Arial", 9, "bold"), bg=C["card"],
                     fg=C["text"], width=14, pady=4).grid(row=0, column=col_i, padx=2)
        tk.Label(grid, text="Actual: Normal", font=F_TINY, bg=C["card"], fg=C["text"], width=14).grid(row=1, column=0)
        tk.Label(grid, text=f"TN: {m['tn']}", font=("Arial", 16, "bold"), bg="#003300", fg=C["normal"], width=14, pady=10).grid(row=1, column=1, padx=2, pady=2)
        tk.Label(grid, text=f"FP: {m['fp']}", font=("Arial", 16, "bold"), bg="#3D1500", fg=C["medium"], width=14, pady=10).grid(row=1, column=2, padx=2, pady=2)
        tk.Label(grid, text="Actual: Attack", font=F_TINY, bg=C["card"], fg=C["text"], width=14).grid(row=2, column=0)
        tk.Label(grid, text=f"FN: {m['fn']}", font=("Arial", 16, "bold"), bg="#3D0000", fg=C["high"], width=14, pady=10).grid(row=2, column=1, padx=2, pady=2)
        tk.Label(grid, text=f"TP: {m['tp']}", font=("Arial", 16, "bold"), bg="#003300", fg=C["normal"], width=14, pady=10).grid(row=2, column=2, padx=2, pady=2)
        tk.Label(cm_box, text=f"Precision: {m['precision']:.1%}    Recall: {m['recall']:.1%}    F1: {m['f1']:.1%}", font=F_TINY, bg=C["card"], fg=C["dim"]).pack(anchor="w", pady=(6, 0))
        #model info
        info = tk.Frame(cm_box, bg=C["card"])
        info.pack(fill="x", pady=(8, 0))
        tk.Label(info, text="Model Information", font=("Arial", 9, "bold"), bg=C["card"], fg=C["text"], anchor="w").pack(fill="x")
        for line in [f"Algorithm: Logistic Regression", f"Test samples: {m.get('test_size', 0)}", f"Threshold: {m.get('threshold', 0.35)}", f"Features: {len(md.FEATURE_COLS) if MODEL_AVAILABLE else 7}"]:
            tk.Label(info, text=line, font=F_TINY, bg=C["card"], fg=C["dim"], anchor="w").pack(fill="x")
        #feature weights - horizontal bars showing importance
        feat_box =tk.Frame(lower, bg=C["card"], padx=14, pady=12)
        feat_box.pack(side="right", fill="y")
        tk.Label(feat_box, text="Top Feature importance", font=("Arial", 10, "bold"), bg=C["card"], fg=C["text"], anchor="w").pack(fill="x", pady=(0, 8))
        weights = self.model.coef_[0]
        abs_w = [abs(w) for w in weights]
        max_w = max(abs_w) if abs_w else 1
        pairs = sorted(zip(md.FEATURE_COLS, abs_w), key=lambda x: x[1], reverse=True)
        for feature, weight in pairs:
            row = tk.Frame(feat_box, bg=C["card"])
            row.pack(fill="x", pady=2)
            tk.Label(row, text=feature, font=F_TINY, bg=C["card"], fg=C["text"], width=18, anchor="w").pack(side="left")
            bar = tk.Canvas(row, height=10, width=120, bg=C["border"], highlightthickness=0)
            bar.pack(side="left", padx=4)
            fill_w = int(120 * (weight / max_w))
            bar.create_rectangle(0, 0, fill_w, 10, fill="#1976D2", width=0)
            tk.Label(row, text=f"{weight/max_w:.2f}", font=F_TINY,
                     bg=C["card"], fg=C["dim"]).pack(side="left")
        button_row = tk.Frame(feat_box, bg=C["card"])
        button_row.pack(fill="x", pady=(12, 0))
        tk.Button(button_row, text="Retrain Model", command=self.retrain_model, bg=C["normal"], fg="#000000", relief="flat", padx=8, pady=5).pack(side="left", padx=(0, 8))
        tk.Button(button_row, text="Export Report", command=self.export_model_report, bg=C["border"], fg=C["text"], relief="flat", padx=8, pady=5).pack(side="left")



    def retrain_model(self):
        messagebox.showinfo("Retrain", "Close UI, run prepare_data.py then model.py, then reopen ui.py.")

    def export_model_report(self):
        if not self.model_metrics:
            messagebox.showinfo("No data", "Model not evaluated yet.")
            return
        m = self.model_metrics
        fname = f"model_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        try:
            with open(fname, "w") as f:
                f.write(f"AI-IDS Model Report\nGenerated: {datetime.now()}\n\n")
                f.write(f"Accuracy: {m['accuracy']:.4f}\nPrecision: {m['precision']:.4f}\n")
                f.write(f"Recall: {m['recall']:.4f}\nF1: {m['f1']:.4f}\n\n")
                f.write(f"TP:{m['tp']} TN:{m['tn']} FP:{m['fp']} FN:{m['fn']}\n")
            messagebox.showinfo("Exported", f"Saved to {fname}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    # =========================================================================
    # PAGE 6: SETTINGS
    # =========================================================================

    def create_settings(self):
        page = tk.Frame(self.content, bg=C["bg"])
        self.page_header(page, "SETTINGS")
        body = tk.Frame(page, bg=C["bg"])
        body.pack(fill="both", expand=True, padx=15, pady=10)
        #detection settings panel
        det = tk.Frame(body, bg=C["card"], padx=14, pady=12)
        det.pack(side="left", fill="both", expand=True, padx=(0, 6))
        tk.Label(det, text="Detection Settings", font=("Arial", 10, "bold"),
                 bg=C["card"], fg=C["text"], anchor="w").pack(fill="x", pady=(0, 10))
        self.s_mode_var = tk.StringVar(value="Logistic Regression")
        self.settings_rows(det, "Detection Mode:", "combo", self.s_mode_var,
                           ["Logistic Regression", "Anomaly Based", "Signature Based"])
        self.s_thresh_var = tk.StringVar(value="35")
        self.settings_rows(det, "Alert Threshold (%):", "entry", self.s_thresh_var)
        self.s_sens_var = tk.StringVar(value="High")
        self.settings_rows(det, "Sensitivity:", "combo", self.s_sens_var, ["Low", "Medium", "High"])
        self.s_autoblock_var = tk.BooleanVar(value=False)
        self.settings_rows(det, "Auto block on CRITICAL:", "check", self.s_autoblock_var)
        self.s_sigupdate_var = tk.BooleanVar(value=True)
        self.settings_rows(det, "Signature auto updates:", "check", self.s_sigupdate_var)
        #system settings panel
        sys = tk.Frame(body, bg=C["card"], padx=14, pady=12)
        sys.pack(side="left", fill="both", expand=True, padx=(0, 6))
        tk.Label(sys, text="System Settings", font=("Arial", 10, "bold"),
                 bg=C["card"], fg=C["text"], anchor="w").pack(fill="x", pady=(0, 10))
        self.s_retention_var = tk.StringVar(value="30 days")
        self.settings_rows(sys, "Log retention:", "combo", self.s_retention_var, ["7 days", "14 days", "30 days", "90 days"])
        self.s_autoexport_var = tk.StringVar(value="Yes")
        self.settings_rows(sys, "Auto-export logs:", "combo", self.s_autoexport_var, ["Yes", "No"])
        self.s_interface_var = tk.StringVar(value="eth0")
        self.settings_rows(sys, "Network interface:", "entry", self.s_interface_var)
        self.s_buffer_var = tk.StringVar(value="512")
        self.settings_rows(sys, "Packet buffer (MB):", "entry", self.s_buffer_var)
        self.s_engine_var = tk.StringVar(value="Active")
        self.settings_rows(sys, "IDS Engine:", "combo", self.s_engine_var, ["Active", "Paused", "Stopped"])
        #user and access settings panel
        usr = tk.Frame(body, bg=C["card"], padx=14, pady=12)
        usr.pack(side="left", fill="both", expand=True)
        tk.Label(usr, text="User + Access Settings", font=("Arial", 10, "bold"), bg=C["card"], fg=C["text"], anchor="w").pack(fill="x", pady=(0, 10))
        #current user display - read only
        row = tk.Frame(usr, bg=C["card"])
        row.pack(fill="x", pady=3)
        tk.Label(row, text="Current user:", font=F_SMALL, bg=C["card"], fg=C["dim"], width=20, anchor="w").pack(side="left")
        tk.Label(row, text=(self.current_user or "").capitalize(), font=F_SMALL, bg=C["card"], fg=C["text"]).pack(side="left")
        row2 = tk.Frame(usr, bg=C["card"])
        row2.pack(fill="x", pady=3)
        tk.Label(row2, text="Change password:", font=F_SMALL, bg=C["card"], fg=C["dim"],  width=20, anchor="w").pack(side="left")
        tk.Button(row2, text="Change", command=self.change_password, bg=C["blue"], fg="white", relief="flat", padx=8, pady=2).pack(side="left")
        self.s_timeout_var = tk.StringVar(value="15")
        self.settings_rows(usr, "Session timeout (mins):", "entry", self.s_timeout_var)
        self.s_accesslog_var = tk.BooleanVar(value=True)
        self.settings_rows(usr, "Access log:", "check", self.s_accesslog_var)
        button_row = tk.Frame(page, bg=C["bg"])
        button_row.pack(pady=(8, 6), padx=15, anchor="e")
        tk.Button(button_row, text="Reset to Default", command=self.reset_settings, bg=C["border"], fg=C["text"], relief="flat", padx=12, pady=5).pack(side="left", padx=(0, 6))
        tk.Button(button_row, text="Save Settings", command=self.save_settings, bg=C["normal"], fg="#000000", relief="flat", padx=12, pady=5).pack(side="left")
        self.red_footer(page)
        return page

    def settings_rows(self, parent, label, widget_type, var, values=None):
        row = tk.Frame(parent, bg=C["card"])
        row.pack(fill="x", pady=3)
        tk.Label(row, text=label, font=F_SMALL, bg=C["card"], fg=C["dim"],
                 width=24, anchor="w").pack(side="left")
        if widget_type == "combo":
            ttk.Combobox(row, textvariable=var, values=values or [],
                         state="readonly", width=16).pack(side="left")
        elif widget_type == "entry":
            tk.Entry(row, textvariable=var, width=14, bg=C["border"],
                     fg=C["text"], insertbackground=C["text"], relief="flat").pack(side="left", ipady=3)
        elif widget_type == "check":
            tk.Checkbutton(row, variable=var, bg=C["card"], fg=C["text"],
                           selectcolor=C["blue"], activebackground=C["card"],
                           relief="flat", cursor="hand2").pack(side="left")

    def change_password(self):
        #opens a new window that takes priority (grab_set) over the main window
        win = tk.Toplevel(self.root)
        win.title("Change Password")
        win.configure(bg=C["bg"])
        win.geometry("300x170")
        win.grab_set()
        tk.Label(win, text="New password:", font=F_BODY, bg=C["bg"], fg=C["text"]).pack(pady=(20, 4))
        new_var = tk.StringVar()
        tk.Entry(win, textvariable=new_var, show="•", width=24, bg=C["border"],
                 fg=C["text"], insertbackground=C["text"], relief="flat").pack(ipady=4)
        def apply():
            if len(new_var.get()) >= 6:
                VALID_USERS[self.current_user] = new_var.get()
                messagebox.showinfo("Done", "Password changed.")
                win.destroy()
            else:
                messagebox.showerror("Error", "Must be at least 6 characters.")
        tk.Button(win, text="Confirm", command=apply,
                  bg=C["blue"], fg="white", relief="flat", padx=20, pady=6).pack(pady=12)

    def save_settings(self):
        messagebox.showinfo("Saved", "Settings saved.")

    def reset_settings(self):
        self.s_mode_var.set("Logistic Regression")
        self.s_thresh_var.set("35")
        self.s_sens_var.set("High")
        self.s_autoblock_var.set(False)
        self.s_sigupdate_var.set(True)
        self.s_retention_var.set("30 days")
        self.s_autoexport_var.set("Yes")
        self.s_interface_var.set("eth0")
        self.s_buffer_var.set("512")
        self.s_engine_var.set("Active")
        self.s_timeout_var.set("15")
        self.s_accesslog_var.set(True)
        messagebox.showinfo("Reset", "Settings reset to defaults.")


    #PAGE 7 logout
    def create_logout(self):
        page = tk.Frame(self.content, bg=C["bg"])
        self.page_header(page, "LOGOUT")

        centre = tk.Frame(page, bg=C["bg"])
        centre.place(relx=0.5, rely=0.45, anchor="center")

        tk.Label(centre, text="You are about to end your session",
                 font=("Arial", 11), bg=C["bg"], fg=C["text"]).pack(pady=(0, 12))

        #session summary box
        self.logout_summary = tk.Frame(centre, bg=C["card2"], padx=20, pady=10)
        self.logout_summary.pack(fill="x", pady=(0, 10))
        self.lo_user_lbl     = tk.Label(self.logout_summary, text="User: —", font=F_SMALL, bg=C["card2"], fg=C["text"], anchor="w")
        self.lo_user_lbl.pack(fill="x")
        self.lo_start_lbl    = tk.Label(self.logout_summary, text="Session started: —", font=F_SMALL, bg=C["card2"], fg=C["text"], anchor="w")
        self.lo_start_lbl.pack(fill="x")
        self.lo_dur_lbl      = tk.Label(self.logout_summary, text="Duration: —", font=F_SMALL, bg=C["card2"], fg=C["text"], anchor="w")
        self.lo_dur_lbl.pack(fill="x")
        self.lo_actions_lbl  = tk.Label(self.logout_summary, text="Actions taken: —", font=F_SMALL, bg=C["card2"], fg=C["text"], anchor="e")
        self.lo_actions_lbl.pack(fill="x")
        self.lo_ack_lbl      = tk.Label(self.logout_summary, text="Alerts acknowledged: —", font=F_SMALL, bg=C["card2"], fg=C["text"], anchor="e")
        self.lo_ack_lbl.pack(fill="x")
        self.lo_activity_lbl = tk.Label(self.logout_summary, text="Last activity: —", font=F_SMALL, bg=C["card2"], fg=C["text"], anchor="e")
        self.lo_activity_lbl.pack(fill="x")

        #red security reminders panel
        red_panel = tk.Frame(centre, bg=C["red_panel"], padx=16, pady=10)
        red_panel.pack(fill="x", pady=(0, 8))
        tk.Label(red_panel, text="SECURITY REMINDERS", font=("Arial", 9, "bold"),
                 bg=C["red_panel"], fg=C["high"], anchor="w").pack(fill="x")
        for r in ["> Ensure all active incidents have been handed over before logging out",
                  "> Unsaved settings changes will be lost",
                  "> Unresolved CRITICAL alerts will remain active",
                  "> Do not leave terminal unattended. Lock or shut down when away"]:
            tk.Label(red_panel, text=r, font=F_TINY, bg=C["red_panel"], fg=C["text"],
                     anchor="w", wraplength=460, justify="left").pack(fill="x", pady=1)

        #green session notice panel
        green_panel = tk.Frame(centre, bg=C["green_panel"], padx=16, pady=10)
        green_panel.pack(fill="x", pady=(0, 14))
        tk.Label(green_panel, text="Session Notice", font=("Arial", 9, "bold"),
                 bg=C["green_panel"], fg=C["normal"], anchor="w").pack(fill="x")
        tk.Label(green_panel, text="IDS engine will continue running after logout. All session activity has been logged. Unauthorised access attempts are recorded and reported.",
                 font=F_TINY, bg=C["green_panel"], fg=C["text"], anchor="w", wraplength=460, justify="left").pack(fill="x")

        tk.Button(centre, text="CONFIRM LOGOUT", command=self.confirm_logout,
                  bg=C["card2"], fg=C["text"], font=("Arial", 12, "bold"),
                  relief="flat", cursor="hand2", padx=36, pady=12).pack()

        self.red_footer(page)
        return page

    def refresh_logout(self):
        if not self.session_start:
            return
        stats = tl.get_session_stats(self.session_start)
        self.lo_user_lbl.configure(text=f"User: {(self.current_user or '').capitalize()}")
        self.lo_start_lbl.configure(text=f"Session started: {stats['start_time']}")
        self.lo_dur_lbl.configure(text=f"Duration: {stats['duration']}")
        self.lo_actions_lbl.configure(text=f"Actions taken: {stats['actions_taken']}")
        self.lo_ack_lbl.configure(text=f"Alerts acknowledged: {stats['alerts_acknowledged']}")
        self.lo_activity_lbl.configure(text=f"Last activity: {stats['last_activity']}")

    def confirm_logout(self):
        self.sim_running = False
        self.current_user = None
        self.session_start= None
        self.model = None
        self.scaler_params = None
        self.model_metrics= None
        self._total_events = 0
        self._src_ips_seen = set()
        self._destination_ips_seen = set()
        self._protocol_counts = {"TCP": 0, "UDP": 0, "ICMP": 0}
        self.show_login()


    #Background simulation
    def start_simulation(self):
        self.sim_running = True
        def loop():
            while self.sim_running:
                event, src, destination, system = al.generate_simulated_event()
                if self.model and self.scaler_params:
                    confidence, severity = md.predict_event(self.model, event, self.scaler_params)
                else:
                    confidence = random.uniform(0.0, 1.0)
                    if confidence < 0.35:
                        severity = "Normal"
                    elif confidence < 0.70:
                        severity = "Medium"
                    else:
                        severity ="High"
                alert_pkg = None
                if severity != "Normal":
                    alert_pkg = al.process_detection(src, destination, confidence, severity, event, affected_system=system)
                self.root.after(0, self.on_event, event, src, destination, confidence, severity)
                if alert_pkg:
                    self.root.after(0, self.on_alert)
                time.sleep(1.5)
        t= threading.Thread(target=loop, daemon=True)
        t.start()


    def on_event(self, event, src,destination, confidence, severity):
        try:
            self.add_lt_row(event, src,destination, confidence, severity)
        except tk.TclError:
            pass

    def on_alert(self):
        try:
            page = self.current_page.get()
            if page =="Dashboard":
                self.refresh_dashboard()
            elif page =="Alerts":
                self.refresh_alerts()
        except tk.TclError:
            pass


# entry point
def main():
    root = tk.Tk()
    app = IDSApplication(root)

    def on_close():
        app.sim_running = False
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)
    root.mainloop()

if __name__ == "__main__":
    main()


