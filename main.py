from scapy.all import sniff, IP, TCP, UDP
import joblib
import pandas as pd
import time

# Load model
model = joblib.load("model.pkl")

columns = [
    "duration","protocol_type","service","flag","src_bytes","dst_bytes","land",
    "wrong_fragment","urgent","hot","num_failed_logins","logged_in","num_compromised",
    "root_shell","su_attempted","num_root","num_file_creations","num_shells",
    "num_access_files","num_outbound_cmds","is_host_login","is_guest_login",
    "count","srv_count","serror_rate","srv_serror_rate","rerror_rate",
    "srv_rerror_rate","same_srv_rate","diff_srv_rate","srv_diff_host_rate",
    "dst_host_count","dst_host_srv_count","dst_host_same_srv_rate",
    "dst_host_diff_srv_rate","dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate","dst_host_serror_rate",
    "dst_host_srv_serror_rate","dst_host_rerror_rate",
    "dst_host_srv_rerror_rate"
]

print("🚀 REAL NIDS RUNNING...")

packet_count = {}
port_scan_tracker = {}
start_time = time.time()

def process_packet(packet):
    global start_time

    try:
        if not packet.haslayer(IP):
            return

        src_ip = packet[IP].src
        length = len(packet)

        # Reset every 10 seconds
        if time.time() - start_time > 10:
            packet_count.clear()
            port_scan_tracker.clear()
            start_time = time.time()

        # Packet count
        packet_count[src_ip] = packet_count.get(src_ip, 0) + 1

        # Port tracking
        if packet.haslayer(TCP):
            port = packet[TCP].dport
        elif packet.haslayer(UDP):
            port = packet[UDP].dport
        else:
            port = 0

        if src_ip not in port_scan_tracker:
            port_scan_tracker[src_ip] = set()

        port_scan_tracker[src_ip].add(port)

        # -------- FEATURE MAPPING --------
        features = [0]*41
        features[0] = length
        features[4] = length
        features[5] = length
        features[22] = packet_count[src_ip]
        features[23] = 1

        if packet.haslayer(TCP):
            features[1] = 1
        elif packet.haslayer(UDP):
            features[1] = 2
        else:
            features[1] = 0

        df = pd.DataFrame([features], columns=columns)
        prediction = model.predict(df)

        # -------- REAL DETECTION --------

        if packet_count[src_ip] > 100:
            msg = f"🚨 DDoS detected from {src_ip}"

        elif len(port_scan_tracker[src_ip]) > 20:
            msg = f"🚨 Port Scan detected from {src_ip}"

        elif prediction[0] == "attack":
            msg = f"🚨 ML Attack detected from {src_ip}"

        else:
            print("Normal traffic")
            return

        print(msg)

        with open("alerts.log", "a") as f:
            f.write(msg + "\n")

    except:
        pass

sniff(prn=process_packet, store=False)