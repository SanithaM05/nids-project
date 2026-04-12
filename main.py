from scapy.all import sniff
import joblib
import pandas as pd
import time

# Load model
model = joblib.load("model.pkl")

# Column names
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

print("✅ NIDS Started...")

# Your IP (optional ignore)
MY_IP = "192.168.1.119"

packet_count = {}
start_time = time.time()

def process_packet(packet):
    global start_time

    try:
        # Reset count every 10 sec
        if time.time() - start_time > 10:
            packet_count.clear()
            start_time = time.time()

        src_ip = packet[0][1].src
        length = len(packet)

        packet_count[src_ip] = packet_count.get(src_ip, 0) + 1

        # -------- FEATURE MAPPING --------
        features = [0]*41
        features[0] = length
        features[4] = length
        features[5] = length
        features[22] = packet_count[src_ip]
        features[23] = 1

        if packet.haslayer("TCP"):
            features[1] = 1
        elif packet.haslayer("UDP"):
            features[1] = 2
        else:
            features[1] = 0

        df = pd.DataFrame([features], columns=columns)

        prediction = model.predict(df)

        # -------- TEST MODE (FOR DEMO) --------
        if length > 60 and packet_count[src_ip]%10 == 0:
            print(f"⚠️ TEST ATTACK from {src_ip}")

            with open("alerts.log", "a") as f:
                f.write(f"Test Attack from {src_ip}\n")

        # -------- REAL LOGIC --------
        elif packet_count[src_ip] > 100:
            print(f"⚠️ DDoS suspected from {src_ip}")

            with open("alerts.log", "a") as f:
                f.write(f"DDoS from {src_ip}\n")

        elif prediction[0] == "attack" and length > 100:
            print(f"⚠️ ML Attack detected from {src_ip}")

            with open("alerts.log", "a") as f:
                f.write(f"ML Attack from {src_ip}\n")

        else:
            print("Normal traffic")

    except:
        pass

# Start sniffing
sniff(prn=process_packet, count=100)