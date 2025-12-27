import paramiko
import time
import os

# --- CONFIGURATION ---
HOSTNAME = "13.60.244.200"  # Your AWS IP
PORT = 22222                # Your Secret SSH Port
USERNAME = "ubuntu"
KEY_FILE = r"D:\honeypot-key.pem" # Your Key Path
REMOTE_FILE = "/home/cowrie/cowrie/var/log/cowrie/cowrie.json"
LOCAL_FILE = "attacks.json" 

def fetch_logs():
    print(f"🔌 Connecting to Sentinel Server ({HOSTNAME})...")
    
    try:
        # 1. Setup SSH Client
        k = paramiko.RSAKey.from_private_key_file(KEY_FILE)
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(HOSTNAME, port=PORT, username=USERNAME, pkey=k)
        
        # 2. SFTP Transfer
        sftp = ssh.open_sftp()
        
        # Check file size first
        remote_attributes = sftp.stat(REMOTE_FILE)
        print(f"📄 Found log file. Size: {remote_attributes.st_size / 1024:.2f} KB")
        
        # Download
        print("⬇️ Downloading latest logs...")
        sftp.get(REMOTE_FILE, LOCAL_FILE)
        
        sftp.close()
        ssh.close()
        print("✅ Sync Complete! 'attacks.json' has been updated.")
        
    except Exception as e:
        print(f"❌ Connection Failed: {e}")

if __name__ == "__main__":
    fetch_logs()