import getpass
import subprocess
import sys
import tempfile
import time
import os
import re
import requests
import shutil
import socket
import psutil

logo = r'''
        ""$o               o$""
         ""$o           o$"                      o
"$""""o                  "o         $"                 o""" $"
     "$o                "$o" $o "  $                 o$"
      "$o               $$$o$$$$o$$$$               $"
        "oooo      o "" ""$$$$$$$$""o"" oo     oooo"
         "$$$$$$oo"oo$$$o" o$$$$oo" o$$$o "o$$$$$$$
               "$ $$$$$$$$$oo   o$$$$$$$$$o"$"
               $ $$$   $$$$$$  o$$$$$$  "$$o"o
              $ $$$$o  $$$$$$  $$$$$$$  $$$$o"o
             $  $$$$$  $$$$$"   "$$$$$ $$$$$$ $
              $o""""" """"         """ """"""$"
             $  o$$$$$"""$$$$$"$$$$$""$$$$$ooo"o
             $  o"$o $$$$$$$$oo$$$$$$$$o $$""  $
          oo$     "$$$$$$$$$$$$$$$$$$$$" o" o $oo
       o$$$"$ $$o"o $$$$$$$"" "$$$$$$$    o$$ $$$$o      UN BUG
     o$$$$" $ $$$$ o "$$$$$oo o$$$$$$  "o$$$$ $ $$$$$
    o$$""    $ $$$$$o" "$$$$$$$$$$$$$ o o$$$$$o$   "" $$
    $$"      $ $$$"  o"o$$$$$$$$$$$$   " "$$$ $       $$o
   o$$       "o $$    "  $$$$$$$$$$$"o    "$$ $       $$$
   $$$      oo$ $       o""$$""$$$o "      $"o$o      $$$o
  o$$$$   o$$$"o"$oo$$$$o" o     $o $$$$$oo$ $$$$o    $$$$
  $$$$   $$$$" $ $$$$$""   $$  o$$$ """$$$$"o" "$$$o  "$$$o
  $$$" o """    $ $$$oo   $$$$o" $$   o$$$"o"   """"$  o$$$
o$"     $$$       $ "$"" o$"o"$$o$$$$  "$$"o"      o$$     "$oo
$ "        $$o       $ "oo$"o$$$"o$o"$$$$o" o"       $$$       ""$o
$$          $$$o       "o$$o$"$$"$$o$$o$$"$$o"       $$$          ""o
             $$$        ""$$$ $$$$$$ $$$$ $"        $$$$            $$
             $$$$           $$$$"$$$o$ $""          $$$
              $$$$             "$$$ """            $$$$
              $$""                                 "$$
           oo$"                                       $ooo
          $                                             "$$

▗▄▄▄▄▖ ▗▄▖ ▗▄▄▖  ▗▄▄▖▗▄▄▄▖
   ▗▞▘▐▌ ▐▌▐▌ ▐▌▐▌   ▐▌   
 ▗▞▘  ▐▌ ▐▌▐▛▀▚▖▐▌▝▜▌▐▛▀▀▘
▐▙▄▄▄▖▝▚▄▞▘▐▌ ▐▌▝▚▄▞▘▐▙▄▄▖ by KL3FT3Z (https://github.com/toxy4ny)
                            -={SSH2TOR Tunnel Automation v.1.0}=-          
'''
print(logo)


def input_nonempty(prompt):
    while True:
        val = input(prompt)
        if val.strip():
            return val

def get_ip(proxychains_conf=None):
    url = 'https://ident.me'
    try:
        if proxychains_conf:
            result = subprocess.check_output(
                ['proxychains4', '-f', proxychains_conf, 'curl', '-s', url],
                stderr=subprocess.DEVNULL
            )
        else:
            result = subprocess.check_output(
                ['curl', '-s', url],
                stderr=subprocess.DEVNULL
            )
        return result.decode().strip()
    except Exception:
        return None


def check_tor_exit(ip):
    try:
        resp = requests.get("https://check.torproject.org/torbulkexitlist")
        return ip in resp.text
    except Exception:
        return False

def is_port_in_use(port):
    """Check if the port on the localhost is busy."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('127.0.0.1', port)) == 0

def kill_process_on_port(port):
    """Find and kill the process that is listening on the specified port."""
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            for conn in proc.net_connections(kind='inet'):
                if conn.status == psutil.CONN_LISTEN and conn.laddr.port == port:
                    print(f"[!] Порт {port} занят процессом PID {proc.pid} ({proc.name()}). Kill...")
                    proc.kill()
                    time.sleep(1)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

def main():
    server_ip = input_nonempty("Server IP: ")
    server_user = input_nonempty("SSH Username: ")
    server_pass = getpass.getpass("SSH Password: ")
    local_port = 1080
    remote_port = 9050

    for tool in ['ssh', 'curl', 'proxychains4', 'sshpass']:
        if not shutil.which(tool):
            print(f"[!] {tool} not found. Install it and try again.")
            sys.exit(1)

    # Проверка и освобождение порта
    if is_port_in_use(local_port):
        print(f"[!] Порт {local_port} already busy. An attempt to shutdown the process...")
        kill_process_on_port(local_port)
        if is_port_in_use(local_port):
            print(f"[!] The port could not be open. {local_port}.")
            sys.exit(1)
        else:
            print(f"[+] Port {local_port} has been successfully open.")

    print("[*] Getting your external IP...")
    my_ip = get_ip()
    print(f"   Your IP: {my_ip}")

    print("[*] Installing an SSH tunnel...")
    ssh_cmd = [
        'sshpass', '-p', server_pass,
        'ssh', '-f', '-N',
        '-L', f'{local_port}:127.0.0.1:{remote_port}',
        f'{server_user}@{server_ip}'
    ]
    try:
        subprocess.check_call(ssh_cmd)
    except Exception as e:
        print(f"[!] Couldn't install SSH tunnel: {e}")
        sys.exit(1)

    with tempfile.NamedTemporaryFile('w', delete=False) as f:
        proxychains_conf = f.name
        f.write("strict_chain\nproxy_dns\n[ProxyList]\nsocks5 127.0.0.1 1080\n")

    time.sleep(5)

    print("[*] Getting an IP through a Tor tunnel...")
    tor_ip = get_ip(proxychains_conf)
    print(f"    Tor IP: {tor_ip}")

    if not tor_ip or tor_ip == my_ip:
        print("[!] The IP has not changed or has not been received! The tunnel is not working.")
        print(f"[*] The temporary proxychains configuration has been saved: {proxychains_conf}")
        sys.exit(1)
    else:
        print("[*] The IP through the tunnel is different from the original one.")
        answer = input("Do you want to check if this IP is a Tor exit node? (Y/n): ").strip().lower()
        if answer in ['', 'y', 'yes', 'д', 'да']:
            print("[*] Checking whether the IP belongs to Tor...")
            if check_tor_exit(tor_ip):
                print(f"[+] IP {tor_ip} found in the list of Tor exit nodes. Everything is working correctly!")
            else:
                print(f"[!] IP {tor_ip} Not found in the list of Tor exit nodes.")
                answer2 = input("Should I continue working with this tunnel? (Y/n): ").strip().lower()
                if answer2 not in ['', 'y', 'yes', 'д', 'да']:
                    print("[*] Shutdown at the user's request.")
                    print(f"[*] The temporary proxychains configuration has been saved: {proxychains_conf}")
                    sys.exit(0)
                else:
                    print("[*] We are continuing to work on your request.")
        else:
            print("[*] We skip checking the Tor output node at the user's request.")
            print(f"[!] Attention: You are using a tunnel, but you have not checked whether the IP is a Tor exit node.")

    print(f"[*] The temporary proxychains configuration has been saved: {proxychains_conf}")
    print(f"[+] The SOCKS5 proxy is available at: socks5://127.0.0.1:{local_port}")
    print("    Use this address in your application or browser to connect through the tunnel.")
    print("[*] Enjoy!")

if __name__ == "__main__":
    main()
