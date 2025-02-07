import socket
import subprocess
import ipaddress
import csv
import argparse
import re

# !IMPORTANT! SCRIPT ONLY FOR WINDOWS

'''
    get_arguments()
        This function retrieves the command-line arguments provided when running the script.
        It returns an object containing the values of these arguments.
'''
def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--ip', dest='ips_to_scan', help='IP address or network address with mask to scan, ex. \'192.168.1.53\' or \'192.168.1.0/24\'', required=True)
    parser.add_argument('-s', '--skip_ips', dest='ips_to_skip', help='IP/IPs addresses to skip when scanning, ex. \'192.168.1.34 192.168.1.44\'', nargs='+')
    parser.add_argument('-o', '--operating_system', dest='check_operating_system', help='If you want check operating system, pass this option', action='store_true')

    return parser.parse_args()


'''
    ping(ip)
        This function pings the given IP address and returns 1 if the host is reachable.
        ip - string representing the IP address to be pinged, e.g., "192.168.1.23".
'''
def ping(ip: str):
    try:
        result = subprocess.run(f'ping -n 2 {ip}', capture_output=True, text=True)
        return 1 if 'TTL' in result.stdout else 0
    except Exception:
        return 0 
    

'''
    gen_ip_addr(network_address: str, skip_ips: list[str])
        This function generates a list of IP addresses within the given network.
        network_address - string representing the network address, e.g., "192.168.1.44" (for a single host) or "192.168.1.0/24" (for a network with a 24-bit mask).
        skip_ips - list of IP addresses to be excluded, e.g., ["192.168.1.4"].
'''
def gen_ip_addr(net_addr: str, ips_to_miss: list[str] = None):
    if '/' not in net_addr:
        return [net_addr]
    network = ipaddress.IPv4Network(net_addr, strict=False)
    addresses = [str(ip) for ip in network.hosts()]
    return [ip for ip in addresses if ip not in (ips_to_miss or [])]



'''
    get_hostname(ip)
        Retrieves the hostname for a given IP address.
'''
def get_hostname(ip: str):
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except socket.herror as e:
        return 'CANT RECOGNIZE'


'''
    get_MAC(ip)
        Returns the MAC address of a given IP by checking the ARP table.
        The function replaces "-" with ":" for better readability.
'''
def get_MAC(ip: str):
    result = subprocess.run(f'arp -a {ip}', capture_output=True, text=True)
    mac = re.search(r'([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}', result.stdout)
    return mac.group().replace('-', ':') if mac else "UNKNOWN MAC"



'''
    get_operating_system(ip)
        Retrieves the Windows operating system version installed on the given IP.
        ip - string representing the IP address to check, e.g., "192.168.1.132".
        
        Returns:
            - The name of the operating system if found.
            - "TIMEOUT" if the request exceeds the waiting time (5 seconds).
            - -1 if no valid response is received.
'''
def get_operating_system(ip: str):
    try:
        result = subprocess.run(
            f'wmic /node:{ip} os get Caption', 
            capture_output=True, timeout=4
        )
        output = result.stdout.decode().replace("\n", "").replace("\r", "")
        output = " ".join(output.split()[1:])
        return output if output else "UNKNOWN OS"
        # if 'LTSC' in result.stdout.decode() or 'Windows 11' in result.stdout.decode():
        #     return 1
        # else:
        #     return 0
    except subprocess.TimeoutExpired:
        return 'TIMEOUT'
    except Exception:
        return -1


'''
    assign_everything(ip_list, check_operating_system)
        This function assigns a hostname to a given IP address.
        If DNS resolution is unsuccessful, it assigns the value "CANNOT RECOGNIZE".
        If an IP address does not respond to a ping, it is considered free.
        The results are saved to a .csv file.
        
        ip_list - list of strings representing IP addresses, e.g., ["192.168.1.23", "192.168.1.24"].
        check_operating_system - flag indicating whether to check the OS (this significantly increases scan time).
'''
def assign_everything(ip_list: list[str], check_operating_system=False):
    data = [['IP Address', 'Hostname', 'MAC', 'Operating system']]
    
    try:
        for i, ip in enumerate(ip_list, 1):
            print(f'\rScanning {ip}: {i}/{len(ip_list)}', end='', flush=True)
            
            if ping(ip) == 1:
                hostname = get_hostname(ip)[:20]  # Skrócenie nazwy hosta
                mac = get_MAC(ip)
                os_info = get_operating_system(ip) if check_operating_system else ''
                data.append([ip, hostname, mac, os_info])
            else:
                data.append([ip, 'FREE', '', ''])

    except KeyboardInterrupt:
        print("\n[!] Scanning interrupted. Saving results...")

    with open(f'{ip_list[0]}_scan_results.csv', mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerows(data)

    print("\n[✔] Results saved to csv file!")




if __name__ == '__main__':
    options = get_arguments()
    ips_to_scan = options.ips_to_scan
    ips_to_skip = options.ips_to_skip
    check_operating_system_flag = options.check_operating_system

    ips_list = gen_ip_addr(ips_to_scan, ips_to_skip)
    assign_everything(ips_list, check_operating_system_flag)
