import csv
import json
import socket
import os
import platform
import ipaddress
from scapy.all import ARP, Ether, srp, IP, TCP, sr1
from concurrent.futures import ThreadPoolExecutor
from utils import get_local_ip, get_user_input, colored_print
from colorama import Fore, Style
import argparse

def scan_ip(ip, timeout=1):
    """
    Sends an ARP request to a specific IP and waits for a response.
    :param ip: The IP address to scan.
    :param timeout: Timeout for the ARP request.
    :return: A dictionary containing the IP, MAC address, device name, and OS if available.
    """
    if ':' in ip:
        # Skip IPv6 addresses, ARP is for IPv4
        return None

    # Create ARP request for the given IP
    arp_request = ARP(pdst=ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp_request

    device_info = {'ip': ip}
    try:
        # Send the packet and wait for a response (timeout in seconds)
        result = srp(packet, timeout=timeout, verbose=0)[0]
        if result:
            device_info['mac'] = result[0][1].hwsrc
            device_info['name'] = get_device_name(ip)
            device_info['os'] = get_os(ip)
            return device_info
    except Exception as e:
        colored_print(f"Error scanning {ip}: {e}", "RED")
        return None

def get_device_name(ip):
    """
    Retrieves the device name using reverse DNS lookup.
    :param ip: The IP address to lookup.
    :return: Device name or 'Unknown' if not resolvable.
    """
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return 'Unknown'

def get_os(ip):
    """
    Attempts to determine the operating system using TCP/IP stack analysis.
    :param ip: The IP address to scan.
    :return: OS guess based on TCP response.
    """
    try:
        pkt = IP(dst=ip)/TCP(dport=80, flags='S')
        response = sr1(pkt, timeout=1, verbose=0)
        if response:
            if response.haslayer(TCP):
                if response[TCP].flags == 0x12:
                    return 'Windows'
                elif response[TCP].flags == 0x14:
                    return 'Linux/Unix'
        return 'Unknown'
    except Exception as e:
        colored_print(f"Error detecting OS for {ip}: {e}", "RED")
        return 'Unknown'

def scan_network_concurrently(ip_range, timeout=1, threads=100):
    """
    Scans the network range concurrently for active clients using ARP requests.
    :param ip_range: List of IP addresses to scan.
    :param timeout: Timeout for each ARP request.
    :param threads: Number of threads to use for scanning.
    :return: List of active clients with IP, MAC, device name, and OS information.
    """
    with ThreadPoolExecutor(max_workers=threads) as executor:
        results = executor.map(lambda ip: scan_ip(ip) or None, ip_range) # TODO: Replace none with ipv6_scan and develop the function.
    return [client for client in results if client is not None]

def export_results(results, file_format, filename):
    """
    Export results to a file in the specified format (CSV or JSON).
    :param results: List of dictionaries containing IP, MAC, device name, and OS information.
    :param file_format: Format for exporting ('csv' or 'json').
    :param filename: Output file name.
    """
    if file_format == 'csv':
        with open(filename, 'w', newline='') as file:
            writer = csv.DictWriter(file, fieldnames=['ip', 'mac', 'name', 'os'])
            writer.writeheader()
            writer.writerows(results)
    elif file_format == 'json':
        with open(filename, 'w') as file:
            json.dump(results, file, indent=4)
    else:
        colored_print(f"Unsupported file format: {file_format}", "RED")

if __name__ == "__main__":
    # Argument parsing for customization
    parser = argparse.ArgumentParser(description="Network Scanner")
    parser.add_argument('--timeout', type=float, default=1, help="Timeout for ARP requests (default: 1s)")
    parser.add_argument('--threads', type=int, default=100, help="Number of threads to use (default: 100)")
    parser.add_argument('--range', type=str, help="Custom IP range (e.g., 192.168.1.0/24)")
    parser.add_argument('--export', type=str, help="Export results to a file (csv or json) with the specified filename")

    args = parser.parse_args()

    # Get local IP to determine network range
    local_ip = get_local_ip()

    if not local_ip:
        colored_print("Could not determine local IP address.", "RED")
    else:
        # Get IP range from user or use default
        ip_range = get_user_input(args.range, local_ip)

        # Show scan range
        colored_print(f"Scanning network range: {ip_range[0].rsplit('.', 1)[0]}.0/24", "GREEN")

        # Scan network concurrently
        active_clients = scan_network_concurrently(ip_range, timeout=args.timeout, threads=args.threads)

        # Display results
        colored_print("\nActive clients on the network:", "YELLOW")
        print(f"{Fore.CYAN}IP Address\t\tMAC Address\t\tDevice Name\t\tOS{Style.RESET_ALL}")
        print("-" * 80)
        for client in active_clients:
            print(f"{Fore.GREEN}{client['ip']}\t\t{client['mac']}\t\t{client['name']}\t\t{client['os']}{Style.RESET_ALL}")
        
        if not active_clients:
            colored_print("No active clients found.", "RED")

        # Export results if requested
        if args.export:
            file_format = args.export.split('.')[-1]
            export_results(active_clients, file_format, args.export)
            colored_print(f"Results exported to {args.export}", "GREEN")
