import socket
from colorama import Fore, Style

def get_local_ip():
    """
    Returns the local IP address of the machine.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0)
        s.connect(('8.8.8.8', 1))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception as e:
        colored_print(f"Error getting local IP: {e}", "RED")
        return None

def get_user_input(custom_range, local_ip):
    """
    Determines the IP range to scan.
    :param custom_range: User input for custom IP range.
    :param local_ip: Local IP to derive default range.
    :return: List of IP addresses to scan.
    """
    if custom_range:
        # Parse custom range (assume /24 subnet)
        base_ip = custom_range.rsplit('.', 1)[0]
        return [f"{base_ip}.{i}" for i in range(1, 255)]
    else:
        # Use default range based on local IP
        ip_parts = local_ip.split('.')
        base_ip = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}."
        return [f"{base_ip}{i}" for i in range(1, 255)]

def colored_print(message, color="WHITE"):
    """
    Prints a message in the specified color.
    :param message: The message to print.
    :param color: The color for the message (options: RED, GREEN, YELLOW, CYAN, WHITE).
    """
    color_mapping = {
        "RED": Fore.RED,
        "GREEN": Fore.GREEN,
        "YELLOW": Fore.YELLOW,
        "CYAN": Fore.CYAN,
        "WHITE": Fore.WHITE
    }
    print(f"{color_mapping.get(color, Fore.WHITE)}{message}{Style.RESET_ALL}")
