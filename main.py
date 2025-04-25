import argparse
import socket
import logging
import ipaddress
import dns.resolver
import dns.reversename
import concurrent.futures

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def reverse_dns_lookup(ip_address):
    """
    Performs a reverse DNS lookup for a given IP address.

    Args:
        ip_address (str): The IP address to perform the lookup on.

    Returns:
        str: The hostname if found, otherwise None.
    """
    try:
        addr = dns.reversename.from_address(ip_address)
        resolver = dns.resolver.Resolver()
        result = resolver.resolve(addr, "PTR")
        return str(result[0])
    except dns.resolver.NXDOMAIN:
        return None
    except dns.resolver.Timeout:
        logging.warning(f"Timeout resolving {ip_address}")
        return None
    except dns.exception.DNSException as e:
        logging.error(f"DNS Exception for {ip_address}: {e}")
        return None
    except Exception as e:
        logging.error(f"Unexpected error for {ip_address}: {e}")
        return None


def is_valid_ip_range(ip_range):
    """
    Validates if the given IP range is valid.

    Args:
        ip_range (str): The IP range to validate (e.g., 192.168.1.0/24).

    Returns:
        bool: True if the IP range is valid, False otherwise.
    """
    try:
        ipaddress.ip_network(ip_range)
        return True
    except ValueError:
        return False

def sweep_ip_range(ip_range, threads=10):
    """
    Sweeps an IP range and performs reverse DNS lookups.

    Args:
        ip_range (str): The IP range to sweep (e.g., 192.168.1.0/24).
        threads (int): Number of threads for concurrent lookups.

    Returns:
        dict: A dictionary containing IP addresses and their corresponding hostnames.
    """
    results = {}

    if not is_valid_ip_range(ip_range):
        logging.error(f"Invalid IP range: {ip_range}")
        return results

    try:
        network = ipaddress.ip_network(ip_range)
        ip_addresses = [str(ip) for ip in network]

        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            future_to_ip = {executor.submit(reverse_dns_lookup, ip): ip for ip in ip_addresses}
            for future in concurrent.futures.as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    hostname = future.result()
                    if hostname:
                        results[ip] = hostname
                        logging.info(f"Found hostname {hostname} for {ip}")
                    else:
                        logging.debug(f"No hostname found for {ip}")
                except Exception as e:
                    logging.error(f"Error processing {ip}: {e}")

    except Exception as e:
        logging.error(f"Error sweeping IP range: {e}")

    return results

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.

    Returns:
        argparse.ArgumentParser: The configured argument parser.
    """
    parser = argparse.ArgumentParser(description="Performs a reverse DNS lookup on a range of IP addresses.")
    parser.add_argument("ip_range", help="The IP range to sweep (e.g., 192.168.1.0/24)")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads for concurrent lookups (default: 10)")
    parser.add_argument("-o", "--output", help="Output file to save the results (optional)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging (DEBUG level)")

    return parser

def main():
    """
    Main function to parse arguments, sweep the IP range, and print/save results.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Verbose logging enabled.")

    ip_range = args.ip_range
    threads = args.threads
    output_file = args.output

    if threads <= 0:
        logging.error("Number of threads must be greater than 0.")
        return

    results = sweep_ip_range(ip_range, threads)

    if results:
        if output_file:
            try:
                with open(output_file, "w") as f:
                    for ip, hostname in results.items():
                        f.write(f"{ip}: {hostname}\n")
                logging.info(f"Results saved to {output_file}")
            except Exception as e:
                logging.error(f"Error writing to file: {e}")
        else:
            print("Results:")
            for ip, hostname in results.items():
                print(f"{ip}: {hostname}")
    else:
        print("No hostnames found.")

if __name__ == "__main__":
    main()