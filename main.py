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
        # I take only the first PTR record. An address can publish several, and this tool reports one name per address, so the rest are dropped without any note in the output.
        return str(result[0])
    # NXDOMAIN and a timeout both come back as None, but I keep them apart in the logs. One means the name does not exist and will not appear later, the other means I learned nothing and a rerun might find it.
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
        # ip_network is strict by default, so a range written with host bits set, like 192.168.1.5/24, is rejected as invalid instead of being quietly rounded down to the network. Main does not explain that, it just gets an empty result.
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

        # Feed the network iterator straight into the lookup loop, with
        # only a small window of lookups in flight at a time. The whole
        # network is never built as a list, so lookups start at once and
        # memory stays flat even for a very large range.
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            pending = {}
            addresses = iter(network)
            exhausted = False
            while True:
                # I cap the window at the thread count itself, not some larger queue. That keeps the number of sockets and resolver objects in play close to the workers that will actually run them, at the cost of refilling more often.
                while not exhausted and len(pending) < threads:
                    try:
                        ip = str(next(addresses))
                    except StopIteration:
                        exhausted = True
                        break
                    pending[executor.submit(reverse_dns_lookup, ip)] = ip
                if not pending:
                    break
                done, _not_done = concurrent.futures.wait(
                    pending, return_when=concurrent.futures.FIRST_COMPLETED)
                for future in done:
                    ip = pending.pop(future)
                    # reverse_dns_lookup swallows its own errors and returns None, so result() here should not raise. If it ever does, the outer handler ends the whole sweep and throws away the names already collected, which is a sharp edge in this design.
                    hostname = future.result()
                    if hostname:
                        results[ip] = hostname
                        logging.info(f"Found hostname {hostname} for {ip}")
                    else:
                        logging.debug(f"No hostname found for {ip}")

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

    # Main returns with no error code on this path because main has no return value and the script just ends. A calling script sees exit 0 for a refused run, so the log line is the only signal.
    if threads <= 0:
        logging.error("Number of threads must be greater than 0.")
        return

    results = sweep_ip_range(ip_range, threads)

    if results:
        if output_file:
            try:
                with open(output_file, "w") as f:
                    # The order in the file is completion order, not address order, because results were filled as futures finished. Anyone diffing two runs of the same range will see lines move around even when nothing changed.
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
