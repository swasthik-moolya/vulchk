import requests
import socket
import threading
from queue import Queue
import re
import time

# --- Configuration ---
TARGET_URL = input("Enter target url: ")  # Replace with the target URL (with permission!)
NUMBER_OF_THREADS = 10  # Adjust based on your system and network
task_queue = Queue()
open_ports = []
vulnerabilities_found = []
potential_leaks = []

# --- Functions for Scanning ---

def is_valid_url(url):
    """ Validates the URL format. """
    regex = re.compile(
        r'^(?:http|ftp)s?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|'  # ...or ipv4
        r'\[?[A-F0-9]*:[A-F0-9:]+\]?)'  # ...or ipv6
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    return re.match(regex, url) is not None

def check_port(port):
    """ Checks if a specific port is open on the target. """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(1)  # Short timeout for quick scans
        result = sock.connect_ex((socket.gethostbyname(TARGET_URL.split('//')[1].split('/')[0]), port))  # Extract hostname
        if result == 0:
            open_ports.append(port)
        sock.close()
    except (socket.gaierror, socket.error):
        pass  # Handle errors silently in threads or log them

def check_vulnerabilities(url):
    """ Checks for vulnerabilities on the given URL. """
    if not is_valid_url(url):
        return  # Skip invalid URLs
    try:
        response = requests.get(url, timeout=5)
        
        # Check for missing security headers
        if 'X-Frame-Options' not in response.headers:
            vulnerabilities_found.append(f"Missing X-Frame-Options header on {url}")
        if 'X-Content-Type-Options' not in response.headers:
            vulnerabilities_found.append(f"Missing X-Content-Type-Options header on {url}")
        if 'X-XSS-Protection' not in response.headers:
            vulnerabilities_found.append(f"Missing X-XSS-Protection header on {url}")

        # Check for potential data leaks
        if "error" in response.text.lower() or "exception" in response.text.lower():
            potential_leaks.append(f"Potential info disclosure via error message on {url}")
        
        # Check for sensitive information in the response
        if "password" in response.text.lower() or "secret" in response.text.lower():
            potential_leaks.append(f"Potential sensitive information found on {url}")

    except requests.exceptions.RequestException:
        pass  # Handle request exceptions

# --- Worker Thread Logic ---

def worker():
    """ Takes tasks from the queue and processes them. """
    while not task_queue.empty():
        task_data = task_queue.get()
        task_type = task_data.get("type")
        
        if task_type == "port":
            check_port(task_data.get("port"))
        elif task_type == "vuln_check":
            check_vulnerabilities(task_data.get("url"))
            
        task_queue.task_done()  # Signal that the task is complete

# --- Main Execution ---

if __name__ == "__main__":
    start_time = time.time()

    # 1. Add tasks to the queue (Example: port scanning common web ports)
    common_ports = [80, 443, 8080, 8443, 21, 22, 23, 25, 110]  # Add more as needed
    for port in common_ports:
        task_queue.put({"type": "port", "port": port})
        
    # Add basic vulnerability check for the main URL
    task_queue.put({"type": "vuln_check", "url": TARGET_URL})

    # 2. Create and start threads
    threads = []
    for _ in range(NUMBER_OF_THREADS):
        thread = threading.Thread(target=worker)
        thread .daemon = True  # Allows main program to exit even if threads are running
        thread.start()
        threads.append(thread)

    # 3. Wait for the queue to be empty
    task_queue.join()  # Blocks until all tasks are processed

    # 4. Print results
    print(f"Scan completed in {time.time() - start_time:.2f} seconds.")
    if open_ports:
        print("\nOpen Ports Found:")
        print(sorted(open_ports))
    else:
        print("\nNo common open ports found.")

    if vulnerabilities_found:
        print("\nPotential Vulnerabilities Found:")
        for vuln in vulnerabilities_found:
            print(f"- {vuln}")
    else:
        print("\nNo basic vulnerabilities detected in this simple scan.")

    if potential_leaks:
        print("\nPotential Data Leaks/Info Disclosure Found:")
        for leak in potential_leaks:
            print(f"- {leak}")
    else:
        print("\nNo potential data leaks detected.")
