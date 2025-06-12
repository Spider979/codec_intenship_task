# BUILD A TOOLKIT WITH MULTIPLE
# MODULES (E.G., PORT SCANNER,
# BRUTE-FORCER) FOR PENETRATION
# TESTING.

# DELIVERABLE: A PYTHON-BASED
# MODULAR TOOLKIT WITH DETAILED
# DOCUMENTATION
import socket
import requests

def port_scanner(target):
    print(f"\n[+] Scanning ports on {target}...")
    for port in range(1, 1025):
        try:
            s = socket.socket()
            s.settimeout(0.5)
            s.connect((target, port))
            print(f"[OPEN] Port {port}")
            s.close()
        except:
            pass

def brute_force(url, username, wordlist_path):
    print(f"\n[+] Starting brute-force on {url} with user '{username}'")
    try:
        with open(wordlist_path, "r") as file:
            for password in file:
                password = password.strip()
                response = requests.get(url, auth=(username, password))
                if response.status_code == 200:
                    print(f"[SUCCESS] Password found: {password}")
                    return
                else:
                    print(f"[FAILED] Tried: {password}")
        print("[-] Password not found in wordlist.")
    except FileNotFoundError:
        print("[-] Wordlist file not found.")

def main():
    while True:
        print("\n=== PenTest Toolkit ===")
        print("1. Port Scanner")
        print("2. Brute Force HTTP Auth")
        print("3. Exit")

        choice = input("Select an option: ")

        if choice == "1":
            target = input("Enter target IP/Domain: ")
            port_scanner(target)
        elif choice == "2":
            url = input("Enter target URL (with http/https): ")
            username = input("Enter username to brute-force: ")
            wordlist_path = input("Enter path to password wordlist: ")
            brute_force(url, username, wordlist_path)
        elif choice == "3":
            print("Exiting toolkit.")
            break
        else:
            print("Invalid choice!")

if __name__ == "__main__":
    main()
