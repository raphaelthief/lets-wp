# Lets-WP - WordPress Pentesting Tool

Let's WP is a lightweight tool designed to assist penetration testers in identifying vulnerabilities on WordPress sites. It simplifies common tasks like discovering default files and directories and performing brute force attacks via the xmlrpc.php API. This tool aims to be a streamlined alternative to more comprehensive tools like WPScan.

⚠️ Disclaimer: This tool is strictly for educational purposes and authorized security testing. Unauthorized use is illegal and unethical.

## Features

Scan Default Paths and Files :
- Detect common WordPress directories (wp-content, wp-admin, etc.).
- Identify sensitive files like wp-config.php, readme.html, robots.txt, and more.
- Determine WordPress version from metadata.

Brute Force Attack via xmlrpc.php :
- Supports multi-threaded brute force attacks.
- Uses system.multicall requests to test multiple passwords in a single request (optimized for WordPress < 4.4).
- Fine control over request timing to evade server restrictions.
- Handles HTTP 429 (Too Many Requests) responses with configurable pauses.

User-Friendly Interface:
- Colorful and well-organized output powered by Colorama.
- File path auto-completion using prompt_toolkit.


## 🛠️ Installation

Clone the repository :
```
git clone https://github.com/raphaelthief/lets-wp.git
cd lets-wp
```

Install the required dependencies:
```
pip install -r requirements.txt
```

## 🔧 Usage

Run the tool :
```
python lets-wp.py
```

Follow the on-screen prompts to select an action :
Option 1 : Scan a WordPress site for default paths and files.
Option 2 : Perform a brute force attack on a target via xmlrpc.php.

## ⚠️ Warnings

Authorization Required : Ensure you have explicit legal authorization before using this tool on any website.
Disclaimer : The author is not responsible for any misuse of this tool.
Ethical Use : This tool is intended to enhance system security, not compromise it.
