<div align="center">
  
![logo](https://github.com/user-attachments/assets/3cac3ab4-c084-44e6-a856-2c0e95a5e596)

[![Follow on Instagram](https://img.shields.io/badge/Instagram-Follow-blue?logo=instagram)](https://www.instagram.com/asperissecurity)
[![Connect on LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue?logo=linkedin)]([https://www.linkedin.com/company/asperis-security/])
[![Contributions](https://img.shields.io/badge/contributions-welcome-brightgreen.svg)](https://github.com/Asperis-Security/xssFuzz/)
</div>

# 🌐 XSSFUZZ

Welcome to **Asperis Security's XSS Detection Tool**! This tool is designed to help identify and validate Cross-Site Scripting (XSS) vulnerabilities through GET requests. With precision and flexibility, it allows security researchers, pentesters and bug bounty hunters to find and mitigate potential XSS issues.

## 🚀 Features

- **🔍 Precise XSS Detection**: Pinpoints XSS vulnerabilities in GET requests.
- **🛡️ WAF Bypass Detection**: It helps you discover tags and attributes that your WAF might miss.
- **🔓 Insecure CSP Detection**: Identifies websites with insecure Content Security Policy (CSP) configurations that could be exploited for XSS attacks.
- **🛠️ Customizable Payloads & Tags**: Tailor scans with custom tags and payloads for specific tests.
- **⚡ Multithreaded Concurrency**: Speed up scanning with concurrent threads.
- **🔐 Custom Headers Support**: Use custom headers for authenticated testing or advance tests.
- **📊 Detailed Reporting**: Generates comprehensive reports for easy management.

## 📚 References

This tool was built with inspiration from the **[XSS Cheatsheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)** provided by PortSwigger. We highly recommend reviewing this resource for further understanding on XSS payloads.

---

## 🛠️ Installation

### Windows
1. Install Python (3.x version).
2. Install dependencies using:
3. 
   ```bash
   pip install -r requirements.txt
   ```
   
4. Download and install Google Chrome and Chrome Driver as specified in the repository.

### Linux
1. Install Python and pip:
   
   ```bash
   sudo apt install python3 python3-pip
   ```
   
3. Install dependencies using:

   ```bash
   pip3 install -r requirements.txt
   ```
5. Execute the install script:
   
   ```bash
   sudo bash linux.sh
   ```

---

## 💻 Usage

### Basic Scan

```bash
python xssFuzz.py -u "<target_url>" -o output.txt
```

This command runs a basic scan on the target URL and saves the results in `output.txt`.

### Verbose Output

```bash
python xssFuzz.py -u "<target_url>" -o output.txt --verbose
```

Provides more detailed information about the scan.

### Tag-Specific Testing

```bash
python xssFuzz.py -u "<target_url>" --tag img -o output.txt
```

Scan only specific HTML tags, such as `<img>`.

### Custom Payloads

```bash
python xssFuzz.py -u "<target_url>" -p "<payload_file>" -o output.txt
```

Use custom payloads to scan specific attack vectors.

### Custom Headers

```bash
python xssFuzz.py -u "<target_url>" -H "Header1:Value,Header2:Value" -o output.txt
```

Include custom headers in your scan.

### Limiting Scope

```bash
python xssFuzz.py -u "<target_url>" --limit 5 -o output.txt
```

Limit the scan to the first 5 tags and 5 events for faster results.

### Increasing Speed with Threads

```bash
python xssFuzz.py -u "<target_url>" -t 10 -o output.txt
```

Increase scan speed by running 10 concurrent threads.

### Validation Mode

```bash
python xssFuzz.py -u "<target_url>" -V -o output.txt
```

Use validation mode to check if identified vulnerabilities are exploitable.

---

## 📊 Output and Reporting

Once the scan is complete, the tool generates a detailed report showing:
1. 🎯 **Vulnerable Parameters**: Lists parameters that are vulnerable to XSS.
2. 📜 **Custom Payloads**: Provides payloads that successfully exploited vulnerabilities.
3. 🚫 **WAF Bypass**: Shows any tags or events that bypassed WAF rules.
4. ✅ **Validation**: Confirms whether detected XSS vulnerabilities are valid and exploitable.


## 📢 Coming Soon

In the next few weeks, we will publish blog articles where we will explain in detail how we use this tool to find vulnerabilities in active websites on the Internet. These articles will range from simple use cases to advanced techniques, including how to bypass WAFs like Cloudflare and other complex exploitations.

Stay tuned for our updates!


## Screenshots
![main](https://github.com/user-attachments/assets/e978b157-c55d-4af5-bc63-1499a605eb5b)
