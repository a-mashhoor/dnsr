# 🛡️ DNS Reconnaissance (dnsr) 🌐

![Shell Script](https://img.shields.io/badge/Shell-Zsh-000000.svg?style=flat&logo=terminal)
![License](https://img.shields.io/badge/License-MIT-1B1B1B.svg?style=flat)
![Version](https://img.shields.io/badge/Version-1.0.0-1B1B1B.svg)

> **_"The gateway to uncovering hidden truths in the DNS layer."_**

A **powerful DNS reconnaissance toolkit** designed for penetration testers, red teams, and security researchers. This script automates `dig` commands to perform comprehensive DNS analysis, including record enumeration, zone transfer testing, reverse DNS lookups, subdomain brute-forcing, and email security checks—all with a hacker's mindset.

---

## 📑 Table of Contents

1. [Features](#-features)
2. [Installation](#-installation)
3. [Usage](#-usage)
4. [Options](#-options)
5. [Sample Outputs](#-sample-outputs)
6. [Wordlist Recommendations](#-wordlist-recommendations)
7. [License](#-license)
8. [Contributing](#-contributing)
9. [Author](#-author)
10. [Troubleshooting](#-troubleshooting)

---

## 🚀 Features <a name="features"></a>

- 🔍 **DNS Record Enumeration**: Query all common record types (`A`, `AAAA`, `MX`, `TXT`, `NS`, `CNAME`, etc.) to map the target's infrastructure.
- 🔄 **Zone Transfer Testing**: Detect misconfigured DNS servers vulnerable to zone transfers (`AXFR`).
- 🔓 **Subdomain Discovery**: Brute-force subdomains using custom wordlists to uncover hidden assets.
- ✉️ **Email Security Analysis**: Validate SPF, DKIM, and DMARC configurations for email spoofing vulnerabilities.
- 📄 **Output Flexibility**: Generate human-readable reports or structured JSON for automation and integration.
- 🖥️ **Colorized Terminal Output**: Hacker-friendly, easy-to-read results with color-coded highlights.
- 📂 **Automated Reporting**: Save findings to files for documentation, further analysis, or client deliverables.

---

## 🔧 Installation <a name="installation"></a>

### Prerequisites

1. **Install Zsh**:
   ```bash
   # Debian/Ubuntu
   sudo apt install zsh

   # RHEL/CentOS
   sudo yum install zsh

   # macOS (usually pre-installed)
   brew update && brew install zsh
   ```

2. **Install `jq`** (for JSON processing):
   ```bash
   # Debian/Ubuntu
   sudo apt install jq

   # RHEL/CentOS
   sudo yum install jq

   # macOS
   brew install jq
   ```

3. **Clone the Script**:
   ```bash
   git clone https://github.com/a-mashhoor/dnsr.git
   chmod +x dns_recon.sh
   ```

From here, you can use it directly or create a symbolic link to add it to your system's PATH:
```bash
sudo ln -s $(pwd)/dns_recon.sh /usr/local/bin/dns_recon
```

---

## ⚙️ Usage <a name="usage"></a>

```bash
./dns_recon.sh -d DOMAIN [OPTIONS]
```

### Basic Recon
```bash
./dns_recon.sh -d example.com -o outputfile.json -j
```

### Full Recon with Subdomain Enumeration
```bash
./dns_recon.sh -d example.com -w subdomains.txt -k default -v -o results.txt -j 
```

### Export Results as JSON
```bash
./dns_recon.sh -d example.com -j -o results.json
```

---

## 🛠️ Options <a name="options"></a>

| Option      | Description                                                                 |
|-------------|-----------------------------------------------------------------------------|
| `-d DOMAIN` | Target domain (required)                                                   |
| `-o FILE`   | Save results to a file                                                     |
| `-w FILE`   | Use a wordlist for subdomain enumeration                                    |
| `-k SELECTOR` | Specify the DKIM selector for email security checks (default: `default`)  |
| `-v`        | Enable verbose mode for detailed logs                                      |
| `-j`        | Output results in JSON format (requires `-o`)                              |
| `-h`        | Display help message                                                       |

---

## 📊 Sample Outputs <a name="sample-outputs"></a>

### JSON Structure
```json
{
  "domain": "example.com",
  "dns_records": {
    "A": "93.184.216.34",
    "MX": "mail.example.com",
    "TXT": [
      "v=spf1 include:_spf.example.com ~all"
    ]
  },
  "zone_transfer": {
    "ns1.example.com": "; Transfer failed."
  },
  "email_security": {
    "spf": "v=spf1 include:_spf.example.com ~all",
    "dmarc": "v=DMARC1; p=none;"
  }
}
```

---

## 📑 Wordlist Recommendations <a name="wordlist-recommendations"></a>

For subdomain enumeration, use these curated wordlists:

- **[SecLists](https://github.com/danielmiessler/SecLists)**: A comprehensive collection of security-related wordlists.
  ```bash
  curl -O https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt
  ```

- **[Assetnote Wordlists](https://wordlists.assetnote.io/)**: High-quality wordlists for bug bounty hunters and pentesters.

---

## 📜 License <a name="license"></a>

This project is licensed under the **MIT License**. See the [LICENSE](https://github.com/a-mashhoor/dnsr?tab=MIT-1-ov-file) file for details.

---

## 🤝 Contributing <a name="contributing"></a>

Contributions are welcome! If you find a bug or have an idea for improvement:

1. Fork the repository.
2. Create a new branch (`git checkout -b feature/YourFeature`).
3. Commit your changes (`git commit -m 'Add some feature'`).
4. Push to the branch (`git push origin feature/YourFeature`).
5. Open a pull request.

For major changes, please open an issue first to discuss your proposed changes.

---

## 📞 Author  <a name="author"></a>

- **Author**: Arshia Mashhoor

---

## 🛠️ Troubleshooting <a name="troubleshooting"></a>

- **Error: Unable to resolve domain**: Ensure the target domain is valid and reachable.
- **Error: JSON output requires an output file**: Use the `-o` option when generating JSON.
- **Zone Transfer Failed**: This is expected if the DNS server is properly configured.

---

> **_"The art of hacking lies not in breaking things, but in understanding them."_**
```

