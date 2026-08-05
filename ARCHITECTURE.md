## 🛠️ Integrated Security Tools

AIMAS can integrate with common Linux cybersecurity utilities, including:

```text
Nmap
ARP-Scan
Netdiscover
Dirb
Gobuster
Nikto
SQLmap
Whois
DNS Utilities
Traceroute
ExifTool
```

The toolkit is designed to provide a centralized GUI workflow while using the underlying security utilities available on the Linux system.

---

## 🏗️ Architecture

```text
AIMAS/
│
├── core/
│   └── Core application logic
│
├── modules/
│   ├── cryptography/
│   ├── network/
│   ├── osint_ai/
│   ├── phishing/
│   └── web/
│
├── services/
│   └── Supporting services and integrations
│
├── ui/
│   └── Graphical User Interface
│
├── data/
│   ├── evasion_tips.json
│   ├── oui_database.csv
│   ├── waf_signatures.json
│   ├── payloads/
│   ├── phishing_templates/
│   └── wordlists/
│
├── main.py
├── main.spec
├── run_aimas.sh
├── AIMAS.ico
├── aimas_icon.png
├── requirements.txt
└── .gitignore
```

---

### Security Tools

Install the required system utilities:

```bash
sudo apt update

sudo apt install -y python3 python3-pip python3-venv \
    nmap arp-scan netdiscover dirb gobuster nikto sqlmap \
    whois dnsutils traceroute exiftool \
    libpango-1.0-0 libpangocairo-1.0-0 libcairo2 \
    libgdk-pixbuf2.0-0 libffi-dev shared-mime-info
```

> `arp-scan`, `netdiscover`, and `nmap` may require elevated privileges during execution. AIMAS handles required authentication through its system authentication workflow.

---

## ⚙️ Optional Configuration

### Have I Been Pwned API

AIMAS can optionally use a **Have I Been Pwned API key** for authorized email breach checks.

The API key can be configured from the AIMAS settings.

Configuration is stored locally in:

```text
~/.aimas/config.ini
```

### ngrok

For controlled security-awareness and phishing simulations that require external access, AIMAS can optionally use an **ngrok authentication token**.

The token is requested when the ngrok functionality is activated for the first time.

> Use external tunneling only for systems, pages, and simulations you own or have explicit authorization to test.

-------

## 🧪 Educational Use Cases

AIMAS can be used in controlled environments for:

```text
Cybersecurity Education
Network Reconnaissance Labs
Penetration Testing Training
Web Security Training
OSINT Exercises
Cryptography Labs
Security Awareness Simulations
CTF Preparation
Cybersecurity Research
```

---

## 📚 Project Structure

AIMAS follows a modular architecture to make the toolkit easier to maintain and extend.

### `core/`

Contains the main application logic and shared functionality.

### `modules/`

Contains the primary cybersecurity capabilities:

```text
cryptography/
network/
osint_ai/
phishing/
web/
```

### `services/`

Contains supporting services, integrations, and application-level functionality.

### `ui/`

Contains the graphical interface and user interaction components.

### `data/`

Contains supporting databases, signatures, wordlists, payload collections, templates, and other static resources required by selected modules.
