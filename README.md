<div align="center">

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=32&pause=1000&color=00F7FF&center=true&vCenter=true&width=900&lines=AIMAS;Advanced+Integrated+Multi-Tool+Assessment+Suite;Linux+Cybersecurity+Toolkit;Graduation+Project+%7C+Cybersecurity+%26+Cloud+Computing" alt="Typing SVG" />

<br/>

![Platform](https://img.shields.io/badge/Platform-Linux-blue?style=for-the-badge\&logo=linux\&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.8%2B-yellow?style=for-the-badge\&logo=python\&logoColor=white)
![GUI](https://img.shields.io/badge/Interface-GUI-00A8E8?style=for-the-badge)
![Security](https://img.shields.io/badge/Focus-Cybersecurity-red?style=for-the-badge)
![OSINT](https://img.shields.io/badge/OSINT%20%26%20AI-Enabled-purple?style=for-the-badge)
![Ethical](https://img.shields.io/badge/Use-Educational%20%26%20Authorized-lightgrey?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

<br/>

> 🎓 **Graduation Project — Ajloun National University (ANU)**
> Faculty of IT · Cybersecurity and Cloud Computing
> **Integrated Cybersecurity Training and Application System**

</div>

---

## 📖 Overview

**AIMAS (Advanced Integrated Multi-Tool Assessment Suite)** is a Linux-based cybersecurity toolkit developed in Python with a graphical user interface (GUI).

The project brings together multiple cybersecurity capabilities into a single environment, allowing students, cybersecurity enthusiasts, and authorized security professionals to perform reconnaissance, network analysis, web security testing, cryptographic analysis, OSINT, and security automation without relying entirely on separate command-line tools.

AIMAS was designed as an academic cybersecurity project with a focus on **practical learning, centralized tooling, automation, and professional reporting**.

> ⚠️ **AIMAS is intended strictly for educational purposes, authorized security assessments, and controlled laboratory environments. Never use it against systems without explicit permission.**

---

## 🎯 Project Goals

AIMAS was designed to:

* Provide a centralized cybersecurity assessment environment
* Simplify the use of common Linux security tools through a GUI
* Help cybersecurity students understand practical security workflows
* Automate common reconnaissance and assessment tasks
* Combine offensive security, reconnaissance, OSINT, cryptography, and web security modules
* Provide structured results and reports
* Reduce the need to manually switch between multiple terminal tools
* Support controlled cybersecurity labs and authorized penetration testing

---

## 🧩 Core Modules

| Module                        | Description                                                                    |
| ----------------------------- | ------------------------------------------------------------------------------ |
| 🌐 **Network Reconnaissance** | Network discovery, host identification, port scanning, and service enumeration |
| 🕵️ **OSINT & AI**            | Open-source intelligence gathering and AI-assisted analysis                    |
| 🔐 **Cryptography**           | Hash analysis, cryptographic utilities, and security-related operations        |
| 🌍 **Web Security**           | Web reconnaissance, enumeration, and authorized security testing               |
| 🎣 **Phishing Simulation**    | Controlled phishing awareness and educational simulations                      |
| ⚙️ **Automation**             | Automates repetitive security assessment workflows                             |
| 🛡️ **Security Utilities**    | Additional tools and utilities supporting cybersecurity assessments            |

---

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

## ✨ Features

| Feature                          | Description                                                 |
| -------------------------------- | ----------------------------------------------------------- |
| 🖥️ **Graphical Interface**      | Perform cybersecurity tasks through an organized GUI        |
| 🔎 **Reconnaissance**            | Discover hosts, services, ports, and network information    |
| 🌐 **Web Assessment**            | Perform authorized web enumeration and security checks      |
| 🕵️ **OSINT & AI**               | Gather and analyze publicly available intelligence          |
| 🔐 **Cryptography**              | Perform cryptographic and hash-related security operations  |
| 🎣 **Phishing Simulation**       | Conduct controlled phishing awareness exercises             |
| ⚙️ **Automation**                | Automate repetitive cybersecurity workflows                 |
| 📊 **Results & Reports**         | Organize and preserve assessment results                    |
| 🔑 **Authentication**            | Secure access to selected AIMAS functionality               |
| 🛡️ **Privilege Authentication** | Handles required system privileges for selected Linux tools |
| 📦 **Modular Architecture**      | Extend functionality through independent modules            |
| 🐧 **Linux Native**              | Designed specifically for Kali Linux, Debian, and Ubuntu    |

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

## 🖥️ Supported Platforms

AIMAS is designed for Linux-based cybersecurity environments.

Recommended:

```text
Kali Linux
Ubuntu
Debian
```

The toolkit relies on several Linux security utilities and system-level capabilities.

---

## 📦 Requirements

### System Requirements

```text
Python 3.8+
Python pip
Python venv
Linux operating system
sudo privileges
Internet connection (for selected OSINT/API features)
```

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

## 🚀 Installation

### 1. Clone the Repository

```bash
git clone https://github.com/Ayham-Megdadi/AIMAS.git
cd AIMAS
```

### 2. Create a Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Python Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Make the Launcher Executable

```bash
chmod +x run_aimas.sh
```

### 5. Launch AIMAS

```bash
python3 main.py
```

Or:

```bash
./run_aimas.sh
```

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

---

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

---

## 🔒 Security & Privacy

AIMAS is designed for authorized security testing.

Users are responsible for ensuring that they have permission before performing security assessments.

The project does not grant permission to:

* Scan networks without authorization
* Test websites without permission
* Collect private information
* Conduct phishing campaigns against real users
* Access systems without authorization
* Perform destructive security testing

---

## 🎓 Academic Project

<div align="center">

```text
╔═══════════════════════════════════════════════════════════╗
║              AIMAS — GRADUATION PROJECT                  ║
║                                                           ║
║     Integrated Cybersecurity Training and                 ║
║              Application System                           ║
║                                                           ║
║     Ajloun National University — ANU                      ║
║     Faculty of IT                                        ║
║     Cybersecurity and Cloud Computing                     ║
║     Academic Year: 2025–2026                              ║
╚═══════════════════════════════════════════════════════════╝
```

</div>

---

## 👨‍💻 Developer

<div align="center">

**Ayham Belal Megdadi**

Cybersecurity & Cloud Computing

Ajloun National University — Jordan

[![LinkedIn](https://img.shields.io/badge/LinkedIn-0077B5?style=flat\&logo=linkedin\&logoColor=white)](https://www.linkedin.com/in/ayham-megdadi)
[![Instagram](https://img.shields.io/badge/Instagram-E4405F?style=flat\&logo=instagram\&logoColor=white)](https://www.instagram.com/ayham_megdadi)

</div>

---

## 🤝 Contributing

Contributions, suggestions, documentation improvements, and educational enhancements are welcome.

Please read [`CONTRIBUTING.md`](./CONTRIBUTING.md) before submitting changes.

---

## 🔐 Security

For security-related concerns, please read [`SECURITY.md`](./SECURITY.md).

Do not use AIMAS against systems or networks without explicit authorization.

---

## ⚖️ Disclaimer

> **AIMAS is developed exclusively for educational purposes, authorized penetration testing, cybersecurity research, and controlled laboratory environments.**

The developers are not responsible for:

* Unauthorized use of the toolkit
* Damage caused by misuse
* Unauthorized network or system access
* Data loss
* Privacy violations
* Any illegal activity performed using this software

**Always obtain explicit authorization before testing systems that you do not own.**

---

<div align="center">

*Built for cybersecurity education and research — Ajloun National University*

⭐ **Star this repository if AIMAS helped you learn something new!**

</div>
