# Security Policy

## 🔐 About AIMAS

**AIMAS (Advanced Integrated Multi-Tool Assessment Suite)** is a Linux-based cybersecurity toolkit developed for educational purposes, authorized security assessments, cybersecurity research, and controlled laboratory environments.

Because AIMAS interacts with security tools and system-level functionality, responsible use and proper authorization are essential.

---

## ⚠️ Responsible Use

AIMAS must only be used against:

* Systems you own
* Systems where you have explicit authorization
* Isolated cybersecurity laboratories
* CTF environments
* Authorized academic or research environments

**Never use AIMAS to scan, attack, access, or collect information from systems without permission.**

---

## 🚨 Reporting a Security Issue

If you discover a genuine security issue in AIMAS that is **not an intentional security-testing feature**, please report it privately to the project team.

Examples of reportable issues include:

* Authentication bypasses within AIMAS
* Unauthorized access to local AIMAS functionality
* Exposure of sensitive configuration data
* Insecure handling of API keys or credentials
* Local privilege escalation caused by AIMAS itself
* Unexpected command execution outside intended functionality
* Sensitive information being unintentionally written to logs or reports
* Vulnerabilities in the application that could compromise the user's system

---

## ❌ Do Not Publicly Disclose Sensitive Issues

For vulnerabilities that could affect users or expose sensitive information:

**Please do NOT open a public GitHub issue containing exploit details, credentials, API keys, or sensitive information.**

Contact the project team privately first so the issue can be reviewed and addressed responsibly.

---

## 🧪 Security Testing Features

Some AIMAS modules intentionally perform security-related actions such as:

* Network reconnaissance
* Port and service discovery
* Web security assessment
* OSINT collection
* Cryptographic analysis
* Security-awareness simulations
* Controlled phishing simulations

These capabilities are **features of the toolkit**, not vulnerabilities in themselves.

They must only be used within authorized environments.

---

## 🔑 Sensitive Information

Users should never store or commit sensitive information inside the repository, including:

* Passwords
* API keys
* Authentication tokens
* Private keys
* Personal credentials
* Confidential assessment data

Users are responsible for protecting any sensitive information generated or collected during authorized assessments.

---

## 🌐 Third-Party Services

Some AIMAS functionality may interact with external services or APIs.

Users are responsible for:

* Following the terms of the relevant service
* Protecting API credentials
* Respecting rate limits
* Obtaining appropriate authorization
* Ensuring collected information is handled lawfully

---

## ⏱ Response Time

We aim to acknowledge valid security reports within **48 hours** and will work to investigate confirmed security issues as quickly as possible.

The actual resolution time may vary depending on the severity and complexity of the issue.

---

## ⚖️ Legal Disclaimer

AIMAS is provided for **educational, research, and authorized cybersecurity testing purposes**.

The project authors are not responsible for unauthorized or illegal use of the toolkit.

By using AIMAS, you agree to use it only against systems and environments for which you have appropriate authorization.

---

<div align="center">

**AIMAS — Advanced Integrated Multi-Tool Assessment Suite**

*Ajloun National University — Cybersecurity & Cloud Computing*

</div>
