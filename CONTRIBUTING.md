# Contributing to AIMAS

Thank you for your interest in contributing to **AIMAS (Advanced Integrated Multi-Tool Assessment Suite)**.

AIMAS is an educational Linux cybersecurity toolkit designed to bring multiple security assessment capabilities together through a unified graphical interface.

We welcome contributions that improve the project's stability, usability, documentation, accessibility, and educational value.

---

## 🤝 What We Welcome

We welcome:

* Bug fixes and stability improvements
* GUI and usability improvements
* Documentation improvements
* Installation and deployment improvements
* Performance optimizations
* New cybersecurity utilities
* New reconnaissance capabilities
* Improvements to OSINT and AI functionality
* Cryptography module improvements
* Web security module improvements
* Improvements to controlled phishing-awareness simulations
* New educational features and lab functionality
* Better error handling and logging
* Linux compatibility improvements
* Improvements to reports and result handling
* Translations and accessibility improvements

---

## 🧩 Adding New Modules

AIMAS follows a modular architecture.

New functionality should preferably be implemented inside the appropriate module:

```text
modules/
├── cryptography/
├── network/
├── osint_ai/
├── phishing/
└── web/
```

When adding a new module:

1. Keep the functionality isolated and modular.
2. Avoid unnecessary dependencies.
3. Provide clear error handling.
4. Document required system tools.
5. Ensure the functionality is intended for authorized security testing.
6. Update the README when introducing a major feature.

---

## 🛡️ Security Requirements

Contributions must not introduce:

* Malware
* Destructive payloads
* Credential theft functionality
* Unauthorized access mechanisms
* Persistence mechanisms intended for malicious use
* Data exfiltration functionality
* Hidden backdoors
* Obfuscated malicious code
* Functionality designed to bypass authorization controls

Security-testing functionality must remain clearly scoped to **authorized and educational use**.

---

## 🧪 Testing

Before submitting a pull request, test your changes in a supported Linux environment.

Recommended environments:

```text
Kali Linux
Ubuntu
Debian
```

Verify that:

* The application starts successfully.
* The GUI remains functional.
* Existing modules continue to work.
* Errors are handled gracefully.
* Required dependencies are documented.
* No unnecessary external dependencies are introduced.

---

## 📝 Code Style

Please follow these general guidelines:

* Use clear and descriptive variable names.
* Keep functions focused and maintainable.
* Add comments where the logic is not immediately obvious.
* Avoid unnecessary duplication.
* Follow standard Python conventions where practical.
* Keep UI logic separated from core functionality when possible.
* Do not commit generated files such as `__pycache__`.

---

## 📁 Repository Structure

Keep new files organized according to the existing structure:

```text
AIMAS/
├── core/
├── modules/
├── services/
├── ui/
├── data/
├── main.py
├── main.spec
├── run_aimas.sh
├── requirements.txt
└── README.md
```

Do not place temporary files, local configuration files, credentials, or generated reports in the repository.

---

## 🔑 Credentials & Secrets

**Never commit:**

* API keys
* Passwords
* Authentication tokens
* Private keys
* Personal credentials
* Local configuration containing secrets

Use environment variables or local configuration files where appropriate.

---

## 📦 Dependencies

If your contribution introduces a Python dependency:

1. Add it to `requirements.txt`.
2. Explain why it is required.
3. Verify that it works on supported Linux distributions.
4. Avoid adding a dependency when the Python standard library already provides the required functionality.

If a system package is required, document it in the README.

---

## 🚀 Pull Requests

Before opening a pull request:

1. Test your changes.
2. Review the modified files.
3. Remove debugging code and temporary files.
4. Update documentation if necessary.
5. Provide a clear pull request title.
6. Explain what changed and why.

Example:

```text
Add network discovery result export
```

---

## 📋 Pull Request Checklist

```text
[ ] Tested on Linux
[ ] Existing functionality still works
[ ] No credentials or secrets committed
[ ] No unnecessary dependencies added
[ ] Documentation updated where required
[ ] Security implications reviewed
[ ] Code is organized according to the project structure
```

---

## ⚖️ Responsible Use

AIMAS is developed for:

* Cybersecurity education
* Authorized penetration testing
* Controlled security labs
* Cybersecurity research
* CTF training
* Security-awareness exercises

Contributions must respect applicable laws and authorization requirements.

---

## 📜 License

By contributing to AIMAS, you agree that your contribution may be distributed under the project's license.

---

<div align="center">

**AIMAS — Advanced Integrated Multi-Tool Assessment Suite**

*Ajloun National University — Cybersecurity & Cloud Computing*

</div>
