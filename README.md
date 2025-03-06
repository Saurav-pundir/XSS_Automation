# XSS_Automation

## 🔥 Automated XSS Testing Tool (Python)

**XSS_Automation** is a Python-based security testing tool that automates the process of testing for **Cross-Site Scripting (XSS)** vulnerabilities. It runs **2,690 payloads** against target input fields to identify possible XSS weaknesses.

## 🚀 Features
- Tests **all 2,690 XSS payloads** from a predefined list.
- Automates **injection testing** on web forms and URLs.
- Supports **GET & POST requests** for flexible testing.
- Customizable **headers & parameters** for advanced configurations.
- Generates a **detailed report** of vulnerable endpoints.

## 🛠️ Installation
```bash
# Clone the repository
git clone https://github.com/Saurav-pundir/XSS_Automation.git
cd XSS_Automation

# Install dependencies
pip install -r requirements.txt
```

## 🎯 Usage
```bash
python xss_automation.py -u <target_url> -p <payloads.txt> -m <GET/POST>
```

### Example:
```bash
python xss_automation.py -u "http://example.com/search.php?q=" -p payloads.txt -m GET
```

## 📝 Arguments
| Argument | Description |
|----------|------------|
| `-u` | Target URL (with parameter placeholder) |
| `-p` | Payload file containing 2,690 XSS strings |
| `-m` | HTTP method (GET or POST) |
| `-h` | Custom headers (optional) |

## ⚠️ Disclaimer
This tool is intended for **educational purposes** and **authorized security testing** only. **Do not use it on unauthorized systems.** The creator is not responsible for misuse.

## 📌 Author
**Saurav Pundir**  
🔗 [GitHub](https://github.com/Saurav-pundir) | [LinkedIn](https://www.linkedin.com/in/saurav-pundir/)
