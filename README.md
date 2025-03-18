# DNS_Spoofer

# DNS Spoofer - Python Script

## 🚨 Disclaimer
This script is intended for **educational and authorized penetration testing** purposes only. Unauthorized use of DNS spoofing is illegal and unethical.

## 📌 Overview
This Python script intercepts DNS queries and responds with a **spoofed IP address**, redirecting the victim to a malicious server. It utilizes **Scapy** for packet manipulation and **NetfilterQueue** for packet interception.

## 🛠 Requirements
Before running the script, ensure the following dependencies are installed:

### 🔹 Install Required Packages
```bash
sudo apt update
sudo apt install python3-pip
pip3 install scapy netfilterqueue
```

### 🔹 Enable IP Forwarding
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
```

### 🔹 Set Up iptables Rule
```bash
sudo iptables -I FORWARD -p udp --dport 53 -j NFQUEUE --queue-num 1
```
This rule redirects **DNS traffic (port 53)** to the NetfilterQueue.

---

## 📜 Usage
1. **Run the script with sudo:**
   ```bash
   sudo python3 dns_spoofer.py
   ```
2. Ensure the **victim's device** is using your machine as its DNS server.
   - Use **ARP spoofing** to redirect their DNS traffic if necessary.

---

## 🚀 How It Works
- Captures **DNS queries** from the victim's machine.
- If the requested domain matches the target, **injects a fake DNS response**.
- The victim is redirected to the attacker's IP instead of the real website.

---

## 🔧 Stopping the Attack
To restore normal network behavior, flush the iptables rules:
```bash
sudo iptables --flush
```

---

## 🔒 Mitigation Strategies (Defensive Measures)
- **Use DNSSEC** to validate DNS responses.
- **Monitor DNS traffic** for unusual activity.
- **Use encrypted DNS** (DNS-over-HTTPS, DNS-over-TLS).
- **Deploy static ARP entries** to prevent MITM attacks.

---

## 📢 Notes
This script is **highly effective in internal network penetration tests** when combined with **ARP spoofing**.

For advanced attacks, consider:
- **DNS Rebinding Attacks**
- **MITM Attacks with Evilginx**
- **Rogue DHCP + DNS Spoofing**

🔹 **Use responsibly!** 🚀



