#!/usr/bin/env python3 
"""
IoT Network Security Analyzer 
Author: Julio Arellano
CYBV 498
"""

import socket                              #for network communication
from datetime import datetime              #for timestampting reports
from collections import defaultdict        #for counting packet flows
import time                                #for potential delays

# NMAP IMPLEMENTATION
try:
    import nmap                             #python wrapper for nmap
except ImportError:
    print("[!] python-nmap required")
    exit(1)                                 #exit if nmap not installed

# SCAPY IMPLEMENTATION(OPTIONAL)
try:
    from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, Raw     #import only necessary components
    SCAPY_AVAILABLE = True
except:
    SCAPY_AVAILABLE = False
    print("[!] Scapy not available - packet analysis disabled")


# DEVICE PROFILER 

class DeviceProfiler:                   #class ids device based on open ports
    def classify(self, ports):
        p = [x["port"] for x in ports]

        if 554 in p:
            return "camera"
        if 1883 in p:
            return "iot_mqtt_device"
        if 6668 in p or 8080 in p:
            return "smart_plug"
        if 22 in p or 445 in p:
            return "computer"
        if 80 in p and len(p) <= 3:
            return "embedded_iot"
        return "unknown_device"


# RISK ENGINE

class RiskEngine:                       #used to calc. numerical risk based on vuln services
    def score(self, ports):
        score = 0
        p = [x["port"] for x in ports]

        if 23 in p: score += 40
        if 554 in p: score += 25
        if 1883 in p: score += 20
        if 80 in p: score += 10
        if 8080 in p: score += 10

        score += len(p) * 2

        return min(score, 100)              #caps scale at 100

    def label(self, score):
        if score >= 70:
            return "CRITICAL"
        if score >= 40:
            return "HIGH"
        if score >= 20:
            return "MEDIUM"
        return "LOW"


# VULN MAPPING

class VulnMapper:                           #generates warning messages about discovered vulnerabilities
    def analyze(self, ports):
        findings = []

        for p in ports:                     #check each open port and generate warning
            port = p["port"]

            if port == 23:
                findings.append("Telnet exposed (plaintext credentials risk)")
            if port == 1883:
                findings.append("MQTT unencrypted IoT messaging")
            if port == 554:
                findings.append("RTSP camera stream exposure")
            if port == 80:
                findings.append("HTTP admin interface exposed")

        return findings


# PACKET ANALYZER (IoT PROFILING)

class PacketAnalyzer:                   #captures packets 
    def __init__(self):
        self.packets = []               #stores packet summaries
        self.findings = []              #stores security observations
        self.flow_count = defaultdict(int)  #track packets per source IP

        self.iot_domains = [                    
            "tuya", "googleapis", "amazonaws", "hikvision",
            "xiaomi", "mqtt", "smartlife", "hue", "nest"
        ]
            #known IoT cloud services to look for in DNS queries
    def analyze_dns(self, pkt):             #check DNS packets for IoT related domain lookups
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            q = pkt[DNSQR].qname.decode(errors="ignore").lower()    #resolve the domain name being queried

            for d in self.iot_domains:
                if d in q:
                    self.findings.append(f"DNS IoT cloud call → {q}")

    def callback(self, pkt):        
        self.packets.append(pkt.summary())      #store text summary of packet

        if pkt.haslayer(IP):                    #count packets per source IP
            self.flow_count[pkt[IP].src] += 1

        self.analyze_dns(pkt)                   #analyze DNS in packet

        if pkt.haslayer(TCP):                   #check for insecure protocols in TCP packets
            if pkt[TCP].dport == 1883:
                self.findings.append("MQTT unencrypted traffic detected")
            if pkt[TCP].dport == 23:
                self.findings.append("Telnet traffic detected")

    def run(self, timeout=30):                  #start packet capture for specified duration
        if not SCAPY_AVAILABLE:
            return                              #exit if scapy is not available

        print(f"\n[*] Packet analysis running for {timeout}s...")
        sniff(prn=self.callback, store=False, timeout=timeout)


# MAIN SCANNER

class IoTScanner:
    def __init__(self, network=None):
        self.nm = nmap.PortScanner()        #initiate nmap scanner

        if network:                         #use provided network or autodetect
            self.network = network
        else:
            self.network = self.auto_network()  #detect local subnet

        self.devices = []                   #list of discovered devices
        self.vulnerable = []                #devices with vulnerabilities
        self.time = datetime.now()          #timestamp for report

    def auto_network(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)    #create a socket to determine own IP
        try:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
        finally:
            s.close()
        return ".".join(ip.split(".")[:3]) + ".0/24"

    
    # DEVICE DISCOVERY 
    def discover(self):
        print(f"\n[*] Discovering devices on {self.network}")

        self.nm.scan(self.network, arguments="-sn -PR") #-sn = ping scan, -PR = ARP ping

        devices = []

        for host in self.nm.all_hosts():                #go through all hosts that respond
            if self.nm[host].state() == "up":
                devices.append({
                    "ip": host,
                    "hostname": self.nm[host].hostname() or "unknown",
                    "open_ports": []
                })

        self.devices = devices
        return devices

    # PORT SCAN
    def scan_ports(self, ip):       #scan all relevant ports for IP 
        self.nm.scan(ip, "23,80,443,554,1883,8080,6668", arguments="-sS -T4")   #-sS = SYN stealth scan, -T4 = faster timing template

        open_ports = []

        if ip not in self.nm.all_hosts():       #check if host responded to scan
            return open_ports

        for proto in self.nm[ip].all_protocols():       #itereate through protocols
            for port in self.nm[ip][proto]:
                if self.nm[ip][proto][port]["state"] == "open":
                    open_ports.append({"port": port})

        return open_ports


    # VULNERABILITY CHECK
    def analyze(self, device):          #analyze open ports to determine risk and vulnerability
        ports = device["open_ports"]

        #prepare analaysis classes
        profiler = DeviceProfiler()
        risk = RiskEngine()
        mapper = VulnMapper()

        #add results to device dictionary
        device["type"] = profiler.classify(ports)
        device["risk_score"] = risk.score(ports)
        device["risk_level"] = risk.label(device["risk_score"])
        device["findings"] = mapper.analyze(ports)

        return device


# REPORT GENERATION

def report(scanner, analyzer):
    lines = []

    #header section
    lines.append("=" * 60)
    lines.append("IoT SECURITY ANALYSIS REPORT")
    lines.append(f"Time: {scanner.time}")
    lines.append(f"Network: {scanner.network}")
    lines.append(f"Devices: {len(scanner.devices)}")
    lines.append(f"High Risk Devices: {len(scanner.vulnerable)}")

    #findings for each vulnerable device
    for d in scanner.vulnerable:
        lines.append(f"\n{d['ip']} ({d['hostname']})")
        lines.append(f"Type: {d['type']}")
        lines.append(f"Risk: {d['risk_score']} ({d['risk_level']})")
        lines.append(f"Ports: {[p['port'] for p in d['open_ports']]}")

        for f in d["findings"]:
            lines.append(f" - {f}")

    #packet analysis section
    if analyzer:
        lines.append("\n=== PACKET INSIGHTS ===")
        lines.append(f"Packets: {len(analyzer.packets)}")
        lines.append(f"Events: {len(analyzer.findings)}")

        for f in analyzer.findings[:10]:
            lines.append(f" - {f}")

    return "\n".join(lines)


# MAIN FUNCTION

def main():         #program entry point
    print("\n=== IoT Security Analyzer (FULL SYSTEM) ===\n")

    net = input("Network (Enter for auto): ").strip()   #get network from user or auto detect

    scanner = IoTScanner(net if net else None)
    analyzer = PacketAnalyzer()

    # STEP 1
    scanner.discover()      #discover devices on network

    # STEP 2
    for d in scanner.devices:   #for each device scan ports and analyze vulns.
        d["open_ports"] = scanner.scan_ports(d["ip"])

        if d["open_ports"]:     #only analyze devices with open ports
            d = scanner.analyze(d)
            scanner.vulnerable.append(d)

            print(f"[+] {d['ip']} → {d['type']} | {d['risk_score']}/100")   #prints real-time results to console

    # STEP 3
    if SCAPY_AVAILABLE:
        choice = input("\nRun packet analysis? (y/n): ").lower()

        if choice == "y":
            t = input("Duration (30 default): ").strip()
            t = int(t) if t else 30     
            analyzer.run(timeout=t)

    # STEP 4
    output = report(scanner, analyzer)

    #creates filename with timestamp
    fname = f"iot_full_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

    with open(fname, "w") as f:
        f.write(output)

    print(f"\n[+] Saved: {fname}")
    print(output)


if __name__ == "__main__":
    main()