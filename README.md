# NetTracePro

NetTracePro is a Python-based network analysis tool that combines ICMP probing and traceroute simulation to visualize network latency and route information. It provides insights into the path of network packets, response times at each hop, and geolocation details of intermediate routers.

---

## 🚀 Features

- **ICMP Probe Analysis:** Sends customizable ICMP probes to analyze network latency.
- **Traceroute Simulation:** Simulates traceroute to identify each hop's IP, location, and response time.
- **Geolocation Integration:** Retrieves city, country, and ASN details for each hop.
- **Data Visualization:** Plots RTT (Round-Trip Time) per hop using matplotlib.
- **Log Generation:** Saves detailed results in a log file (`network_scan_results.txt`).

---

## 📦 Requirements

- Python 3.x
- Scapy
- Requests
- Matplotlib

Install all dependencies using:

```bash
pip install -r requirements.txt
