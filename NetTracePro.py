from scapy.all import *
import time
import matplotlib.pyplot as plt
import statistics
import requests

hop_rtt_data = {}

def analyze_icmp_response(response, sent_time, target_ip):
    if response is None:
        print(f"No response - Target {target_ip} may be down or ICMP blocked.")
    elif response.haslayer(ICMP):
        latency = (time.time() - sent_time) * 1000  # Measure latency from the sent time
        print(f"ICMP Echo Reply from {response[IP].src} | Latency: {latency:.2f} ms | Code: {response[ICMP].code}")
    else:
        print(f"Unexpected response from {response[IP].src}: {response.summary()}")

def send_icmp_probe(target_ip, num_probes):
    for _ in range(num_probes):
        packet = IP(dst=target_ip) / ICMP()
        sent_time = time.time()  # Capture the send time
        response = sr1(packet, timeout=2, verbose=0)
        analyze_icmp_response(response, sent_time, target_ip)

def get_geolocation_info(ip_address):
    url = f"https://ipinfo.io/{ip_address}/json"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            city = data.get('city', 'Unknown')
            country = data.get('country', 'Unknown')
            asn = data.get('org', 'ASN Unknown')
            return city, country, asn
    except Exception:
        pass
    return "Unknown", "Unknown", "ASN Unknown"

def traceroute_simulation(target_ip):
    max_ttl = 30
    print("\nStarting Traceroute Simulation:")
    
    for ttl in range(1, max_ttl + 1):
        packet = IP(dst=target_ip, ttl=ttl) / ICMP()
        sent_time = time.time()
        response = sr1(packet, timeout=2, verbose=0)

        if response is None:
            print(f"TTL={ttl} No Response")
            continue

        rtt = (time.time() - sent_time) * 1000
        ip_src = response[IP].src

        # Fetch geolocation details
        city, country, asn = get_geolocation_info(ip_src)

        print(f"TTL={ttl} Response from {ip_src} | Location: {city}, {country} | ASN: {asn} | RTT: {rtt:.2f} ms")

        if ttl not in hop_rtt_data:
            hop_rtt_data[ttl] = []
        hop_rtt_data[ttl].append(rtt)

        if ip_src == target_ip:
            print(f"Reached target {target_ip} at TTL={ttl} | Location: {city}, {country} | ASN: {asn} | RTT: {rtt:.2f} ms")
            break

def plot_visualizations():
    try:
        hop_numbers = sorted(hop_rtt_data.keys())
        avg_rtt_per_hop = [statistics.mean(rtts) if rtts else 0 for ttl, rtts in hop_rtt_data.items()]
        
        # Filter out hops with no data for plotting
        valid_hop_numbers = [ttl for ttl, rtts in hop_rtt_data.items() if rtts]
        valid_avg_rtt_per_hop = [rtt for rtt in avg_rtt_per_hop if rtt > 0]
        
        # Plot RTT per hop visualization
        plt.figure(figsize=(12, 6))
        plt.bar(valid_hop_numbers, valid_avg_rtt_per_hop, color='blue', alpha=0.6)
        plt.xlabel("Hop Number (TTL)")
        plt.ylabel("Average RTT (ms)")
        plt.title("Traceroute Hop RTT Analysis")
        plt.xticks(valid_hop_numbers)
        plt.grid(True)
        plt.show()

    except Exception as e:
        print(f"Error in plotting visualizations: {e}")

def main():
    target_ip = input("Enter the target IP address: ")
    num_probes = int(input("Enter the number of ICMP probes: "))
   
    print("\nStarting ICMP Probe Analysis:")
    send_icmp_probe(target_ip, num_probes)

    traceroute_simulation(target_ip)

    plot_visualizations()

    # Save the results to a log file
    with open("network_scan_results.txt", "w") as file:
        file.write("Hop RTT Analysis\n")
        for ttl, rtts in hop_rtt_data.items():
            file.write(f"TTL={ttl} | Average RTT={statistics.mean(rtts) if rtts else 0:.2f} ms\n")
    print("Results logged in network_scan_results.txt")

if __name__ == "__main__":
    main()
