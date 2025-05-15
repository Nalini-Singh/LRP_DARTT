
import nmap
import networkx as nx
import matplotlib.pyplot as plt

def scan_network(subnet):
    nm = nmap.PortScanner()
    nm.scan(hosts=subnet, arguments='-sn')
    active_hosts = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]
    return [host for host, status in active_hosts if status == 'up']

def visualize_network(hosts):
    G = nx.Graph()
    G.add_node("Scanner")
    for host in hosts:
        G.add_edge("Scanner", host)
    nx.draw(G, with_labels=True, node_color='skyblue', node_size=1500, font_size=10)
    plt.title("Network Scan Visualization")
    plt.show()

def detailed_scan(target_ip):
    nm = nmap.PortScanner()
    nm.scan(target_ip, arguments='-sV --script vulners')
    results = []
    for port in nm[target_ip]['tcp']:
        service = nm[target_ip]['tcp'][port]
        cves = service.get('script', {}).get('vulners', 'N/A')
        results.append({
            'port': port,
            'service': service['name'],
            'version': service['version'],
            'cves': cves
        })
    return results
