
# vulscanner.py (amended discover to return hosts, simplified XML handling)
import nmap
import pandas as pd
import xml.etree.ElementTree as et
import os

OUTPUT_DIR = 'outputs'
if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR)


def discover(network):
    nm = nmap.PortScanner()
    nm.scan(hosts=network, arguments='-sn')
    hosts = [h for h in nm.all_hosts() if nm[h]['status']['state'] == 'up']
    with open(os.path.join(OUTPUT_DIR, 'hosts'), 'w') as f:
        for h in hosts:
            f.write(h + '\n')
    return hosts


def vulscan(Host):
    nm = nmap.PortScanner()
    target = Host['IP']
    args = f"-sV -sS {'-p '+Host['Port'] if Host['Port'] else ''} --script vulners"
    nm.scan(target, arguments=args)
    base = os.path.join(OUTPUT_DIR, f'nmap-{target.replace('/','_')}')
    xml_path = base + '.xml'
    csv_path = base + '.csv'
    # write XML
    with open(xml_path, 'wb') as f:
        f.write(nm.get_nmap_last_output())
    # parse and export CSV
    rows = []
    root = et.parse(xml_path).getroot()
    for port in root.iter('port'):
        rows.append({
            'Port': port.attrib['portid'],
            'Service': port.find('service').attrib['name'],
            'Version': port.find('service').attrib.get('version',''),
            'CVE': port.find('script').attrib.get('id','') if port.find('script') is not None else ''
        })
    pd.DataFrame(rows).to_csv(csv_path, index=False)
    return base

