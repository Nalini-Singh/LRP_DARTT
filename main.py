
from scanner import scan_network, visualize_network, detailed_scan
from exploits import get_exploits, launch_exploit
from reports import create_pdf_report, create_md_report
from sessions import init_db, save_session
from logs import log_info, log_error
import datetime

def main():
    init_db()

    subnet = input("Enter subnet (e.g., 192.168.1.0/24): ")
    hosts = scan_network(subnet)
    visualize_network(hosts)

    target_ip = input("Select target IP: ")
    results = detailed_scan(target_ip)
    print(results)

    port = input("Enter port number to explore exploits: ")
    service_name = next((res['service'] for res in results if str(res['port']) == port), None)

    exploits = get_exploits(service_name)
    print("Available exploits:", exploits)

    exploit_choice = input("Enter exploit name to deploy: ")
    launch_exploit(exploit_choice, target_ip, port)

    session_data = {
        'Target IP': target_ip,
        'Open Ports': ', '.join([str(res['port']) for res in results]),
        'Exploits Used': exploit_choice,
        'Time': str(datetime.datetime.now())
    }

    save_session("Session1", target_ip, session_data['Open Ports'], "Found vulnerabilities", exploit_choice)
    create_pdf_report(session_data, 'pentest_report.pdf')
    create_md_report(session_data, 'pentest_report.md')

    log_info("Completed pen-testing session successfully.")

if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        log_error(f"Error during execution: {e}")
