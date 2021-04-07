from cisa.cisa import get_vulnerability_reports, get_ics_threats
from config.misp import save_threat, save_vuln
import argparse


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--vulns", help="Gather only vulnerability reports(Bulletins) by CISA.", action="store_true")
    parser.add_argument("-t", "--threats", help="Gather only ICS-Threats(Advisories) by CISA.", action="store_true")
    parser.add_argument("-f", "--full", help="Gather all the rss entries available, not only the last entry.", action="store_true")
    parser.add_argument("-p", "--proxy", help="Set a proxy for sending the alert to your MISP instance..", action="store_true")

    args = parser.parse_args()
    proxy_usage = False

    if args.full:
        if args.threats:
            print("[*] Gathering all the entries from ICS threats by reported CISA.")
            threats = get_ics_threats(all_entries=True)
        elif args.vulns:
            print("[*] Gathering all the entries from Vulnerability Bulletins by reported CISA.")
            products_wt_vulns = get_vulnerability_reports(all_entries=True)
        else:
            print("[*] Gathering all the entries from ICS threats and Vulnerability Bulletins reported by CISA.")
            products_wt_vulns = get_vulnerability_reports(all_entries=True)
            threats = get_ics_threats(all_entries=True)

    elif args.threats:
        print("[*] Gathering only the last entry from ICS threats reported by CISA")
        threats = get_ics_threats(all_entries=False)
    elif args.vulns:
        print("[*] Gathering only the last entry from Vulnerability Bulletins reported by CISA.")
        products_wt_vulns = get_vulnerability_reports(all_entries=False)
    else:
        print("[*] Gathering only the last entry from ICS threats and Vulnerability Bulletins reported by CISA.")
        products_wt_vulns = get_vulnerability_reports(all_entries=False)
        threats = get_ics_threats(all_entries=False)

    if len(products_wt_vulns) == 0 and len(threats) == 0:
        print("[!] There aren't new alerts of your interest.")
    else:
        if args.proxy:
            proxy_usage = True
        else:
            proxy_usage = False
        save_vuln(products_wt_vulns, proxy_usage)
        save_threat(threats, proxy_usage)
        print("[!] Number of vulnerabilities sent to MISP: "+str(len(products_wt_vulns)))
        print("[!] Number of threats sent to MISP: "+str(len(threats)))



if __name__ == '__main__':
    main()
