from cisa.cisa import get_vulnerability_reports, get_ics_threats
from config.misp import save_threat, save_vuln
import argparse


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--vulns", help="Gather only vulnerability reports(Bulletins) by CISA.",
                        action="store_true")
    parser.add_argument("-t", "--threats", help="Gather only ICS-Threats(Advisories) by CISA.",
                        action="store_true")
    parser.add_argument("-f", "--full", help="Gather all the rss entries available of threats and vulnerabilities.",
                        action="store_true")
    parser.add_argument("-p", "--proxy", help="Set a proxy for sending the alert to your MISP instance..",
                        action="store_true")

    args = parser.parse_args()
    proxy_usage = False
    products_wt_vulns = []
    threats = []

    if args.full:
        print("[*] Gathering ICS threat entries reported by CISA.")
        threats = get_ics_threats()
        print("[*] Gathering Vulnerability bulletin entries reported by CISA.")
        products_wt_vulns = get_vulnerability_reports()
    elif args.threats:
        print("[*] Gathering ICS threat entries reported by CISA.")
        threats = get_ics_threats()
    elif args.vulns:
        print("[*] Gathering Vulnerability bulletin entries reported by CISA.")
        products_wt_vulns = get_vulnerability_reports()
    else:
        print("[*] Please, choose a valid argument. Type -h for checking the available arguments.")
        exit(0)

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
