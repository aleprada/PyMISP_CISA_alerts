import pymisp.exceptions
from pymisp import PyMISP,MISPEvent, MISPAttribute, PyMISPError, MISPObject
from config.config import config_parser
from cisa.cisa import CISAVulnerability, CISAICSThreat


def misp_connection(url, misp_key, proxies_usage):
    try:
        if proxies_usage:
            proxies = {}
            proxies ["http"] = config_parser("misp","http")
            proxies ["https"] = config_parser("misp","https")
            misp = PyMISP(url, misp_key, False, 'json', proxies=proxies)
        else:
            misp = PyMISP(url, misp_key, False, 'json',None)
    except PyMISPError:
        print("\t [!] Error connecting to MISP instance. Check if your MISP instance it's up!")
        return None

    return misp


def create_event(misp):
    event = MISPEvent()
    event.distribution = 0
    event.threat_level_id = 1
    event.analysis = 0
    return event


def save_vuln(vuln_list, proxies_usage):
    misp = misp_connection(config_parser("misp","url"),config_parser("misp","api_key"),proxies_usage)
    for vuln in vuln_list:
        try:
            event = create_event(misp)
            event.add_tag("circl:incident-classification=\"vulnerability\"")
            event.info = "[CISA] New vulnerability reported"
            vulnerability_object = MISPObject('vulnerability')
            vulnerability_object.add_attribute("created", vuln.published)
            vulnerability_object.add_attribute("cvss-score", vuln.cvss)
            vulnerability_object.add_attribute("id", vuln.cve_info)
            vulnerability_object.add_attribute("description", vuln.description)
            event.add_object(vulnerability_object)
            event = misp.add_event(event, pythonify=True)
            print("\t [*] Event with ID "+str(event.id) + " has been successfully stored.")
        except pymisp.exceptions.NewEventError as e:
            print("[!] Exception: "+ str(e))
            print("\t[!] There was a problem creating the following event: "+vuln.description)


def save_threat(threat_list, proxies_usage):
    misp = misp_connection(config_parser("misp","url"),config_parser("misp","api_key"), proxies_usage)
    for threat in threat_list:
        try:
            event = create_event(misp)
            event.add_tag("circl:incident-classification=\"vulnerability\"")
            event.info = "[CISA] New ICS threat detected"
            event.add_attribute('link',threat.link)
            event.add_attribute('comment',threat.summary)
            event = misp.add_event(event, pythonify=True)
            print("\t [*] Event with ID "+str(event.id) + " has been successfully stored.")
        except pymisp.exceptions.NewEventError as e:
            print("[!] Exception: " + str(e))
            print("\t[!] There was a problem creating the following event: " + threat.summary)
