import feedparser
from lxml.html import fromstring
from config.config import get_software_list


class CISAVulnerability:
    def __init__(self, vendor_product, description, published, cvss, cve_info):
        self.vendor_product = vendor_product
        self.description = description
        self.published = published
        self.cvss = cvss
        self.cve_info = cve_info

    def show_vulnerability_info(self):
        print("[*] Vulnerability found!")
        print("\t[-] Vendor-product: "+self.vendor_product)
        print("\t[-] Description: "+self.description)
        print("\t[-] Published: "+self.published)
        print("\t[-] Scoring: "+self.cvss)
        print("\t[-] CVE: " + self.cve_info)


class CISAICSThreat:
    def __init__(self, title, summary, published, link):
        self.title = title
        self.summary = summary
        self.published = published
        self.link = link

    def show_threat_info(self):
        print("[*] Threat found!")
        print("\t[-] Title: "+self.title)
        print("\t[-] Summary: "+self.summary)
        print("\t[-] Published: "+self.published)
        print("\t[-] Link: "+self.link)


def check_vuln_products(vulnerabibility_list):
    product_list = get_software_list()
    vuln_alert = []
    for v in vulnerabibility_list:
        for p in product_list:
            if p in v.description:
                vuln_alert.append(v)
    return vuln_alert


def check_ics_threats(threat_list):
    threats= get_software_list()
    threat_alert = []
    for t in threat_list:
        for p in threats:
            if p in t.summary:
                threat_alert.append(t)
    return threat_alert


def feed_vulnerability_reports(all_entries):
    vulnerability_list = []
    rss = 'https://us-cert.cisa.gov/ncas/bulletins.xml'
    feed = feedparser.parse(rss)

    if all_entries is False:
        last_etag = feed.etag
        last_modified = feed.modified
        # check if new version exists
        feed_update = feedparser.parse(rss, etag=last_etag, modified=last_modified)
        if feed_update.status == 304:
            print("\t[!] There aren't new vulnerability reports")
            return vulnerability_list
        else:
            feed = feed_update

    for key in feed["entries"]:
        title = key['title']
        url = key['links'][0]['href']
        summary = key['summary']
        doc = fromstring(summary)
        tr_elements = doc.xpath('//tr')
        for j in range(1,len(tr_elements)):
            items = tr_elements[j]
            if len(items) != 5:
                break
            count = 0
            for t in items.iterchildren():
                data = t.text_content().strip()
                if count == 0:
                    vendor = data
                elif count == 1:
                    description = data
                elif count ==2:
                    published = data
                elif count ==3:
                    cvss = data
                elif count == 4:
                    info = data
                    cisa = CISAVulnerability(vendor, description, published, cvss, info)
                    vulnerability_list.append(cisa)
                count = count +1
    return vulnerability_list


def feed_ics_threats(all_entries):
    cisa_threats = []
    rss="https://us-cert.cisa.gov/ics/advisories/advisories.xml"
    feed = feedparser.parse(rss)
    if all_entries is False:
        last_etag = feed.etag
        last_modified = feed.modified
        # check if new version exists
        feed_update = feedparser.parse(rss, etag=last_etag, modified=last_modified)
        if feed_update.status == 304:
            print("\t[!] There aren't new threat reports")
            return cisa_threats
        else:
            feed = feed_update

    for key in feed["entries"]:
        title = key['title']
        summary = key['summary'].replace("<p>","").replace("<p>","")
        published = key['published']
        link = key['link']
        threat = CISAICSThreat(title,summary, published, link)
        cisa_threats.append(threat)
    return cisa_threats


def get_vulnerability_reports(all_entries):
    products_wt_vulns = []
    vulnerability_list = feed_vulnerability_reports(all_entries)
    if vulnerability_list is not None:
        products_wt_vulns = check_vuln_products(vulnerability_list)
        for p in products_wt_vulns:
            p.show_vulnerability_info()
    return products_wt_vulns


def get_ics_threats(all_entries):
    threats = feed_ics_threats(all_entries)
    if threats is not None:
        filtered_threats = check_ics_threats(threats)
        for t in filtered_threats:
            t.show_threat_info()
    return filtered_threats

