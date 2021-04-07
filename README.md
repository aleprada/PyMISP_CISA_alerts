**PyMISP CISA Alerts** 

The aim of this tool is to provide a simple and automated way of gathering alerts 
about vulnerabilities and some threats regarding ICS/SCADA. The tool uses the [feedparser](https://pypi.org/project/feedparser/)
Python library for consuming RSS feed published by [CISA](https://us-cert.cisa.gov/ncas), 
which publishes alerts regarding this topic regularly.

The alerts gathered will be correlated to a keywords list(software.txt) in order 
to be aware of the vulnerabilities that you want to monitor. If any of the alerts contain
one or more keywords stored in the software.txt file, the alerts will be sent to the 
configured [MISP](https://www.misp-project.org/) instance.

**National Cyber Awareness System**

The tool gathers information from the followings sources within the CISA NCAS.
* **Bulletins**: Weekly summaries of new vulnerabilities (including patch information if available).
* **Advisories**: Timely information about current security issues, vulnerabilities and exploits.
  
**MISP**

The alerts containing any of the keywords stored in the software.txt file will be sent
to the configured MISP instance. The events created will contain the tag "vulnerability".

**Using the tool**

Gathering **only the last entry from ICS threats and Vulnerability Bulletins** by CISA.

```bash 
python main.py
```
Gathering **only the last entry from Vulnerability Bulletins** by CISA.
```bash 
python main.py --vulns 
```
Gathering **only the last entry from ICS threats** reported by CISA.
```bash 
python main.py --threats
```
 Gathering **all the entries from ICS threats and Vulnerability Bulletins** reported by CISA.
```bash 
python main.py --full
```

Using **proxy for MISP instance** connection.
```bash 
python main.py --proxy
```
