**PyMISP CISA Alerts** 

![Build Status](https://travis-ci.com/aleprada/PyMISP_CISA_alerts.svg?branch=main&status=passed)

The aim of this tool is to provide a simple and automated way of gathering alerts 
about vulnerabilities and some threats regarding ICS/SCADA. The tool uses the [feedparser](https://pypi.org/project/feedparser/)
Python library for consuming RSS feed published by [CISA](https://us-cert.cisa.gov/ncas), 
which publishes alerts regarding this topic regularly.

The alerts gathered **will be correlated to a keywords list(software.txt)** in order 
to be aware of the vulnerabilities that you want to monitor. If any of the alerts contain
one or more keywords stored in the software.txt file, the alerts will be sent to the 
configured [MISP](https://www.misp-project.org/) instance.

**National Cyber Awareness System (NCAS)**

The tool gathers information from the followings sources within the CISA NCAS.
* **Bulletins**: Weekly summaries of new vulnerabilities (including patch information if available).
* **Advisories**: Timely information about current security issues, vulnerabilities and exploits.
  
**MISP**

The alerts containing any of the keywords stored in the software.txt file will be sent
to the configured MISP instance. The events created will contain the tag "vulnerability".

**Configuration**

In order to send only **relevant threats and vulnerabilities** to your MISP instance, you will have to create a list of
software products that you want to monitor. This list will be stored in the software.txt file (config/config_files/).
For instance, imagine that you want to stay up to date about vulnerabilities in AXIS Q16 cameras and Siemens S7-1200 PLCs,
you will add to the software.txt file the following elements:

* AXIS Q16
* Siemens S7-1200

Besides, the software.txt file, there's a SQLite database (config->sqlite) for storing the entries
that you already have analysed. 

**Using the tool**

Gathering **only Vulnerability Bulletins** from CISA reports.
```bash 
python main.py --vulns 
```
Gathering **only ICS threats** from CISA reports.
```bash 
python main.py --threats
```
 Gathering **entries from ICS threats and Vulnerability Bulletins** reported by CISA.
```bash 
python main.py --full
```

Using **proxy for MISP instance** connection.
```bash 
python main.py --proxy
```
