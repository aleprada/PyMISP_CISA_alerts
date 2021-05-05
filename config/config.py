from datetime import datetime
from sqlite3 import Error
import configparser
import sqlite3
import os
import sys


def config_parser(section, key):
    config = configparser.ConfigParser()
    try:
        config.read(os.path.join(os.path.dirname(__file__)+"/config_files/config.ini"))
        result = config.get(section, key)
        return result
    except config.NoOptionError:
        raise Exception("There was a problem with configuration file. The key does not exist.")
    except config.NoSectionError:
        raise Exception("There was a problem with configuration file. The key does not exist.")


def config_parser_section(section):
    parser = config = configparser.ConfigParser()
    try:
        parser.read(os.path.dirname(__file__)+"/config_files/config.ini")
        result = dict(parser.items(section))
        return result
    except config.NoSectionError:
        raise Exception("There was a problem with configuration file. The key does not exist.")


def get_software_list():
    path_software_list = os.path.join(os.path.dirname(__file__) + "/config_files/software.txt")
    software_list = []
    with open(path_software_list, "r") as ins:
        for line in ins:
            software_list.append(line.strip())
        ins.close()
    return software_list


def create_connection():
    db_file = os.path.join(os.path.dirname(__file__))+'/sqlite/entries.db'
    conn = None
    try:
        conn = sqlite3.connect(db_file)
    except Error as e:
        print(e)
    return conn


def save_threat_db(url, title, published):
    timestamp = datetime.now()
    conn = create_connection()
    sql = ''' INSERT OR IGNORE INTO threats(timestamp,url,title,published)
              VALUES(?,?,?,?) '''
    cur = conn.cursor()
    cur.execute(sql, (timestamp, url, title, published))
    conn.commit()
    return cur.lastrowid


def check_saved_threats(threat_url):
    exists = False
    sql = '''SELECT url FROM threats WHERE url=?'''
    conn = create_connection()
    cur = conn.cursor()
    cur.execute(sql, (threat_url,))
    result = cur.fetchone()
    if result:
        exists = True
    return exists


def save_vuln(url, title, published):
    timestamp = datetime.now()
    conn = create_connection()
    sql = ''' INSERT OR IGNORE INTO vulns(timestamp,url,title,published)
              VALUES(?,?,?,?) '''
    cur = conn.cursor()
    cur.execute(sql, (timestamp, url, title, published))
    conn.commit()
    return cur.lastrowid


def check_saved_vulns(vuln_url):
    exists = False
    sql = '''SELECT url FROM vulns WHERE url=?'''
    conn = create_connection()
    cur = conn.cursor()
    cur.execute(sql, (vuln_url,))
    result = cur.fetchone()
    if result:
        exists = True
    return exists
