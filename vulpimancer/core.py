#!/usr/bin/env python3
"""
vulpimancer/core.py  -  v1.0.0
===========================================================================
Vulpimancer Async Reconnaissance Engine  —  Authorised Security Assessments Only

Disclaimer: This tool is intended for legal and ethical security testing
purposes only. The developer is not responsible for any unauthorized or
illegal usage.

WARNING: AUTHORISED USE ONLY — Only run against systems you own or have
explicit written permission to test.  Unauthorised scanning is illegal in
most jurisdictions (CFAA, Computer Misuse Act, IT Act, etc.)

Author: Abhishek Zalavadiya

Phases
------
  0  Subdomain Enumeration  - DNS brute + crt.sh + Amass + Subfinder (threaded)
  1  DNS Resolution          - aiodns + stdlib fallback
  2  Port Scanning           - Async TCP connect with double-verify + Nmap wrapper
  4  HTTP/HTTPS Probing      - Robust HTTP engine (retry + HTTPS->HTTP fallback)
  5  TLS/SSL Analysis        - SNI retry + legacy TLS compatibility
  6  Technology Fingerprinting - 60+ signatures
  7  Sensitive Path Probe    - Baseline comparison + content analysis
  8  CVE Discovery           - NIST NVD API v2 + Nuclei integration
  9  Reporting               - SQLite + JSON + HTML + coloured terminal summary

New in v1.0.0
--------------
  MOD-1  Robust HTTP Engine    - max_retries=3, timeout=15s, HTTPS->HTTP fallback,
                                 live status/retry CLI feedback via Rich
  MOD-2  Port Scanner & Nmap   - Top-1000 port group, --nmap flag for nmap -sV -Pn
  MOD-3  TLS/SSL Handler       - SSLError -> SNI retry, --tls-legacy flag
  MOD-4  CVE Discovery (Nuclei)- subprocess nuclei, Critical+High filter, JSON parse
  MOD-5  Recon Module          - threaded amass+subfinder, merge+dedup, save .txt
"""

import argparse
import asyncio
import hashlib
import ipaddress
import json
import logging
import logging.handlers
import os
import random
import re
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import aiohttp
import aiosqlite
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

try:
    from rich.console import Console
    from rich.table import Table
    from rich import box
    HAS_RICH       = True
    _console       = Console()
    _err_console   = Console(stderr=True)
except ImportError:
    HAS_RICH       = False
    _console       = None
    _err_console   = None

try:
    import aiodns
    HAS_AIODNS = True
except ImportError:
    HAS_AIODNS = False


# ===========================================================================
# CONSTANTS
# ===========================================================================

VERSION             = "1.0.0"
DEFAULT_DB          = "vulpimancer_results.db"
DEFAULT_RPS         = 15
DEFAULT_CONCURRENCY = 80
DEFAULT_TIMEOUT     = 15        # MOD-1: 15s
DEFAULT_RETRIES     = 3         # MOD-1: 3 retries
DEFAULT_SCHEMES     = ["http", "https"]
BUCKET_MULTIPLIER   = 2

# MOD-2: Top-1000 common ports (nmap default list)
_TOP_1000_PORTS: List[int] = [
    1,3,6,7,9,13,17,19,20,21,22,23,24,25,26,30,32,37,42,43,49,53,70,79,
    80,81,82,83,84,85,88,89,90,99,100,106,109,110,111,113,119,125,135,139,
    143,144,146,161,163,179,199,211,222,254,255,256,259,264,280,301,306,311,
    340,366,389,406,407,416,417,425,427,443,444,445,458,464,465,481,497,500,
    512,513,514,515,524,541,543,544,545,548,554,555,563,587,593,616,617,625,
    631,636,646,648,666,667,668,683,687,691,700,705,711,714,720,722,726,749,
    765,777,783,787,800,801,808,843,873,880,888,898,900,901,902,903,911,912,
    981,987,990,992,993,995,999,1000,1001,1002,1007,1009,1010,1011,1021,1022,
    1023,1024,1025,1026,1027,1028,1029,1030,1031,1032,1033,1034,1035,1036,
    1037,1038,1039,1040,1042,1043,1044,1045,1046,1047,1048,1050,1051,1052,
    1053,1054,1055,1056,1057,1058,1059,1060,1061,1062,1063,1064,1065,1066,
    1067,1068,1069,1070,1071,1072,1073,1074,1075,1076,1077,1078,1079,1080,
    1081,1082,1083,1084,1085,1086,1087,1088,1089,1090,1091,1092,1093,1094,
    1095,1096,1097,1098,1099,1100,1102,1104,1105,1106,1107,1108,1110,1111,
    1112,1113,1114,1117,1119,1121,1122,1123,1124,1126,1130,1131,1132,1137,
    1138,1141,1145,1147,1148,1149,1151,1152,1154,1163,1164,1165,1166,1169,
    1174,1175,1183,1185,1186,1187,1192,1198,1199,1201,1213,1216,1217,1218,
    1233,1234,1236,1244,1247,1248,1259,1271,1272,1277,1287,1296,1300,1301,
    1309,1310,1311,1322,1328,1334,1352,1417,1433,1434,1443,1455,1461,1494,
    1500,1501,1503,1521,1524,1533,1556,1580,1583,1594,1600,1641,1658,1666,
    1687,1688,1700,1717,1718,1719,1720,1721,1723,1755,1761,1782,1783,1801,
    1805,1812,1839,1840,1862,1863,1864,1875,1900,1914,1935,1947,1971,1972,
    1974,1984,1998,1999,2000,2001,2002,2003,2004,2005,2006,2007,2008,2009,
    2010,2013,2020,2021,2022,2030,2033,2034,2035,2038,2040,2041,2042,2043,
    2045,2046,2047,2048,2049,2065,2068,2099,2100,2103,2105,2106,2107,2111,
    2119,2121,2126,2135,2144,2160,2161,2170,2179,2190,2191,2196,2200,2222,
    2251,2260,2288,2301,2323,2366,2381,2382,2383,2393,2394,2399,2401,2492,
    2500,2522,2525,2557,2601,2602,2604,2605,2607,2608,2638,2701,2702,2710,
    2717,2718,2725,2800,2809,2811,2869,2875,2909,2910,2920,2967,2968,2998,
    3000,3001,3003,3005,3006,3007,3011,3013,3017,3030,3031,3052,3071,3077,
    3128,3168,3211,3221,3260,3261,3268,3269,3283,3300,3301,3306,3322,3323,
    3324,3325,3333,3351,3367,3369,3370,3371,3372,3389,3390,3404,3476,3493,
    3517,3527,3546,3551,3580,3659,3689,3690,3703,3737,3766,3784,3800,3801,
    3809,3814,3826,3827,3828,3851,3869,3871,3878,3880,3889,3905,3914,3918,
    3920,3945,3971,3986,3995,3998,4000,4001,4002,4003,4004,4005,4006,4045,
    4111,4125,4126,4129,4224,4242,4279,4321,4343,4443,4444,4445,4446,4449,
    4550,4567,4662,4848,4899,4900,4998,5000,5001,5002,5003,5004,5009,5030,
    5033,5050,5051,5054,5060,5061,5080,5087,5100,5101,5102,5120,5190,5200,
    5214,5221,5222,5225,5226,5269,5280,5298,5357,5405,5414,5431,5432,5440,
    5500,5510,5544,5550,5555,5560,5566,5631,5633,5666,5678,5679,5718,5730,
    5800,5801,5802,5810,5811,5815,5822,5825,5850,5859,5862,5877,5900,5901,
    5902,5903,5904,5906,5907,5910,5911,5915,5922,5925,5950,5952,5959,5960,
    5961,5962,5963,5987,5988,5989,5998,5999,6000,6001,6002,6003,6004,6005,
    6006,6007,6009,6025,6059,6100,6101,6106,6112,6123,6129,6156,6346,6389,
    6502,6510,6543,6547,6565,6566,6567,6580,6646,6666,6667,6668,6669,6689,
    6692,6699,6779,6788,6789,6792,6839,6881,6901,6969,7000,7001,7002,7004,
    7007,7019,7025,7070,7100,7103,7106,7200,7201,7402,7435,7443,7496,7512,
    7625,7627,7676,7741,7777,7778,7800,7911,7920,7921,7937,7938,7999,8000,
    8001,8002,8007,8008,8009,8010,8011,8021,8022,8031,8042,8045,8080,8081,
    8082,8083,8084,8085,8086,8087,8088,8089,8090,8093,8099,8100,8180,8181,
    8192,8193,8194,8200,8222,8254,8290,8291,8292,8300,8333,8383,8400,8402,
    8443,8500,8600,8649,8651,8652,8654,8701,8800,8873,8888,8899,8994,9000,
    9001,9002,9003,9009,9010,9011,9040,9050,9071,9080,9081,9090,9091,9099,
    9100,9101,9102,9103,9110,9111,9200,9207,9220,9290,9415,9418,9485,9500,
    9502,9503,9535,9575,9593,9594,9595,9618,9666,9876,9877,9878,9898,9900,
    9917,9929,9943,9944,9968,9998,9999,10000,10001,10002,10003,10004,10009,
    10010,10012,10024,10025,10082,10180,10215,10243,10566,10616,10617,10621,
    10626,10628,10629,10778,11110,11111,11967,12000,12174,12265,12345,13456,
    13722,13782,13783,14000,14238,14441,14442,15000,15002,15003,15004,15660,
    15742,16000,16001,16012,16016,16018,16080,16113,16992,16993,17877,17988,
    18040,18101,18988,19101,19283,19315,19350,19780,19801,19842,20000,20005,
    20031,20221,20222,20828,21571,22939,23502,24444,24800,25734,25735,26214,
    27000,27352,27353,27355,27356,27715,28201,30000,30718,30951,31038,31337,
    32768,32769,32770,32771,32772,32773,32774,32775,32776,32777,32778,32779,
    32780,32781,32782,32783,32784,32785,33354,33899,34571,34572,34573,35500,
    38292,40193,40911,41511,42510,44176,44442,44443,44501,45100,48080,49152,
    49153,49154,49155,49156,49157,49158,49159,49160,49161,49163,49165,49167,
    49175,49176,49400,49999,50000,50001,50002,50003,50006,50300,50389,50500,
    50636,50800,51103,51493,52673,52822,52848,52869,54045,54328,55055,55056,
    55555,55600,56737,56738,57294,57797,58080,60020,60443,61532,61900,62078,
    63331,64623,64680,65000,65129,65389,
]

PORT_GROUPS: Dict[str, List[int]] = {
    "web":      [80, 443, 8080, 8443, 8000, 8008, 8888, 9090, 9443, 3000, 5000],
    "common":   [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
                 993, 995, 1723, 3306, 3389, 5900, 8080, 8443, 8888, 27017],
    "top1000":  _TOP_1000_PORTS,
    "extended": list(range(1, 1025)) + [3000, 3306, 3389, 5000, 5432, 5900,
                6379, 8080, 8443, 8888, 9200, 9300, 27017, 27018],
}

WEB_PORTS   = {80,443,8080,8443,8000,8008,8888,9090,9443,3000,4000,5000,
               7000,7001,8001,8002,8003,8181,8280,8800,9000,9001,9080,9200,10000}
HTTPS_PORTS = {443, 8443, 9443, 4443}

SUBDOMAIN_WORDLIST = [
    "www","www2","web","web1","web2","m","mobile",
    "mail","mail2","smtp","smtp2","imap","pop","pop3","webmail","exchange",
    "autodiscover","owa","dev","dev1","dev2","development","test","test1","test2",
    "testing","stage","staging","staging2","preprod","uat","qa","qa1","qa2",
    "sandbox","demo","preview","beta","alpha","canary","rc","hotfix","feature",
    "prod","production","live","app","app1","app2","apps","api","api2","api-v1",
    "api-v2","rest","graphql","gateway","proxy","lb","load","loadbalancer","ha",
    "cluster","node1","node2","node3","worker","worker1","worker2",
    "admin","administrator","admin2","panel","control","cpanel","whm","plesk",
    "webmin","manage","management","phpmyadmin","pma","adminer",
    "static","static2","cdn","cdn1","cdn2","media","images","img","assets",
    "files","upload","uploads","download","downloads","s3","storage","blob",
    "bucket","data","resources","res","auth","sso","login","logout","signup",
    "register","account","accounts","id","identity","oauth","oauth2","openid",
    "git","gitlab","github","bitbucket","svn","repo","code","ci","cd","jenkins",
    "build","builds","pipeline","deploy","artifact","nexus","artifactory","sonar",
    "registry","docker","harbor","k8s","kubernetes","rancher","openshift",
    "monitor","monitoring","nagios","zabbix","grafana","kibana","elastic",
    "elasticsearch","logstash","splunk","graylog","syslog","metrics","prometheus",
    "influx","influxdb","datadog","status","health","ping","uptime",
    "db","db1","db2","database","mysql","postgres","postgresql","redis","redis1",
    "mongo","mongodb","cassandra","couchdb","kafka","rabbitmq","activemq","queue",
    "broker","mq","socket","ws","wss","stream","internal","intranet","corp",
    "office","hr","finance","erp","crm","helpdesk","servicedesk","it","tools",
    "ns","ns1","ns2","ns3","dns","dns1","dns2","fw","firewall","router","switch",
    "vpn","vpn2","remote","remote2","rdp","bastion","jump","jumpserver",
    "wiki","docs","documentation","confluence","jira","trello","slack","teams",
    "lync","skype","chat","support","help","kb","knowledgebase","forum","community",
    "shop","store","ecom","checkout","cart","payment","billing","pay","invoice",
    "wordpress","wp","drupal","joomla","magento","cms","blog","news","press",
    "aws","azure","gcp","cloud","saas","vault","consul","etcd","secret","secrets",
    "analytics","tracking","stats","report","reports","dashboard",
    "ftp","sftp","ntp","time","calendar","video","audio","tv","stream","rss",
    "feed","sitemap","robots","server","host","node","box","srv","vps",
    "backup","backups","old","archive","bak","new","v2","v3","next","classic",
    "tomcat","manager","jboss","wildfly","glassfish","weblogic","sharepoint",
    "cpanel2","secure","protected","private",
    "dev-api","test-api","staging-api","prod-api",
    "dev-app","test-app","staging-app","prod-app","api-dev","api-test","api-staging",
]
_s: Set[str] = set()
_wl: List[str] = []
for _w in SUBDOMAIN_WORDLIST:
    if _w not in _s:
        _s.add(_w)
        _wl.append(_w)
SUBDOMAIN_WORDLIST = _wl

SENSITIVE_PATHS = [
    "/.env","/.env.local","/.env.production","/.env.backup","/.env.dev",
    "/.env.test","/.env.staging","/config.php","/config.yml","/config.yaml",
    "/config.json","/configuration.php","/settings.py","/settings.php",
    "/database.yml","/database.php","/db.php","/wp-config.php",
    "/wp-config.php.bak","/wp-config.php~","/config/database.yml",
    "/config/secrets.yml","/application.properties","/application.yml",
    "/.aws/credentials","/.ssh/id_rsa","/.ssh/authorized_keys",
    "/.git/config","/.git/HEAD","/.git/COMMIT_EDITMSG",
    "/admin","/admin/","/admin/login","/administrator","/wp-admin",
    "/wp-login.php","/phpmyadmin","/pma","/adminer","/cpanel","/webmin",
    "/plesk","/manager/html","/console","/dashboard","/panel",
    "/actuator","/actuator/health","/actuator/env","/actuator/mappings",
    "/actuator/beans","/actuator/loggers","/actuator/threaddump",
    "/actuator/heapdump","/metrics","/health","/info","/status","/ping",
    "/_cat/indices","/_cluster/health","/_nodes",
    "/api","/api/v1","/api/v2","/graphql","/swagger-ui.html","/swagger.json",
    "/openapi.json","/api-docs","/v1/api-docs","/swagger-ui/index.html",
    "/robots.txt","/sitemap.xml","/crossdomain.xml","/.htaccess","/.htpasswd",
    "/web.config","/server-status","/server-info","/phpinfo.php","/info.php",
    "/test.php","/debug.php","/README.md","/README.txt","/CHANGELOG.md",
    "/backup.zip","/backup.tar.gz","/backup.sql","/dump.sql","/db.sql",
    "/database.sql","/logs/error.log","/log/error.log","/error.log",
    "/latest/meta-data/","/computeMetadata/v1/","/metadata/instance",
]
_MIN_BODY_BYTES = 80
_SENSITIVE_BODY_KEYWORDS = [
    "password","passwd","secret","api_key","apikey","DB_","DATABASE_URL",
    "AWS_","PRIVATE_KEY","token","credential","private","[database]",
    "Host:","User:","root:","admin:","Index of /",
]
_TAKEOVER_CNAME_PATTERNS = [
    r"\.github\.io$",r"\.s3\.amazonaws\.com$",r"\.blob\.core\.windows\.net$",
    r"\.azurewebsites\.net$",r"\.cloudapp\.azure\.com$",r"\.herokudns\.com$",
    r"\.herokussl\.com$",r"\.fastly\.net$",r"\.netlify\.app$",r"\.surge\.sh$",
    r"\.pantheonsite\.io$",r"\.unbounce\.com$",r"\.wpengine\.com$",
    r"\.myshopify\.com$",r"\.zendesk\.com$",r"\.readme\.io$",r"\.ghost\.io$",
    r"\.bigcartel\.com$",r"\.cargo\.site$",r"\.tilda\.ws$",
]
_MULTI_LABEL_SUFFIXES: Set[str] = {
    "ac.in","edu.in","ac.uk","edu.au","ac.nz","edu.sg","ac.za","ac.jp","ac.kr",
    "edu.cn","edu.hk","edu.my","edu.pk","gov.in","gov.uk","gov.au","gov.nz",
    "gov.sg","gov.za","gov.br","gov.ar","gob.mx","gov.cn","go.jp","go.kr",
    "co.in","co.uk","co.nz","co.jp","co.kr","co.za","com.au","com.br","com.cn",
    "com.hk","com.mx","com.sg","net.in","net.au","net.br","org.in","org.au",
    "org.uk","net.uk","org.nz","net.nz","mil.in","nic.in","res.in","ernet.in",
    "ac.ae","gov.ae","edu.ae","co.ae",
}
TECH_SIGNATURES = [
    ("Apache",         r"Apache(?:/([\d.]+))?",          "server"),
    ("Nginx",          r"nginx(?:/([\d.]+))?",           "server"),
    ("IIS",            r"Microsoft-IIS(?:/([\d.]+))?",   "server"),
    ("Tomcat",         r"Apache-Coyote(?:/([\d.]+))?",   "server"),
    ("LiteSpeed",      r"LiteSpeed",                      "server"),
    ("Caddy",          r"Caddy",                          "server"),
    ("OpenResty",      r"openresty(?:/([\d.]+))?",        "server"),
    ("Gunicorn",       r"gunicorn(?:/([\d.]+))?",         "server"),
    ("Jetty",          r"Jetty(?:\(([\d.]+)\))?",         "server"),
    ("Werkzeug",       r"Werkzeug(?:/([\d.]+))?",         "server"),
    ("PHP",            r"PHP(?:/([\d.]+))?",              "x-powered-by"),
    ("ASP.NET",        r"ASP\.NET",                       "x-powered-by"),
    ("Express",        r"Express",                        "x-powered-by"),
    ("Django",         r"Django",                         "x-powered-by"),
    ("Laravel",        r"Laravel",                        "x-powered-by"),
    ("WordPress",      r"WordPress(?:/([\d.]+))?",        "body"),
    ("Drupal",         r"Drupal (\d+)",                   "body"),
    ("Joomla",         r"Joomla! ([\d.]+)",               "body"),
    ("Magento",        r"Magento(?:/([\d.]+))?",          "body"),
    ("Cloudflare",     r"cloudflare",                     "server"),
    ("Cloudflare",     r"__cfduid|cf-ray",                "set-cookie"),
    ("Fastly",         r"Fastly",                         "server"),
    ("Akamai",         r"AkamaiGHost",                    "server"),
    ("AWS CloudFront", r"CloudFront",                     "server"),
    ("Sucuri",         r"Sucuri",                         "server"),
    ("Imperva",        r"X-Iinfo",                        "header:x-iinfo"),
    ("F5 BIG-IP",      r"BigIP|BIG-IP",                   "server"),
    ("ModSecurity",    r"Mod_Security|NOYB",              "server"),
    ("Spring Boot",    r"Whitelabel Error Page|Spring",   "body"),
    ("Ruby on Rails",  r"X-Runtime",                      "header:x-runtime"),
    ("Next.js",        r"x-nextjs-cache|__NEXT_DATA__",   "body"),
    ("React",          r"react-root|__react",             "body"),
    ("Vue.js",         r"__vue__",                        "body"),
    ("Angular",        r"ng-version",                     "body"),
]


# ===========================================================================
# CLI OUTPUT  — Rich first, ANSI fallback
# ===========================================================================

_USE_COLOR = sys.stdout.isatty() or bool(os.environ.get("FORCE_COLOR", ""))


class C:
    RESET   = "\033[0m"   if _USE_COLOR else ""
    BOLD    = "\033[1m"   if _USE_COLOR else ""
    DIM     = "\033[2m"   if _USE_COLOR else ""
    RED     = "\033[91m"  if _USE_COLOR else ""
    GREEN   = "\033[92m"  if _USE_COLOR else ""
    YELLOW  = "\033[93m"  if _USE_COLOR else ""
    BLUE    = "\033[94m"  if _USE_COLOR else ""
    MAGENTA = "\033[95m"  if _USE_COLOR else ""
    CYAN    = "\033[96m"  if _USE_COLOR else ""
    WHITE   = "\033[97m"  if _USE_COLOR else ""
    GRAY    = "\033[90m"  if _USE_COLOR else ""


def _c(text: str, *codes: str) -> str:
    if not codes:
        return str(text)
    return "".join(codes) + str(text) + C.RESET


def _banner():
    logo = r"""
 ██╗   ██╗██╗   ██╗██╗     ██████╗ ██╗███╗   ███╗ █████╗ ███╗   ██╗ ██████╗███████╗██████╗
 ██║   ██║██║   ██║██║     ██╔══██╗██║████╗ ████║██╔══██╗████╗  ██║██╔════╝██╔════╝██╔══██╗
 ██║   ██║██║   ██║██║     ██████╔╝██║██╔████╔██║███████║██╔██╗ ██║██║     █████╗  ██████╔╝
 ╚██╗ ██╔╝██║   ██║██║     ██╔═══╝ ██║██║╚██╔╝██║██╔══██║██║╚██╗██║██║     ██╔══╝  ██╔══██╗
  ╚████╔╝ ╚██████╔╝███████╗██║     ██║██║ ╚═╝ ██║██║  ██║██║ ╚████║╚██████╗███████╗██║  ██║
   ╚═══╝   ╚═════╝ ╚══════╝╚═╝     ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝╚══════╝╚═╝  ╚═╝"""
    disclaimer = (
        "  Disclaimer: This tool is intended for legal and ethical security testing\n"
        "  purposes only. The developer is not responsible for any unauthorized or\n"
        "  illegal usage.\n"
    )
    if HAS_RICH and _console:
        _console.print(logo, style="bold cyan")
        _console.print(
            f"  Async Recon Engine  v{VERSION}  ·  Authorised use only",
            style="dim")
        _console.print(
            f"  Author: Abhishek Zalavadiya\n",
            style="dim")
        _console.print(disclaimer, style="bold yellow")
    else:
        print(_c(logo, C.CYAN, C.BOLD))
        print(_c(f"  Async Recon Engine  v{VERSION}  ·  Authorised use only", C.GRAY))
        print(_c(f"  Author: Abhishek Zalavadiya\n", C.GRAY))
        print(_c(disclaimer, C.YELLOW))


def _section(title: str):
    if HAS_RICH and _console:
        _console.rule(f"[bold white]{title}[/bold white]", style="blue")
    else:
        bar = "─" * 70
        print(f"\n{_c(bar, C.BLUE)}")
        print(f"{_c('  ' + title, C.BOLD, C.WHITE)}")
        print(f"{_c(bar, C.BLUE)}")


def _ok(msg: str):
    if HAS_RICH and _console:
        _console.print(f"  [bold green]✔[/bold green]  {msg}", highlight=False)
    else:
        print(f"  {_c('✔', C.GREEN, C.BOLD)}  {msg}")


def _warn(msg: str):
    if HAS_RICH and _console:
        _console.print(f"  [bold yellow]⚠[/bold yellow]  {msg}", highlight=False)
    else:
        print(f"  {_c('⚠', C.YELLOW, C.BOLD)}  {msg}")


def _err(msg: str):
    if HAS_RICH and _err_console:
        _err_console.print(f"  [bold red]✘[/bold red]  {msg}", highlight=False)
    else:
        print(f"  {_c('✘', C.RED, C.BOLD)}  {msg}", file=sys.stderr)


def _info(msg: str):
    if HAS_RICH and _console:
        _console.print(f"  [dim]·[/dim]  {msg}", highlight=False)
    else:
        print(f"  {_c('·', C.GRAY)}  {msg}")


def _find(msg: str):
    if HAS_RICH and _console:
        _console.print(f"  [bold red]🔥[/bold red]  {msg}", highlight=False)
    else:
        print(f"  {_c('🔥', C.RED, C.BOLD)}  {msg}")


def _http_status_feedback(
    url: str, attempt: int, status_code: Optional[int],
    max_retries: int = DEFAULT_RETRIES,
    error: Optional[str] = None,
) -> None:
    """MOD-1: Live HTTP status / retry CLI feedback — always shown."""
    # Show attempt prefix only on retries (attempt > 1) or errors, to reduce noise
    show_attempt = attempt > 1 or error is not None
    attempt_prefix = f"[attempt {attempt}/{max_retries}] " if show_attempt else ""
    if status_code is not None:
        col = (C.GREEN  if 200 <= status_code < 300 else
               C.CYAN   if 300 <= status_code < 400 else
               C.YELLOW if 400 <= status_code < 500 else C.RED)
        _info(
            f"{attempt_prefix}"
            f"{_c(str(status_code), col, C.BOLD)}  "
            f"{_c(url, C.CYAN)}"
        )
    elif error:
        _info(
            f"{attempt_prefix}"
            f"{_c('ERR', C.RED, C.BOLD)}  "
            f"{_c(url, C.GRAY)}  "
            f"{_c(error[:60], C.YELLOW)}"
        )


def _progress(current: int, total: int, label: str = ""):
    if not _USE_COLOR:
        return
    width  = 30
    filled = int(width * current / max(total, 1))
    bar    = "█" * filled + "░" * (width - filled)
    pct    = int(100 * current / max(total, 1))
    print(
        f"\r  [{_c(bar, C.CYAN)}] {_c(f'{pct:3d}%', C.BOLD)} {_c(label, C.GRAY):<48}",
        end="", flush=True,
    )
    if current >= total:
        print()


def _table(
    headers: List[str],
    rows: List[List[str]],
    col_colors: Optional[List[Optional[str]]] = None,
):
    if not rows:
        _info(_c("(none)", C.GRAY))
        return

    if HAS_RICH and _console:
        try:
            from rich.table import Table as _RichTable
            from rich import box as _box
            tbl = _RichTable(
                box=_box.SIMPLE_HEAD, show_header=True,
                header_style="bold cyan", border_style="blue", expand=False)
            for h in headers:
                tbl.add_column(h, overflow="fold")
            for row in rows:
                padded = (list(row) + [""] * len(headers))[:len(headers)]
                tbl.add_row(*[re.sub(r"\033\[[0-9;]*m", "", str(c)) for c in padded])
            _console.print(tbl)
            return
        except Exception:
            pass

    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            if i < len(widths):
                plain = re.sub(r"\033\[[0-9;]*m", "", str(cell))
                widths[i] = max(widths[i], len(plain))

    def _sep(left, mid, right, fill):
        return "  " + left + mid.join(fill * (w + 2) for w in widths) + right

    def _row_render(cells, is_header=False):
        parts = []
        for i, (cell, w) in enumerate(zip(cells, widths)):
            plain = re.sub(r"\033\[[0-9;]*m", "", str(cell))
            pad   = w - len(plain)
            s     = str(cell) + " " * pad
            if is_header:
                s = _c(s, C.BOLD, C.CYAN)
            elif col_colors and i < len(col_colors) and col_colors[i]:
                s = _c(str(cell) + " " * pad, col_colors[i])
            parts.append(f" {s} ")
        return "  |" + "|".join(parts) + "|"

    print(_c(_sep("┌", "┬", "┐", "─"), C.GRAY))
    print(_c(_row_render(headers, is_header=True), C.GRAY))
    print(_c(_sep("├", "┼", "┤", "─"), C.GRAY))
    for row in rows:
        padded = (list(row) + [""] * len(headers))[:len(headers)]
        print(_c(_row_render(padded), C.GRAY))
    print(_c(_sep("└", "┴", "┘", "─"), C.GRAY))


def _severity_color(sev: str) -> str:
    s = (sev or "").upper()
    if s == "CRITICAL": return C.RED + C.BOLD
    if s == "HIGH":     return C.RED
    if s == "MEDIUM":   return C.YELLOW
    if s == "LOW":      return C.GREEN
    return C.GRAY


def _status_color(code: Optional[int]) -> str:
    if code is None:       return C.GRAY
    if 200 <= code < 300:  return C.GREEN
    if 300 <= code < 400:  return C.CYAN
    if 400 <= code < 500:  return C.YELLOW
    if 500 <= code < 600:  return C.RED
    return C.GRAY


def _status_label(code: Optional[int]) -> str:
    if code is None:       return "UNKNOWN"
    if code == 200:        return "LIVE"
    if 201 <= code < 300:  return "OK"
    if 300 <= code < 400:  return "REDIRECT"
    if code == 401:        return "AUTH"
    if code == 403:        return "PROTECTED"
    if code == 404:        return "NOT FOUND"
    if 400 <= code < 500:  return "CLIENT ERR"
    if 500 <= code < 600:  return "SERVER ERR"
    return str(code)


# ===========================================================================
# LOGGING  — silent rotating JSON log, never crash the CLI
# ===========================================================================

class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: Dict = {
            "ts":    datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "msg":   record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        skip = set(logging.LogRecord.__dict__) | {
            "msg","args","levelname","levelno","pathname","filename",
            "module","exc_info","exc_text","stack_info","lineno",
            "funcName","created","msecs","relativeCreated","thread",
            "threadName","processName","process","name","message",
        }
        payload.update({k: v for k, v in record.__dict__.items()
                        if k not in skip and not k.startswith("_")})
        return json.dumps(payload, default=str)


def build_logger(name: str, log_file: Optional[str] = None,
                 level: int = logging.WARNING) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(level)
    if log_file:
        fh = logging.handlers.RotatingFileHandler(
            log_file, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8")
        fh.setFormatter(_JsonFormatter())
        logger.addHandler(fh)
    logger.propagate = False
    return logger


log = build_logger("netra")


# ===========================================================================
# DATA CLASSES
# ===========================================================================

@dataclass
class HostEntry:
    raw: str
    hostname: str = ""
    port: Optional[int] = None
    resolved_ips: List[str] = field(default_factory=list)
    cname: Optional[str] = None
    resolve_error: Optional[str] = None
    is_subdomain: bool = False
    source: str = "input"
    takeover_hint: Optional[str] = None

    def __post_init__(self):
        raw = self.raw.strip()
        if raw.startswith("["):
            bracket_end = raw.find("]")
            if bracket_end != -1:
                self.hostname = raw[1:bracket_end]
                rem = raw[bracket_end + 1:]
                if rem.startswith(":"):
                    try:
                        self.port = int(rem[1:])
                    except ValueError:
                        pass
            else:
                self.hostname = raw
            return
        if ":" in raw:
            parts = raw.rsplit(":", 1)
            try:
                candidate = int(parts[1])
                if 1 <= candidate <= 65535 and ":" not in parts[0]:
                    self.hostname = parts[0]
                    self.port     = candidate
                else:
                    self.hostname = raw
            except ValueError:
                self.hostname = raw
        else:
            self.hostname = raw


@dataclass
class PortResult:
    host: str
    ip: str
    port: int
    is_open: bool
    banner: Optional[str] = None
    service_guess: Optional[str] = None
    nmap_service: Optional[str] = None   # MOD-2
    nmap_version: Optional[str] = None   # MOD-2
    scanned_at: str = field(
        default_factory=lambda: datetime.now(tz=timezone.utc).isoformat())


@dataclass
class TLSInfo:
    host: str
    port: int
    subject_cn: Optional[str]
    issuer: Optional[str]
    san_domains: List[str]
    not_before: Optional[str]
    not_after: Optional[str]
    is_expired: bool
    days_to_expiry: Optional[int]
    cipher_suite: Optional[str]
    tls_version: Optional[str]
    self_signed: bool
    error: Optional[str] = None
    sni_retry: bool = False              # MOD-3


@dataclass
class SensitiveFinding:
    path: str
    status: int
    body_size: int
    confidence: str
    reason: str


@dataclass
class ProbeResult:
    host: str
    scheme: str
    port: Optional[int]
    url: str
    resolved_ip: Optional[str]
    attempt: int
    status_code: Optional[int]
    response_length: Optional[int]
    title: Optional[str]
    server_header: Optional[str]
    content_type: Optional[str]
    response_time_ms: Optional[float]
    redirect_url: Optional[str]
    technologies: List[str]
    sensitive_paths_found: List[SensitiveFinding]
    error: Optional[str]
    fallback_http: bool = False          # MOD-1
    probed_at: str = field(
        default_factory=lambda: datetime.now(tz=timezone.utc).isoformat())


@dataclass
class CVEFinding:
    product: str
    version: str
    cve_id: str
    cvss_score: Optional[float]
    severity: str
    description: str
    published: str


@dataclass
class NucleiResult:                      # MOD-4
    template_id: str
    name: str
    severity: str
    host: str
    matched_at: str
    description: str
    tags: List[str] = field(default_factory=list)


# ===========================================================================
# TOKEN BUCKET
# ===========================================================================

class TokenBucket:
    def __init__(self, rate: float, capacity: float):
        self._rate     = rate
        self._capacity = capacity
        self._tokens   = capacity
        self._last     = time.monotonic()
        self._lock     = asyncio.Lock()

    async def acquire(self, tokens: float = 1.0) -> None:
        while True:
            async with self._lock:
                now = time.monotonic()
                self._tokens = min(
                    self._capacity,
                    self._tokens + (now - self._last) * self._rate)
                self._last = now
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return
                wait = (tokens - self._tokens) / self._rate
            await asyncio.sleep(wait)


# ===========================================================================
# MOD-1: ROBUST HTTP ENGINE
# ===========================================================================

def _build_requests_session(max_retries: int = 3,
                              timeout: int = 15) -> requests.Session:
    """
    MOD-1: Shared requests.Session with HTTPAdapter retry policy.
    max_retries=3, timeout=15s, backoff, status force-list.
    SSL warnings suppressed for VAPT context.
    """
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    sess  = requests.Session()
    retry = Retry(
        total=max_retries,
        backoff_factor=1.5,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "HEAD"],
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    sess.mount("http://",  adapter)
    sess.mount("https://", adapter)
    sess.headers.update({
        "User-Agent": f"Vulpimancer/{VERSION} (authorised-assessment)",
        "Accept":     "*/*",
    })
    sess.verify = False
    return sess


def robust_get(
    url: str,
    max_retries: int = DEFAULT_RETRIES,
    timeout: int = DEFAULT_TIMEOUT,
    fallback_http: bool = True,
    verbose: bool = True,
) -> Tuple[Optional[requests.Response], bool]:
    """
    MOD-1 Core: Resilient synchronous GET.
    - max_retries=3, timeout=15s (configurable).
    - On SSLError: auto-fallback to HTTP and log/warn.
    - Live CLI feedback: attempt #, status code, errors.
    Returns (response | None, did_http_fallback).
    """
    sess         = _build_requests_session(max_retries=0, timeout=timeout)
    did_fallback = False

    for attempt in range(1, max_retries + 1):
        try:
            if verbose and attempt > 1:
                _info(f"[attempt {attempt}/{max_retries}] GET {_c(url, C.CYAN)}")
            resp = sess.get(url, timeout=timeout, allow_redirects=True)
            if verbose:
                _http_status_feedback(url, attempt, resp.status_code, max_retries)
            return resp, did_fallback

        except requests.exceptions.SSLError as ssl_exc:
            log.warning("SSLError on GET", extra={"url": url, "attempt": attempt,
                                                   "err": str(ssl_exc)})
            # MOD-1: HTTPS → HTTP protocol fallback
            if fallback_http and url.startswith("https://"):
                http_url = "http://" + url[len("https://"):]
                _warn(
                    f"[attempt {attempt}] SSL error — falling back to "
                    f"{_c('HTTP', C.YELLOW)}: {_c(http_url, C.YELLOW)}"
                )
                try:
                    resp = sess.get(http_url, timeout=timeout, allow_redirects=True)
                    if verbose:
                        _http_status_feedback(http_url, attempt, resp.status_code,
                                              max_retries)
                    return resp, True
                except Exception as inner_exc:
                    log.warning("HTTP fallback failed",
                                extra={"url": http_url, "err": str(inner_exc)})
                    if verbose:
                        _http_status_feedback(http_url, attempt, None, max_retries,
                                              error=str(inner_exc)[:60])
            else:
                if verbose:
                    _http_status_feedback(url, attempt, None, max_retries,
                                          error="SSLError")

        except requests.exceptions.ConnectionError as exc:
            log.warning("ConnectionError", extra={"url": url, "attempt": attempt,
                                                   "err": str(exc)})
            if verbose:
                _http_status_feedback(url, attempt, None, max_retries,
                                      error=str(exc)[:60])

        except requests.exceptions.Timeout:
            log.warning("Timeout", extra={"url": url, "attempt": attempt,
                                           "timeout": timeout})
            if verbose:
                _http_status_feedback(url, attempt, None, max_retries,
                                      error=f"Timeout after {timeout}s")

        except Exception as exc:
            log.error("Unexpected GET error", extra={"url": url, "attempt": attempt,
                                                      "err": str(exc)})
            if verbose:
                _http_status_feedback(url, attempt, None, max_retries,
                                      error=str(exc)[:60])

        if attempt < max_retries:
            wait = min(2 ** attempt + random.uniform(0, 1), 10)
            _info(f"  Retrying in {wait:.1f}s ...")
            time.sleep(wait)

    return None, did_fallback


# ===========================================================================
# MOD-2: NMAP WRAPPER
# ===========================================================================

def _nmap_available() -> bool:
    return shutil.which("nmap") is not None


def run_nmap(
    target: str,
    ports: Optional[List[int]] = None,
    extra_args: Optional[List[str]] = None,
) -> List[Dict]:
    """
    MOD-2: Execute `nmap -sV -Pn --open` on target.
    Parses XML output via regex into a structured list of dicts.
    Top-1000 ports used by default (matching nmap's own default).
    Results are shown in the Vulpimancer Rich/ANSI table.
    Errors are logged silently — never crash the CLI.
    """
    if not _nmap_available():
        log.warning("nmap not found in PATH")
        _warn("nmap not found — install nmap for enhanced version scanning")
        return []

    _section("NMAP SCAN  (nmap -sV -Pn --open)")
    _info(f"Running nmap against {_c(target, C.CYAN)} ...")

    cmd = ["nmap", "-sV", "-Pn", "--open", "-oX", "-"]
    if ports:
        cmd += ["-p", ",".join(str(p) for p in ports[:300])]
    else:
        cmd += ["--top-ports", "1000"]      # MOD-2: default top-1000
    if extra_args:
        cmd += extra_args
    cmd.append(target)

    results: List[Dict] = []
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        xml  = proc.stdout
        if not xml.strip():
            _warn("nmap returned empty output")
            return []

        # Parse XML with regex (avoids lxml/xml dependency)
        for proto, portid, pblock in re.findall(
                r'<port\s+protocol="(\w+)"\s+portid="(\d+)">(.*?)</port>',
                xml, re.DOTALL):
            state_m = re.search(r'<state\s+state="(\w+)"', pblock)
            svc_m   = re.search(
                r'<service\s+name="([^"]*)"(?:[^>]*product="([^"]*)")?'
                r'(?:[^>]*version="([^"]*)")?(?:[^>]*extrainfo="([^"]*)")?',
                pblock)
            cpe_m   = re.search(r'<cpe>([^<]+)</cpe>', pblock)
            state   = state_m.group(1) if state_m else "unknown"
            svc     = svc_m.group(1)   if svc_m  else ""
            ver     = " ".join(filter(None, [
                svc_m.group(2) if svc_m and svc_m.group(2) else "",
                svc_m.group(3) if svc_m and svc_m.group(3) else "",
                svc_m.group(4) if svc_m and svc_m.group(4) else "",
            ])).strip()
            results.append({
                "port":     int(portid),
                "protocol": proto,
                "state":    state,
                "service":  svc,
                "version":  ver,
                "cpe":      cpe_m.group(1) if cpe_m else "",
            })

        if results:
            rows = []
            for r in results:
                col = C.GREEN if r["state"] == "open" else C.GRAY
                rows.append([
                    _c(str(r["port"]), col, C.BOLD), r["protocol"],
                    _c(r["state"], col),              r["service"] or "-",
                    (r["version"] or "-")[:50],       (r["cpe"] or "-")[:35],
                ])
            _table(["Port", "Proto", "State", "Service", "Version", "CPE"], rows,
                   col_colors=[C.YELLOW, C.GRAY, None, C.GREEN, C.WHITE, C.CYAN])
            _ok(f"nmap: {_c(str(len(results)), C.YELLOW, C.BOLD)} port(s) parsed")
        else:
            _info("nmap: no open ports detected")

    except subprocess.TimeoutExpired:
        log.error("nmap timed out", extra={"target": target})
        _warn("nmap timed out after 300s")
    except FileNotFoundError:
        log.error("nmap binary not found")
    except Exception as exc:
        log.error("nmap error", extra={"err": str(exc)})
        _warn(f"nmap error (logged): {str(exc)[:80]}")

    return results


# ===========================================================================
# MOD-3: TLS/SSL HANDLER  (SSLError -> SNI retry, legacy TLS compat)
# ===========================================================================

def _parse_cert_dt(val) -> Optional[str]:
    try:
        if isinstance(val, str):
            return val
        return datetime(*val[:6], tzinfo=timezone.utc).isoformat()
    except Exception:
        return str(val)


def _tls_connect_sync(
    host: str, port: int, timeout: float,
    ctx: ssl.SSLContext, use_sni: bool,
) -> Tuple:
    """Blocking TLS connect — runs in executor."""
    sni = host if use_sni else None
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=sni) as ssock:
            return ssock.getpeercert(), ssock.cipher(), ssock.version()


async def analyse_tls(
    host: str,
    port: int,
    timeout: float = DEFAULT_TIMEOUT,
    legacy_tls: bool = False,
) -> TLSInfo:
    """
    MOD-3: TLS/SSL Analysis with SNI retry and legacy TLS compatibility.
    1st attempt: standard context with SNI enabled.
    On SSLError: log warning and retry with explicit SNI (server_hostname).
    --tls-legacy: lowers minimum TLS version to TLS 1.0 for older servers.
    All errors are logged silently — never raises to caller.
    """
    loop      = asyncio.get_event_loop()
    sni_used  = False
    cert = cipher = tls_ver = None
    error_msg: Optional[str] = None

    def _build_ctx() -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_OPTIONAL
        if legacy_tls:
            # MOD-3: allow TLS 1.0/1.1 for compatibility
            try:
                ctx.minimum_version = ssl.TLSVersion.TLSv1
            except AttributeError:
                ctx.options &= ~ssl.OP_NO_TLSv1
                ctx.options &= ~ssl.OP_NO_TLSv1_1
        return ctx

    async def _attempt(use_sni: bool):
        return await asyncio.wait_for(
            loop.run_in_executor(
                None,
                lambda: _tls_connect_sync(host, port, timeout, _build_ctx(), use_sni)),
            timeout=timeout + 2)

    try:
        cert, cipher, tls_ver = await _attempt(use_sni=True)
    except ssl.SSLError as ssl_exc:
        # MOD-3: SSLError → retry with explicit SNI disabled (server may not support SNI)
        log.warning("SSLError — retrying with explicit SNI",
                    extra={"host": host, "port": port, "err": str(ssl_exc)})
        _warn(f"SSL handshake failed for {_c(host, C.CYAN)}:{port} — "
              f"retrying with {_c('SNI', C.YELLOW)} ...")
        try:
            cert, cipher, tls_ver = await _attempt(use_sni=False)
            sni_used = True
            _ok(f"SNI retry succeeded for {_c(host, C.GREEN)}:{port}")
        except Exception as exc2:
            error_msg = f"SSLError (SNI retry failed): {exc2}"
            log.warning("SNI retry also failed",
                        extra={"host": host, "port": port, "err": str(exc2)})
    except Exception as exc:
        error_msg = f"TLS error: {exc}"
        log.warning("TLS error", extra={"host": host, "port": port, "err": str(exc)})

    if error_msg or cert is None:
        return TLSInfo(
            host=host, port=port,
            subject_cn=None, issuer=None, san_domains=[],
            not_before=None, not_after=None,
            is_expired=False, days_to_expiry=None,
            cipher_suite=None, tls_version=None,
            self_signed=False,
            error=error_msg or "No certificate returned",
            sni_retry=sni_used)

    subject    = dict(x[0] for x in cert.get("subject", []))
    issuer_d   = dict(x[0] for x in cert.get("issuer",  []))
    cn         = subject.get("commonName")
    iss        = issuer_d.get("organizationName") or issuer_d.get("commonName")
    sans       = [v for _t, v in cert.get("subjectAltName", []) if _t == "DNS"]
    not_before = _parse_cert_dt(cert.get("notBefore"))
    not_after  = _parse_cert_dt(cert.get("notAfter"))
    days_left  = None
    is_expired = False
    try:
        na_dt      = datetime.strptime(
            cert.get("notAfter", ""), "%b %d %H:%M:%S %Y %Z"
        ).replace(tzinfo=timezone.utc)
        days_left  = (na_dt - datetime.now(tz=timezone.utc)).days
        is_expired = days_left < 0
    except Exception:
        pass

    return TLSInfo(
        host=host, port=port,
        subject_cn=cn, issuer=iss, san_domains=sans,
        not_before=not_before, not_after=not_after,
        is_expired=is_expired, days_to_expiry=days_left,
        cipher_suite=cipher[0] if cipher else None,
        tls_version=tls_ver,
        self_signed=(subject == issuer_d),
        sni_retry=sni_used)


# ===========================================================================
# MOD-4: CVE DISCOVERY — NUCLEI INTEGRATION
# ===========================================================================

def _nuclei_available() -> bool:
    return shutil.which("nuclei") is not None


def run_nuclei(
    target: str,
    severity_filter: Optional[List[str]] = None,
    templates_path: Optional[str] = None,
    timeout: int = 120,
) -> List[NucleiResult]:
    """
    MOD-4: Run Nuclei via subprocess.
    - Severity filter: Critical + High only (default).
    - Parses JSONL output line by line.
    - Filters again after parsing (defence in depth).
    - All errors silently logged — CLI never crashes.
    Returns list of NucleiResult for display.
    """
    if not _nuclei_available():
        log.warning("nuclei not found in PATH")
        _warn(
            "nuclei not installed — install with:\n"
            "  go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        )
        return []

    if severity_filter is None:
        severity_filter = ["critical", "high"]

    _section("CVE DISCOVERY  (Nuclei — Critical + High only)")
    _info(f"Running nuclei against {_c(target, C.CYAN)} "
          f"[severity: {_c(', '.join(severity_filter).upper(), C.RED)}] ...")

    tmp_out  = tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False, mode="w")
    out_path = tmp_out.name
    tmp_out.close()

    cmd = [
        "nuclei", "-u", target,
        "-jsonl", "-o", out_path,
        "-silent",
        "-severity", ",".join(severity_filter),
        "-timeout", str(max(timeout // 10, 5)),
    ]
    if templates_path:
        cmd += ["-t", templates_path]

    results: List[NucleiResult] = []
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if proc.returncode not in (0, 1):
            log.warning("nuclei exited with unexpected code",
                        extra={"rc": proc.returncode, "stderr": proc.stderr[:200]})

        # MOD-4: parse JSONL and apply Critical/High filter
        try:
            with open(out_path, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    sev = (obj.get("info", {}).get("severity", "") or "").lower()
                    # Double-filter: CLI flag + post-parse check
                    if sev not in [s.lower() for s in severity_filter]:
                        continue
                    results.append(NucleiResult(
                        template_id = obj.get("template-id", "unknown"),
                        name        = obj.get("info", {}).get("name", "unknown"),
                        severity    = sev.upper(),
                        host        = obj.get("host", target),
                        matched_at  = obj.get("matched-at", ""),
                        description = (obj.get("info", {}).get("description") or "")[:200],
                        tags        = obj.get("info", {}).get("tags", []),
                    ))
        except FileNotFoundError:
            log.warning("nuclei output file missing", extra={"path": out_path})

        if results:
            rows = []
            for nr in sorted(results, key=lambda x: 0 if x.severity == "CRITICAL" else 1):
                col = C.RED + C.BOLD if nr.severity == "CRITICAL" else C.RED
                rows.append([
                    _c(nr.severity, col),
                    nr.template_id[:40],
                    nr.name[:40],
                    _c(nr.host, C.CYAN),
                    nr.matched_at[:50],
                    (nr.description or "-")[:50],
                ])
            _table(
                ["Severity", "Template", "Name", "Host", "Matched At", "Description"],
                rows)
            _find(f"Nuclei: {_c(str(len(results)), C.RED, C.BOLD)} "
                  f"Critical/High finding(s) — verify manually")
        else:
            _ok("Nuclei: no Critical/High findings")

    except subprocess.TimeoutExpired:
        log.error("nuclei timeout", extra={"target": target, "timeout": timeout})
        _warn(f"Nuclei timed out after {timeout}s")
    except FileNotFoundError:
        log.error("nuclei binary missing")
    except Exception as exc:
        log.error("nuclei error", extra={"err": str(exc)})
        _warn(f"Nuclei error (logged): {str(exc)[:80]}")
    finally:
        try:
            Path(out_path).unlink(missing_ok=True)
        except Exception:
            pass

    return results


# ===========================================================================
# MOD-5: RECON MODULE — Amass + Subfinder (parallel threads)
# ===========================================================================

def _subfinder_available() -> bool:
    return shutil.which("subfinder") is not None


def _amass_available() -> bool:
    return shutil.which("amass") is not None


def _run_subfinder(domain: str, timeout: int = 60) -> Set[str]:
    """Run subfinder passively and return a set of discovered subdomains."""
    found: Set[str] = set()
    if not _subfinder_available():
        log.warning("subfinder not in PATH")
        return found
    try:
        proc = subprocess.run(
            ["subfinder", "-d", domain, "-silent", "-all"],
            capture_output=True, text=True, timeout=timeout)
        for line in proc.stdout.splitlines():
            sub = line.strip().lower()
            if sub and "." in sub:
                found.add(sub)
    except subprocess.TimeoutExpired:
        log.warning("subfinder timed out", extra={"domain": domain, "timeout": timeout})
    except Exception as exc:
        log.error("subfinder error", extra={"domain": domain, "err": str(exc)})
    return found


def _run_amass(domain: str, timeout: int = 90) -> Set[str]:
    """Run amass passive enumeration and return a set of discovered subdomains."""
    found: Set[str] = set()
    if not _amass_available():
        log.warning("amass not in PATH")
        return found
    try:
        proc = subprocess.run(
            ["amass", "enum", "-passive", "-d", domain, "-nocolor"],
            capture_output=True, text=True, timeout=timeout)
        for line in proc.stdout.splitlines():
            sub = line.strip().lower()
            # Skip amass status/banner lines (start with "[")
            if sub and "." in sub and not sub.startswith("["):
                found.add(sub)
    except subprocess.TimeoutExpired:
        log.warning("amass timed out", extra={"domain": domain, "timeout": timeout})
    except Exception as exc:
        log.error("amass error", extra={"domain": domain, "err": str(exc)})
    return found


def _merge_dedup_subdomains(a: Set[str], b: Set[str]) -> List[str]:
    """
    MOD-5: Merge both tool outputs, remove duplicates using dict.fromkeys
    (preserves order), sort alphabetically, return clean list.
    """
    merged = sorted(a | b)
    return list(dict.fromkeys(merged))


def threaded_recon(
    domain: str,
    output_file: Optional[str] = None,
    subfinder_timeout: int = 60,
    amass_timeout: int = 90,
) -> List[str]:
    """
    MOD-5: Multi-threaded passive recon using subfinder + amass simultaneously.
    - Both tools run in daemon threads launched at the same time.
    - Results are merged, deduplicated, sorted, then saved to .txt.
    - Returns the final unique list for integration into the main pipeline.
    """
    _section("RECON MODULE  (Subfinder + Amass — parallel threads)")

    available = [t for t in ["subfinder", "amass"] if shutil.which(t)]
    if not available:
        _warn("Neither subfinder nor amass found in PATH — skipping threaded recon")
        _info("Install subfinder: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
        _info("Install amass:     go install github.com/owasp-amass/amass/v4/...@master")
        return []

    _info(f"Launching {_c(' + '.join(available), C.CYAN)} for "
          f"{_c(domain, C.CYAN)} (parallel threads) ...")

    results_sf:    Set[str] = set()
    results_amass: Set[str] = set()
    _lock = threading.Lock()

    def _sf_worker():
        _info(f"  [{_c('thread:subfinder', C.MAGENTA)}] starting ...")
        found = _run_subfinder(domain, timeout=subfinder_timeout)
        with _lock:
            results_sf.update(found)
        _ok(f"  [{_c('thread:subfinder', C.MAGENTA)}] done → "
            f"{_c(str(len(found)), C.GREEN)} subdomains")

    def _amass_worker():
        _info(f"  [{_c('thread:amass', C.MAGENTA)}] starting ...")
        found = _run_amass(domain, timeout=amass_timeout)
        with _lock:
            results_amass.update(found)
        _ok(f"  [{_c('thread:amass', C.MAGENTA)}] done → "
            f"{_c(str(len(found)), C.GREEN)} subdomains")

    threads: List[threading.Thread] = []
    if _subfinder_available():
        t = threading.Thread(target=_sf_worker, daemon=True, name="subfinder")
        t.start()
        threads.append(t)
    if _amass_available():
        t = threading.Thread(target=_amass_worker, daemon=True, name="amass")
        t.start()
        threads.append(t)

    # Wait for both threads (with generous timeout)
    join_timeout = max(subfinder_timeout, amass_timeout) + 15
    for t in threads:
        t.join(timeout=join_timeout)
        if t.is_alive():
            log.warning(f"{t.name} thread still running after timeout")

    # MOD-5: merge + deduplicate
    unique = _merge_dedup_subdomains(results_sf, results_amass)

    _ok(
        f"Recon merged: {_c(str(len(unique)), C.BOLD, C.GREEN)} unique subdomains "
        f"(subfinder={_c(str(len(results_sf)), C.CYAN)}, "
        f"amass={_c(str(len(results_amass)), C.CYAN)})"
    )

    # Save to .txt for next pipeline stage
    if output_file is None:
        ts          = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"vulpimancer_recon_{domain}_{ts}.txt"
    try:
        Path(output_file).write_text(
            "\n".join(unique) + ("\n" if unique else ""), encoding="utf-8")
        _ok(f"Recon output saved → {_c(output_file, C.CYAN)}")
    except Exception as exc:
        log.error("Failed to save recon output", extra={"err": str(exc)})
        _warn(f"Could not save recon file: {exc}")

    return unique


# ===========================================================================
# DNS HELPERS
# ===========================================================================

def extract_registered_domain(hostname: str) -> str:
    hostname = hostname.rstrip(".").lower()
    parts    = hostname.split(".")
    if len(parts) < 2:
        return hostname
    if len(parts) >= 3:
        suffix = ".".join(parts[-2:])
        if suffix in _MULTI_LABEL_SUFFIXES:
            return ".".join(parts[-3:])
    return ".".join(parts[-2:])


async def _dns_resolve_fqdn(
    fqdn: str,
    resolver: Optional["aiodns.DNSResolver"],
    semaphore: asyncio.Semaphore,
) -> Tuple[List[str], Optional[str]]:
    async with semaphore:
        ips: List[str] = []
        cname: Optional[str] = None

        if HAS_AIODNS and resolver is not None:
            try:
                cn_r  = await asyncio.wait_for(resolver.query(fqdn, "CNAME"), timeout=3)
                cname = cn_r[0].cname if cn_r else None
            except Exception:
                pass
            try:
                result = await asyncio.wait_for(resolver.query(fqdn, "A"), timeout=3)
                ips    = [r.host for r in result]
            except Exception:
                pass

        if not ips:
            try:
                loop  = asyncio.get_event_loop()
                infos = await asyncio.wait_for(
                    loop.run_in_executor(
                        None,
                        lambda f=fqdn: socket.getaddrinfo(
                            f, None, socket.AF_UNSPEC, socket.SOCK_STREAM)),
                    timeout=4)
                seen: Set[str] = set()
                for info in infos:
                    ip = info[4][0]
                    if ip not in seen:
                        seen.add(ip)
                        ips.append(ip)
            except Exception:
                pass

        return ips, cname


def _check_takeover_hint(cname: Optional[str]) -> Optional[str]:
    if not cname:
        return None
    for pattern in _TAKEOVER_CNAME_PATTERNS:
        if re.search(pattern, cname, re.IGNORECASE):
            return f"CNAME → {cname} (possible takeover candidate)"
    return None


# ===========================================================================
# crt.sh PASSIVE ENUMERATION
# ===========================================================================

async def _enum_crtsh(
    domain: str,
    session: aiohttp.ClientSession,
    timeout: float = 15,
) -> List[str]:
    found: Set[str] = set()
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        async with session.get(
            url,
            timeout=aiohttp.ClientTimeout(total=timeout),
            headers={"Accept": "application/json"},
            ssl=True,
        ) as resp:
            if resp.status != 200:
                return []
            data = await resp.json(content_type=None)
            for entry in data:
                for sub in entry.get("name_value", "").splitlines():
                    sub = sub.strip().lower().lstrip("*.")
                    if sub.endswith("." + domain) and sub != domain:
                        found.add(sub)
    except Exception as exc:
        log.debug("crt.sh query failed", extra={"domain": domain, "err": str(exc)})
    return sorted(found)


# ===========================================================================
# PHASE 0 — SUBDOMAIN ENUMERATION
# ===========================================================================

async def _detect_wildcard_dns(
    domain: str,
    resolver: Optional["aiodns.DNSResolver"],
) -> Optional[str]:
    rand_labels = [
        "netra-wc-" + "".join(
            random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=12))
        for _ in range(3)
    ]
    semaphore = asyncio.Semaphore(3)
    results   = await asyncio.gather(
        *[_dns_resolve_fqdn(f"{lbl}.{domain}", resolver, semaphore)
          for lbl in rand_labels])
    resolved  = [r for (r, _) in results if r]
    if len(resolved) >= 2:
        return resolved[0][0] if resolved[0] else "unknown"
    return None


async def enumerate_subdomains(
    domain: str,
    resolver: Optional["aiodns.DNSResolver"],
    session: aiohttp.ClientSession,
    concurrency: int = 80,
    verbose: bool = True,
    use_external_tools: bool = False,  # MOD-5: --recon flag
) -> List[HostEntry]:
    """
    Hybrid subdomain enumeration:
      1. crt.sh passive
      2. MOD-5: Amass + Subfinder via threaded_recon() (if --recon)
      3. DNS brute-force (wildcard-safe, skipped if wildcard detected)
    All sources are deduplicated via found_map keyed by FQDN.
    """
    found_map: Dict[str, HostEntry] = {}

    # Step 1: crt.sh passive
    _info(f"  crt.sh passive enum for {_c(domain, C.CYAN)} ...")
    crt_subs = await _enum_crtsh(domain, session)
    if crt_subs:
        _ok(f"  crt.sh → {_c(str(len(crt_subs)), C.BOLD)} candidate(s)")
    else:
        _info("  crt.sh → no results (or rate-limited)")

    sem = asyncio.Semaphore(concurrency)

    async def _resolve_crt(fqdn: str):
        ips, cname = await _dns_resolve_fqdn(fqdn, resolver, sem)
        if ips:
            e = HostEntry(raw=fqdn, is_subdomain=True, source="crt.sh")
            e.resolved_ips  = ips
            e.cname         = cname
            e.takeover_hint = _check_takeover_hint(cname)
            return fqdn, e
        return fqdn, None

    for fqdn, e in await asyncio.gather(*[_resolve_crt(s) for s in crt_subs]):
        if e:
            found_map[fqdn] = e

    # Step 2: MOD-5 external tools via executor (non-blocking)
    if use_external_tools:
        _info("  Launching threaded recon (subfinder + amass) ...")
        loop     = asyncio.get_event_loop()
        ext_subs = await loop.run_in_executor(
            None, lambda: threaded_recon(domain, output_file=None))
        _info(f"  Resolving {len(ext_subs)} external recon result(s) ...")
        for sub in ext_subs:
            if sub in found_map:
                continue
            ips, cname = await _dns_resolve_fqdn(sub, resolver, sem)
            if ips:
                e = HostEntry(raw=sub, is_subdomain=True, source="amass/subfinder")
                e.resolved_ips  = ips
                e.cname         = cname
                e.takeover_hint = _check_takeover_hint(cname)
                found_map[sub]  = e

    # Step 3: Wildcard check before brute-force
    wc_ip = await _detect_wildcard_dns(domain, resolver)
    if wc_ip is not None:
        _warn(f"  Wildcard DNS on {_c(domain, C.YELLOW)} ({wc_ip}) "
              "— brute-force skipped (all results would be false positives)")
    else:
        total = len(SUBDOMAIN_WORDLIST)
        done  = 0

        async def _check_brute(sub: str):
            nonlocal done
            fqdn = f"{sub}.{domain}"
            if fqdn in found_map:
                done += 1
                return
            ips, cname = await _dns_resolve_fqdn(fqdn, resolver, sem)
            done += 1
            if verbose and done % 30 == 0:
                _progress(done, total, f"bruteforce: {sub}.{domain}")
            if ips:
                e = HostEntry(raw=fqdn, is_subdomain=True, source="bruteforce")
                e.resolved_ips  = ips
                e.cname         = cname
                e.takeover_hint = _check_takeover_hint(cname)
                found_map[fqdn] = e

        await asyncio.gather(*[_check_brute(s) for s in SUBDOMAIN_WORDLIST])
        if verbose:
            _progress(total, total, "brute-force done")

    return list(found_map.values())


# ===========================================================================
# PHASE 1 — DNS RESOLUTION
# ===========================================================================

async def resolve_host(
    entry: HostEntry,
    resolver: Optional["aiodns.DNSResolver"] = None,
) -> HostEntry:
    hostname = entry.hostname
    if entry.resolved_ips:
        return entry
    try:
        ipaddress.ip_address(hostname)
        entry.resolved_ips = [hostname]
        return entry
    except ValueError:
        pass

    resolved = False
    if HAS_AIODNS and resolver is not None:
        try:
            result = await asyncio.wait_for(resolver.query(hostname, "A"), timeout=5)
            entry.resolved_ips = [record.host for record in result]
            resolved = True
        except Exception:
            pass

    if not resolved:
        try:
            loop  = asyncio.get_event_loop()
            infos = await asyncio.wait_for(
                loop.run_in_executor(
                    None,
                    lambda: socket.getaddrinfo(
                        hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)),
                timeout=8)
            seen: Set[str] = set()
            for info in infos:
                ip = info[4][0]
                if ip not in seen:
                    seen.add(ip)
                    entry.resolved_ips.append(ip)
        except Exception as exc:
            entry.resolve_error = str(exc)

    return entry


# ===========================================================================
# PHASE 2 — PORT SCANNING  (double-verify + optional nmap)
# ===========================================================================

SERVICE_HINTS: Dict[int, str] = {
    21:"FTP", 22:"SSH", 23:"Telnet", 25:"SMTP", 53:"DNS",
    80:"HTTP", 110:"POP3", 111:"RPC", 135:"MSRPC", 139:"NetBIOS",
    143:"IMAP", 443:"HTTPS", 445:"SMB", 993:"IMAPS", 995:"POP3S",
    1433:"MSSQL", 1521:"Oracle", 1723:"PPTP",
    3306:"MySQL", 3389:"RDP", 5432:"PostgreSQL",
    5900:"VNC", 6379:"Redis", 8080:"HTTP-Alt",
    8443:"HTTPS-Alt", 9200:"Elasticsearch",
    9300:"Elasticsearch-Transport", 27017:"MongoDB", 27018:"MongoDB",
}
BANNER_PATTERNS: List[Tuple[str, str]] = [
    (r"SSH-\d+\.\d+",           "SSH"),
    (r"220.*[Ff][Tt][Pp]",      "FTP"),
    (r"220.*[Ss][Mm][Tt][Pp]",  "SMTP"),
    (r"\+OK",                    "POP3"),
    (r"\* OK.*IMAP",             "IMAP"),
    (r"RFB \d+\.\d+",            "VNC"),
    (r"REDIS",                   "Redis"),
    (r"MongoDB",                 "MongoDB"),
    (r"HTTP/1\.[01]",            "HTTP"),
]


async def _tcp_connect(ip: str, port: int, timeout: float) -> bool:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False


async def scan_port(
    ip: str, port: int, host: str,
    timeout: float = 3.0,
    semaphore: Optional[asyncio.Semaphore] = None,
) -> PortResult:
    """Double-verify TCP port scan — port must respond twice to be marked open."""
    ctx = semaphore or asyncio.Semaphore(1)
    async with ctx:
        if not await _tcp_connect(ip, port, timeout):
            return PortResult(host=host, ip=ip, port=port, is_open=False)
        await asyncio.sleep(0.15)
        if not await _tcp_connect(ip, port, timeout):
            return PortResult(host=host, ip=ip, port=port, is_open=False)

        banner        = None
        service_guess = SERVICE_HINTS.get(port)
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=timeout)
            try:
                writer.write(b"\r\n")
                await writer.drain()
                data   = await asyncio.wait_for(reader.read(256), timeout=2)
                banner = data.decode("utf-8", errors="replace").strip()[:200]
                for pattern, name in BANNER_PATTERNS:
                    if re.search(pattern, banner, re.IGNORECASE):
                        service_guess = name
                        break
            except Exception:
                pass
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
        except Exception:
            pass

        return PortResult(host=host, ip=ip, port=port, is_open=True,
                          banner=banner, service_guess=service_guess)


async def scan_ports(
    entry: HostEntry, ports: List[int],
    timeout: float = 3.0, concurrency: int = 100,
) -> List[PortResult]:
    if not entry.resolved_ips:
        return []
    ip        = entry.resolved_ips[0]
    semaphore = asyncio.Semaphore(concurrency)
    results   = await asyncio.gather(
        *[scan_port(ip, p, entry.hostname, timeout, semaphore) for p in ports])
    return list(results)


# ===========================================================================
# PHASE 6 — TECHNOLOGY FINGERPRINTING
# ===========================================================================

def fingerprint_technologies(
    headers: Dict[str, str],
    body: str,
    url: str,
) -> List[str]:
    techs: Set[str] = set()

    def _check(src: str, pattern: str, name: str, has_ver: bool):
        m = re.search(pattern, src, re.IGNORECASE)
        if m:
            if has_ver and m.lastindex and m.group(1):
                techs.add(f"{name}/{m.group(1)}")
            else:
                techs.add(name)

    for name, pattern, where in TECH_SIGNATURES:
        has_ver = "(" in pattern
        if where == "server":
            _check(headers.get("server", ""), pattern, name, has_ver)
        elif where == "x-powered-by":
            _check(headers.get("x-powered-by", ""), pattern, name, has_ver)
        elif where == "set-cookie":
            _check(headers.get("set-cookie", ""), pattern, name, has_ver)
        elif where == "body":
            _check(body, pattern, name, has_ver)
        elif where.startswith("header:"):
            hdr = where.split(":", 1)[1]
            _check(headers.get(hdr, ""), pattern, name, has_ver)

    if url.startswith("http://") and headers.get("location", "").startswith("https://"):
        techs.add("HTTPS-Redirect")

    for h, label in {
        "strict-transport-security": "HSTS",
        "content-security-policy":   "CSP",
        "x-frame-options":           "X-Frame-Options",
        "x-content-type-options":    "X-Content-Type-Options",
    }.items():
        if h in headers:
            techs.add(f"Header:{label}")

    return sorted(techs)


def _extract_title(body: str) -> Optional[str]:
    m = re.search(r"<title[^>]*>([^<]{1,200})</title>", body,
                  re.IGNORECASE | re.DOTALL)
    if m:
        return m.group(1).strip()[:120]
    return None


# ===========================================================================
# PHASE 4 — HTTP PROBING  (MOD-1: status feedback, HTTPS->HTTP fallback)
# ===========================================================================

def _build_url(scheme: str, hostname: str, port: Optional[int]) -> str:
    if port and port not in (80, 443):
        return f"{scheme}://{hostname}:{port}/"
    return f"{scheme}://{hostname}/"


async def _async_fetch(
    session: aiohttp.ClientSession,
    url: str,
    timeout: float,
    allow_redirects: bool = True,
) -> Tuple[Optional[int], Optional[bytes], Dict[str, str], Optional[str]]:
    """Low-level async fetch — used internally for sensitive path probing."""
    try:
        async with session.get(
            url,
            timeout=aiohttp.ClientTimeout(total=timeout),
            allow_redirects=allow_redirects,
            ssl=False,
        ) as resp:
            body = await resp.read()
            hdrs = {k.lower(): v for k, v in resp.headers.items()}
            return resp.status, body, hdrs, str(resp.url)
    except Exception:
        return None, None, {}, None


async def probe_host(
    entry: HostEntry,
    scheme: str,
    port: Optional[int],
    session: aiohttp.ClientSession,
    bucket: TokenBucket,
    semaphore: asyncio.Semaphore,
    *,
    timeout: float,
    max_retries: int,
    probe_paths: bool = True,
    legacy_tls: bool = False,
) -> Optional[ProbeResult]:
    """
    MOD-1: Async HTTP probing with:
    - Retry loop (max_retries=3, timeout=15s)
    - Live CLI status feedback via _http_status_feedback()
    - HTTPS → HTTP fallback on SSL errors
    - Sensitive path probing only on HTTP 200 hosts
    """
    url         = _build_url(scheme, entry.hostname, port)
    resolved_ip = entry.resolved_ips[0] if entry.resolved_ips else None

    status = resp_len = server = ct = error = redirect_url = title = None
    technologies:    List[str]            = []
    sensitive_found: List[SensitiveFinding] = []
    elapsed_ms   = 0.0
    attempt      = 1
    body_str     = ""
    did_fallback = False

    for attempt in range(1, max_retries + 1):
        await bucket.acquire()
        async with semaphore:
            t0       = time.monotonic()
            probe_url = url
            try:
                async with session.get(
                    probe_url,
                    timeout=aiohttp.ClientTimeout(total=timeout),
                    allow_redirects=True,
                    ssl=False,
                ) as resp:
                    body_bytes   = await resp.read()
                    elapsed_ms   = (time.monotonic() - t0) * 1000
                    status       = resp.status
                    resp_len     = len(body_bytes)
                    hdrs         = {k.lower(): v for k, v in resp.headers.items()}
                    server       = hdrs.get("server")
                    ct           = hdrs.get("content-type")
                    redirect_url = str(resp.url) if str(resp.url) != probe_url else None
                    body_str     = body_bytes.decode("utf-8", errors="replace")[:60_000]
                    technologies = fingerprint_technologies(hdrs, body_str, probe_url)
                    title        = _extract_title(body_str)
                    error        = None
                    # MOD-1: live CLI feedback
                    _http_status_feedback(probe_url, attempt, status, max_retries)
                    break

            except aiohttp.ClientConnectorSSLError as ssl_exc:
                # MOD-1: HTTPS → HTTP fallback
                log.warning("HTTPS SSL error in async probe",
                            extra={"url": probe_url, "attempt": attempt,
                                   "err": str(ssl_exc)})
                _warn(f"SSL error in async probe: {_c(probe_url, C.CYAN)}")
                if scheme == "https":
                    http_url = "http://" + probe_url[len("https://"):]
                    _warn(f"[attempt {attempt}/{max_retries}] SSL error — trying "
                          f"{_c('HTTP', C.YELLOW)}: {_c(http_url, C.YELLOW)}")
                    try:
                        async with session.get(
                            http_url,
                            timeout=aiohttp.ClientTimeout(total=timeout),
                            allow_redirects=True,
                            ssl=False,
                        ) as resp2:
                            body_bytes   = await resp2.read()
                            elapsed_ms   = (time.monotonic() - t0) * 1000
                            status       = resp2.status
                            resp_len     = len(body_bytes)
                            hdrs         = {k.lower(): v for k, v in resp2.headers.items()}
                            server       = hdrs.get("server")
                            ct           = hdrs.get("content-type")
                            redirect_url = (str(resp2.url)
                                            if str(resp2.url) != http_url else None)
                            body_str     = body_bytes.decode("utf-8", errors="replace")[:60_000]
                            technologies = fingerprint_technologies(hdrs, body_str, http_url)
                            title        = _extract_title(body_str)
                            error        = None
                            did_fallback = True
                            _http_status_feedback(http_url, attempt, status, max_retries)
                            break
                    except Exception as inner:
                        error = f"SSL+HTTP fallback failed: {inner}"
                        log.warning("HTTP fallback also failed",
                                    extra={"url": http_url, "err": str(inner)})
                else:
                    error = f"SSLError: {ssl_exc}"

            except asyncio.TimeoutError:
                error = "TimeoutError"
                _http_status_feedback(probe_url, attempt, None, max_retries,
                                      error=f"Timeout after {timeout}s")
            except aiohttp.ClientConnectorError as exc:
                error = f"ConnectorError: {exc}"
                _http_status_feedback(probe_url, attempt, None, max_retries,
                                      error=str(exc)[:60])
                if "Network is unreachable" in str(exc) or "ENETUNREACH" in str(exc):
                    break
            except aiohttp.ClientResponseError as exc:
                msg   = exc.message
                error = f"ResponseError: {exc.status} {msg}"
                if "8190" in msg or "too long" in msg.lower():
                    error = f"HeaderTooLong: {msg}"
                    break
            except aiohttp.ClientError as exc:
                msg   = str(exc)
                error = ("HeaderTooLong: oversized headers"
                         if ("8190" in msg or "too long" in msg.lower())
                         else f"ClientError: {exc}")
            except Exception as exc:
                error = f"UnexpectedError: {exc}"
                log.error("Unexpected probe error",
                          extra={"url": probe_url, "err": str(exc)})

            elapsed_ms = (time.monotonic() - t0) * 1000
            if "HeaderTooLong" in (error or "") or "ENETUNREACH" in (error or ""):
                break
            if attempt < max_retries:
                wait = min(2 ** attempt + random.uniform(0, 1), 30)
                await asyncio.sleep(wait)

    # Sensitive path probing only on confirmed live (200) hosts
    if error is None and status == 200 and probe_paths:
        baseline_hash, baseline_len = _compute_baseline(body_str, resp_len or 0)
        sensitive_found = await _probe_sensitive_paths(
            session, scheme, entry.hostname, port, bucket, timeout,
            baseline_hash=baseline_hash, baseline_len=baseline_len)

    return ProbeResult(
        host=entry.hostname, scheme=scheme, port=port, url=url,
        resolved_ip=resolved_ip, attempt=attempt,
        status_code=status, response_length=resp_len,
        title=title,
        server_header=server, content_type=ct,
        response_time_ms=round(elapsed_ms, 2),
        redirect_url=redirect_url,
        technologies=technologies,
        sensitive_paths_found=sensitive_found,
        error=error,
        fallback_http=did_fallback,
    )


# ===========================================================================
# PHASE 7 — SENSITIVE PATH PROBING
# ===========================================================================

def _compute_baseline(body: str, body_len: int) -> Tuple[str, int]:
    h = hashlib.md5(body.encode("utf-8", errors="replace")).hexdigest()
    return h, body_len


def _body_has_sensitive_keywords(body: str) -> bool:
    for kw in _SENSITIVE_BODY_KEYWORDS:
        if kw in body:
            return True
    return False


async def _probe_sensitive_paths(
    session: aiohttp.ClientSession,
    scheme: str,
    hostname: str,
    port: Optional[int],
    bucket: TokenBucket,
    timeout: float,
    concurrency: int = 12,
    baseline_hash: str = "",
    baseline_len: int = 0,
) -> List[SensitiveFinding]:
    found: List[SensitiveFinding] = []
    sem  = asyncio.Semaphore(concurrency)
    base = _build_url(scheme, hostname, port).rstrip("/")

    async def _check(path: str):
        await bucket.acquire()
        async with sem:
            full_url = base + path
            status, body, _hdrs, _ = await _async_fetch(
                session, full_url, timeout, allow_redirects=False)

            if status is None:
                return

            if status in (401, 403):
                found.append(SensitiveFinding(
                    path=path, status=status,
                    body_size=len(body) if body else 0,
                    confidence="PROTECTED",
                    reason="Access denied — endpoint exists but is protected",
                ))
                return

            if status not in (200, 204):
                return

            body_bytes = body or b""
            body_len   = len(body_bytes)
            if body_len < _MIN_BODY_BYTES:
                return

            body_str  = body_bytes.decode("utf-8", errors="replace")
            body_hash = hashlib.md5(body_bytes).hexdigest()

            if body_hash == baseline_hash:
                return  # Exact catch-all match
            if baseline_len > 0 and abs(body_len - baseline_len) < 50:
                return  # Same-size catch-all

            has_keywords = _body_has_sensitive_keywords(body_str)
            if has_keywords:
                confidence, reason = "HIGH", "Sensitive keywords found in response body"
            elif body_len > 200:
                confidence, reason = "MEDIUM", "Unique response body with substantial content"
            else:
                confidence, reason = "LOW", "Unique small response body"

            found.append(SensitiveFinding(
                path=path, status=status,
                body_size=body_len,
                confidence=confidence,
                reason=reason,
            ))

    await asyncio.gather(*[_check(p) for p in SENSITIVE_PATHS])
    return found


# ===========================================================================
# PHASE 8 — CVE CORRELATION  (NIST NVD + Nuclei via MOD-4)
# ===========================================================================

async def lookup_cves(
    product: str, version: str,
    session: aiohttp.ClientSession,
    max_results: int = 5,
) -> List[CVEFinding]:
    findings: List[CVEFinding] = []
    keyword = f"{product} {version}".strip()
    url     = (f"https://services.nvd.nist.gov/rest/json/cves/2.0"
               f"?keywordSearch={keyword}&resultsPerPage={max_results}")
    try:
        async with session.get(
            url,
            timeout=aiohttp.ClientTimeout(total=15),
            headers={"Accept": "application/json"},
            ssl=True,
        ) as resp:
            if resp.status != 200:
                return findings
            data = await resp.json()
            for item in data.get("vulnerabilities", []):
                cve_obj   = item.get("cve", {})
                cve_id    = cve_obj.get("id", "UNKNOWN")
                desc      = next(
                    (d["value"] for d in cve_obj.get("descriptions", [])
                     if d.get("lang") == "en"), "No description")
                published = cve_obj.get("published", "")
                metrics   = cve_obj.get("metrics", {})
                score     = None
                severity  = "UNKNOWN"
                for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    mlist = metrics.get(key, [])
                    if mlist:
                        cvss_data = mlist[0].get("cvssData", {})
                        score     = cvss_data.get("baseScore")
                        severity  = cvss_data.get("baseSeverity",
                                                   mlist[0].get("baseSeverity", "UNKNOWN"))
                        break
                findings.append(CVEFinding(
                    product=product, version=version,
                    cve_id=cve_id, cvss_score=score,
                    severity=severity,
                    description=f"[Potential] {desc[:280]}",
                    published=published,
                ))
    except Exception as exc:
        log.warning("CVE lookup failed",
                    extra={"product": product, "version": version, "err": str(exc)})
    return findings


# ===========================================================================
# DATABASE
# ===========================================================================

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS dns_records (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    host          TEXT    NOT NULL,
    resolved_ip   TEXT,
    cname         TEXT,
    takeover_hint TEXT,
    resolve_error TEXT,
    is_subdomain  INTEGER DEFAULT 0,
    source        TEXT    DEFAULT 'input',
    resolved_at   TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE TABLE IF NOT EXISTS port_results (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    host          TEXT    NOT NULL,
    ip            TEXT    NOT NULL,
    port          INTEGER NOT NULL,
    is_open       INTEGER NOT NULL,
    banner        TEXT,
    service_guess TEXT,
    nmap_service  TEXT,
    nmap_version  TEXT,
    scanned_at    TEXT    NOT NULL
);
CREATE TABLE IF NOT EXISTS tls_results (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    host            TEXT NOT NULL,
    port            INTEGER NOT NULL,
    subject_cn      TEXT,
    issuer          TEXT,
    san_domains     TEXT,
    not_before      TEXT,
    not_after       TEXT,
    is_expired      INTEGER,
    days_to_expiry  INTEGER,
    cipher_suite    TEXT,
    tls_version     TEXT,
    self_signed     INTEGER,
    sni_retry       INTEGER DEFAULT 0,
    error           TEXT,
    analysed_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE TABLE IF NOT EXISTS probe_results (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    host                  TEXT,
    scheme                TEXT,
    port                  INTEGER,
    url                   TEXT    NOT NULL,
    resolved_ip           TEXT,
    attempt               INTEGER,
    status_code           INTEGER,
    response_length       INTEGER,
    title                 TEXT,
    server_header         TEXT,
    content_type          TEXT,
    response_time_ms      REAL,
    redirect_url          TEXT,
    technologies          TEXT,
    sensitive_paths_found TEXT,
    error                 TEXT,
    fallback_http         INTEGER DEFAULT 0,
    probed_at             TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS cve_findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    host        TEXT,
    product     TEXT,
    version     TEXT,
    cve_id      TEXT,
    cvss_score  REAL,
    severity    TEXT,
    description TEXT,
    published   TEXT,
    found_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE TABLE IF NOT EXISTS nuclei_results (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    template_id  TEXT,
    name         TEXT,
    severity     TEXT,
    host         TEXT,
    matched_at   TEXT,
    description  TEXT,
    tags         TEXT,
    found_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_port_host    ON port_results(host, is_open);
CREATE INDEX IF NOT EXISTS idx_probe_host   ON probe_results(host);
CREATE INDEX IF NOT EXISTS idx_probe_status ON probe_results(status_code);
CREATE INDEX IF NOT EXISTS idx_cve_severity ON cve_findings(severity);
CREATE INDEX IF NOT EXISTS idx_nuclei_sev   ON nuclei_results(severity);
"""


async def init_db(path: str) -> aiosqlite.Connection:
    conn = await aiosqlite.connect(path)
    await conn.executescript(SCHEMA_SQL)
    await conn.commit()
    return conn


async def save_dns(conn: aiosqlite.Connection, entry: HostEntry) -> None:
    rows = [(entry.hostname, ip, entry.cname, entry.takeover_hint,
             entry.resolve_error, int(entry.is_subdomain), entry.source)
            for ip in entry.resolved_ips] or \
           [(entry.hostname, None, entry.cname, entry.takeover_hint,
             entry.resolve_error, int(entry.is_subdomain), entry.source)]
    await conn.executemany(
        "INSERT INTO dns_records "
        "(host, resolved_ip, cname, takeover_hint, resolve_error, is_subdomain, source) "
        "VALUES (?,?,?,?,?,?,?)", rows)
    await conn.commit()


async def save_port(conn: aiosqlite.Connection, r: PortResult) -> None:
    await conn.execute(
        "INSERT INTO port_results "
        "(host,ip,port,is_open,banner,service_guess,nmap_service,nmap_version,scanned_at) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        (r.host, r.ip, r.port, int(r.is_open),
         r.banner, r.service_guess, r.nmap_service, r.nmap_version, r.scanned_at))
    await conn.commit()


async def save_tls(conn: aiosqlite.Connection, t: TLSInfo) -> None:
    await conn.execute(
        "INSERT INTO tls_results (host,port,subject_cn,issuer,san_domains,"
        "not_before,not_after,is_expired,days_to_expiry,cipher_suite,"
        "tls_version,self_signed,sni_retry,error) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (t.host, t.port, t.subject_cn, t.issuer,
         json.dumps(t.san_domains), t.not_before, t.not_after,
         int(t.is_expired), t.days_to_expiry, t.cipher_suite,
         t.tls_version, int(t.self_signed), int(t.sni_retry), t.error))
    await conn.commit()


async def save_probe(conn: aiosqlite.Connection, r: ProbeResult) -> None:
    await conn.execute(
        "INSERT INTO probe_results (host,scheme,port,url,resolved_ip,attempt,"
        "status_code,response_length,title,server_header,content_type,response_time_ms,"
        "redirect_url,technologies,sensitive_paths_found,error,fallback_http,probed_at) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (r.host, r.scheme, r.port, r.url, r.resolved_ip, r.attempt,
         r.status_code, r.response_length, r.title, r.server_header, r.content_type,
         r.response_time_ms, r.redirect_url,
         json.dumps(r.technologies),
         json.dumps([
             {"path": f.path, "status": f.status,
              "confidence": f.confidence, "reason": f.reason}
             for f in r.sensitive_paths_found
         ]),
         r.error, int(r.fallback_http), r.probed_at))
    await conn.commit()


async def save_cve(conn: aiosqlite.Connection,
                   host: str, finding: CVEFinding) -> None:
    await conn.execute(
        "INSERT INTO cve_findings "
        "(host,product,version,cve_id,cvss_score,severity,description,published) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (host, finding.product, finding.version, finding.cve_id,
         finding.cvss_score, finding.severity,
         finding.description, finding.published))
    await conn.commit()


async def save_nuclei(conn: aiosqlite.Connection, nr: NucleiResult) -> None:
    await conn.execute(
        "INSERT INTO nuclei_results (template_id,name,severity,host,matched_at,description,tags) "
        "VALUES (?,?,?,?,?,?,?)",
        (nr.template_id, nr.name, nr.severity, nr.host, nr.matched_at,
         nr.description, json.dumps(nr.tags)))
    await conn.commit()


# ===========================================================================
# HOST FILE / PORT PARSER
# ===========================================================================

def parse_hosts_file(path: str) -> List[HostEntry]:
    entries: List[HostEntry] = []
    with open(path, encoding="utf-8") as fh:
        for raw_line in fh:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            entries.append(HostEntry(raw=line))
    return entries


def parse_ports(port_spec: str) -> List[int]:
    if port_spec in PORT_GROUPS:
        return PORT_GROUPS[port_spec]
    ports: Set[int] = set()
    for part in port_spec.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = (int(x) for x in part.split("-", 1))
            if not (1 <= lo <= 65535 and 1 <= hi <= 65535):
                raise ValueError(f"Invalid port range: {lo}-{hi}")
            ports.update(range(lo, hi + 1))
        else:
            p = int(part)
            if not (1 <= p <= 65535):
                raise ValueError(f"Invalid port: {p}")
            ports.add(p)
    return sorted(ports)


# ===========================================================================
# HTML REPORT GENERATOR
# ===========================================================================

async def generate_html_report(db_path: str, output_path: str) -> None:
    conn = await aiosqlite.connect(db_path)
    conn.row_factory = aiosqlite.Row

    async def q(sql, params=()):
        async with conn.execute(sql, params) as cur:
            return await cur.fetchall()

    dns     = await q("SELECT * FROM dns_records ORDER BY is_subdomain, host")
    ports   = await q("SELECT * FROM port_results WHERE is_open=1 ORDER BY host,port")
    tls     = await q("SELECT * FROM tls_results ORDER BY host,port")
    probes  = await q("SELECT * FROM probe_results ORDER BY status_code, host, scheme")
    cves    = await q("SELECT * FROM cve_findings ORDER BY cvss_score DESC")
    nucleis = await q("SELECT * FROM nuclei_results ORDER BY severity, host")

    now        = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    live_count = sum(1 for r in probes if r["status_code"] == 200)
    takeovers  = [r for r in dns if r["takeover_hint"]]
    crit_high  = [r for r in nucleis if r["severity"] in ("CRITICAL", "HIGH")]

    def _badge(text, color):
        return (f'<span style="background:{color};color:#fff;'
                f'padding:2px 7px;border-radius:4px;font-size:11px">{text}</span>')

    def _status_badge(code):
        if code is None:       return _badge("?", "#555")
        if 200 <= code < 300:  return _badge(str(code), "#2ea043")
        if 300 <= code < 400:  return _badge(str(code), "#2f81f7")
        if 400 <= code < 500:  return _badge(str(code), "#d29922")
        return _badge(str(code), "#da3633")

    def _tbl(rows, cols):
        if not rows:
            return "<p><em>None</em></p>"
        h    = "".join(f"<th>{c}</th>" for c in cols)
        body = ""
        for row in rows:
            cells = ""
            for c in cols:
                val = row[c] if row[c] is not None else "—"
                if c == "status_code":
                    val = _status_badge(row[c])
                elif c == "takeover_hint" and row[c]:
                    val = f'<span style="color:#f85149">{row[c]}</span>'
                elif c == "is_open":
                    val = (_badge("OPEN", "#2ea043") if row[c]
                           else _badge("CLOSED", "#555"))
                elif c == "severity":
                    col = {"CRITICAL": "#da3633", "HIGH": "#f85149",
                           "MEDIUM": "#d29922", "LOW": "#2ea043"}.get(
                        str(row[c]).upper(), "#555")
                    val = _badge(str(row[c]), col)
                cells += f"<td>{val}</td>"
            body += f"<tr>{cells}</tr>"
        return f"<table><thead><tr>{h}</tr></thead><tbody>{body}</tbody></table>"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Vulpimancer {VERSION} Report</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Courier New',monospace;background:#0d1117;color:#c9d1d9;padding:24px}}
h1{{color:#58a6ff;margin-bottom:4px;font-size:1.8em}}
h2{{color:#79c0ff;margin:28px 0 10px;border-bottom:2px solid #30363d;padding-bottom:6px}}
.meta{{color:#8b949e;font-size:12px;margin-bottom:20px}}
table{{width:100%;border-collapse:collapse;font-size:12px;margin-bottom:20px}}
th{{background:#161b22;color:#79c0ff;text-align:left;padding:8px 12px;border:1px solid #30363d}}
td{{padding:6px 12px;border:1px solid #21262d;vertical-align:top;word-break:break-word}}
tr:hover td{{background:#161b22}}
.stat{{display:inline-flex;flex-direction:column;align-items:center;
       padding:14px 24px;background:#161b22;border:1px solid #30363d;
       border-radius:8px;margin:4px;min-width:120px}}
.stat-n{{font-size:30px;font-weight:bold;color:#58a6ff}}
.stat-l{{font-size:11px;color:#8b949e;margin-top:4px}}
.alert{{background:#3d1a1c;border:1px solid #f85149;border-radius:6px;
        padding:12px 16px;margin-bottom:16px;color:#f85149}}
.alert-nuclei{{background:#1a1a3d;border:1px solid #da3633;border-radius:6px;
               padding:12px 16px;margin-bottom:16px;color:#f85149}}
</style>
</head>
<body>
<h1>Vulpimancer {VERSION} Reconnaissance Report</h1>
<div class="meta">Generated: {now} | Database: {db_path}</div>
{"".join(f'<div class="alert">⚠ Subdomain Takeover: {r["host"]} → {r["takeover_hint"]}</div>'
         for r in takeovers)}
{"".join(f'<div class="alert-nuclei">🔥 Nuclei [{nr["severity"]}]: {nr["name"]} — {nr["matched_at"]}</div>'
         for nr in crit_high[:5])}
<div>
  <div class="stat"><span class="stat-n">{len(set(r["host"] for r in dns))}</span><span class="stat-l">Hosts</span></div>
  <div class="stat"><span class="stat-n">{len(set(r["host"] for r in dns if r["is_subdomain"]))}</span><span class="stat-l">Subdomains</span></div>
  <div class="stat"><span class="stat-n">{len(ports)}</span><span class="stat-l">Open Ports</span></div>
  <div class="stat"><span class="stat-n">{live_count}</span><span class="stat-l">Live (200)</span></div>
  <div class="stat"><span class="stat-n">{len(cves)}</span><span class="stat-l">NVD CVEs</span></div>
  <div class="stat"><span class="stat-n">{len(nucleis)}</span><span class="stat-l">Nuclei Hits</span></div>
  <div class="stat"><span class="stat-n">{len(takeovers)}</span><span class="stat-l">Takeover Hints</span></div>
</div>
<h2>DNS Resolution</h2>
{_tbl(dns, ["host","resolved_ip","cname","takeover_hint","is_subdomain","source","resolved_at"])}
<h2>Open Ports</h2>
{_tbl(ports, ["host","ip","port","service_guess","nmap_service","nmap_version","banner"])}
<h2>TLS / SSL Analysis</h2>
{_tbl(tls, ["host","port","subject_cn","issuer","days_to_expiry","cipher_suite","tls_version","self_signed","sni_retry","is_expired","error"])}
<h2>Web Service Probes</h2>
{_tbl(probes, ["host","scheme","port","status_code","title","server_header","content_type","response_time_ms","technologies","redirect_url","fallback_http"])}
<h2>CVE Findings (NIST NVD — Potential)</h2>
{_tbl(cves, ["host","product","version","cve_id","cvss_score","severity","description"])}
<h2>Nuclei Findings (Critical + High)</h2>
{_tbl(nucleis, ["severity","template_id","name","host","matched_at","description"])}
</body>
</html>"""

    Path(output_path).write_text(html, encoding="utf-8")
    await conn.close()


# ===========================================================================
# TERMINAL SUMMARY
# ===========================================================================

def print_terminal_summary(
    resolved:       List[HostEntry],
    all_open_ports: Dict[str, List[PortResult]],
    live_probes:    List[ProbeResult],
    tls_infos:      List[TLSInfo],
    cve_findings:   List[Tuple[str, CVEFinding]],
    nuclei_results: List[NucleiResult],
    nmap_results:   List[Dict],
    args:           argparse.Namespace,
) -> None:

    live_hosts    = [e for e in resolved if e.resolved_ips]
    total_open    = sum(len(v) for v in all_open_ports.values())
    live_200      = [r for r in live_probes if r.error is None and r.status_code == 200]
    redirect_3xx  = [r for r in live_probes if r.error is None and r.status_code
                     and 300 <= r.status_code < 400]
    protected_403 = [r for r in live_probes if r.error is None and r.status_code == 403]
    crit_high_cve = [c for _, c in cve_findings
                     if (c.severity or "").upper() in ("CRITICAL", "HIGH")]
    crit_high_nuc = [nr for nr in nuclei_results
                     if nr.severity in ("CRITICAL", "HIGH")]
    takeover_hints = [e for e in resolved if e.takeover_hint]
    http_fallbacks = [r for r in live_probes if r.fallback_http]
    sni_retries    = [t for t in tls_infos if t.sni_retry]

    # ── Summary bar ─────────────────────────────────────────────────────────
    _section("SCAN SUMMARY  v1.0.0")
    for label, value, color in [
        ("Targets scanned",    len(resolved),        C.CYAN),
        ("DNS resolved",       len(live_hosts),       C.GREEN),
        ("Subdomains found",   sum(1 for e in resolved if e.is_subdomain), C.MAGENTA),
        ("Open ports",         total_open,            C.YELLOW if total_open else C.GRAY),
        ("Live (HTTP 200)",    len(live_200),         C.GREEN  if live_200  else C.GRAY),
        ("Redirects (3xx)",    len(redirect_3xx),     C.CYAN   if redirect_3xx else C.GRAY),
        ("Protected (403)",    len(protected_403),    C.YELLOW if protected_403 else C.GRAY),
        ("HTTP fallbacks",     len(http_fallbacks),   C.YELLOW if http_fallbacks else C.GRAY),
        ("SNI retries",        len(sni_retries),      C.YELLOW if sni_retries else C.GRAY),
        ("NVD CVEs (potential)", len(cve_findings),   C.RED    if cve_findings else C.GREEN),
        ("Nuclei Critical/High", len(crit_high_nuc),  C.RED    if crit_high_nuc else C.GREEN),
        ("Takeover hints",     len(takeover_hints),   C.RED    if takeover_hints else C.GREEN),
    ]:
        bar = ("█" * min(value, 35)).ljust(35)
        print(f"  {_c(label.ljust(25), C.GRAY)}  "
              f"{_c(bar, color)}  "
              f"{_c(str(value).rjust(4), C.BOLD, color)}")

    # ── DNS ─────────────────────────────────────────────────────────────────
    _section("DNS RESOLUTION")
    rows = []
    for e in resolved:
        st  = _c("OK", C.GREEN) if e.resolved_ips else _c("FAIL", C.RED)
        ips = ", ".join(e.resolved_ips[:2]) if e.resolved_ips else (e.resolve_error or "-")
        src = _c(e.source, C.MAGENTA) if e.source != "input" else ""
        tk  = _c("⚠ TAKEOVER?", C.RED) if e.takeover_hint else ""
        rows.append([e.hostname, ips, st, src, tk])
    _table(["Hostname", "IP(s)", "Status", "Source", "Takeover?"], rows,
           col_colors=[C.CYAN, C.WHITE, None, C.MAGENTA, C.RED])

    # ── Open Ports ──────────────────────────────────────────────────────────
    if total_open:
        _section("OPEN PORTS")
        rows = []
        for hostname, results in all_open_ports.items():
            for r in results:
                svc = r.nmap_service or r.service_guess or "?"
                ver = r.nmap_version or ""
                rows.append([hostname, r.ip, str(r.port),
                             svc, ver[:30], (r.banner or "")[:48]])
        _table(["Host", "IP", "Port", "Service", "Version", "Banner"], rows,
               col_colors=[C.CYAN, C.WHITE, C.YELLOW, C.GREEN, C.CYAN, C.GRAY])

    # ── Nmap results (if --nmap was used) ───────────────────────────────────
    if nmap_results:
        _section(f"NMAP SERVICE VERSIONS  ({len(nmap_results)} ports)")
        rows = []
        for r in nmap_results:
            col = C.GREEN if r["state"] == "open" else C.GRAY
            rows.append([
                _c(str(r["port"]), col, C.BOLD), r["protocol"],
                _c(r["state"], col), r["service"] or "-",
                (r["version"] or "-")[:50],
            ])
        _table(["Port", "Proto", "State", "Service", "Version"], rows,
               col_colors=[C.YELLOW, C.GRAY, None, C.GREEN, C.WHITE])

    # ── Live hosts (200) ─────────────────────────────────────────────────────
    if live_200:
        _section(f"✔  LIVE WEB HOSTS  —  HTTP 200  ({len(live_200)} hosts)")
        rows = []
        for r in live_200:
            tech = ", ".join(r.technologies[:3]) or "-"
            ms   = f"{r.response_time_ms:.0f}ms" if r.response_time_ms else "-"
            t    = (r.title or "-")[:50]
            fb   = _c(" [HTTP↓]", C.YELLOW) if r.fallback_http else ""
            rows.append([
                r.url + fb,
                _c("200 LIVE", C.GREEN + C.BOLD),
                t, r.server_header or "-", ms, tech,
            ])
        _table(["URL", "Status", "Title", "Server", "Time", "Tech"], rows,
               col_colors=[C.CYAN, None, C.WHITE, C.YELLOW, C.GRAY, C.GREEN])

    if redirect_3xx:
        _section(f"↪  REDIRECTS  —  3xx  ({len(redirect_3xx)} hosts)")
        rows = []
        for r in redirect_3xx:
            rows.append([r.url, _c(str(r.status_code), C.CYAN),
                         r.redirect_url or "-"])
        _table(["URL", "Code", "Redirects To"], rows,
               col_colors=[C.GRAY, None, C.CYAN])

    if protected_403:
        _section(f"🔒  PROTECTED  —  403  ({len(protected_403)} hosts)")
        rows = [[_c(r.url, C.GRAY), _c("403", C.YELLOW),
                 r.server_header or "-"] for r in protected_403]
        _table(["URL", "Code", "Server"], rows,
               col_colors=[C.GRAY, None, C.GRAY])

    # ── Sensitive paths ──────────────────────────────────────────────────────
    all_real_findings = [
        (r.url, f)
        for r in live_200
        for f in r.sensitive_paths_found
        if f.confidence in ("HIGH", "MEDIUM", "LOW")
    ]
    all_protected_paths = [
        (r.url, f)
        for r in live_probes
        for f in r.sensitive_paths_found
        if f.confidence == "PROTECTED"
    ]

    if all_real_findings:
        _section(f"🔥  SENSITIVE PATHS  —  REAL FINDINGS  ({len(all_real_findings)})")
        rows = []
        order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        for url, f in sorted(all_real_findings,
                              key=lambda x: order.get(x[1].confidence, 3)):
            conf_col = (C.RED if f.confidence == "HIGH" else
                        C.YELLOW if f.confidence == "MEDIUM" else C.GREEN)
            rows.append([
                _c(url, C.CYAN),
                _c(f.path, C.WHITE),
                _c(str(f.status), C.GREEN),
                _c(f.confidence, conf_col + C.BOLD),
                f.reason[:55],
            ])
        _table(["Base URL", "Path", "Status", "Confidence", "Reason"], rows)
    else:
        _section("SENSITIVE PATHS")
        _ok("No real sensitive paths found (false-positive filtering active)")

    if all_protected_paths:
        _section(f"🔒  PROTECTED PATHS (403/401)  ({len(all_protected_paths)})")
        _info("Endpoints exist but require authentication — not direct findings")
        rows = []
        for url, f in all_protected_paths[:20]:
            rows.append([_c(url, C.GRAY), f.path, _c(str(f.status), C.YELLOW)])
        _table(["Base URL", "Path", "Status"], rows,
               col_colors=[C.GRAY, C.WHITE, None])

    # ── Takeover hints ───────────────────────────────────────────────────────
    if takeover_hints:
        _section(f"⚠  SUBDOMAIN TAKEOVER HINTS  ({len(takeover_hints)})")
        _warn("Manual verification required before reporting!")
        rows = []
        for e in takeover_hints:
            rows.append([_c(e.hostname, C.RED), e.cname or "-", e.takeover_hint or "-"])
        _table(["Subdomain", "CNAME", "Hint"], rows,
               col_colors=[C.RED, C.YELLOW, C.WHITE])

    # ── TLS ──────────────────────────────────────────────────────────────────
    valid_tls = [t for t in tls_infos if not t.error]
    if valid_tls:
        _section("TLS / SSL")
        rows = []
        for t in valid_tls:
            days  = str(t.days_to_expiry) if t.days_to_expiry is not None else "?"
            d_col = (C.RED if (t.days_to_expiry is not None and t.days_to_expiry < 30)
                     else C.GREEN)
            exp   = (_c("EXPIRED", C.RED) if t.is_expired
                     else _c(f"{days}d", d_col))
            ss    = (_c("self-signed", C.YELLOW) if t.self_signed
                     else _c("CA-signed", C.GREEN))
            sni   = _c(" [SNI]", C.CYAN) if t.sni_retry else ""
            rows.append([f"{t.host}:{t.port}", t.subject_cn or "-",
                         t.tls_version or "-", t.cipher_suite or "-",
                         exp, ss + sni])
        _table(["Endpoint", "CN", "TLS", "Cipher", "Expiry", "CA/Notes"], rows,
               col_colors=[C.CYAN, C.WHITE, C.YELLOW, C.GRAY, None, None])

    # ── Nuclei (MOD-4) ───────────────────────────────────────────────────────
    if nuclei_results:
        _section(f"🔥  NUCLEI FINDINGS  —  Critical + High  ({len(nuclei_results)})")
        _warn("Nuclei results require manual verification before reporting")
        rows = []
        for nr in sorted(nuclei_results,
                         key=lambda x: 0 if x.severity == "CRITICAL" else 1):
            col = C.RED + C.BOLD if nr.severity == "CRITICAL" else C.RED
            rows.append([
                _c(nr.severity, col),
                nr.template_id[:35],
                nr.name[:40],
                _c(nr.host, C.CYAN),
                nr.matched_at[:45],
                (nr.description or "-")[:45],
            ])
        _table(
            ["Severity", "Template", "Name", "Host", "Matched At", "Description"],
            rows)
    else:
        _section("NUCLEI FINDINGS")
        _ok("No Nuclei Critical/High findings")

    # ── NVD CVEs ─────────────────────────────────────────────────────────────
    if cve_findings:
        _section(f"CVE FINDINGS  ({len(cve_findings)} potential — verify manually)")
        rows = []
        for host, c in sorted(cve_findings, key=lambda x: -(x[1].cvss_score or 0)):
            col   = _severity_color(c.severity)
            score = _c(f"{c.cvss_score or '?':>4}", col)
            sev   = _c((c.severity or "?").ljust(8), col)
            rows.append([host, c.cve_id, f"{c.product}/{c.version}",
                         score, sev, (c.description or "")[:60]])
        _table(["Host", "CVE ID", "Product", "CVSS", "Severity", "Description"],
               rows, col_colors=[C.CYAN, C.YELLOW, C.WHITE, None, None, C.GRAY])
    else:
        _section("CVE FINDINGS")
        _ok("No NVD CVEs correlated")

    # ── Footer ───────────────────────────────────────────────────────────────
    print()
    _ok(f"Database  {_c(args.db, C.CYAN)}")
    _ok(f"HTML      {_c(args.db.replace('.db','_report.html'), C.CYAN)}")
    _ok(f"JSON      {_c(args.db.replace('.db','_report.json'), C.CYAN)}")
    print()


# ===========================================================================
# MAIN PIPELINE
# ===========================================================================

async def run(args: argparse.Namespace) -> None:
    _banner()

    stop_event = asyncio.Event()

    def _shutdown(sig):
        _warn(f"Received {sig.name} — stopping gracefully ...")
        stop_event.set()

    loop = asyncio.get_running_loop()

    def _silent_exc(loop, ctx):
        exc = ctx.get("exception")
        if exc and "DNS" in type(exc).__name__:
            return
        if "future" in ctx.get("message", "").lower():
            return
        loop.default_exception_handler(ctx)

    loop.set_exception_handler(_silent_exc)

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, lambda s=sig: _shutdown(s))
        except NotImplementedError:
            pass

    # ── Target loading ───────────────────────────────────────────────────────
    if args.target:
        entries = [HostEntry(raw=args.target)]
    elif args.hosts:
        entries = parse_hosts_file(args.hosts)
        if not entries:
            _err(f"No targets found in '{args.hosts}'.")
            return
    else:
        _err("No target. Use --target example.com or --hosts hosts.txt")
        return

    try:
        ports = parse_ports(args.ports)
    except ValueError as e:
        _err(f"Port error: {e}")
        return

    _info(
        f"Targets: {_c(str(len(entries)), C.BOLD)}  "
        f"Ports: {_c(str(len(ports)), C.BOLD)}  "
        f"Concurrency: {_c(str(args.concurrency), C.BOLD)}  "
        f"RPS: {_c(str(args.rps), C.BOLD)}"
    )

    conn      = await init_db(args.db)
    bucket    = TokenBucket(args.rps, args.rps * BUCKET_MULTIPLIER)
    semaphore = asyncio.Semaphore(args.concurrency)

    resolver = None
    if HAS_AIODNS:
        resolver = aiodns.DNSResolver(nameservers=["8.8.8.8", "1.1.1.1", "9.9.9.9"])
    else:
        _warn("aiodns not installed — using stdlib DNS (slower)")

    connector       = aiohttp.TCPConnector(
        limit=args.concurrency, ttl_dns_cache=300, force_close=False)
    session_headers = {
        "User-Agent": f"Vulpimancer/{VERSION} (authorised-assessment)",
        "Accept":     "*/*",
    }

    all_tls_infos:     List[TLSInfo]                = []
    all_cve_pairs:     List[Tuple[str, CVEFinding]]  = []
    all_open_ports:    Dict[str, List[PortResult]]   = {}
    all_nuclei:        List[NucleiResult]            = []
    all_nmap_results:  List[Dict]                    = []

    async with aiohttp.ClientSession(
            connector=connector, headers=session_headers) as session:

        # ── Phase 0: Subdomain Enumeration ──────────────────────────────────
        if args.subdomains:
            _section("PHASE 0  SUBDOMAIN ENUMERATION")
            extra_entries: List[HostEntry] = []
            for entry in entries:
                hostname = entry.hostname
                try:
                    ipaddress.ip_address(hostname)
                    continue
                except ValueError:
                    pass
                base = extract_registered_domain(hostname)
                _info(f"Enumerating {_c(base, C.CYAN)} ...")
                subs = await enumerate_subdomains(
                    base, resolver, session, args.concurrency,
                    verbose=True,
                    use_external_tools=args.recon,  # MOD-5
                )
                if subs:
                    _ok(f"Found {_c(str(len(subs)), C.BOLD, C.GREEN)} subdomains for {base}")
                    for s in subs:
                        src_tag = _c(f"[{s.source}]", C.MAGENTA)
                        tk_tag  = _c(" ⚠", C.RED) if s.takeover_hint else ""
                        _ok(f"  {_c(s.hostname, C.GREEN)} → "
                            f"{_c(', '.join(s.resolved_ips[:2]), C.GRAY)} "
                            f"{src_tag}{tk_tag}")
                    extra_entries.extend(subs)
                else:
                    _info("No subdomains found")

            entries.extend(extra_entries)
            seen_h: Set[str] = set()
            unique: List[HostEntry] = []
            for e in entries:
                if e.hostname not in seen_h:
                    seen_h.add(e.hostname)
                    unique.append(e)
            entries = unique
            _info(f"Total hosts after enum: {_c(str(len(entries)), C.BOLD)}")

        # ── Phase 1: DNS ─────────────────────────────────────────────────────
        _section("PHASE 1  DNS RESOLUTION")
        _info(f"Resolving {len(entries)} host(s) ...")
        resolved: List[HostEntry] = []
        for entry in entries:
            r = await resolve_host(entry, resolver)
            resolved.append(r)
            await save_dns(conn, r)
            if r.resolved_ips:
                tk = _c(" ⚠ TAKEOVER?", C.RED) if r.takeover_hint else ""
                _ok(f"{_c(r.hostname, C.CYAN)} → "
                    f"{_c(', '.join(r.resolved_ips[:2]), C.GREEN)}{tk}")
            else:
                _warn(f"{_c(r.hostname, C.GRAY)} — unresolved")

        live = [e for e in resolved if e.resolved_ips]
        _info(f"Resolved: {_c(str(len(live)), C.GREEN)}  "
              f"Failed: {_c(str(len(resolved)-len(live)), C.RED if (len(resolved)-len(live)) else C.GRAY)}")

        # ── Phase 2: Port Scanning ───────────────────────────────────────────
        _section("PHASE 2  PORT SCANNING  (double-verify)")
        _info(f"Scanning {len(ports)} ports on {len(live)} host(s) ...")

        for idx, entry in enumerate(live, 1):
            if stop_event.is_set():
                break
            _progress(idx, len(live), entry.hostname)
            results      = await scan_ports(
                entry, ports,
                timeout=min(args.timeout, 3.0),
                concurrency=min(args.concurrency, 200))
            open_results = [r for r in results if r.is_open]
            all_open_ports[entry.hostname] = open_results
            for r in results:
                await save_port(conn, r)
            if open_results:
                pts = "  ".join(
                    _c(f"{r.port}/{r.service_guess or '?'}", C.YELLOW)
                    for r in open_results)
                _ok(f"{_c(entry.hostname, C.CYAN)}  {pts}")

        total_open = sum(len(v) for v in all_open_ports.values())
        _info(f"Open ports: {_c(str(total_open), C.YELLOW if total_open else C.GRAY)}")

        # ── MOD-2: Optional Nmap ─────────────────────────────────────────────
        if args.nmap:
            for entry in live:
                if stop_event.is_set():
                    break
                open_for_host = all_open_ports.get(entry.hostname, [])
                open_port_list = [r.port for r in open_for_host]
                nmap_res = run_nmap(entry.hostname, ports=open_port_list or None)
                all_nmap_results.extend(nmap_res)
                # Enrich PortResult objects with nmap service/version
                nmap_by_port = {r["port"]: r for r in nmap_res}
                for pr in open_for_host:
                    if pr.port in nmap_by_port:
                        pr.nmap_service = nmap_by_port[pr.port].get("service", "")
                        pr.nmap_version = nmap_by_port[pr.port].get("version", "")

        # ── Phase 4/7: HTTP Probing ──────────────────────────────────────────
        _section("PHASE 4/7  HTTP PROBING + PATH DISCOVERY  (MOD-1: retry + fallback)")

        probe_tasks = []
        for entry in live:
            if stop_event.is_set():
                break
            open_for_host  = all_open_ports.get(entry.hostname, [])
            open_port_nums = {r.port for r in open_for_host}
            pairs: Set[Tuple[str, Optional[int]]] = set()
            for p in open_port_nums:
                if p in WEB_PORTS:
                    scheme = "https" if p in HTTPS_PORTS else "http"
                    if scheme in args.schemes:
                        pairs.add((scheme, p if p not in (80, 443) else None))
            for scheme in args.schemes:
                pairs.add((scheme, None))
            if entry.port and entry.port not in (80, 443):
                scheme = "https" if entry.port in HTTPS_PORTS else "http"
                if scheme in args.schemes:
                    pairs.add((scheme, entry.port))
            for scheme, port in pairs:
                probe_tasks.append(
                    probe_host(
                        entry, scheme, port, session,
                        bucket, semaphore,
                        timeout=args.timeout,
                        max_retries=args.retries,
                        probe_paths=not args.no_paths,
                        legacy_tls=args.tls_legacy,
                    ))

        _info(f"Probing {len(probe_tasks)} URL(s) ...")
        probe_results = await asyncio.gather(*probe_tasks)
        live_probes   = [r for r in probe_results if r is not None]

        for r in live_probes:
            await save_probe(conn, r)
            if r.error is None:
                code      = _c(str(r.status_code or "?"), _status_color(r.status_code))
                label     = _c(f"[{_status_label(r.status_code)}]",
                               _status_color(r.status_code))
                title_str = _c(f' "{r.title}"', C.WHITE) if r.title else ""
                fb_tag    = _c(" [HTTP↓]", C.YELLOW) if r.fallback_http else ""
                _ok(f"{_c(r.url, C.CYAN)}{fb_tag}  {code} {label}{title_str}")
                for f in r.sensitive_paths_found:
                    if f.confidence in ("HIGH", "MEDIUM"):
                        _find(f"  {_c(f.path, C.RED)} [{f.status}] "
                              f"— {_c(f.confidence, C.RED + C.BOLD)}: {f.reason}")
            else:
                _info(f"{_c(r.url, C.GRAY)}  {_c(r.error[:60], C.RED)}")

        # ── Phase 5: TLS ─────────────────────────────────────────────────────
        _section("PHASE 5  TLS ANALYSIS  (MOD-3: SNI retry)")
        for entry in live:
            if stop_event.is_set():
                break
            open_for_host = all_open_ports.get(entry.hostname, [])
            tls_port_list = [r.port for r in open_for_host if r.port in HTTPS_PORTS]
            if 443 in ports and 443 not in tls_port_list and entry.resolved_ips:
                tls_port_list.append(443)
            for p in set(tls_port_list):
                t = await analyse_tls(entry.hostname, p, args.timeout,
                                      legacy_tls=args.tls_legacy)
                await save_tls(conn, t)
                all_tls_infos.append(t)
                if t.error:
                    _warn(f"{entry.hostname}:{p}  {_c(t.error[:60], C.RED)}")
                else:
                    days_col = (C.RED if (t.days_to_expiry or 9999) < 30 else C.GREEN)
                    exp      = (_c("EXPIRED", C.RED) if t.is_expired
                                else _c(f"{t.days_to_expiry}d", days_col))
                    sni_tag  = _c(" [SNI-retry]", C.CYAN) if t.sni_retry else ""
                    _ok(f"{_c(entry.hostname, C.CYAN)}:{p}  "
                        f"CN={_c(t.subject_cn or '?', C.WHITE)}  "
                        f"ver={_c(t.tls_version or '?', C.YELLOW)}  "
                        f"expiry={exp}{sni_tag}")

        # ── MOD-4: Nuclei CVE Discovery ──────────────────────────────────────
        if args.nuclei and not stop_event.is_set():
            for entry in live:
                if stop_event.is_set():
                    break
                target_url = (f"https://{entry.hostname}"
                              if 443 in {r.port for r in all_open_ports.get(entry.hostname, [])}
                              else f"http://{entry.hostname}")
                nuc = run_nuclei(
                    target_url,
                    severity_filter=["critical", "high"],
                    timeout=args.nuclei_timeout,
                )
                all_nuclei.extend(nuc)
                for nr in nuc:
                    await save_nuclei(conn, nr)

        # ── Phase 8: NVD CVE ─────────────────────────────────────────────────
        if not args.no_cve and not stop_event.is_set():
            _section("PHASE 8  CVE CORRELATION  (NIST NVD — potential only)")
            pv_pairs: Set[Tuple[str, str]] = set()
            for r in live_probes:
                if r.server_header:
                    m = re.match(r"([A-Za-z\-]+)[/ ]([\d.]+)", r.server_header)
                    if m:
                        pv_pairs.add((m.group(1), m.group(2)))
                for tech in r.technologies:
                    if "/" in tech:
                        p2, v = tech.split("/", 1)
                        pv_pairs.add((p2.strip(), v.strip()))

            if pv_pairs:
                _info(f"Checking {len(pv_pairs)} product/version pair(s) via NIST NVD ...")
                for product, version in pv_pairs:
                    if stop_event.is_set():
                        break
                    cve_list   = await lookup_cves(product, version, session)
                    hosts_with = set()
                    for r in live_probes:
                        if r.server_header:
                            m = re.match(r"([A-Za-z\-]+)[/ ]([\d.]+)",
                                         r.server_header or "")
                            if m and m.group(1) == product:
                                hosts_with.add(r.host)
                        for tech in r.technologies:
                            if tech.startswith(f"{product}/"):
                                hosts_with.add(r.host)
                    if not hosts_with:
                        hosts_with = {"unknown"}
                    for finding in cve_list:
                        for host in hosts_with:
                            await save_cve(conn, host, finding)
                            all_cve_pairs.append((host, finding))
                        col = _severity_color(finding.severity)
                        _warn(f"  {_c(finding.cve_id, col)}  "
                              f"CVSS={_c(str(finding.cvss_score or '?'), col)}  "
                              f"[Potential] {product}/{version}")
                    await asyncio.sleep(10)  # NVD rate: 6 req/min without key
            else:
                _info("No versioned technologies detected for NVD lookup")

    # ── Reports ──────────────────────────────────────────────────────────────
    report_html = args.db.replace(".db", "_report.html")
    report_json = args.db.replace(".db", "_report.json")

    await generate_html_report(args.db, report_html)

    live_200_count   = sum(1 for r in live_probes
                           if r.error is None and r.status_code == 200)
    real_sensitive   = sum(
        1 for r in live_probes
        for f in r.sensitive_paths_found
        if f.confidence in ("HIGH", "MEDIUM", "LOW"))

    summary = {
        "generated_at":         datetime.now(tz=timezone.utc).isoformat(),
        "tool_version":         VERSION,
        "db":                   args.db,
        "hosts_scanned":        len(resolved),
        "hosts_resolved":       len(live),
        "subdomains_found":     sum(1 for e in resolved if e.is_subdomain),
        "open_ports":           sum(len(v) for v in all_open_ports.values()),
        "live_200":             live_200_count,
        "sensitive_real":       real_sensitive,
        "cve_findings":         len(all_cve_pairs),
        "critical_high_cves":   len([c for _, c in all_cve_pairs
                                     if (c.severity or "").upper()
                                     in ("CRITICAL", "HIGH")]),
        "nuclei_findings":      len(all_nuclei),
        "nuclei_critical_high": len([nr for nr in all_nuclei
                                     if nr.severity in ("CRITICAL", "HIGH")]),
        "takeover_hints":       sum(1 for e in resolved if e.takeover_hint),
        "http_fallbacks":       sum(1 for r in live_probes if r.fallback_http),
        "sni_retries":          sum(1 for t in all_tls_infos if t.sni_retry),
        "nmap_used":            args.nmap,
        "recon_used":           getattr(args, "recon", False),
    }
    Path(report_json).write_text(json.dumps(summary, indent=2), encoding="utf-8")
    await conn.close()

    print_terminal_summary(
        resolved, all_open_ports, live_probes,
        all_tls_infos, all_cve_pairs,
        all_nuclei, all_nmap_results, args)


# ===========================================================================
# CLI
# ===========================================================================

def parse_args(argv=None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=(
            f"Vulpimancer v{VERSION} — Async Recon Engine (authorised security assessments only)\n"
            "\n"
            "New flags in v1:\n"
            "  --nmap          Run nmap -sV -Pn on discovered open ports\n"
            "  --recon         Run subfinder + amass in parallel threads\n"
            "  --nuclei        Run Nuclei (Critical + High filter)\n"
            "  --tls-legacy    Allow TLS 1.0/1.1 for compatibility\n"
            "  --ports top1000 Scan top-1000 nmap ports (default: common)\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="WARNING: Authorised use only — never scan without permission.")

    # Target
    p.add_argument("--hosts",   default=None,
                   help="Path to newline-delimited target file")
    p.add_argument("--target",  default=None,
                   help="Single target (e.g. --target example.com)")

    # Output
    p.add_argument("--db",      default=DEFAULT_DB,
                   help="SQLite output database path")

    # Scanning
    p.add_argument("--ports",   default="common",
                   help="Port spec: web | common | top1000 | extended | 80,443 | 8000-8100")
    p.add_argument("--rps",         type=float, default=DEFAULT_RPS,
                   help="Requests per second (rate limit)")
    p.add_argument("--concurrency", type=int,   default=DEFAULT_CONCURRENCY,
                   help="Async concurrency limit")
    p.add_argument("--timeout",     type=float, default=DEFAULT_TIMEOUT,
                   help="Per-request timeout in seconds (MOD-1: 15s)")
    p.add_argument("--retries",     type=int,   default=DEFAULT_RETRIES,
                   help="HTTP retry attempts (MOD-1: 3)")
    p.add_argument("--schemes", nargs="+", default=DEFAULT_SCHEMES,
                   choices=["http", "https"],
                   help="HTTP schemes to probe")

    # Phase flags
    p.add_argument("--subdomains",  action="store_true",
                   help="Enable subdomain enumeration (crt.sh + brute-force)")
    p.add_argument("--recon",       action="store_true",
                   help="MOD-5: Also run subfinder + amass in parallel threads")
    p.add_argument("--nmap",        action="store_true",
                   help="MOD-2: Run nmap -sV -Pn on open ports after TCP scan")
    p.add_argument("--nuclei",      action="store_true",
                   help="MOD-4: Run Nuclei (Critical + High) against live hosts")
    p.add_argument("--nuclei-timeout", type=int, default=120,
                   dest="nuclei_timeout",
                   help="Nuclei subprocess timeout in seconds (default: 120)")
    p.add_argument("--tls-legacy",  action="store_true", dest="tls_legacy",
                   help="MOD-3: Allow TLS 1.0/1.1 for older server compatibility")
    p.add_argument("--no-paths",    action="store_true",
                   help="Skip sensitive path probing")
    p.add_argument("--no-cve",      action="store_true",
                   help="Skip NIST NVD CVE correlation")

    # Logging
    p.add_argument("--log-file", default=None,
                   help="JSON rotating log file path (silent — CLI never crashes)")
    p.add_argument("--debug",    action="store_true",
                   help="Write DEBUG messages to log file")
    p.add_argument("--version",  action="version", version=VERSION)

    return p.parse_args(argv)


def main(argv=None) -> None:
    args  = parse_args(argv)
    level = logging.DEBUG if args.debug else logging.WARNING
    if args.log_file:
        fh = logging.handlers.RotatingFileHandler(
            args.log_file, maxBytes=10 * 1024 * 1024,
            backupCount=5, encoding="utf-8")
        fh.setFormatter(_JsonFormatter())
        fh.setLevel(level)
        log.addHandler(fh)
        log.setLevel(level)
    try:
        asyncio.run(run(args))
    except KeyboardInterrupt:
        print()
        _warn("Interrupted by user")


if __name__ == "__main__":
    main()
