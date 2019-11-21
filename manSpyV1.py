#!/usr/bin/python
# -*- coding: utf-8 -*-
#                   ____
#  __ _  ___ ____  / __/__  __ __
# /  ' \/ _ `/ _ \_\ \/ _ \/ // /
#/_/_/_/\_,_/_//_/___/ .__/\_, /
#                   /_/   /___/
#
# Auteur	     : Mansour eddih
# Outil 		 : ManSpy
# Usage		     : ./manspy.py 'exemple.com' (ou) python manspy.py 'exemple.com'.
# La description : cet outil permet de automatiser le processus d'analyse de sécurité à la multitude
#                  d’outils de sécurité Linux disponibles et certains scripts personnalisés.


# Importer les librairies
import sys
import socket
import subprocess
import os
import time
import signal
import random
import string
import threading
import re
from urlparse import urlsplit



# Temps d'analyse éc..
intervals = (
    ('h', 3600),
    ('m', 60),
    ('s', 1),
    )
def display_time(seconds, granularity=3):
    result = []
    seconds = seconds + 1
    for name, count in intervals:
        value = seconds // count
        if value:
            seconds -= value * count
            result.append("{}{}".format(value, name))
    return ' '.join(result[:granularity])


def url_maker(url):
	if not re.match(r'http(s?)\:', url):
		url = 'http://' + url
	parsed = urlsplit(url)
	host = parsed.netloc
	if host.startswith('www.'):
		host = host[4:]
	return host

def verifier_internet():
    os.system('ping -c1 google.com > ms_net 2>&1')
    if "0% packet loss" in open('ms_net').read():
        val = 1
    else:
        val = 0
    os.system('rm ms_net > /dev/null 2>&1')
    return val


# la classe de module de couleur
class bcolors:
    HEADER = '\033[95m'
    TBLUE = '\033[94m'
    TGREEN = '\033[92m'
    TLRED = '\033[91m'
    WARNING = '\033[93m'
    BADFAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

    BG_YLL = "\033[103m"
    BG_LB = "\033[105m"
    BG_Cyan = '\033[46m'
    BG_ERR_TXT = '\033[41m'  #Pour les erreurs critiques et les plantages
    BG_HEAD_TXT = '\033[100m'
    BG_ENDL_TXT = '\033[46m'
    BG_CRIT_TXT = '\033[45m'
    BG_HIGH_TXT = '\033[41m'
    BG_MED_TXT = '\033[43m'
    BG_LOW_TXT = '\033[44m'
    BG_INFO_TXT = '\033[42m'


# Classifie la gravité de la vulnérabilité
def vul_info(val):
    resultat = ''
    if val == 'c':
        resultat = bcolors.BG_CRIT_TXT + " critique " + bcolors.ENDC
    elif val == 'e':
        resultat = bcolors.BG_HIGH_TXT + " élevé " + bcolors.ENDC
    elif val == 'm':
        resultat = bcolors.BG_MED_TXT + " moyen " + bcolors.ENDC
    elif val == 'f':
        resultat = bcolors.BG_LOW_TXT + " faible " + bcolors.ENDC
    else:
        resultat = bcolors.BG_INFO_TXT + " info " + bcolors.ENDC
    return resultat
    
    
# Les index
proc_haut = bcolors.BADFAIL + "●" + bcolors.ENDC
proc_med = bcolors.WARNING + "●" + bcolors.ENDC
proc_fible = bcolors.TGREEN + "●" + bcolors.ENDC

# Lie la vulnérabilité au niveau de menace...
def vul_as_info(v1, v2, v3):
    print (bcolors.BOLD + "Niveau de menace de vulnérabilité" + bcolors.ENDC)
    print ("\t" + vul_info(v2) + " " + bcolors.WARNING + str(rep_outil[v1][0]) + bcolors.ENDC)
    print (bcolors.BOLD + "Définition de la vulnérabilité" + bcolors.ENDC)
    print ("\t" + bcolors.BADFAIL + str(outils_correctifs[v3 - 1][1]) + bcolors.ENDC)
    print (bcolors.BOLD + "Assainissement de la vulnérabilité" + bcolors.ENDC)
    print ("\t" + bcolors.TGREEN + str(outils_correctifs[v3 - 1][2]) + bcolors.ENDC)

# ManSpy Help
def helper():
    print (bcolors.TBLUE + "Les informations:" + bcolors.ENDC)
    print ("------------")
    print ("\t./manSpy.py exemple.com: analyse le domaine 'exemple.com'")
    print ("\t./manSpy.py --help     : Affiche ce contexte d'aide.")
    print (bcolors.TBLUE + "Interactives:" + bcolors.ENDC)
    print ("------------")
    print (bcolors.TLRED +"\tCtrl+C:"+bcolors.ENDC+" Ignore le test en cours.")
    print (bcolors.TLRED +"\tCtrl+Z:"+bcolors.ENDC+" Quitte ManSpy.")
    print (bcolors.TBLUE + "Les index:" + bcolors.ENDC)
    print ("--------")
    print ("\t[" + proc_haut + "]: Le processus de numérisation peut prendre plus de temps (non prévisible).")
    print ("\t[" + proc_med + "]: Le processus de numérisation peut prendre moins de 10 minutes.")
    print ("\t[" + proc_fible + "]: Le processus de numérisation peut prendre moins d’une minute ou deux.")
    print (bcolors.BG_Cyan + "Les informations de vulnérabilité" + bcolors.ENDC)
    print ("--------------------------")
    print ("\t" + vul_info(
        'c') + ": A besion une attention immédiate car cela peut entraîner des compromissions ou une indisponibilité du service.")
    print ("\t" + vul_info(
        'e') + "    : Peut ne pas conduire à un compromis immédiat, mais les chances de probabilité sont grandes.")
    print ("\t" + vul_info(
        'm') + "  : L'attaquant peut mettre en corrélation plusieurs vulnérabilités de ce type pour lancer une attaque sophistiquée.")
    print ("\t" + vul_info('f') + "     : Pas un problème grave, mais il est recommandé d'assister à la conclusion.")
    print ("\t" + vul_info(
        'i') + "    : Ne pas classé comme une vulnérabilité,tout simplement une alerte informationnelle utile à prendre en compte.\n")


# Effacment
def clear():
        sys.stdout.write("\033[F")
        sys.stdout.write("\033[K")

# ManSpy Logo
def logo():
    print (bcolors.WARNING)
    print("""\
 _____ ______   ________  ________   ________  ________  ___    ___ 
|\   _ \  _   \|\   __  \|\   ___  \|\   ____\|\   __  \|\  \  /  /|
\ \  \\\__\ \  \ \  \|\  \ \  \\ \  \ \  \___|\ \  \|\  \ \  \/  / /
 \ \  \\|__| \  \ \   __  \ \  \\ \  \ \_____  \ \   ____\ \    / / 
  \ \  \    \ \  \ \  \ \  \ \  \\ \  \|____|\  \ \  \___|\/  /  /  
   \ \__\    \ \__\ \__\ \__\ \__\\ \__\____\_\  \ \__\ __/  / /    
    \|__|     \|__|\|__|\|__|\|__| \|__|\_________\|__||\___/ /     
                                       \|_________|    \|___|/      

     """ + bcolors.TLRED + """(Mansour Eddih - Maryem Abouhafes - Hanane Rajji '4isi')
                            """)
    print (bcolors.ENDC)

class Spinner:
    occupe = False
    retard = 0.05

    @staticmethod
    def spinning_cursor():
        while 1:
            for cursor in '|/\\': yield cursor #←↑↓→
            #for cursor in '←↑↓→': yield cursor !! prob affichage !!!
    def __init__(self, retard=None):
        self.spinner_generator = self.spinning_cursor()
        if retard and float(retard): self.retard = retard

    def spinner_task(self):
        try:
            while self.occupe:
                #sys.stdout.write(next(self.spinner_generator))
                print bcolors.BG_ERR_TXT+next(self.spinner_generator)+bcolors.ENDC,
                sys.stdout.flush()
                time.sleep(self.retard)
                sys.stdout.write('\b')
                sys.stdout.flush()
        except (KeyboardInterrupt, SystemExit):
            #clear()
            print "\n\t"+ bcolors.BG_ERR_TXT+"ManSpy à reçu une série des clicks sur Ctrl + C. Quitter..." +bcolors.ENDC
            sys.exit(1)

    def start(self):
        self.occupe = True
        threading.Thread(target=self.spinner_task).start()

    def stop(self):
        try:
            self.occupe = False
            time.sleep(self.retard)
        except (KeyboardInterrupt, SystemExit):
            #clear()
            print "\n\t"+ bcolors.BG_ERR_TXT+"ManSpy à reçu une série des clicks sur Ctrl + C. Quitter..." +bcolors.ENDC
            sys.exit(1)

spinner = Spinner()


noms_outils = [
                
                
                ["host", "host - Vérifie l'existence d'une adresse IPV6.", "host", 1],
                ["aspnet_config_err", "ASP.Net Misconfiguration - Vérifie si ASP.Net Misconfiguration.", "wget", 1],
                ["wp_check", "WordPress Checker - Vérifie l'installation de WordPress.", "wget", 1],
                ["drp_check", "Drupal Checker - Vérifie l’installation de Drupal.", "wget", 1],
                ["joom_check", "Joomla Checker - Vérifie l’installation de Joomla.", "wget", 1],
                ["uniscan", "Uniscan - Vérifie les fichiers robots.txt et sitemap.xml", "uniscan", 1],
                ["wafw00f", "Wafw00f - Vérifications des pare-feu applicatifs.", "wafw00f", 1],
                ["nmap", "Nmap - Analyse rapide [seulement quelques vérifications de ports] "," nmap ", 1],
                ["theharvester", "The Harvester - Analyse les emails en utilisant la recherche passive de Google.", "theharvester", 1],
                ["dnsrecon", "DNSRecon - tente plusieurs transferts de zone sur des serveurs de noms.", "dnsrecon", 1],
                ["féroce", "Féroce - Tentatives de transfert de zone [Pas de force brutale]", "féroce", 1],
                ["dnswalk", "DNSWalk - Tentative de transfert de zone.", "dnswalk", 1],
                ["whois", "WHOis - Vérifications des informations de contact de l'administrateur.", "whois", 1],
                ["nmap_header", "Nmap [Vérification du filtre XSS] - Vérifie si l'en-tête de protection XSS est présent.", "nmap", 1],
                ["nmap_sloris", "Nmap [Slowloris DoS] - Vérifications de la vulnérabilité de déni de service de Slowloris.", "nmap", 1],
                ["sslyze_hbleed", "SSLyze - Vérifie uniquement la vulnérabilité Heartbleed.", "sslyze", 1],
                ["nmap_hbleed", "Nmap [Heartbleed] - Vérifie uniquement la vulnérabilité de Heartbleed.", "nmap", 1],
                
                
                ["nmap_poodle", "Nmap [POODLE] - Vérifie uniquement la vulnérabilité du caniche.", "nmap", 1],
                ["nmap_ccs", "Nmap [Injection OpenSSL CCS] - Vérifie uniquement l'injection CCS.", "nmap", 1],
                ["nmap_freak", "Nmap [FREAK] - Vérifie uniquement la vulnérabilité de FREAK.", "nmap", 1],
                ["nmap_logjam", "Nmap [LOGJAM] - Vérifications de la vulnérabilité de LOGJAM.", "nmap", 1],
                ["sslyze_ocsp", "SSLyze - Vérifie l'agrafage OCSP.", "sslyze", 1],
                ["sslyze_zlib", "SSLyze - Vérifications de la compression ZLib Deflate.", "sslyze", 1],
                ["sslyze_reneg", "SSLyze - Vérifie la prise en charge de la renégociation sécurisée et la renégociation du client.", "sslyze", 1],
                ["sslyze_resum", "SSLyze - Vérifie la prise en charge de la reprise de session avec [ID de session / tickets TLS].", "sslyze", 1],
                ["lbd", "LBD - Vérifications des équilibreurs de charge DNS / HTTP.", "lbd", 1],
                ["golismero_dns_malware", "Golismero - Vérifie si le domaine est spoofé ou détourné.", "golismero", 1],
                ["golismero_heartbleed", "Golismero - Recherche uniquement la vulnérabilité Heartbleed.", "golismero", 1],
                ["golismero_brute_url_predictables", "Golismero - BruteForces pour certains fichiers du domaine.", "golismero", 1],
                ["golismero_brute_directories", "Golismero - BruteForces pour certains répertoires du domaine.", "golismero", 1],
                ["golismero_sqlmap", "Golismero - SQLMap [ne récupère que la bannière DB]", "golismero", 1],
                ["dirb", "DirB - Brute la cible pour les répertoires ouverts.", "dirb", 1],
                ["xsser", "XSSer - Vérifications d'attaques de script intersite [XSS].", "xsser", 1],
                ["golismero_ssl_scan", "Analyses SSL Golismero - Effectue des analyses liées à SSL.", "golismero", 1],
                ["golismero_zone_transfer", "Transfert de zone Golismero - Tentative de transfert de zone.", "golismero", 1],
                ["golismero_nikto", "Golismero Nikto Scans - Utilise Nikto Plugin pour détecter les vulnérabilités.", "golismero", 1],
                ["golismero_brute_subdomains", "Sous-domaines de Golismero Bruter - Découverte de sous-domaines de forces brutes.", "golismero", 1],
                ["dnsenum_zone_transfer", "DNSEnum - Tentative de transfert de zone.", "dnsenum", 1],
                ["fierce_brute_subdomains", "Fierce Subdomains Bruter - Découverte du sous-domaine des forces brutes.", "farce", 1],
                ["dmitry_email", "DMitry - Récolte de manière passive les emails du domaine.", "dmitry", 1],
                ["dmitry_subdomains", "DMitry - Récolte de manière passive des sous-domaines du domaine.", "dmitry", 1],
                ["nmap_telnet", "Nmap [TELNET] - Vérifie si le service TELNET est en cours d'exécution.", "nmap", 1],
                ["nmap_ftp", "Nmap [FTP] - Vérifie si le service FTP est en cours d'exécution.", "nmap", 1],
                ["nmap_stuxnet", "Nmap [STUXNET] - Vérifie si l'host est affecté par le ver STUXNET.", "nmap", 1],
                ["webdav", "WebDAV - Vérifie si WEBDAV est activé sur le répertoire personnel.", "davtest", 1],
                ["golismero_finger", "Golismero - Fait une empreinte digitale sur le domaine.", "golismero", 1],
                
                
               
               
                ["uniscan_filebrute", "Uniscan - Brutes pour les noms de fichiers sur le domaine.", "uniscan", 1],
                ["uniscan_dirbrute", "Uniscan - Annuaires Brutes sur le domaine", "uniscan", 1],
                ["uniscan_ministresser", "Uniscan - Tester le domaine.", "uniscan", 1],
                ["uniscan_rfi", "Uniscan - Vérifications LFI, RFI et RCE.", "uniscan", 1],
                ["uniscan_xss", "Uniscan - Vérifications XSS, SQLi, BSQLi et autres vérifications.", "uniscan", 1],
                ["nikto_xss", "Nikto - Vérifie l'en-tête XSS d'Apache Expect.", "nikto", 1],
                ["nikto_subrute", "Nikto - Brutes Subdomains.", "nikto", 1],
                ["nikto_shellshock", "Nikto - Vérifications du bogue Shellshock.", "nikto", 1],
                ["nikto_internalip", "Nikto - Recherche des fuites internes IP", "nikto", 1],
                ["nikto_putdel", "Nikto - Vérifie si HTTP PUT DEL.", "nikto", 1],
                ["nikto_headers", "Nikto - Vérifie les en-têtes de domaine.", "nikto", 1],
                ["nikto_ms01070", "Nikto - Vérifications de la vulnérabilité MS10-070.", "nikto", 1],
                ["nikto_servermsgs", "Nikto - Vérifications des problèmes de serveur.", "nikto", 1],
                ["nikto_outdated", "Nikto - Vérifie si le serveur est obsolète.", "nikto", 1],
                ["nikto_httpoptions", "Nikto - Vérifie les options HTTP sur le domaine.", "nikto", 1],
                ["nikto_cgi", "Nikto - Énumère les répertoires CGI.", "nikto", 1],
                ["nikto_ssl", "Nikto - Effectue des vérifications SSL.", "nikto", 1],
                ["nikto_sitefiles", "Nikto - Vérifie la présence de fichiers intéressants sur le domaine.", "nikto", 1],
                ["nikto_paths", "Nikto - Vérifie les chemins injectables.", "nikto", 1],
                ["dnsmap_brute", "DNSMap - Brutes Subdomains.", "dnsmap", 1],
                ["nmap_sqlserver", "Nmap - Vérifications de la base de données MS-SQL Server", "nmap", 1],
                ["nmap_mysql", "Nmap - Vérifie la base de données MySQL", "nmap", 1],
                ["nmap_oracle", "Nmap - Vérifications de la base de données ORACLE", "nmap", 1],
                ["nmap_rdp_udp", "Nmap - Vérifie le service Bureau à distance via UDP", "nmap", 1],
                ["nmap_rdp_tcp", "Nmap - Vérifie le service Bureau à distance via TCP", "nmap", 1],
                ["nmap_full_ps_tcp", "Nmap - Effectue une analyse complète du port TCP", "nmap", 1],
                ["nmap_full_ps_udp", "Nmap - Effectue une analyse complète du port UDP", "nmap", 1],
                ["nmap_snmp", "Nmap - Vérifications du service SNMP", "nmap", 1],
                ["aspnet_elmah_axd", "Vérifications pour ASP.net Elmah Logger", "wget", 1],
                ["nmap_tcp_smb", "Vérifie le service SMB sur TCP", "nmap", 1],
                ["nmap_udp_smb", "Vérifications du service SMB sur UDP", "nmap", 1],
                ["wapiti", "Wapiti - Vérifications de SQLi, RCE, XSS et autres vulnérabilités", "wapiti", 1],
                ["nmap_iis", "Nmap - Vérifications de IIS WebDAV", "nmap", 1],
                ["whatweb", "WhatWeb - Vérifie l'en-tête de protection X-XSS", "whatweb", 1]
            ]


cmd_outils   = [
                ["host ",""],
                ["wget -O temp_aspnet_config_err --tries=1 ","/%7C~.aspx"],
                ["wget -O temp_wp_check --tries=1 ","/wp-admin"],
                ["wget -O temp_drp_check --tries=1 ","/user"],
                ["wget -O temp_joom_check --tries=1 ","/administrator"],
                ["uniscan -e -u ",""],
                ["wafw00f ",""],
                ["nmap -F --open -Pn ",""],
                ["theharvester -l 50 -b google -d ",""],
                ["dnsrecon -d ",""],
                ["fierce -wordlist xxx -dns ",""],
                ["dnswalk -d ","."],
                ["whois ",""],
                ["nmap -p80 --script http-security-headers -Pn ",""],
                ["nmap -p80,443 --script http-slowloris --max-parallelism 500 -Pn ",""],
                ["sslyze --heartbleed ",""],
                ["nmap -p443 --script ssl-heartbleed -Pn ",""],
                ["nmap -p443 --script ssl-poodle -Pn ",""],
                ["nmap -p443 --script ssl-ccs-injection -Pn ",""],
                ["nmap -p443 --script ssl-enum-ciphers -Pn ",""],
                ["nmap -p443 --script ssl-dh-params -Pn ",""],
                ["sslyze --certinfo=basic ",""],
                ["sslyze --compression ",""],
                ["sslyze --reneg ",""],
                ["sslyze --resum ",""],
                ["lbd ",""],
                ["golismero -e dns_malware scan ",""],
                ["golismero -e heartbleed scan ",""],
                ["golismero -e brute_url_predictables scan ",""],
                ["golismero -e brute_directories scan ",""],
                ["golismero -e sqlmap scan ",""],
                ["dirb http://"," -fi"],
                ["xsser --all=http://",""],
                ["golismero -e sslscan scan ",""],
                ["golismero -e zone_transfer scan ",""],
                ["golismero -e nikto scan ",""],
                ["golismero -e brute_dns scan ",""],
                ["dnsenum ",""],
                ["fierce -dns ",""],
                ["dmitry -e ",""],
                ["dmitry -s ",""],
                ["nmap -p23 --open -Pn ",""],
                ["nmap -p21 --open -Pn ",""],
                ["nmap --script stuxnet-detect -p445 -Pn ",""],
                ["davtest -url http://",""],
                ["golismero -e fingerprint_web scan ",""],
                ["uniscan -w -u ",""],
                ["uniscan -q -u ",""],
                ["uniscan -r -u ",""],
                ["uniscan -s -u ",""],
                ["uniscan -d -u ",""],
                ["nikto -Plugins 'apache_expect_xss' -host ",""],
                ["nikto -Plugins 'subdomain' -host ",""],
                ["nikto -Plugins 'shellshock' -host ",""],
                ["nikto -Plugins 'cookies' -host ",""],
                ["nikto -Plugins 'put_del_test' -host ",""],
                ["nikto -Plugins 'headers' -host ",""],
                ["nikto -Plugins 'ms10-070' -host ",""],
                ["nikto -Plugins 'msgs' -host ",""],
                ["nikto -Plugins 'outdated' -host ",""],
                ["nikto -Plugins 'httpoptions' -host ",""],
                ["nikto -Plugins 'cgi' -host ",""],
                ["nikto -Plugins 'ssl' -host ",""],
                ["nikto -Plugins 'sitefiles' -host ",""],
                ["nikto -Plugins 'paths' -host ",""],
                ["dnsmap ",""],
                ["nmap -p1433 --open -Pn ",""],
                ["nmap -p3306 --open -Pn ",""],
                ["nmap -p1521 --open -Pn ",""],
                ["nmap -p3389 --open -sU -Pn ",""],
                ["nmap -p3389 --open -sT -Pn ",""],
                ["nmap -p1-65535 --open -Pn ",""],
                ["nmap -p1-65535 -sU --open -Pn ",""],
                ["nmap -p161 -sU --open -Pn ",""],
                ["wget -O temp_aspnet_elmah_axd --tries=1 ","/elmah.axd"],
                ["nmap -p445,137-139 --open -Pn ",""],
                ["nmap -p137,138 --open -Pn ",""],
                ["wapiti "," -f txt -o temp_wapiti"],
                ["nmap -p80 --script=http-iis-webdav-vuln -Pn ",""],
                ["whatweb "," -a 1"]
            ]

rep_outil   = [
                ["N'a pas d'adresse IPv6. C'est bien d'en avoir un.","i",1],
                ["ASP.Net est mal configuré pour afficher les erreurs de pile de serveurs à l'écran.","m",2],
                ["WordPress Installation trouvée. Rechercher les vulnérabilités correspond à cette version.","i",3],
                ["Drupal Installation trouvée. Rechercher les vulnérabilités correspond à cette version.","i",4],
                ["Joomla Installation trouvée. Rechercher les vulnérabilités correspond à cette version.","i",5],
                ["robots.txt/sitemap.xml a trouvé. Vérifiez ces fichiers pour toute information.","i",6],
                ["Aucun pare-feu d'application Web à été détecté","m",7],
                ["Certains ports sont ouverts. Effectuer une analyse complète manuellement.","f",8],
                ["Adresses email trouvées.","f",9],
                ["Transfert de zone réussi avec DNSRecon. Reconfigurer le DNS immédiatement","e",10],
                ["Transfert de zone réussi avec fierce. Reconfigurer le DNS immédiatement.","e",10],
                ["Transfert de zone réussi avec dnswalk. Reconfigurer le DNS immédiatement.","e",10],
                ["Informations Whois disponibles publiquement.","i",11],
                ["Le filtre de protection XSS est désactivé.","m",12],
                ["Vulnérable au déni de service de Slowloris.","c",13],
                ["Vulnérabilité HEARTBLEED trouvée avec SSLyze.","e",14],
                ["Vulnérabilité HEARTBLEED trouvée avec Nmap.","e",14],
                ["Vulnérabilité POODLE détectée.","e",15],
                ["OpenSSL CCS Injection détectée","e",16],
                ["Vulnérabilité FREAK détectée","e",17],
                ["Vulnérabilité de LOGJAM détectée.","e",18],
                ["Réponse OCSP infructueuse.","m",19],
                ["Le serveur prend en charge la compression Deflate.","m",20],
                ["La renégociation sécurisée n'est pas prise en charge.","m",21],
                ["Reprise sécurisée non prise en charge avec (ID de session / Billets TLS).","m",22],
                ["Aucun équilibreur de charge basé sur DNS / HTTP trouvé.","f",23],
                ["le domaine est spoofed/hijacked.","e",24],
                ["Vulnérabilité HEARTBLEED trouvée avec Golismero.","e",14],
                ["OOpen Files Found avec Golismero BruteForce.","m",25],
                ["Open Directories Found avec Golismero BruteForce.","m",26],
                ["DB Banner récupéré avec SQLMap.","f",27],
                ["épertoires ouverts trouvés avec DirB.","m",26],
                ["XSSer a trouvé des vulnérabilités XSS.","c",28],
                ["Trouvé des vulnérabilités SSL liées à Golismero.","m",29],
                ["Transfert de zone réussi avec Golismero. Reconfigurer DNS immédiatement.","e",10],
                ["Golismero Nikto Plugin a découvert des vulnérabilités.","m",30],
                ["FSous-domaines trouvés avec Golismero.","m",31],
                ["Transfert de zone réussi avec DNSEnum. Reconfigurer DNS immédiatement.","e",10],
                ["Sous-domaines trouvés avec Fierce.","m",31],
                ["Adresses email découvertes avec DMitry.","f",9],
                ["Sous-domaines découverts avec DMitry.","m",31],
                ["Telnet Service Detected.","e",32],
                ["Vulnérable à STUXNET.", "c", 34],
                ["WebDAV activé.", "m", 35],
                ["Trouvé des informations à travers Fingerprinting.", "f", 36],
                ["Ouvrir les fichiers trouvés avec Uniscan.", "m", 25],
                ["Open Directories Found with Uniscan.", "m", 26],
                ["Vulnérable aux stress tests.", "e", 37],
                ["Uniscan a détecté un possible LFI, RFI ou RCE.", "e", 38],
                ["Uniscan a détecté une éventuelle XSS, SQLi, BSQLi.", "e", 39],
                ["En-tête XSS non présent dans Apache Expect.", "m", 12],
                ["Sous-domaines trouvés avec Nikto.", "m", 31],
                ["Serveur Web vulnérable au bogue Shellshock.", "c", 40],
                ["Le serveur Web présente une adresse IP interne.", "f", 41],
                ["Méthodes HTTP PUT DEL activées.", "m", 42],
                ["Quelques en-têtes vulnérables exposés.", "m", 43],
                ["Serveur Web vulnérable à MS10-070.", "e", 44],
                ["Quelques problèmes trouvés sur le serveur Web.", "m", 30],
                ["Le serveur Web est obsolète.", "e", 45],
                ["Quelques problèmes rencontrés avec les options HTTP.", "f", 42],
                ["CGI Directories Enumerated.", "f", 26],
                ["Vulnérabilités identifiées dans les scans SSL.", "m", 29],
                ["Fichiers intéressants détectés.", "m", 25],
                ["Chemins injectables détectés.", "f", 46],
                ["Sous-domaines trouvés avec DNSMap.", "m", 31],
                ["Service de base de données MS-SQL détecté.", "f", 47],
                ["Service de base de données MySQL détecté.", "f", 47],
                ["Service ORACLE DB détecté.", "f", 47],
                ["Serveur RDP détecté sur UDP.", "e", 48],
                ["Serveur RDP détecté sur TCP.", "e", 48],
                ["Les ports TCP sont ouverts", "f", 8],
                ["Les ports UDP sont ouverts", "f", 8],
                ["Service SNMP détecté.", "m", 49],
                ["Elmah est configuré.", "m", 50],
                ["Les ports SMB sont ouverts sur TCP", "m", 51],
                ["Les ports SMB sont ouverts sur UDP", "m", 51],
                ["Wapiti a découvert une série de vulnérabilités", "e", 30],
                ["IIS WebDAV est activé", "m", 35],
                ["La protection X-XSS n'est pas présente", "m", 12]

            ]

outils_status = [
                ["a IPv6", 1, proc_fible, "<15s", "ipv6", ["introuvable", "a IPv6"]],
                ["Erreur de serveur", 0, proc_fible, "<30s", "asp.netmisconf", ["incapable de résoudre l'adresse de l'host", "Connexion expirée"]],
                ["wp-login", 0, proc_fible, "<30s", "wpcheck", ["impossible de résoudre l'adresse de l'host", "connexion expirée"]],
                ["drupal", 0, proc_fible, "<30s", "drupalcheck", ["incapable de résoudre l'adresse de l'host", "La connexion a expiré"]],
                ["joomla", 0, proc_fible, "<30s", "joomlacheck", ["incapable de résoudre l'adresse de l'host", "La connexion a expiré"]],
                ["[+]", 0, proc_fible, "<40s", "robotscheck", ["Utilisation de la valeur non initialisée dans unpack à"]],
                ["No WAF", 0, proc_fible, "<45s", "wafcheck", ["semble être en panne"]],
                ["tcp open", 0, proc_med, "<2m", "nmapopen", ["Impossible de résoudre"]],
                ["Aucun email trouvé", 1, proc_med, "<3m", "moissonneuse", ["Aucun host trouvé", "Aucun email trouvé"]],
                ["[+] Le transfert de zone a réussi !!", 0, proc_fible, "<20s", "dnsreconzt", ["Impossible de résoudre le domaine"]],
                ["Whoah, ça a marché", 0, proc_fible, "<30s", "fiercezt", ["none"]],
                ["0 erreurs", 0, proc_fible, "<35s", "dnswalkzt", ["!!! 0 échecs, 0 avertissements, 3 erreurs."]],
                ["Email Email:", 0, proc_fible, "<25s", "whois", ["Aucune correspondance pour le domaine"]],
                ["Le filtre XSS est désactivé", 0, proc_fible, "<20s", "nmapxssh", ["Échec de la résolution"]],
                ["VULNERABLE", 0, proc_haut, "<45m", "nmapdos", ["Échec de la résolution"]],
                ["Le serveur est vulnérable à Heartbleed", 0, proc_fible, "<40s", "sslyzehb", ["Impossible de résoudre le nom d'host"]],
                ["VULNERABLE", 0, proc_fible, "<30s", "nmap1", ["Impossible de résoudre"]],
                ["VULNERABLE", 0, proc_fible, "<35s", "nmap2", ["Impossible de résoudre"]],
                ["VULNERABLE", 0, proc_fible, "<35s", "nmap3", ["Impossible de résoudre"]],
                ["VULNERABLE", 0, proc_fible, "<30s", "nmap4", ["Impossible de résoudre"]],
                ["VULNERABLE", 0, proc_fible, "<35s", "nmap5", ["Impossible de résoudre"]],
                ["ERREUR - l'état de la réponse OCSP n'aboutit pas", 0, proc_fible,"<25s", "sslyze1", ["Impossible de résoudre le nom d'host"]],
                ["VULNERABLE", 0, proc_fible, "<30s", "sslyze2", ["Impossible de résoudre le nom d'host"]],
                ["VULNERABLE", 0, proc_fible, "<25s", "sslyze3", ["Impossible de résoudre le nom d'host"]],
                ["VULNERABLE", 0, proc_fible, "<30s", "sslyze4", ["Impossible de résoudre le nom d'host"]],
                ["N'utilise PAS l'équilibrage de charge", 0, proc_med, "<4m", "lbd", ["NON TROUVE"]],
                ["Aucune vulnérabilité trouvée", 1, proc_fible, "<45s", "golism1", ["Impossible de résoudre le nom de domaine", "Aucune vulnérabilité trouvée"]],
                ["Aucune vulnérabilité trouvée", 1, proc_fible, "<40s", "golism2", ["Impossible de résoudre le nom de domaine", "Aucune vulnérabilité trouvée"]],
                ["Aucune vulnérabilité trouvée", 1, proc_fible, "<45s", "golism3", ["Impossible de résoudre le nom de domaine", "Aucune vulnérabilité trouvée"]],
                ["Aucune vulnérabilité trouvée", 1, proc_fible, "<40s", "golism4", ["Impossible de résoudre le nom de domaine", "Aucune vulnérabilité trouvée"]],
                ["Aucune vulnérabilité trouvée", 1, proc_fible, "<45s", "golism5", ["Impossible de résoudre le nom de domaine", "Aucune vulnérabilité trouvée"]],
                ["TROUVE: 0", 1, proc_haut, "<35m", "dirb", ["PEU NE RÉSOLVE host", "TROUVE: 0"]],
                ["Impossible de trouver une vulnérabilité!", 1, proc_med, "<4m", "xsser", ["XSSer ne fonctionne pas correctement!", "Impossible de trouver une vulnérabilité!"]],
                ["ID d’occurrence", 0, proc_fible, "<45s", "golism6", ["Impossible de résoudre le nom de domaine"]],
                ["Transfert de zone DNS réussi", 0, proc_fible, "<30s", "golism7", ["Impossible de résoudre le nom de domaine"]],
                ["Nikto a trouvé 0 vulnérabilités", 1, proc_med, "<4m", "golism8", ["Impossible de résoudre le nom de domaine", "Nikto a trouvé 0 vulnérabilités"]],
                ["Fuite possible du sous-domaine", 0, proc_haut, "<30m", "golism9", ["Impossible de résoudre le nom de domaine"]],
                ["Echec de la requête d'enregistrement AXFR:", 1, proc_fible, "<45s", "dnsenumzt", ["La requête d'enregistrement NS a échoué:", "Echec de la requête d'enregistrement AXFR", "aucun enregistrement NS pour"]],
                ["0 entrées trouvées", 1, proc_haut, "<75m", "fierce2", ["trouvé 0 entrées", "is gimp"]],
                ["0 message (s) trouvé (s)", 1, proc_fible, "<30s", "dmitry1", ["Impossible de localiser l'adresse IP de l'host", "0 message (s) trouvé (s)"]],
                ["Trouvé 0 sous-domaine (s) possible (s)", 1, proc_fible, "<35s", "dmitry2", ["Impossible de localiser l'adresse IP de l'host", "Trouvé 0 sous-domaine (s) possible"]],
                ["open", 0, proc_fible, "<15s", "nmaptelnet", ["Impossible de résoudre"]],
                ["open", 0, proc_fible, "<15s", "nmapftp", ["Impossible de résoudre le problème"]],
                ["open", 0, proc_fible, "<20s", "nmapstux", ["Impossible de résoudre le problème"]],
                ["SUCCEED", 0, proc_fible, "<30s", "webdav", ["n'est pas activé par DAV ou n'est pas accessible."]],
                ["Aucune vulnérabilité trouvée", 1, proc_fible, "<15s", "golism10", ["Impossible de résoudre le nom de domaine", "Aucune vulnérabilité trouvée"]],
                ["[+]", 0, proc_med, "<2m", "uniscan2", ["Utilisation de la valeur non initialisée dans unpack à"]],
                ["[+]", 0, proc_med, "<5m", "uniscan3", ["Utilisation de la valeur non initialisée dans unpack à"]],
                ["[+]", 0, proc_med, "<9m", "uniscan4", ["Utilisation de la valeur non initialisée dans unpack à"]],
                ["[+]", 0, proc_med, "<8m", "uniscan5", ["Utilisation de la valeur non initialisée dans unpack à"]],
                ["[+]", 0, proc_med, "<9m", "uniscan6", ["Utilisation de la valeur non initialisée dans unpack à"]],
                ["0 article (s) signalé (s)", 1, proc_fible, "<35s", "nikto1", ["ERREUR: impossible de résoudre le nom d'host", "0 article (s) signalé (s)", "Aucun serveur Web trouvé", "0 host (s) testé (s) "]],
                ["0 article (s) signalé (s)", 1, proc_fible, "<35s", "nikto2", ["ERREUR: impossible de résoudre le nom d'host", "0 article (s) signalé (s)", "Aucun serveur Web trouvé", "0 host (s) testé (s) "]],
                ["0 article (s) signalé (s)", 1, proc_fible, "<35s", "nikto3", ["ERREUR: impossible de résoudre le nom d'host", "0 article (s) signalé (s)", "Aucun serveur Web trouvé", "0 host (s) testé (s) "]],
                ["0 article (s) signalé (s)", 1, proc_fible, "<35s", "nikto4", ["ERREUR: impossible de résoudre le nom d'host", "0 article (s) signalé (s)", "Aucun serveur Web trouvé", "0 host (s) testé (s) "]],
                ["0 article (s) signalé (s)", 1, proc_fible, "<35s", "nikto5", ["ERREUR: impossible de résoudre le nom d'host", "0 article (s) signalé (s)", "Aucun serveur Web trouvé", "0 host (s) testé (s) "]],
                ["0 article (s) signalé (s)", 1, proc_fible, "<35s", "nikto6", ["ERREUR: impossible de résoudre le nom d'host", "0 article (s) signalé (s)", "Aucun serveur Web trouvé", "0 host (s) testé (s) "]],
                ["0 article (s) signalé (s)", 1, proc_fible, "<35s", "nikto7", ["ERREUR: impossible de résoudre le nom d'host", "0 article (s) signalé (s)", "Aucun serveur Web trouvé", "0 host (s) testé (s) "]],
                ["0 article (s) signalé (s)", 1, proc_fible, "<35s", "nikto8", ["ERREUR: impossible de résoudre le nom d'host", "0 article (s) signalé (s)", "Aucun serveur Web trouvé", "0 host (s) testé (s) "]],
                ["0 article (s) signalé (s)", 1, proc_fible, "<35s", "nikto9", ["ERREUR: impossible de résoudre le nom d'host", "0 article (s) signalé (s)", "Aucun serveur Web trouvé", "0 host (s) testé (s) "]],
                ["0 article (s) signalé (s)", 1, proc_fible, "<35s", "nikto10", ["ERREUR: impossible de résoudre le nom d'host", "0 article (s) signalé (s)", "Aucun serveur Web trouvé", "0 host (s) testé (s) "]],
                ["0 article (s) signalé (s)", 1, proc_fible, "<35s", "nikto11", ["ERREUR: impossible de résoudre le nom d'host", "0 article (s) signalé (s)", "Aucun serveur Web trouvé", "0 host (s) testé (s) "]],
                ["0 article (s) signalé (s)", 1, proc_fible, "<35s", "nikto12", ["ERREUR: impossible de résoudre le nom d'host", "0 article (s) signalé (s)", "Aucun serveur Web trouvé", "0 host (s) testé (s) "]],
                ["0 article (s) signalé (s)", 1, proc_fible, "<35s", "nikto13", ["ERREUR: impossible de résoudre le nom d'host", "0 article (s) signalé (s)", "Aucun serveur Web trouvé", "0 host (s) testé (s) "]],
                ["0 élément (s) signalé (s)", 1, proc_fible, "<35s", "nikto14", "ERREUR: Impossible de résoudre le nom d'host, 0 élément (s) signalé (s)"],
                ["# 1", 0, proc_haut, "<30m", "dnsmap_brute", ["[+] 0 (sous) domaines et 0 adresses IP trouvées"]],
                ["open", 0, proc_fible, "<15s", "nmapmssql", ["Impossible de résoudre le problème"]],
                ["open", 0, proc_fible, "<15s", "nmapmysql", ["Impossible de résoudre"]],
                ["open", 0, proc_fible, "<15s", "nmaporacle", ["Impossible de résoudre le problème"]],
                ["open", 0, proc_fible, "<15s", "nmapudprdp", ["Impossible de résoudre"]],
                ["open", 0, proc_fible, "<15s", "nmaptcprdp", ["Impossible de résoudre le problème"]],
                ["open", 0, proc_haut, "> 50m", "nmapfulltcp", ["Impossible de résoudre"]],
                ["open", 0, proc_haut, "> 75m", "nmapfulludp", ["Impossible de résoudre"]],
                ["open", 0, proc_fible, "<30s", "nmapsnmp", ["Impossible de résoudre le problème"]],
                ["Journal des erreurs de Microsoft SQL Server", 0, proc_fible, "<30s", "elmahxd", ["impossible de résoudre l'adresse de l'host", "Connexion expirée"]],
                ["open", 0, proc_fible, "<20s", "nmaptcpsmb", ["Impossible de résoudre le problème"]],
                ["open", 0, proc_fible, "<20s", "nmapudpsmb", ["Impossible de résoudre le problème"]],
                ["Host:", 0, proc_med, "<5m", "wapiti", ["none"]],
                ["WebDAV est ENABLED", 0, proc_fible, "<40s", "nmapwebdaviis", ["Échec de la résolution"]],
                ["X-XSS-Protection [1", 1, proc_med, "<3m", "whatweb", ["Expiration du délai", "Erreur de socket", "X-XSS-Protection [1"]]

            ]
outils_correctifs = [
					    [1, "Il ne s'agit pas d'une vulnérabilité, mais simplement d'une alerte informative. L'host ne prend pas en charge IPv6. IPv6 offre davantage de sécurité car IPSec (responsable de CIA - Confidentiality, Integrity and Availablity) est intégré à ce modèle. Il est donc bon d'avoir Prise en charge IPv6. ",
    "Il est recommandé de mettre en œuvre IPv6. Vous trouverez plus d'informations sur la mise en oeuvre de IPv6 à partir de cette ressource. Https://www.cisco.com/c/en/us/solutions/collateral/enterprise/cisco-on-cisco/ IPv6-Implementation_CS.html "],
                        [2, "Fuite d'informations sensibles détectée. L'application ASP.Net ne filtre pas les caractères illégaux dans l'URL. L'attaquant injecte un caractère spécial (% 7C ~ .aspx) pour que l'application crache des informations sensibles sur la pile de serveurs." ,
                        "Il est recommandé de filtrer les caractères spéciaux dans l'URL et de définir une page d'erreur personnalisée dans de telles situations au lieu d'afficher les messages d'erreur par défaut. Cette ressource vous aide à configurer une page d'erreur personnalisée sur une application Microsoft .Net. Https: // docs.microsoft.com/en-us/aspnet/web-forms/overview/older-versions-getting-started/deploying-web-site-projects/displaying-a-custom-error-page-cs "],
                        [3, "Il n'est pas mauvais d'avoir un CMS dans WordPress. Il est probable que la version contienne des vulnérabilités ou que des scripts tiers associés à celle-ci puissent comporter des vulnérabilités",
                        "Il est recommandé de masquer la version de WordPress. Cette ressource contient plus d'informations sur la sécurisation de votre blog WordPress. Https://codex.wordpress.org/Hardening_WordPress"],
                        [4, "Il n'est pas mauvais d'avoir un CMS dans Drupal. Il est probable que la version contienne des vulnérabilités ou que des scripts tiers associés à celle-ci puissent comporter des vulnérabilités",
                        "Il est recommandé de dissimuler la version de Drupal. Cette ressource contient des informations supplémentaires sur la sécurisation de votre blog Drupal. Https://www.drupal.org/docs/7/site-building-best-practices/ensure-that- votre-site est sécurisé "],
                        [5, "Il n'est pas mauvais d'avoir un CMS dans Joomla. Il est probable que la version contienne des vulnérabilités ou que des scripts tiers associés à celle-ci puissent comporter des vulnérabilités",
                        "Il est recommandé de dissimuler la version de Joomla. Cette ressource contient des informations supplémentaires sur la sécurisation de votre blog Joomla. Https://www.incapsula.com/blog/10-tips-to-improve-your-joomla-website- security.html "],
                        [6, "Parfois, robots.txt ou sitemap.xml peuvent contenir des règles telles que certains liens auxquels les robots d'exploration et les moteurs de recherche ne sont pas supposés accéder / indexés. Les moteurs de recherche peuvent ignorer ces liens, mais les attaquants pourront y accéder directement. ",
                        "Il est judicieux de ne pas inclure de liens sensibles dans les robots ou les fichiers de sitemap."],
                        [7, "Sans pare-feu pour applications Web, un attaquant peut essayer d’injecter divers modèles d’attaque soit manuellement, soit à l’aide de scanners automatisés. Un scanner automatique peut envoyer des hordes de vecteurs d’attaque et des modèles pour valider une attaque. Il existe également des chances que l’application obtenir DoS`ed (déni de service) ",
                        "Les pare-feu pour applications Web offrent une excellente protection contre les attaques Web courantes telles que XSS, SQLi, etc. Ils offrent également une ligne de défense supplémentaire à votre infrastructure de sécurité. Cette ressource contient des informations sur les pare-feu pour applications Web qui pourraient convenir à votre application. Https: // www .gartner.com / reviews / market / web-application-firewall "],
                        [8, "Les ports ouverts donnent aux pirates un indice pour exploiter les services. Les pirates tentent de récupérer les informations des bannières par les ports et comprennent le type de service exécuté par l'host",
                        "Il est recommandé de fermer les ports des services inutilisés et d'utiliser un pare-feu pour filtrer les ports si nécessaire. Cette ressource peut donner davantage d'informations. Https://security.stackexchange.com/a/145781/6137"],
                        [9, "Il est très moins probable que des adresses e-mail soient utilisées pour compromettre une cible. Toutefois, les attaquants l'utilisent comme donnée complémentaire pour rassembler des informations autour de la cible. Un attaquant peut utiliser le nom d'utilisateur de l'adresse e-mail et mener des attaques en force brutale. sur les serveurs de messagerie, mais également sur d’autres panneaux légitimes tels que SSH, CMS, etc., avec une liste de mots de passe, car ils portent un nom légitime. Il s’agit toutefois d’un scénario dans le noir, l’attaquant pouvant réussir ou non, en fonction du niveau d'intérêt ",
                        "Etant donné que les chances d’exploitation sont faibles, il n’est pas nécessaire de prendre des mesures. Une réparation appropriée consisterait à choisir différents noms d’utilisateur pour différents services, ce qui serait plus judicieux."],
                    [10, "Le transfert de zone révèle des informations topologiques critiques sur la cible. L'attaquant sera en mesure d'interroger tous les enregistrements et aura des connaissances plus ou moins complètes sur votre host.",
    "La bonne pratique consiste à limiter le transfert de zone en indiquant au maître quelles sont les adresses IP des esclaves auxquels l'accès peut être accordé pour la requête. Cette ressource SANS fournit des informations supplémentaires. Https://www.sans.org/reading-room/ livres blancs / dns / sécuriser-dns-zone-transfer-868 "],
                     [11, "L’adresse e-mail de l’administrateur et d’autres informations (adresse, téléphone, etc.) sont disponibles publiquement. Un attaquant peut utiliser ces informations pour exploiter une attaque. Ceci ne peut pas être utilisé pour mener une attaque directe, car ce n’est pas le cas. Cependant, un attaquant utilise ces données pour créer des informations sur la cible. ",
"Certains administrateurs auraient intentionnellement rendu ces informations publiques. Dans ce cas, vous pouvez les ignorer. Dans le cas contraire, il est recommandé de les masquer. Cette ressource fournit des informations sur ce correctif. Http://www.name.com/blog/ how-tos / tutorial-2/2013/06 / protégez-vos-informations-personnelles-avec-whois-privacy / "],
                    [12, "Comme la cible manque de cet en-tête, les anciens navigateurs seront sujets aux attaques XSS réfléchies.",
                    "Les navigateurs modernes ne rencontrent aucun problème avec cette vulnérabilité (en-têtes manquants). Cependant, il est vivement recommandé aux anciens navigateurs d'être mis à niveau."],
                    [13, "Cette attaque fonctionne en ouvrant plusieurs connexions simultanées au serveur Web et les maintient en vie aussi longtemps que possible en envoyant en continu des requêtes HTTP partielles, qui ne sont jamais terminées. Elles passent facilement à travers IDS en envoyant des requêtes partielles.",
                    "Si vous utilisez Apache Module,` mod_antiloris` pourrait vous aider. Pour d'autres configurations, vous pouvez trouver des solutions plus détaillées pour cette ressource. Https://www.acunetix.com/blog/articles/slow-http-dos-attacks-mitigate -apache-http-server / "],
                    [14, "Cette vulnérabilité porte gravement atteinte à la confidentialité des informations privées de votre host. Un attaquant peut maintenir la connexion TLS vivante et récupérer au maximum 64 Ko de données par battement de coeur.",
                    "PFS (Perfect Forward Secrecy) peut être implémenté pour rendre le décryptage difficile. Des informations complètes sur les mesures correctives et les ressources sont disponibles à l'adresse http://heartbleed.com/"],
                   [15, "By exploiting this vulnerability, an attacker will be able gain access to sensitive data in a n encrypted session such as session ids, cookies and with those data obtained, will be able to impersonate that particular user.",
							"This is a flaw in the SSL 3.0 Protocol. A better remediation would be to disable using the SSL 3.0 protocol. For more information, check this resource. https://www.us-cert.gov/ncas/alerts/TA14-290A"],
                  	[16, "This attacks takes place in the SSL Negotiation (Handshake) which makes the client unaware of the attack. By successfully altering the handshake, the attacker will be able to pry on all the information that is sent from the client to server and vice-versa",
							"Upgrading OpenSSL to latest versions will mitigate this issue. This resource gives more information about the vulnerability and the associated remediation. http://ccsinjection.lepidum.co.jp/"],
                    [17, "Avec cette vulnérabilité, l'attaquant sera en mesure de mener une attaque par MiTM et de compromettre ainsi le facteur de confidentialité.",
                    "La mise à niveau de OpenSSL vers la dernière version résoudra ce problème. Les versions antérieures à 1.1.0 sont exposées à cette vulnérabilité. Vous trouverez plus d'informations dans cette ressource. Https://bobcares.com/blog/how-to-fix-sweet32- anniversaires-vulnérabilité-cve-2016-2183 / "],
                    [18, "Avec l'attaque LogJam, l'attaquant sera en mesure de rétrograder la connexion TLS, ce qui lui permettra de lire et de modifier les données transmises via la connexion.",
                    "Assurez-vous que toutes les bibliothèques TLS que vous utilisez sont à jour, que les serveurs que vous maintenez utilisent des nombres premiers de 2048 bits ou plus, et que les clients que vous gérez rejettent les nombres principaux de Diffie-Hellman inférieurs à 1024 bits. Pour plus d'informations, reportez-vous à la section ressource. https://weakdh.org/ "],
                    [19, "Autorise des attaquants distants à provoquer un déni de service (plantage) et éventuellement à obtenir des informations sensibles dans les applications qui utilisent OpenSSL, via un message de négociation ClientHello malformé déclenchant un accès mémoire en dehors des limites."
                    "Les versions OpenSSL 0.9.8h à 0.9.8q et 1.0.0 à 1.0.0c sont vulnérables. Il est recommandé de mettre à niveau la version OpenSSL. Vous trouverez plus de ressources et d’informations ici. Https://www.openssl.org/news /secadv/20110208.txt "],
                    [20, "autrement appelé BREACH atack, exploite la compression dans le protocole HTTP sous-jacent. Un attaquant sera en mesure d'obtenir des adresses électroniques, des jetons de session, etc., à partir du trafic Web crypté TLS.",
                    "Désactiver la compression TLS n'atténue pas cette vulnérabilité. La première étape consiste à désactiver la compression Zlib, suivie des autres mesures mentionnées dans cette ressource. Http://breachattack.com/"],					    
                [21, "Appelée autrement attaque par texte brut, qui permet aux attaquants de MiTM d’insérer des données dans des sessions HTTPS et éventuellement d’autres types de sessions protégées par TLS ou SSL, en envoyant une demande non authentifiée traitée rétroactivement par un serveur contexte post-renégociation. ",
                "Les étapes détaillées de la correction peuvent être trouvées dans ces ressources. Https://securingtomorrow.mcafee.com/technical-how-to/tips-securing-ssl-renegotiation/ https://www.digicert.com/news/2011- 06-03-ssl-renego / "],
                [22, "Cette vulnérabilité permet à des attaquants de voler des sessions TLS existantes à des utilisateurs.",
                "Le meilleur conseil est de désactiver la reprise de session. Pour renforcer la reprise de session, suivez cette ressource qui contient des informations considérables. Https://wiki.crashtest-security.com/display/KB/Harden+TLS+Session+Resumption"],
                [23, "Cela n'a rien à voir avec les risques de sécurité. Toutefois, les attaquants peuvent utiliser cette indisponibilité d'équilibreurs de charge comme un avantage pour exploiter une attaque par déni de service sur certains services ou sur l'application elle-même."
                "Les équilibreurs de charge sont fortement encouragés pour toutes les applications Web. Ils améliorent les performances et la disponibilité des données en cas de panne du serveur. Pour en savoir plus sur les équilibreurs de charge et leur configuration, consultez cette ressource. Https: //www.digitalocean. com / communauté / tutoriels / qu'est-ce que l'équilibrage de charge "],
                [24, "Un attaquant peut transmettre des requêtes arrivant à l'URL légitime ou à l'application Web à une adresse tierce ou à l'emplacement de l'attaquant pouvant servir de logiciel malveillant et affecter l'ordinateur de l'utilisateur final.",
                "Il est vivement recommandé de déployer DNSSec sur la cible de l'host. Le déploiement complet de DNSSEC garantit que l'utilisateur final se connecte au site Web ou à un autre service correspondant à un nom de domaine particulier. Pour plus d'informations, consultez cette ressource. Https: / /www.cloudflare.com/dns/dnssec/how-dnssec-works/ "],
                [25, "Les attaquants peuvent trouver une quantité considérable d'informations dans ces fichiers. Il existe même des chances que les attaquants obtiennent des informations critiques à partir de ces fichiers.",
                "Il est recommandé de bloquer ou de restreindre l'accès à ces fichiers, sauf en cas de nécessité."],
                [26, "Les attaquants peuvent trouver une quantité considérable d'informations dans ces répertoires. Il existe même des chances que les attaquants obtiennent des informations critiques à partir de ces répertoires.",
                "Il est recommandé de bloquer ou de restreindre l'accès à ces répertoires, sauf en cas de nécessité."],
                [27, "Peut ne pas être vulnérable SQLi. Un attaquant sera en mesure de savoir que l'host utilise un backend pour l'opération.",
                "La capture de bannières devrait être restreinte et l'accès aux services de l'extérieur devrait être réduit au minimum."],
                [28, "Un attaquant sera capable de voler des cookies, de déformer une application Web ou de se rediriger vers une adresse tierce pouvant servir de logiciel malveillant.",
                "La validation des entrées et la désinfection des sorties peuvent totalement empêcher les attaques XSS. Les attaques XSS peuvent être atténuées à l'avenir en suivant correctement une méthodologie de codage sécurisé. La ressource complète suivante fournit des informations détaillées sur la résolution de cette vulnérabilité. Https: // www. owasp.org/index.php/XSS_(Cross_Site_Scripting)_Prevention_Cheat_Sheet "],
                [29, "Des vulnérabilités liées à SSL annulent le facteur de confidentialité. Un attaquant peut effectuer une attaque par MiTM, intrépéter et espionner la communication.",
                "Une mise en œuvre correcte et une version mise à niveau des bibliothèques SSL et TLS sont essentielles pour bloquer les vulnérabilités liées à SSL."],
                [30, "Un scanner particulier a détecté plusieurs vulnérabilités qu'un attaquant pourrait tenter d'exploiter la cible.",
                "Reportez-vous à MS-Rapport-de-vulnérabilite pour afficher les informations complètes de la vulnérabilité, une fois l'analyse terminée."],        				
                     [31, "Les attaquants peuvent collecter davantage d'informations sur les sous-domaines relatifs au domaine parent. Ils peuvent même rechercher d'autres services dans les sous-domaines et essayer de connaître l'architecture de la cible. L'attaquant a même des chances de trouver des vulnérabilités en tant que surface d'attaque. devient plus grand avec plus de sous-domaines découverts. ",
                    "Il est parfois sage de bloquer les sous-domaines tels que le développement, le déploiement vers le monde extérieur, car cela donne plus d'informations à l'attaquant sur la pile technologique. Les pratiques de nommage complexes permettent également de réduire la surface d'attaque, car les attaquants ont du mal à exécuter le sous-domaine dictionnaires et listes de mots. "],
                    [32, "Grâce à ce protocole obsolète, un attaquant peut être capable de mener MiTM et d'autres attaques compliquées.",
                    "Il est vivement recommandé de cesser d'utiliser ce service, qui est largement obsolète. SSH peut être utilisé pour remplacer TELNET. Pour plus d'informations, consultez cette ressource https://www.ssh.com/ssh/telnet"],
                    [33, "Ce protocole ne prend pas en charge les communications sécurisées et l’attaquant a probablement de grandes chances d’écouter la communication. En outre, de nombreux programmes FTP disposent d’exploits disponibles sur le Web, de sorte qu’un attaquant peut planter directement l’application ou obtenir un SHELL. accès à cette cible. ",
                    "Le correctif suggéré consiste à utiliser un protocole SSH au lieu de FTP. Il prend en charge la communication sécurisée et les chances d'attaques de MiTM sont plutôt rares."],
                    [34, "Le StuxNet est un ver 'worm' de niveau 3 qui expose des informations critiques sur l’organisation cible. Il s’agissait d’une cyberarme qui visait à contrecarrer le renseignement nucléaire iranien. Je me demande comment elle est arrivée ici? J'espère que ce n’est pas une fausse Nmap positif;) ",
                    "Il est vivement recommandé d'effectuer une analyse complète des rootkit sur l'host. Pour plus d'informations, consultez cette ressource. Https://www.symantec.com/security_response/writeup.jsp?docid=2010-071400-3123-99&tabid=3 "],
                    [35, "WebDAV est supposé contenir plusieurs vulnérabilités. Dans certains cas, un attaquant peut cacher un fichier DLL malveillant dans le partage WebDAV mais, après avoir convaincu un utilisateur d'ouvrir un fichier parfaitement inoffensif et légitime, exécuter du code dans le contexte de cet utilisateur ",
                    "Il est recommandé de désactiver WebDAV. Vous trouverez sur cette URL des ressources critiques concernant la désactivation de WebDAV. Https://www.networkworld.com/article/2202909/network-security/-webdav-is-bad---says- security-researcher.html "],
                    [36, "Les attaquants font toujours une empreinte digitale sur n'importe quel serveur avant de lancer une attaque. Empreinte digitale leur donne des informations sur le type de serveur, le contenu qu'ils servent, les dernières heures de modification, etc., cela donne à un attaquant plus d'informations sur la cible" ,
                    "Une bonne pratique consiste à masquer les informations au monde extérieur. Dans ce cas, les attaquants auront du mal à comprendre la technologie du serveur et par conséquent à tirer parti d'une attaque."],
                    [37, "Les pirates tentent généralement de rendre inutilisables les applications ou les services Web en inondant la cible, en bloquant l'accès aux utilisateurs légitimes. Cela peut affecter les activités d'une entreprise ou d'une organisation ainsi que la réputation",
                    "En veillant à ce que les équilibreurs de charge appropriés soient en place, en configurant des limites de débit et de multiples restrictions de connexion, ces attaques peuvent être considérablement atténuées."],
                    [38, "Les intrus pourront inclure à distance des fichiers shell et accéder au système de fichiers principal. Ils pourront également lire tous les fichiers. Il est encore plus probable que l’attaquant exécute du code à distance système de fichiers.",
                    "Les pratiques en matière de code sécurisé préviendront principalement les attaques par LFI, RFI et RCE. La ressource suivante fournit des informations détaillées sur les pratiques de codage sécurisé. Https://wiki.sei.cmu.edu/confluence/display/seccode/Top+10+Secure+ Codage + Pratiques "],
                    [39, "Les pirates seront capables de voler des données sur le backend. Ils pourront également s’authentifier sur le site et se faire passer pour n'importe quel utilisateur car ils ont le contrôle total sur le backend. Ils peuvent même effacer toute la base de données. Les attaquants peuvent aussi voler les informations de cookie d'un utilisateur authentifié et il peut même rediriger la cible vers une adresse malveillante ou altérer totalement l'application. ",
                    "La validation des entrées doit être effectuée correctement avant toute interrogation directe des informations de la base de données. Un développeur doit se rappeler de ne pas faire confiance aux entrées des utilisateurs finaux. En suivant une méthodologie de codage sécurisé, attaquez comme SQLi, XSS et BSQLi. Les guides de ressources suivants mettre en œuvre une méthodologie de codage sécurisé pour le développement d'applications. https://wiki.sei.cmu.edu/confluence/display/seccode/Top+10+Secure+Coding+Practices "],
                    [40, "Des attaquants exploitent la vulnérabilité de BASH pour exécuter du code à distance sur la cible. Un attaquant expérimenté peut facilement prendre le contrôle du système cible et accéder aux sources internes de la machine",
                    "Cette vulnérabilité peut être atténuée en appliquant un correctif à la version de BASH. La ressource suivante fournit une analyse approfondie de la vulnérabilité et de la façon de la réduire. Https://www.symantec.com/connect/blogs/shellshock-all-you-need -know-about-bash-bug-vulnérabilité https://www.digitalocean.com/community/tutorials/how-to-protect-your-server-against-the-shellshock-bash-vulnerability "],
                    [41, "Donne à l'attaquant une idée de la façon dont la configuration des adresses est effectuée en interne sur le réseau de l'organisation. La découverte des adresses privées utilisées au sein d'une organisation peut aider les attaquants à mener des attaques au niveau de la couche réseau visant à pénétrer l'infrastructure interne de l'entreprise.",
                    "Limiter les informations de la bannière au monde extérieur à partir du service de publication. Plus d'informations sur la réduction de cette vulnérabilité peuvent être trouvées ici. Https://portswigger.net/kb/issues/00600300_private-ip-addresses-disclosed"],
                    [42, "Un attaquant a des chances de manipuler des fichiers sur le serveur Web.",
                    "Il est recommandé de désactiver les méthodes HTTP PUT et DEL si vous n'utilisez pas de services d'API REST. Les ressources suivantes vous aident à désactiver ces méthodes. Http://www.techstacks.com/howto/disable-http- methods-in-tomcat.html https://docs.oracle.com/cd/E19857-01/820-5627/gghwc/index.html https://developer.ibm.com/answers/questions/321629/how- désactiver-méthodes-http-head-put-delete-option / "],
                    [43, "Les attaquants essaient d'en savoir plus sur la cible grâce à la quantité d'informations exposées dans les en-têtes. Un attaquant peut savoir quel type de pile technologique une application Web met en valeur et de nombreuses autres informations.",
                    "La capture de bannières devrait être restreinte et l'accès aux services de l'extérieur devrait être réduit au minimum."],
                    [44, "Un attaquant qui parviendrait à exploiter cette vulnérabilité pourrait lire des données, telles que l'état d'affichage, qui était chiffré par le serveur. Cette vulnérabilité peut également être utilisée pour la falsification de données, qui, si elle est exploitée correctement, peut être utilisée pour le déchiffrement et la sauvegarde. altérer les données cryptées par le serveur. ",
                    "Microsoft a publié une série de correctifs sur son site Web afin d'atténuer ce problème. Les informations requises pour corriger cette vulnérabilité peuvent être déduites de cette ressource. Https://docs.microsoft.com/en-us/security-updates/securitybulletins/ 2010 / ms10-070 "],
                    [45, "Tout serveur Web obsolète peut contenir plusieurs vulnérabilités, car leur assistance aurait pris fin. Un attaquant peut utiliser cette opportunité pour exploiter ses attaques.",
                    "Il est vivement recommandé de mettre à niveau le serveur Web vers la dernière version disponible."],
                    [46, "Les pirates seront en mesure de manipuler les URL facilement via une requête GET / POST. Ils pourront injecter facilement plusieurs vecteurs d'attaque dans l'URL et être en mesure de surveiller la réponse",
                    "En garantissant des techniques de désinfection appropriées et en utilisant des pratiques de codage sécurisées, il sera impossible à l'attaquant de pénétrer à travers. La ressource suivante donne un aperçu détaillé des pratiques de codage sécurisées. Https://wiki.sei.cmu.edu/confluence/display/ seccode / Top + 10 + Secure + Coding + Practices "],
                    [47, "Puisque l'attaquant a connaissance du type de serveur utilisé par la cible, il pourra lancer un exploit ciblé pour la version en question. Il peut également essayer de s'authentifier à l'aide des informations d'identification par défaut.",
                    "Des correctifs de sécurité opportuns pour le système doivent être installés. Les informations d'identification par défaut doivent être modifiées. Si possible, les informations de la bannière peuvent être modifiées pour tromper l'attaquant. La ressource suivante fournit des informations supplémentaires sur la sécurisation de votre système. Http: // kb.bodhost.com/secure-database-server/ "],
                    [48, "Les attaquants peuvent lancer des exploits distants pour faire planter le service ou utiliser des outils tels que ncrack pour essayer de forcer brute le mot de passe sur la cible.",
                    "Il est recommandé de bloquer le service vers le monde extérieur et de le rendre accessible uniquement via un ensemble d'adresses IP autorisées uniquement. Cette ressource fournit des informations sur les risques, ainsi que sur les étapes permettant de bloquer le service. Https: / /www.perspectiverisk.com/remote-desktop-service-vulnerabilities/ "],
                    [49, "Les pirates seront en mesure de lire les chaînes de la communauté via le service et d'énumérer toute une information de la cible. De plus, il existe plusieurs vulnérabilités d'exécution de code à distance et de déni de service liées aux services SNMP.",
                    "Utilisez un pare-feu pour bloquer les ports du monde extérieur. L'article suivant donne un aperçu du verrouillage du service SNMP. Https://www.techrepublic.com/article/lock-it-down-dont-allow-snmp-to -compromise-network-security / "],
					
				    [50, "Les attaquants pourront trouver les journaux et les informations d'erreur générés par l'application. Ils pourront également voir les codes d'état générés sur l'application. En combinant toutes ces informations, l'attaquant sera en mesure d'exploiter une attaque.",
    "En limitant l'accès à l'application de journalisation du monde extérieur, cela sera amplement suffisant pour atténuer cette faiblesse."],
                    [51, "Les cybercriminels ciblent principalement ce service car il leur est très facile de mener une attaque à distance en exécutant des exploits. WannaCry Ransomware par exemple.",
                    "Exposer le service SMB au monde extérieur est une mauvaise idée. Il est recommandé d’installer les derniers correctifs pour le service afin de ne pas compromettre. La ressource suivante fournit des informations détaillées sur les concepts de SMB Hardening. Https: //kb.iweb. com / hc / fr-fr / articles / 115000274491-Sécurisation-Windows-SMB-et-NetBios-NetBT-Services "]	
				
				
			]

precheck_outils = [
					["wapiti"], ["whatweb"], ["nmap"], ["golismero"], ["host"], ["wget"], ["uniscan"], ["wafw00f"], ["dirb"], ["davtest"], ["theharvester"], ["xsser"], ["dnsrecon"],["fierce"], ["dnswalk"], ["mansour"], ["whois"], ["sslyze"], ["lbd"], ["golismero"], ["dnsenum"],["dmitry"], ["davtest"], ["nikto"], ["dnsmap"]
			     ]

scan_shuffle = list(zip(noms_outils, cmd_outils, rep_outil, outils_status))
random.shuffle(scan_shuffle)
noms_outils, cmd_outils, rep_outil, outils_status = zip(*scan_shuffle)
tool_checks = (len(noms_outils) + len(rep_outil) + len(outils_status)) / 3 

tool = 0

runTest = 1


arg1 = 0
arg2 = 1
arg3 = 2
arg4 = 3
arg5 = 4
arg6 = 5

# Detectevul
rs_vul_list = list()
rs_vul_num = 0
rs_vul = 0

rs_total_elapsed = 0

rs_avail_tools = 0

rs_skipped_checks = 0

if len(sys.argv) == 1 :
    logo()
    helper()
else:
    target = sys.argv[1].lower()

#Vérifier tout d'abord la connectivité...
    ms_internet_dispo = verifier_internet()
    if ms_internet_dispo == 0:
        print ("\t"+ bcolors.BG_ERR_TXT + "Il semble y avoir un problème de connexion à Internet. Veuillez réessayer ou plus tard." +bcolors.ENDC)
        sys.exit(1)

    elif target == '--help' or target == '-h' or target == '--h':
    	logo()
        helper()
        sys.exit(1)
    else:

        target = url_maker(target)
        os.system('rm te* > /dev/null 2>&1') #Effacement des fichiers d'analyse précédents
        os.system('clear')
        os.system('setterm -cursor off')
        logo()
        print bcolors.BG_HEAD_TXT+"[ Vérification des outils d'analyses disponibles... Initiée. ]"+bcolors.ENDC
        indispo_outils = 0
        indispo_outils_noms = list()
        while (rs_avail_tools < len(precheck_outils)):
			precmd = str(precheck_outils[rs_avail_tools][arg1])
			try:
				p = subprocess.Popen([precmd], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,shell=True)
				output, err = p.communicate()
				val = output + err
			except:
				print "\t"+bcolors.BG_ERR_TXT+"ManSpy a été arreté d'une manière brusque...!!"+bcolors.ENDC
				sys.exit(1)
			if "not found" in val:
				print "\t"+bcolors.TBLUE+precheck_outils[rs_avail_tools][arg1]+bcolors.ENDC+bcolors.BADFAIL+"...indisponible."+bcolors.ENDC
				for scanner_index, scanner_val in enumerate(noms_outils):
					if scanner_val[2] == precheck_outils[rs_avail_tools][arg1]:
						scanner_val[3] = 0 #désactiver le scanner car il n'est pas disponible.
						indispo_outils_noms.append(precheck_outils[rs_avail_tools][arg1])
						indispo_outils = indispo_outils + 1
			else:
				print "\t"+bcolors.TBLUE+precheck_outils[rs_avail_tools][arg1]+bcolors.ENDC+bcolors.TGREEN+"...disponible."+bcolors.ENDC
			rs_avail_tools = rs_avail_tools + 1
			clear()
        indispo_outils_noms = list(set(indispo_outils_noms))
        if indispo_outils == 0:
        	print "\t"+bcolors.TGREEN+"Tous les outils d'analyse sont disponibles. Tous les contrôles de vulnérabilité seront effectués par ManSpy."+bcolors.ENDC
        else:
        	print "\t"+bcolors.WARNING+"Certains de ces outils "+bcolors.BADFAIL+str(indispo_outils_noms)+bcolors.ENDC+bcolors.WARNING+" sont indisponibles. ManSpy peut toujours effectuer des tests en excluant ces outils des tests. Veuillez installer ces outils pour utiliser pleinement les fonctionnalités de ManSpy."+bcolors.ENDC
        print bcolors.BG_ENDL_TXT+"[ Vérification des outils d'analyses disponibles... Terminé. ]"+bcolors.ENDC
        print "\n"
        print bcolors.BG_HEAD_TXT+"[Phase d'analyse préliminaire lancée ... chargée "+str(tool_checks)+" vulnerability checks.  ]"+bcolors.ENDC
        #while (tool < 1):
        while(tool < len(noms_outils)):
            print "["+outils_status[tool][arg3]+outils_status[tool][arg4]+"] Déploiement "+str(tool+1)+"/"+str(tool_checks)+" | "+bcolors.TBLUE+noms_outils[tool][arg2]+bcolors.ENDC,
            if noms_outils[tool][arg4] == 0:
            	print bcolors.WARNING+"...Outil d'analyse non disponible. sauté le test automatiquement..."+bcolors.ENDC
		rs_skipped_checks = rs_skipped_checks + 1
            	tool = tool + 1
            	continue
            spinner.start()
            scan_start = time.time()
            temp_file = "temp_"+noms_outils[tool][arg1]
            cmd = cmd_outils[tool][arg1]+target+cmd_outils[tool][arg2]+" > "+temp_file+" 2>&1"

            try:
                subprocess.check_output(cmd, shell=True)
            except KeyboardInterrupt:
                runTest = 0
            except:
                runTest = 1

            if runTest == 1:
                    spinner.stop()
                    scan_stop = time.time()
                    elapsed = scan_stop - scan_start
                    rs_total_elapsed = rs_total_elapsed + elapsed
                    print bcolors.TBLUE+"\b...Terminé en "+display_time(int(elapsed))+bcolors.ENDC+"\n"
                    clear()
                    rs_tool_output_file = open(temp_file).read()
                    if outils_status[tool][arg2] == 0:
                    	if outils_status[tool][arg1].lower() in rs_tool_output_file.lower():
                        	#print "\t"+ vul_info(rep_outil[tool][arg2]) + bcolors.BADFAIL +" "+ rep_outil[tool][arg1] + bcolors.ENDC
                        	vul_as_info(tool,rep_outil[tool][arg2],rep_outil[tool][arg3])
                        	rs_vul_list.append(noms_outils[tool][arg1]+"*"+noms_outils[tool][arg2])
                    else:
                    	if any(i in rs_tool_output_file for i in outils_status[tool][arg6]):
                    		m = 1 # makadir walou.
                    	else:
                        	#print "\t"+ vul_info(rep_outil[tool][arg2]) + bcolors.BADFAIL +" "+ rep_outil[tool][arg1] + bcolors.ENDC
                        	vul_as_info(tool,rep_outil[tool][arg2],rep_outil[tool][arg3])
                        	rs_vul_list.append(noms_outils[tool][arg1]+"*"+noms_outils[tool][arg2])
            else:
                    runTest = 1
                    spinner.stop()
                    scan_stop = time.time()
                    elapsed = scan_stop - scan_start
                    rs_total_elapsed = rs_total_elapsed + elapsed
                    print bcolors.TBLUE+"\b\b\b\b...Interrompu dans "+display_time(int(elapsed))+bcolors.ENDC+"\n"
                    clear()
                    print "\t"+bcolors.WARNING + "Test ignoré. Effectuer Suivant. Appuyez sur Ctrl + Z pour quitter ManSpy." + bcolors.ENDC
                    rs_skipped_checks = rs_skipped_checks + 1

            tool=tool+1

        print bcolors.BG_ENDL_TXT+"[ l'analyse préliminaire est terminée.. ]"+bcolors.ENDC
        print "\n"

 #################### Phase de rapport et de documentation ###########################
        print bcolors.BG_HEAD_TXT+"[ Phase de génération de rapport lancée. ]"+bcolors.ENDC
        if len(rs_vul_list)==0:
        	print "\t"+bcolors.TGREEN+"Aucune vulnérabilité détectée."+bcolors.ENDC
        else:
        	with open("MS-Rapport-de-vulnérabilite", "a") as report:
        		while(rs_vul < len(rs_vul_list)):
        			vuln_info = rs_vul_list[rs_vul].split('*')
	        		report.write(vuln_info[arg2])
	        		report.write("\n------------------------\n\n")
	        		temp_report_name = "temp_"+vuln_info[arg1]
	        		with open(temp_report_name, 'r') as temp_report:
	    				data = temp_report.read()
	        			report.write(data)
	        			report.write("\n\n")
	        		temp_report.close()
	       			rs_vul = rs_vul + 1

	       		print "\tRapport de vulnérabilité complet pour "+bcolors.TBLUE+target+bcolors.ENDC+" named "+bcolors.TGREEN+"`MS-Rapport-de-vulnérabilite`"+bcolors.ENDC+" est disponible dans le même répertoire que RapidScan se trouve."

        	report.close()
        # Écrire tous les fichiers numérisés dans le journal MS-Debug à des fins de débogage.
        for file_index, file_name in enumerate(noms_outils):
        	with open("MS-Debug-ScLog", "a") as report:
        		try:
	        		with open("temp_"+file_name[arg1], 'r') as temp_report:
		    				data = temp_report.read()
		    				report.write(file_name[arg2])
	        				report.write("\n------------------------\n\n")
		        			report.write(data)
		        			report.write("\n\n")
		        	temp_report.close()
	        	except:
	        		break
	        report.close()

        print "\tNombre total de vulnérabilité controles : "+bcolors.BOLD+bcolors.TGREEN+str(len(noms_outils))+bcolors.ENDC
        print "\tNombre total de vérifications de vulnérabilité ignorées: "+bcolors.BOLD+bcolors.WARNING+str(rs_skipped_checks)+bcolors.ENDC
        print "\tNombre total de vulnérabilités détectées    : "+bcolors.BOLD+bcolors.BADFAIL+str(len(rs_vul_list))+bcolors.ENDC
        print "\tTemps total écoulé pour l'analyse             : "+bcolors.BOLD+bcolors.TBLUE+display_time(int(rs_total_elapsed))+bcolors.ENDC
        print "\n"
        print "\tÀ des fins de débogage, vous pouvez afficher la sortie complète générée par tous les outils nommés"+bcolors.TBLUE+"`MS-Debug-ScLog`"+bcolors.ENDC+" sous le même répertoire."
        print bcolors.BG_ENDL_TXT+"[ La phase de génération de rapports est terminée. ]"+bcolors.ENDC

        os.system('setterm -cursor on')
        os.system('rm te* > /dev/null 2>&1') # Effacement des fichiers d'analyse précédents
