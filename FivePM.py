import streamlit as st
import re
import os
import pandas as pd
import geoip2.database
import plotly.express as px
import plotly.graph_objects as go
from pathlib import Path
import tempfile
from collections import defaultdict, Counter
import ipaddress
import streamlit.components.v1 as components
import requests
import hashlib
import logging
import configparser
import json
import subprocess
import sys

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Gated print statements so they only run once per session
if 'app_init_done' not in st.session_state:
    print("")
    print("Developed by Jacob Wilson")
    print("dfirvault@gmail.com")
    print("")
    st.session_state.app_init_done = True

class ConfigManager:
    """Manages API keys and settings from a local config file"""
    
    def __init__(self, config_dir=None):
        if config_dir is None:
            self.config_dir = Path.home() / ".fivepm"
        else:
            self.config_dir = Path(config_dir)
        
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.config_path = self.config_dir / "config.ini"
        self.config = configparser.ConfigParser()
        
        if self.config_path.exists():
            self.config.read(self.config_path)
        else:
            self.create_default_config()

    def create_default_config(self):
        self.config['virustotal'] = {'api_key': ''}
        self.config['otx'] = {'api_key': ''}
        self.save_config()

    def save_config(self):
        with open(self.config_path, 'w') as configfile:
            self.config.write(configfile)

    def get_api_key(self, service):
        try:
            return self.config.get(service, 'api_key', fallback='')
        except configparser.NoSectionError:
            self.create_default_config()
            return ''

    def set_api_key(self, service, api_key):
        if service not in self.config:
            self.config[service] = {}
        self.config[service]['api_key'] = api_key
        self.save_config()

class GeoIPManager:
    """Manages GeoIP database download and verification"""
    
    DATABASE_URLS = {
        "city": "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb",
        "asn": "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-ASN.mmdb"
    }
    
    def __init__(self, db_dir=None):
        if db_dir is None:
            self.db_dir = Path.home() / ".fivepm" / "geoip"
        else:
            self.db_dir = Path(db_dir)
        
        self.db_dir.mkdir(parents=True, exist_ok=True)
    
    def get_db_path(self, db_type):
        return self.db_dir / f"GeoLite2-{db_type.capitalize()}.mmdb"
    
    def download_database(self, db_type, progress_callback=None):
        if db_type not in self.DATABASE_URLS:
            raise ValueError(f"Unknown database type: {db_type}")
        
        url = self.DATABASE_URLS[db_type]
        db_path = self.get_db_path(db_type)
        
        try:
            response = requests.get(url, stream=True, timeout=30)
            response.raise_for_status()
            
            total_size = int(response.headers.get('content-length', 0))
            downloaded_size = 0
            
            with open(db_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        downloaded_size += len(chunk)
                        
                        if progress_callback and total_size > 0:
                            progress = (downloaded_size / total_size) * 100
                            progress_callback(progress)
            
            return True
            
        except requests.exceptions.RequestException as e:
            st.error(f"Failed to download {db_type} database: {str(e)}")
            if db_path.exists():
                db_path.unlink()
            return False
    
    def database_exists(self, db_type):
        db_path = self.get_db_path(db_type)
        if not db_path.exists():
            return False
        try:
            with geoip2.database.Reader(str(db_path)):
                return True
        except Exception:
            db_path.unlink()
            return False
    
    def ensure_databases(self, required_types=None):
        if required_types is None:
            required_types = ["city", "asn"]
        missing_dbs = [db_type for db_type in required_types if not self.database_exists(db_type)]
        if missing_dbs:
            return self.download_databases(missing_dbs)
        return True
    
    def download_databases(self, db_types, show_progress=True):
        success_count = 0
        for db_type in db_types:
            progress_bar, progress_text = None, None
            if show_progress:
                st.info(f"📥 Downloading {db_type} database...")
                progress_bar = st.progress(0)
                progress_text = st.empty()
            
            def update_progress(progress):
                if progress_bar:
                    progress_bar.progress(int(progress))
                if progress_text:
                    progress_text.text(f"Downloading... {progress:.1f}%")
            
            if self.download_database(db_type, update_progress):
                success_count += 1
                if show_progress:
                    progress_bar.progress(100)
                    progress_text.text("✅ Download complete!")
                    st.success(f"{db_type.capitalize()} database downloaded successfully")
            elif show_progress:
                progress_text.text("❌ Download failed")
        
        return success_count == len(db_types)

class ThreatIntelClient:
    """Manages API calls to VirusTotal and OTX"""
    
    def __init__(self, vt_api_key, otx_api_key):
        self.vt_api_key = vt_api_key
        self.otx_api_key = otx_api_key
        self.vt_headers = {"x-apikey": self.vt_api_key}
        self.otx_headers = {"X-OTX-API-KEY": self.otx_api_key}

    @st.cache_data(ttl=3600)
    def get_vt_ip_report(_self, ip_address):
        if not _self.vt_api_key:
            return {"error": "VirusTotal API key is not configured."}
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
        try:
            response = requests.get(url, headers=_self.vt_headers, timeout=10)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"error": f"VirusTotal request failed: {str(e)}"}

    @st.cache_data(ttl=3600)
    def get_vt_domain_report(_self, domain):
        if not _self.vt_api_key:
            return {"error": "VirusTotal API key is not configured."}
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        try:
            response = requests.get(url, headers=_self.vt_headers, timeout=10)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"error": f"VirusTotal request failed: {str(e)}"}

    @st.cache_data(ttl=3600)
    def get_otx_ip_report(_self, ip_address):
        if not _self.otx_api_key:
            return {"error": "OTX API key is not configured."}
        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip_address}/general"
        try:
            response = requests.get(url, headers=_self.otx_headers, timeout=10)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"error": f"OTX request failed: {str(e)}"}

    @st.cache_data(ttl=3600)
    def get_otx_domain_report(_self, domain):
        if not _self.otx_api_key:
            return {"error": "OTX API key is not configured."}
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"
        try:
            response = requests.get(url, headers=_self.otx_headers, timeout=10)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"error": f"OTX request failed: {str(e)}"}

class ThreatIntelligenceScanner:
    def __init__(self):
        # ========================
        # MASSIVELY EXPANDED INDICATORS
        # ========================
        self.indicators = {
            # --- Network Indicators ---
            'ipv4_address': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            'ipv6_address': r'(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}',
            'domain': r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}',
            'email_address': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'url': r'https?://[^\s]+|www\.[^\s]+',
            'onion_domain': r'\b[a-z2-7]{16,56}\.onion\b', # .onion domains
            
            # --- Cryptocurrency ---
            'bitcoin_address': r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b',
            'ethereum_address': r'\b0x[a-fA-F0-9]{40}\b',
            'monero_address': r'\b4[0-9AB][1-9A-Za-z]{93}\b', # Monero addresses

            # --- Hash Patterns ---
            'md5_hash': r'\b[a-f0-9]{32}\b',
            'sha1_hash': r'\b[a-f0-9]{40}\b',
            'sha256_hash': r'\b[a-f0-9]{64}\b',
            
            # --- Security Vulnerabilities ---
            'cve_id': r'CVE-\d{4}-\d{4,7}',
            
            # --- Common Malware Tools ---
            'mimikatz': r'(?i)mimikatz',
            'metasploit': r'(?i)metasploit',
            'cobalt_strike': r'(?i)cobalt.strike',
            'empire': r'(?i)empire',
            'beacon': r'(?i)beacon',
            'nishang': r'(?i)nishang',
            'covenant': r'(?i)covenant',
            'poshc2': r'(?i)poshc2',
            'sqlmap': r'(?i)sqlmap',
            'nikto': r'(?i)nikto',
            'bloodhound': r'(?i)bloodhound',
            'sharphound': r'(?i)sharphound',
            'merlin_c2': r'(?i)merlin', # NEW
            'starkiller': r'(?i)starkiller', # NEW (Empire GUI)
            
            # --- Credential Access ---
            'sekurlsa_logonpasswords': r'(?i)sekurlsa::logonpasswords',
            'lsass_process': r'(?i)lsass\.exe',
            'procdump': r'(?i)procdump',
            'pwdump': r'(?i)pwdump',
            'dcsync': r'(?i)dcsync',
            'pass_the_hash': r'(?i)pass the hash',
            'lazagne': r'(?i)laZagne', # NEW
            'mimipenguin': r'(?i)mimipenguin', # NEW
            'rubeus': r'(?i)rubeus', # NEW
            'sam_dump': r'(?i)sam.dump', # NEW
            'ntds_dit': r'(?i)ntds\.dit', # NEW
            'shadow_copy': r'(?i)shadowcopy', # NEW
            'invoke_kerberoast': r'(?i)Invoke-Kerberoast',
            'get_gpp_password': r'(?i)Get-GPPPassword',
            'find_gpp_password': r'(?i)GPPref.xml',

            # --- Shells & C2 ---
            'reverse_shell': r'(?i)(bash.*-i|nc.*-e|netcat.*-e|python.*socket|php.*exec.*socket)',
            'bind_shell': r'(?i)(nc.*-l.*-p|netcat.*-l.*-p|listen.*port)',
            'powershell_iex': r'(?i)powershell.*iex',
            'http_beacon': r'(?i)http.*beacon',
            'meterpreter': r'(?i)meterpreter',
            'sliver_c2': r'(?i)sliver',
            'brute_ratel': r'(?i)brute.ratel',
            'havoc_c2': r'(?i)havoc',
            'mythic_c2': r'(?i)mythic',
            'koadic': r'(?i)koadic', # NEW
            'web_shell_passthru': r'(?i)passthru\(', # NEW
            'web_shell_shell_exec': r'(?i)shell_exec\(', # NEW
            'web_shell_system': r'(?i)system\(', # NEW
            'web_shell_cmd_asp': r'(?i)cmd\.asp', # NEW
            'web_shell_aspx_cmd': r'Response\.Write.*Shell', # NEW
            'china_chopper_ua': r'AntSword|China.Chopper', # NEW
            
            # --- Suspicious Commands & LOLBAS ---
            'powershell_download': r'(?i)(Invoke-WebRequest|wget|curl).*http',
            'base64_encoded': r'(?i)base64.*decode',
            'certutil_decode': r'(?i)certutil.*-decode',
            'bitsadmin': r'(?i)bitsadmin.*transfer',
            'encoded_command': r'(?i)encodedcommand',
            'frombase64string': r'(?i)frombase64string',
            'rundll32': r'(?i)rundll32',
            'regsvr32': r'(?i)regsvr32',
            'mshta': r'(?i)mshta',
            'schtasks': r'(?i)schtasks',
            'net_user': r'(?i)net user',
            'msbuild': r'(?i)msbuild\.exe', # NEW
            'cmstp': r'(?i)cmstp\.exe', # NEW
            'dnscmd': r'(?i)dnscmd\.exe', # NEW
            'wmic_process_call': r'(?i)wmic.*process.call.create', # NEW
            'certify': r'(?i)certify\.exe', # NEW (AD CS abuse)
            'adexplorer': r'(?i)adexplorer', # NEW (Sysinternals)

            # --- Persistence ---
            'scheduled_task': r'(?i)schtasks.*create',
            'registry_run': r'(?i)reg.add.*HKCU.*Software.*Microsoft.*Windows.*CurrentVersion.*Run',
            'wmi_persistence': r'(?i)wmic.*shadowcopy',
            'image_file_options': r'Image.File.Execution.Options', # NEW
            'silent_process_exit': r'SilentProcessExit', # NEW
            'startup_folder': r'AppData.*Microsoft.*Windows.*Start.Menu.*Programs.*Startup', # NEW

            # --- Lateral Movement ---
            'psexec': r'(?i)psexec',
            'wmic_remote': r'(?i)wmic.*/node:',
            'winrm': r'(?i)winrm.*invoke',
            'wmiexec': r'(?i)wmiexec',
            'dcom_exec': r'(?i)dcomexec', # NEW (Impacket)
            'smb_exec': r'(?i)smbexec', # NEW (Impacket)
            'evil_winrm': r'(?i)evil-winrm', # NEW
            
            # --- Defense Evasion ---
            'amsi_bypass': r'(?i)(amsi.*bypass|amsiutils)',
            'uac_bypass': r'(?i)uac.*bypass',
            'process_hollowing': r'(?i)process.*hollow',
            'etw_bypass': r'(?i)etwbypass',
            'sharpblock': r'(?i)sharpblock',
            'mp_preference_disable': r'(?i)Set-MpPreference.*DisableRealtimeMonitoring',
            'wevtutil_clear': r'(?i)wevtutil.cl',
            'fsutil_usn_delete': r'(?i)fsutil.usn.deletejournal', # NEW
            'timestomp': r'(?i)timestomp', # NEW
            
            # --- Memory & Crypto Artifacts ---
            'virtual_alloc': r'(?i)virtualalloc',
            'write_process_memory': r'(?i)writeprocessmemory',
            'shellcode': r'(?i)shellcode',
            'xor_decode': r'(?i)xor decode',
            'rc4_key': r'(?i)rc4 key',
            'aes_key': r'(?i)aes key',
            
            # --- Remote Access Tools ---
            'anydesk': r'(?i)anydesk',
            'teamviewer': r'(?i)teamviewer',
            'logmein': r'(?i)logmein',
            'vnc_connect': r'(?i)vnc',
            'ngrok': r'(?i)ngrok',
            'serveo': r'(?i)serveo\.net',
            'putty': r'(?i)putty\.exe', # NEW
            'plink': r'(?i)plink\.exe', # NEW
            'screenconnect': r'(?i)screenconnect', # NEW
            
            # --- Ransomware ---
            'vssadmin_delete': r'(?i)vssadmin.*delete.shadows',
            'wbadmin_delete': r'(?i)wbadmin.delete.catalog',
            'bcedit_recovery': r'(?i)bcedit.*recoveryenabled.No',
            'ransom_note_readme': r'(?i)README-TO-DECRYPT.txt',
            'ransom_note_instruct': r'(?i)DECRYPT_INSTRUCTIONS.txt',
            'lockbit_ext': r'\.lockbit',
            'ransom_stop_service': r'(?i)net.stop.*(sql|veeam|msexchange|backup)', # NEW
            'blackcat_ext': r'\.alpha', # NEW (BlackCat)
            'play_ext': r'\.play', # NEW (Play Ransomware)
            'clop_ext': r'\.clop', # NEW (Clop)

            # --- Cloud & Identity ---
            'aws_assume_role': r'(?i)sts:AssumeRole',
            'aws_get_secret': r'(?i)GetSecretValue',
            'azure_ad': r'(?i)azuread',
            'okta_auth': r'(?i)okta',
            'saml_token': r'(?i)saml',
            'adfs_auth': r'(?i)adfs',
            'aws_cli': r'(?i)aws.cli', # NEW
            'azure_cli': r'(?i)az.cli', # NEW
            'gcloud_cli': r'(?i)gcloud', # NEW
            'roadrecon': r'(?i)roadrecon', # NEW (Azure AD)
            
            # --- Exfiltration ---
            'rclone': r'(?i)rclone',
            'dnscat2': r'(?i)dnscat2',
            'curl_upload': r'(?i)curl.*-T',
            'pastebin': r'pastebin\.com', # NEW
            'anonfiles': r'anonfiles\.com', # NEW
            'mega_nz': r'mega\.nz', # NEW
            '7zip_compress': r'7z.a.-p', # NEW (password protected zip)
            
            # --- Linux/Mac Specific ---
            'xmrig': r'(?i)xmrig', # NEW (Crypto miner)
            'ssh_agent_hijack': r'SSH_AUTH_SOCK', # NEW
            'cronjob': r'(?i)cronjob', # NEW
            'chmod_exec': r'chmod.*\+x', # NEW
            'launchdaemon': r'(?i)LaunchDaemons', # NEW (Mac persistence)
            'launchagent': r'(?i)LaunchAgents', # NEW (Mac persistence)
            'linux_tsunami_backdoor': r'tsunami', # NEW
            'linux_keylogger': r'logkey|keylog', # NEW
                
            # --- Supply Chain & DevOps ---
            'github_actions': r'(?i)actions/checkout',
            'github_token': r'ghp_[0-9a-zA-Z]{36}', 
            'npm_token': r'npm_[0-9a-zA-Z]{36}', 
            'artifactory_cred': r'(?i)artifactory',
            'jenkins_cred': r'(?i)jenkins',
            'terraform_vars': r'(?i)tfvars',
            'docker_sock': r'docker.sock', # NEW
            'kubernetes_token': r'--token.*kubeconfig', # NEW

            # --- Other IOCs ---
            'suspicious_extension': r'\.(ps1|vbs|bat|cmd|js|jse|wsf|wsh|scr|pif|exe|dll|sys)$',
            'obfuscated_code': r'(?i)(xor.*base64|string.*reverse|char.*array)',
            'suspicious_user_agent': r'(?i)(python-requests|curl|wget)',
            'encoded_payload': r'[A-Za-z0-9+/]{40,}={0,2}',
            'ssh_private_key': r'(?i)-----BEGIN.*PRIVATE KEY-----',
            'id_rsa': r'(?i)id_rsa',
        }
        
    def is_valid_ip(self, ip_str):
        try:
            ip = ipaddress.ip_address(ip_str)
            return not ip.is_private and not ip.is_loopback and not ip.is_multicast
        except ValueError:
            return False
    
    def scan_file(self, file_path, display_name=None):
        """Scan a single file for indicators"""
        findings = defaultdict(list)
        name_to_display = display_name if display_name else file_path
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
                content = file.read()
                line_number = 0
                
                for line in content.split('\n'):
                    line_number += 1
                    for indicator_name, pattern in self.indicators.items():
                        matches = re.finditer(pattern, line)
                        for match in matches:
                            match_value = match.group()
                            if indicator_name in ['ipv4_address', 'ipv6_address']:
                                if not self.is_valid_ip(match_value):
                                    continue
                            elif indicator_name == 'email_address':
                                if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', match_value):
                                    continue
                            elif indicator_name == 'domain':
                                if match_value.lower() in ['localhost', 'example.com']:
                                    continue
                                if re.search(f'@{re.escape(match_value)}', line):
                                    continue
                            
                            findings[indicator_name].append({
                                'file': name_to_display,
                                'line_number': line_number,
                                'content': line.strip(),
                                'match': match_value
                            })
        except Exception as e:
            st.warning(f"Could not read file {name_to_display}: {str(e)}")
        
        return findings
    
    def scan_directory(self, directory_path):
        all_findings = defaultdict(list)
        scanned_files = 0
        for root, dirs, files in os.walk(directory_path):
            for file in files:
                file_path = os.path.join(root, file)
                findings = self.scan_file(file_path, display_name=file_path)
                scanned_files += 1
                for indicator, matches in findings.items():
                    all_findings[indicator].extend(matches)
        return all_findings, scanned_files

class GeoIPAnalyzer:
    def __init__(self, geoip_manager):
        self.geoip_manager = geoip_manager
        self.city_reader = None
        self.asn_reader = None
        self._initialize_readers()
    
    def _initialize_readers(self):
        try:
            city_path = self.geoip_manager.get_db_path("city")
            asn_path = self.geoip_manager.get_db_path("asn")
            if city_path.exists():
                self.city_reader = geoip2.database.Reader(str(city_path))
            if asn_path.exists():
                self.asn_reader = geoip2.database.Reader(str(asn_path))
        except Exception as e:
            logger.error(f"Error initializing GeoIP databases: {str(e)}")
    
    def get_ip_info(self, ip_address):
        try:
            if self.city_reader:
                response = self.city_reader.city(ip_address)
                country_name = response.country.name if response.country else 'Unknown'
                country_code = response.country.iso_code if response.country else 'XX'
                city_name = response.city.name if response.city else 'Unknown'
                
                return {
                    'ip': ip_address,
                    'country': country_name,
                    'country_code': country_code,
                    'city': city_name,
                    'latitude': response.location.latitude if response.location else 0,
                    'longitude': response.location.longitude if response.location else 0,
                    'asn': self.get_asn_info(ip_address)
                }
        except Exception as e:
            logger.debug(f"GeoIP lookup failed for {ip_address}: {str(e)}")
        
        return {
            'ip': ip_address, 'country': 'Unknown', 'country_code': 'XX',
            'city': 'Unknown', 'latitude': 0, 'longitude': 0, 'asn': 'Unknown'
        }
    
    def get_asn_info(self, ip_address):
        try:
            if self.asn_reader:
                response = self.asn_reader.asn(ip_address)
                return response.autonomous_system_organization if response.autonomous_system_organization else 'Unknown'
        except Exception as e:
            logger.debug(f"ASN lookup failed for {ip_address}: {str(e)}")
        return 'Unknown'
    
    def close(self):
        if self.city_reader: self.city_reader.close()
        if self.asn_reader: self.asn_reader.close()

def optimize_large_dataset(findings, max_samples=1000):
    optimized = {}
    for indicator_type, matches in findings.items():
        if len(matches) > max_samples:
            optimized[indicator_type] = {
                'type': 'summary',
                'total_count': len(matches),
                'sample': matches, # Keep all data for searching
                'summary_stats': get_summary_stats(matches, indicator_type)
            }
        else:
            optimized[indicator_type] = {
                'type': 'full',
                'data': matches,
                'total_count': len(matches)
            }
    return optimized

def get_summary_stats(matches, indicator_type):
    if indicator_type in ['ipv4_address', 'ipv6_address']:
        unique_ips = Counter(match['match'] for match in matches)
        file_counts = Counter(match['file'] for match in matches)
        return {
            'unique_ips_count': len(unique_ips),
            'top_ips': dict(unique_ips.most_common(20)),
            'top_files': dict(file_counts.most_common(10))
        }
    else:
        unique_matches = Counter(match['match'] for match in matches)
        file_counts = Counter(match['file'] for match in matches)
        return {
            'unique_matches_count': len(unique_matches),
            'top_matches': dict(unique_matches.most_common(20)),
            'top_files': dict(file_counts.most_common(10))
        }

def set_active_tab_and_filter(indicator_type, indicator_options):
    """Callback to switch tabs and set the filter"""
    
    full_option_name = None
    for option in indicator_options:
        if option.startswith(indicator_type):
            full_option_name = option
            break
    
    if full_option_name:
        st.session_state.selected_indicator_dropdown = full_option_name
        st.session_state.active_tab = "🔍 Detailed Findings"
    else:
        st.session_state.active_tab = "🔍 Detailed Findings"

def main():
    st.set_page_config(
        page_title="Threat Intelligence Scanner",
        page_icon="🔍",
        layout="wide"
    )
    
    st.title("🔍 FivePM - Advanced Threat Intelligence Scanner")
    st.markdown("This application scans files and directories for threat indicators and enriches them with GeoIP and Threat Intelligence data.")
    
    config_manager = ConfigManager()
    geoip_manager = GeoIPManager()
    
    vt_key = config_manager.get_api_key('virustotal')
    otx_key = config_manager.get_api_key('otx')
    ti_client = ThreatIntelClient(vt_api_key=vt_key, otx_api_key=otx_key)
    
    if 'scan_results' not in st.session_state:
        st.session_state.scan_results = None
    if 'geo_data' not in st.session_state:
        st.session_state.geo_data = None
    if 'selected_directory' not in st.session_state:
        st.session_state.selected_directory = None
    if 'geoip_available' not in st.session_state:
        st.session_state.geoip_available = False
    if 'active_tab' not in st.session_state:
        st.session_state.active_tab = "📋 Indicators Overview"
    if 'selected_indicator_dropdown' not in st.session_state:
        st.session_state.selected_indicator_dropdown = None

    st.sidebar.header("⚙️ API Configuration")
    with st.sidebar.expander("Enter API Keys"):
        new_vt_key = st.text_input("VirusTotal API Key", value=vt_key, type="password")
        new_otx_key = st.text_input("OTX API Key", value=otx_key, type="password")
        
        if st.button("Save API Keys"):
            config_manager.set_api_key('virustotal', new_vt_key)
            config_manager.set_api_key('otx', new_otx_key)
            st.success("API keys saved successfully!")
            st.rerun()

    st.sidebar.header("🌍 GeoIP Databases")
    city_exists = geoip_manager.database_exists("city")
    asn_exists = geoip_manager.database_exists("asn")
    
    col1, col2 = st.sidebar.columns(2)
    with col1: st.metric("City DB", "✅" if city_exists else "❌")
    with col2: st.metric("ASN DB", "✅" if asn_exists else "❌")
    
    if not (city_exists and asn_exists):
        st.sidebar.warning("GeoIP databases not found!")
        if st.sidebar.button("📥 Download GeoIP Databases", type="primary"):
            with st.sidebar:
                if geoip_manager.download_databases(["city", "asn"]):
                    st.session_state.geoip_available = True
                    st.rerun()
    else:
        st.sidebar.success("GeoIP databases ready!")
        st.session_state.geoip_available = True
        if st.sidebar.button("🔄 Update Databases"):
            with st.sidebar:
                if geoip_manager.download_databases(["city", "asn"]):
                    st.success("Databases updated successfully!")
                    st.rerun()
    
    st.sidebar.header("📁 Input Options")
    input_option = st.sidebar.radio(
        "Choose input type:",
        ["Upload File", "Select Directory"]
    )
    
    scanner = ThreatIntelligenceScanner()
    
    if input_option == "Upload File":
        uploaded_file = st.sidebar.file_uploader(
            "Choose a file to scan",
            type=['txt', 'log', 'py', 'js', 'php', 'html', 'xml', 'json', 'csv', 'ps1', 'bat', 'cmd', 'yml', 'yaml', 'config', 'conf']
        )
        if uploaded_file is not None:
            with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(uploaded_file.name)[1]) as tmp_file:
                tmp_file.write(uploaded_file.getvalue())
                tmp_path = tmp_file.name
            
            if st.sidebar.button("Scan File"):
                with st.spinner("Scanning file for threats..."):
                    findings = scanner.scan_file(tmp_path, display_name=uploaded_file.name)
                    st.session_state.scan_results = optimize_large_dataset(findings)
                    st.session_state.scanned_files = 1
                    st.session_state.active_tab = "📋 Indicators Overview"
                os.unlink(tmp_path)
    
    else:  # Select Directory
        st.sidebar.subheader("📁 Select Directory")
        
        if st.sidebar.button("📂 Browse Folders"):
            try:
                python_executable = sys.executable
                picker_script_path = "folder_picker.py"
                if not os.path.exists(picker_script_path):
                    st.sidebar.error(f"Error: `{picker_script_path}` not found.")
                    st.sidebar.warning("Make sure this file is in the same directory.")
                else:
                    result = subprocess.run(
                        [python_executable, picker_script_path],
                        capture_output=True, text=True, check=True
                    )
                    output = json.loads(result.stdout)
                    if "error" in output:
                        st.sidebar.error(f"Error from picker: {output['error']}")
                    elif "folder_path" in output:
                        st.session_state.selected_directory = output["folder_path"]
                        st.rerun() 
                        
            except Exception as e:
                st.sidebar.error(f"Failed to launch folder picker: {e}")
                st.sidebar.warning("Note: This feature only works when running locally.")

        if st.sidebar.button("🗑️ Clear Selection"):
            st.session_state.selected_directory = None
            st.session_state.scan_results = None
            st.rerun()
        
        if st.session_state.selected_directory:
            st.sidebar.success(f"Selected: `{st.session_state.selected_directory}`")
        
        if st.session_state.selected_directory and st.sidebar.button("🔍 Scan Directory", type="primary"):
            if os.path.exists(st.session_state.selected_directory) and os.path.isdir(st.session_state.selected_directory):
                with st.spinner("Scanning directory for threats..."):
                    findings, scanned_files = scanner.scan_directory(st.session_state.selected_directory)
                    st.session_state.scan_results = optimize_large_dataset(findings)
                    st.session_state.scanned_files = scanned_files
                    st.session_state.active_tab = "📋 Indicators Overview"
            else:
                st.error("Selected directory path is no longer valid!")

    if st.session_state.scan_results:
        findings = st.session_state.scan_results
        
        st.header("📊 Scan Summary")
        col1, col2, col3, col4 = st.columns(4)
        total_indicators = sum(finding['total_count'] for finding in findings.values())
        total_files = st.session_state.scanned_files
        
        with col1: st.metric("Files Scanned", total_files)
        with col2: st.metric("Total Indicators Found", f"{total_indicators:,}")
        with col3: st.metric("Indicator Types", len(findings))
        if st.session_state.selected_directory:
            with col4: st.metric("Scanned Directory", os.path.basename(st.session_state.selected_directory))
        
        if total_indicators > 10000:
            st.warning(f"⚠️ Large dataset detected: {total_indicators:,} indicators found. Using optimized views.")
        
        st.header("📈 Overview Dashboard")
        
        tab_names = ["📋 Indicators Overview", "🌍 IP Analysis", "🔍 Detailed Findings", "📊 Statistics"]
        selected_tab = st.radio(
            "Navigation",
            tab_names,
            horizontal=True,
            label_visibility="collapsed",
            key="active_tab" 
        )

        if selected_tab == tab_names[0]:
            display_indicators_overview(findings)
        
        elif selected_tab == tab_names[1]:
            display_ip_analysis(findings, geoip_manager, ti_client)
        
        elif selected_tab == tab_names[2]:
            display_detailed_findings(findings, ti_client)
        
        elif selected_tab == tab_names[3]:
            display_statistics(findings)
        
        st.sidebar.header("💾 Export Results")
        if st.sidebar.button("Export Summary to CSV"):
            export_summary_to_csv(findings)

def display_indicators_overview(findings):
    """Display overview of all indicators"""
    st.subheader("Indicator Summary")
    
    categories = {
        'Network': ['ipv4_address', 'ipv6_address', 'domain', 'email_address', 'url', 'onion_domain'],
        'Cryptocurrency': ['bitcoin_address', 'ethereum_address', 'monero_address'],
        'Hashes': ['md5_hash', 'sha1_hash', 'sha256_hash'],
        'Security': ['cve_id'],
        'Common Malware': ['mimikatz', 'metasploit', 'cobalt_strike', 'empire', 'beacon', 'nishang', 
                         'covenant', 'poshc2', 'sqlmap', 'nikto', 'bloodhound', 'sharphound'],
        'Remote Access & C2': ['anydesk', 'teamviewer', 'logmein', 'vnc_connect', 'ngrok', 'serveo', 
                            'sliver_c2', 'brute_ratel', 'havoc_c2', 'mythic_c2', 'koadic', 'putty', 
                            'plink', 'screenconnect', 'merlin_c2', 'starkiller'],
        'Ransomware': ['vssadmin_delete', 'wbadmin_delete', 'bcedit_recovery', 'ransom_note_readme', 
                      'ransom_note_instruct', 'lockbit_ext', 'ransom_stop_service', 'blackcat_ext',
                      'play_ext', 'clop_ext'],
        'Credential Access': ['sekurlsa_logonpasswords', 'lsass_process', 'procdump', 'pwdump', 
                             'dcsync', 'pass_the_hash', 'lazagne', 'mimipenguin', 'rubeus', 'sam_dump',
                             'ntds_dit', 'shadow_copy', 'invoke_kerberoast', 'get_gpp_password', 'find_gpp_password'],
        'Web Shells': ['web_shell_passthru', 'web_shell_shell_exec', 'web_shell_system', 'web_shell_cmd_asp',
                      'web_shell_aspx_cmd', 'china_chopper_ua'],
        'Lateral Movement': ['psexec', 'wmic_remote', 'winrm', 'invoke', 'wmiexec', 'dcom_exec',
                            'smb_exec', 'evil_winrm'],
        'Defense Evasion': ['amsi_bypass', 'uac_bypass', 'process_hollowing', 'etw_bypass', 'sharpblock', 
                           'mp_preference_disable', 'wevtutil_clear', 'fsutil_usn_delete', 'timestomp'],
        'Command & Control': ['reverse_shell', 'bind_shell', 'powershell_iex', 'dns_tunneling', 
                           'http_beacon', 'meterpreter'],
        'LOLBAS & Suspicious': ['powershell_download', 'base64_encoded', 'certutil_decode', 'bitsadmin',
                               'encoded_command', 'frombase64string', 'rundll32', 'regsvr32', 'mshta',
                               'schtasks', 'net_user', 'msbuild', 'cmstp', 'dnscmd', 'wmic_process_call',
                               'certify', 'adexplorer'],
        'Persistence': ['scheduled_task', 'registry_run', 'wmi_persistence', 'image_file_options',
                       'silent_process_exit', 'startup_folder'],
        'Exfiltration': ['rclone', 'dnscat2', 'curl_upload', 'pastebin', 'anonfiles', 'mega_nz', '7zip_compress'],
        'Cloud & Identity': ['aws_assume_role', 'aws_get_secret', 'azure_ad', 'okta_auth', 'saml_token', 'adfs_auth',
                           'aws_cli', 'azure_cli', 'gcloud_cli', 'roadrecon'],
        'Linux/Mac Specific': ['xmrig', 'ssh_agent_hijack', 'cronjob', 'chmod_exec', 'launchdaemon',
                             'launchagent', 'linux_tsunami_backdoor', 'linux_keylogger'],
        'Supply Chain & DevOps': ['github_actions', 'github_token', 'npm_token', 'artifactory_cred', 
                                 'jenkins_cred', 'terraform_vars', 'docker_sock', 'kubernetes_token'],
        'Other Artifacts': ['virtual_alloc', 'write_process_memory', 'shellcode', 'xor_decode', 'rc4_key',
                          'aes_key', 'suspicious_extension', 'obfuscated_code', 'suspicious_user_agent',
                          'encoded_payload', 'ssh_private_key', 'id_rsa']
    }
    
    # Build the list of options for the callback
    indicator_options = [f"{it} ({f['total_count']:,})" for it, f in findings.items() if f['total_count'] > 0]

    for category, indicators in categories.items():
        st.subheader(f"{category} Indicators")
        cols = st.columns(4)
        indicator_count = 0
        
        for indicator_type in indicators:
            if indicator_type in findings:
                finding_data = findings[indicator_type]
                count = finding_data['total_count']
                
                if count > 0:
                    with cols[indicator_count % 4]:
                        label = f"**{indicator_type.replace('_', ' ').title()}**\n\n## {count:,}"
                        st.button(
                            label, 
                            key=f"metric_btn_{indicator_type}", 
                            on_click=set_active_tab_and_filter, 
                            args=(indicator_type, indicator_options),
                            use_container_width=True
                        )
                    indicator_count += 1
        
        if indicator_count == 0:
            st.info(f"No {category.lower()} indicators found")
    
    st.subheader("Top Indicators Overall")
    indicator_counts = []
    for indicator_type, finding_data in findings.items():
        count = finding_data['total_count']
        if count > 0:
            indicator_counts.append((indicator_type, count))
    
    indicator_counts.sort(key=lambda x: x[1], reverse=True)
    
    if indicator_counts:
        top_indicators_df = pd.DataFrame(indicator_counts[:15], columns=['Indicator', 'Count'])
        fig = px.bar(top_indicators_df, x='Count', y='Indicator', orientation='h',
                    title="Top 15 Indicators by Count")
        st.plotly_chart(fig, use_container_width=True)

def display_ti_report(report_data):
    if 'error' in report_data:
        st.error(report_data['error'])
        return
    
    if 'data' in report_data and 'attributes' in report_data['data']:
        st.subheader("VirusTotal Summary")
        attrs = report_data['data']['attributes']
        stats = attrs.get('last_analysis_stats', {})
        col1, col2, col3 = st.columns(3)
        col1.metric("Malicious", stats.get('malicious', 0), "🚩")
        col2.metric("Suspicious", stats.get('suspicious', 0), "⚠️")
        col3.metric("Harmless", stats.get('harmless', 0), "✅")
        with st.expander("Full VT Report (JSON)"):
            st.json(report_data)
    
    elif 'pulse_info' in report_data:
        st.subheader("AlienVault OTX Summary")
        st.metric("Pulse Count", report_data.get('pulse_info', {}).get('count', 0), " pulses")
        with st.expander("Full OTX Report (JSON)"):
            st.json(report_data)
    else:
        st.json(report_data)

def display_global_heatmap(df_geo):
    st.subheader("🌍 Global IP Heatmap")
    map_data = df_geo[(df_geo['latitude'] != 0) & (df_geo['longitude'] != 0)]
    if map_data.empty:
        st.info("No valid geolocations found to display on the map.")
        return
    try:
        fig = px.density_mapbox(
            map_data, lat='latitude', lon='longitude', radius=10,
            center=dict(lat=0, lon=0), zoom=1,
            mapbox_style="open-street-map",
            title="Heatmap of Geolocated IP Addresses"
        )
        fig.update_layout(margin=dict(r=0, t=30, l=0, b=0))
        st.plotly_chart(fig, use_container_width=True)
    except Exception as e:
        st.error(f"Failed to render heatmap: {e}")

def display_ip_analysis(findings, geoip_manager, ti_client):
    ip_indicators = [it for it in ['ipv4_address', 'ipv6_address'] if it in findings]
    if not ip_indicators:
        st.info("No IP addresses found in the scan.")
        return
    
    all_ip_data = []
    for ip_indicator in ip_indicators:
        ip_data = findings[ip_indicator]
        all_ip_data.extend(ip_data.get('sample', ip_data.get('data', [])))
    
    if not all_ip_data:
        st.info("No valid IP addresses found for analysis.")
        return
    
    st.subheader("IP Address Analysis")
    
    if not st.session_state.geoip_available:
        st.warning("GeoIP analysis requires databases. Please download them from the sidebar.")
        unique_ips = Counter(match['match'] for match in all_ip_data)
        top_ips_df = pd.DataFrame(unique_ips.most_common(20), columns=['IP Address', 'Count'])
        st.dataframe(top_ips_df, use_container_width=True)
        return
    
    geo_analyzer = GeoIPAnalyzer(geoip_manager)
    unique_ips = set(match['match'] for match in all_ip_data)
    with st.spinner(f"Geolocating {len(unique_ips):,} unique IP addresses..."):
        geo_data = [geo_analyzer.get_ip_info(ip) for ip in list(unique_ips)[:1000]]
    geo_analyzer.close()
    
    if not geo_data:
        st.info("No geolocation data could be retrieved for the found IPs.")
        return
        
    df_geo = pd.DataFrame(geo_data)
    display_global_heatmap(df_geo)
    
    st.subheader("Country & ASN Distribution")
    col1, col2 = st.columns(2)
    with col1:
        country_counts = df_geo['country'].value_counts().reset_index()
        country_counts.columns = ['Country', 'Count']
        country_counts_chart = country_counts[country_counts['Country'] != 'Unknown']
        if not country_counts_chart.empty:
            fig_country_bar = px.bar(country_counts_chart.head(15), x='Count', y='Country', orientation='h', title="Top 15 Countries by IP Count")
            st.plotly_chart(fig_country_bar, use_container_width=True)
        else: st.info("No country information available.")
    
    with col2:
        asn_counts = df_geo['asn'].value_counts().reset_index()
        asn_counts.columns = ['ASN', 'Count']
        asn_counts = asn_counts[asn_counts['ASN'] != 'Unknown']
        if not asn_counts.empty:
            fig_asn = px.bar(asn_counts.head(15), x='Count', y='ASN', orientation='h', title="Top 15 ASNs by IP Count")
            st.plotly_chart(fig_asn, use_container_width=True)
        else: st.info("No ASN information available.")
    
    st.subheader("🔍 Drill Down Analysis & TI Lookup")
    
    valid_countries = sorted([c for c in df_geo['country'].unique() if c not in [None, 'Unknown']])
    unique_asns = sorted([a for a in df_geo['asn'].unique() if a not in [None, 'Unknown']])
    
    col1, col2 = st.columns(2)
    with col1: selected_countries = st.multiselect("Filter by Country:", options=valid_countries)
    with col2: selected_asns = st.multiselect("Filter by ASN:", options=unique_asns)
    
    filtered_geo = df_geo.copy()
    if selected_countries: filtered_geo = filtered_geo[filtered_geo['country'].isin(selected_countries)]
    if selected_asns: filtered_geo = filtered_geo[filtered_geo['asn'].isin(selected_asns)]
    
    if not filtered_geo.empty:
        st.info(f"Showing {len(filtered_geo)} matching IP addresses")
        
        for _, row in filtered_geo.iterrows():
            ip = row['ip']
            st.markdown("---")
            col1, col2, col3 = st.columns([4, 1, 1])
            with col1:
                st.write(f"**{ip}** | {row['country']} | {row['city']} | {row['asn']}")
            with col2:
                if st.button("VirusTotal", key=f"vt_{ip}"):
                    st.session_state.show_details_ip = ip
                    st.session_state.show_details_service = 'vt'
            with col3:
                if st.button("OTX", key=f"otx_{ip}"):
                    st.session_state.show_details_ip = ip
                    st.session_state.show_details_service = 'otx'
            
            if st.session_state.get('show_details_ip') == ip:
                service = st.session_state.get('show_details_service')
                if service == 'vt':
                    with st.spinner("Querying VirusTotal..."):
                        report = ti_client.get_vt_ip_report(ip)
                        display_ti_report(report)
                elif service == 'otx':
                    with st.spinner("Querying OTX..."):
                        report = ti_client.get_otx_ip_report(ip)
                        display_ti_report(report)
        st.markdown("---")
    
    else:
        st.info("No IP addresses match the current filters")

def display_detailed_findings(findings, ti_client):
    st.subheader("Detailed Findings")
    
    indicator_options = [f"{it} ({f['total_count']:,})" for it, f in findings.items() if f['total_count'] > 0]
    if not indicator_options:
        st.info("No indicators found to display.")
        return
    
    selected_indicator = st.selectbox(
        "Select indicator to view details:", 
        indicator_options,
        index=indicator_options.index(st.session_state.selected_indicator_dropdown) if st.session_state.selected_indicator_dropdown in indicator_options else 0,
        key="selected_indicator_dropdown" 
    )
    
    if selected_indicator:
        indicator_type = selected_indicator.split(' (')[0]
        finding_data = findings[indicator_type]
        is_ti_supported = indicator_type in ['ipv4_address', 'domain']
        
        all_data = finding_data.get('sample', finding_data.get('data', []))
        
        st.info(f"Search through all {len(all_data):,} findings for this indicator.")
        search_query = st.text_input(f"Search in {indicator_type} matches:", key=f"search_{indicator_type}")
        
        filtered_data = []
        if search_query:
            search_query_lower = search_query.lower()
            for item in all_data:
                if search_query_lower in item['match'].lower() or search_query_lower in item['content'].lower():
                    filtered_data.append(item)
        else:
            filtered_data = all_data

        if not is_ti_supported:
            st.dataframe(pd.DataFrame(filtered_data), use_container_width=True)
        else:
            st.markdown(f"**Showing `{len(filtered_data[:100])}` of `{len(filtered_data)}` search results.** (Max 100 displayed for performance)")
            
            for i, item in enumerate(filtered_data[:100]): 
                match = item['match']
                unique_key = f"{match}_{item['file']}_{item['line_number']}_{i}"
                
                st.markdown("---")
                col1, col2, col3 = st.columns([4, 1, 1])
                with col1:
                    st.write(f"**{match}**")
                    st.caption(f"File: {item['file']} | Line: {item['line_number']}")
                    st.code(item['content'], language="text")
                
                with col2:
                    if st.button("VirusTotal", key=f"vt_detail_{unique_key}"):
                        st.session_state.show_details_match = unique_key
                        st.session_state.show_details_service = 'vt'
                with col3:
                    if st.button("OTX", key=f"otx_detail_{unique_key}"):
                        st.session_state.show_details_match = unique_key
                        st.session_state.show_details_service = 'otx'

                if st.session_state.get('show_details_match') == unique_key:
                    service = st.session_state.get('show_details_service')
                    if service == 'vt':
                        with st.spinner("Querying VirusTotal..."):
                            report = ti_client.get_vt_domain_report(match) if indicator_type == 'domain' else ti_client.get_vt_ip_report(match)
                            display_ti_report(report)
                    elif service == 'otx':
                        with st.spinner("Querying OTX..."):
                            report = ti_client.get_otx_domain_report(match) if indicator_type == 'domain' else ti_client.get_otx_ip_report(match)
                            display_ti_report(report)
            st.markdown("---")

def display_statistics(findings):
    st.subheader("📊 Comprehensive Statistics")
    st.subheader("File Distribution")
    all_files = []
    for finding_data in findings.values():
        if finding_data.get('type') == 'summary':
            all_files.extend(finding_data['summary_stats']['top_files'].keys())
        else:
            all_files.extend(match['file'] for match in finding_data.get('data', []))
    
    if all_files:
        file_counts = Counter(all_files)
        top_files_df = pd.DataFrame(file_counts.most_common(10), columns=['File', 'Count'])
        fig_files = px.bar(top_files_df, x='Count', y='File', orientation='h', title="Top 10 Files with Most Indicators")
        st.plotly_chart(fig_files, use_container_width=True)
    else:
        st.info("No file data to display.")

def export_summary_to_csv(findings):
    export_data = []
    for indicator_type, finding_data in findings.items():
        count = finding_data['total_count']
        data_type = finding_data.get('type', 'full')
        sample_size = len(finding_data.get('sample', finding_data.get('data', [])))
        export_data.append({
            'indicator_type': indicator_type,
            'total_count': count,
            'sample_size': sample_size,
            'data_type': data_type
        })
    
    df_export = pd.DataFrame(export_data)
    csv = df_export.to_csv(index=False)
    st.sidebar.download_button(
        label="Download Summary CSV",
        data=csv,
        file_name="threat_scan_summary.csv",
        mime="text/csv"
    )

if __name__ == "__main__":
    main()
