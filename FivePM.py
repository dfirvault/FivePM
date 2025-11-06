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

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

print("")
print("Developed by Jacob Wilson")
print("dfirvault@gmail.com")
print("")

class GeoIPManager:
    """Manages GeoIP database download and verification"""
    
    DATABASE_URLS = {
        "city": "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb",
        "asn": "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-ASN.mmdb"
    }
    
    def __init__(self, db_dir=None):
        if db_dir is None:
            # Use user's home directory by default
            self.db_dir = Path.home() / ".threat_scanner" / "geoip"
        else:
            self.db_dir = Path(db_dir)
        
        self.db_dir.mkdir(parents=True, exist_ok=True)
    
    def get_db_path(self, db_type):
        """Get the path for a specific database type"""
        return self.db_dir / f"GeoLite2-{db_type.capitalize()}.mmdb"
    
    def download_database(self, db_type, progress_callback=None):
        """Download a GeoIP database with progress tracking"""
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
            # Clean up partial download
            if db_path.exists():
                db_path.unlink()
            return False
    
    def database_exists(self, db_type):
        """Check if database exists and is valid"""
        db_path = self.get_db_path(db_type)
        
        if not db_path.exists():
            return False
        
        # Check if file is readable and valid
        try:
            # Try to open the database to verify it's valid
            with geoip2.database.Reader(str(db_path)):
                return True
        except Exception:
            # Database is corrupted or invalid
            db_path.unlink()
            return False
    
    def ensure_databases(self, required_types=None):
        """Ensure required databases are available, download if missing"""
        if required_types is None:
            required_types = ["city", "asn"]
        
        missing_dbs = []
        for db_type in required_types:
            if not self.database_exists(db_type):
                missing_dbs.append(db_type)
        
        if missing_dbs:
            return self.download_databases(missing_dbs)
        
        return True
    
    def download_databases(self, db_types, show_progress=True):
        """Download multiple databases with progress display"""
        success_count = 0
        
        for db_type in db_types:
            if show_progress:
                st.info(f"📥 Downloading {db_type} database...")
                progress_bar = st.progress(0)
                progress_text = st.empty()
            else:
                progress_bar = None
                progress_text = None
            
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
            else:
                if show_progress:
                    progress_text.text("❌ Download failed")
        
        return success_count == len(db_types)

class ThreatIntelligenceScanner:
    def __init__(self):
        # ========================
        # EXPANDED INDICATORS
        # ========================
        self.indicators = {
            # Network Indicators
            'ipv4_address': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            'ipv6_address': r'(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}',
            'domain': r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}',
            'email_address': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'url': r'https?://[^\s]+|www\.[^\s]+',
            
            # Cryptocurrency
            'bitcoin_address': r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b',
            'ethereum_address': r'\b0x[a-fA-F0-9]{40}\b',
            
            # Hash Patterns
            'md5_hash': r'\b[a-f0-9]{32}\b',
            'sha1_hash': r'\b[a-f0-9]{40}\b',
            'sha256_hash': r'\b[a-f0-9]{64}\b',
            
            # Security Vulnerabilities
            'cve_id': r'CVE-\d{4}-\d{4,7}',
            
            # Malware and Tool Indicators
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
            
            # Credential Access
            'sekurlsa_logonpasswords': r'(?i)sekurlsa::logonpasswords',
            'lsass_process': r'(?i)lsass\.exe',
            'procdump': r'(?i)procdump',
            'pwdump': r'(?i)pwdump',
            'dcsync': r'(?i)dcsync',
            'pass_the_hash': r'(?i)pass the hash',
            
            # Reverse Shell Patterns
            'reverse_shell': r'(?i)(bash.*-i|nc.*-e|netcat.*-e|python.*socket|php.*exec.*socket)',
            'bind_shell': r'(?i)(nc.*-l.*-p|netcat.*-l.*-p|listen.*port)',
            'powershell_iex': r'(?i)powershell.*iex',
            
            # Suspicious Commands
            'powershell_download': r'(?i)(Invoke-WebRequest|wget|curl).*http',
            'base64_encoded': r'(?i)base64.*decode',
            'certutil_decode': r'(?i)certutil.*-decode',
            'bitsadmin': r'(?i)bitsadmin.*transfer',
            'encoded_command': r'(?i)encodedcommand',
            'frombase64string': r'(?i)frombase64string',
            
            # System Utilities Abuse
            'rundll32': r'(?i)rundll32',
            'regsvr32': r'(?i)regsvr32',
            'mshta': r'(?i)mshta',
            'schtasks': r'(?i)schtasks',
            'net_user': r'(?i)net user',
            
            # Persistence Mechanisms
            'scheduled_task': r'(?i)schtasks.*create',
            'registry_run': r'(?i)reg.add.*HKCU.*Software.*Microsoft.*Windows.*CurrentVersion.*Run',
            'wmi_persistence': r'(?i)wmic.*shadowcopy',
            
            # Lateral Movement
            'psexec': r'(?i)psexec',
            'wmic_remote': r'(?i)wmic.*/node:',
            'winrm': r'(?i)winrm.*invoke',
            'wmiexec': r'(?i)wmiexec',
            
            # Defense Evasion
            'amsi_bypass': r'(?i)(amsi.*bypass|amsiutils)',
            'uac_bypass': r'(?i)uac.*bypass',
            'process_hollowing': r'(?i)process.*hollow',
            'etw_bypass': r'(?i)etwbypass',
            'sharpblock': r'(?i)sharpblock',
            
            # Command and Control
            'dns_tunneling': r'(?i)nslookup.*-',
            'http_beacon': r'(?i)http.*beacon',
            'meterpreter': r'(?i)meterpreter',
            
            # Memory Operations
            'virtual_alloc': r'(?i)virtualalloc',
            'write_process_memory': r'(?i)writeprocessmemory',
            'shellcode': r'(?i)shellcode',
            
            # Cryptography and Obfuscation
            'xor_decode': r'(?i)xor decode',
            'rc4_key': r'(?i)rc4 key',
            'aes_key': r'(?i)aes key',
            
            # Additional IOCs
            'suspicious_extension': r'\.(ps1|vbs|bat|cmd|js|jse|wsf|wsh|scr|pif|exe|dll|sys)$',
            'obfuscated_code': r'(?i)(xor.*base64|string.*reverse|char.*array)',
            'suspicious_user_agent': r'(?i)(python-requests|curl|wget)',
            'encoded_payload': r'[A-Za-z0-9+/]{40,}={0,2}',
            'ssh_private_key': r'(?i)-----BEGIN.*PRIVATE KEY-----',
            'id_rsa': r'(?i)id_rsa',
        }
        
    def is_valid_ip(self, ip_str):
        """Validate if string is a valid IP address"""
        try:
            ipaddress.ip_address(ip_str)
            return True
        except ValueError:
            return False
    
    def scan_file(self, file_path):
        """Scan a single file for indicators"""
        findings = defaultdict(list)
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
                content = file.read()
                line_number = 0
                
                for line in content.split('\n'):
                    line_number += 1
                    for indicator_name, pattern in self.indicators.items():
                        matches = re.finditer(pattern, line)
                        for match in matches:
                            # Additional validation for specific indicators
                            if indicator_name in ['ipv4_address', 'ipv6_address']:
                                if not self.is_valid_ip(match.group()):
                                    continue
                            elif indicator_name == 'email_address':
                                # Basic email validation
                                email = match.group()
                                if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
                                    continue
                            
                            findings[indicator_name].append({
                                'file': file_path,
                                'line_number': line_number,
                                'content': line.strip(),
                                'match': match.group()
                            })
        except Exception as e:
            st.warning(f"Could not read file {file_path}: {str(e)}")
        
        return findings
    
    def scan_directory(self, directory_path):
        """Scan all files in a directory"""
        all_findings = defaultdict(list)
        scanned_files = 0
        
        for root, dirs, files in os.walk(directory_path):
            for file in files:
                file_path = os.path.join(root, file)
                findings = self.scan_file(file_path)
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
        """Initialize GeoIP readers with automatic database management"""
        try:
            city_path = self.geoip_manager.get_db_path("city")
            asn_path = self.geoip_manager.get_db_path("asn")
            
            if city_path.exists():
                self.city_reader = geoip2.database.Reader(str(city_path))
                logger.info("City database initialized successfully")
            if asn_path.exists():
                self.asn_reader = geoip2.database.Reader(str(asn_path))
                logger.info("ASN database initialized successfully")
                
        except Exception as e:
            logger.error(f"Error initializing GeoIP databases: {str(e)}")
    
    def get_ip_info(self, ip_address):
        """Get geographic information for an IP address"""
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
            # Log the error but don't show it to the user for every failed lookup
            logger.debug(f"GeoIP lookup failed for {ip_address}: {str(e)}")
        
        # Return default values if lookup fails
        return {
            'ip': ip_address,
            'country': 'Unknown',
            'country_code': 'XX',
            'city': 'Unknown',
            'latitude': 0,
            'longitude': 0,
            'asn': 'Unknown'
        }
    
    def get_asn_info(self, ip_address):
        """Get ASN information for an IP address"""
        try:
            if self.asn_reader:
                response = self.asn_reader.asn(ip_address)
                return response.autonomous_system_organization if response.autonomous_system_organization else 'Unknown'
        except Exception as e:
            logger.debug(f"ASN lookup failed for {ip_address}: {str(e)}")
        return 'Unknown'
    
    def close(self):
        """Close database readers"""
        if self.city_reader:
            self.city_reader.close()
        if self.asn_reader:
            self.asn_reader.close()

def folder_picker():
    """Create a folder picker using JavaScript"""
    html = """
    <script>
    function triggerFilePicker() {
        const input = document.createElement('input');
        input.type = 'file';
        input.webkitdirectory = true;
        input.multiple = true;
        
        input.onchange = function(e) {
            const files = e.target.files;
            if (files.length > 0) {
                const path = files[0].webkitRelativePath;
                const folder = path.split('/')[0];
                // Get the directory path
                const fullPath = files[0].path.substring(0, files[0].path.lastIndexOf(folder)) + folder;
                
                // Send the path to Streamlit
                const code = `window.parent.postMessage({type: 'folderSelected', path: '${fullPath}'}, '*');`;
                input.remove();
                eval(code);
            }
        };
        
        input.click();
    }
    
    // Trigger the file picker when this script runs
    triggerFilePicker();
    </script>
    """
    components.html(html, height=0)

# In the main function, replace the JavaScript message handler and folder selection section with:
    # JavaScript message handler
    components.html("""
    <script>
    window.addEventListener('message', function(event) {
        if (event.data.type === 'folderSelected') {
            // Update the Streamlit session state
            const path = event.data.path;
            window.parent.postMessage({
                type: 'streamlit:setComponentValue',
                value: path
            }, '*');
        }
    });
    </script>
    """, height=0)
    
    # Check for folder selection from frontend
    try:
        if st.session_state.get('folder_input'):
            folder_path = st.session_state.folder_input
            if folder_path and folder_path != st.session_state.get('last_folder', ''):
                st.session_state.selected_directory = folder_path
                st.session_state.last_folder = folder_path
                st.rerun()
    except:
        pass

    # Add a hidden text input to capture the folder path
    folder_path = st.text_input("Selected folder:", key="folder_input", label_visibility="collapsed", value="")

def optimize_large_dataset(findings, max_samples=1000):
    """Optimize large datasets by sampling and creating summaries"""
    optimized = {}
    
    for indicator_type, matches in findings.items():
        if len(matches) > max_samples:
            # For large datasets, store summary statistics
            optimized[indicator_type] = {
                'type': 'summary',
                'total_count': len(matches),
                'sample': matches[:max_samples],  # Keep a sample for display
                'summary_stats': get_summary_stats(matches, indicator_type)
            }
        else:
            # For small datasets, keep all data
            optimized[indicator_type] = {
                'type': 'full',
                'data': matches,
                'total_count': len(matches)
            }
    
    return optimized

def get_summary_stats(matches, indicator_type):
    """Generate summary statistics for large datasets"""
    if indicator_type in ['ipv4_address', 'ipv6_address']:
        # Count unique IPs
        unique_ips = Counter(match['match'] for match in matches)
        top_ips = dict(unique_ips.most_common(20))
        
        # File distribution
        file_counts = Counter(match['file'] for match in matches)
        top_files = dict(file_counts.most_common(10))
        
        return {
            'unique_ips_count': len(unique_ips),
            'top_ips': top_ips,
            'top_files': top_files
        }
    else:
        # Generic summary for other indicators
        unique_matches = Counter(match['match'] for match in matches)
        file_counts = Counter(match['file'] for match in matches)
        
        return {
            'unique_matches_count': len(unique_matches),
            'top_matches': dict(unique_matches.most_common(20)),
            'top_files': dict(file_counts.most_common(10))
        }

def main():
    st.set_page_config(
        page_title="Threat Intelligence Scanner",
        page_icon="🔍",
        layout="wide"
    )
    
    st.title("🔍 Advanced Threat Intelligence Scanner")
    st.markdown("""
    This application scans files and directories for various threat indicators including:
    - **Network Indicators**: IP addresses, domains, emails, URLs
    - **Cryptocurrency**: Bitcoin, Ethereum addresses
    - **Malware Signatures**: Mimikatz, Cobalt Strike, Metasploit, etc.
    - **Attack Patterns**: Reverse shells, credential dumping, lateral movement
    - **Security Vulnerabilities**: CVE IDs, suspicious commands
    - **Cryptographic Artifacts**: Hashes, encryption keys, obfuscated code
    """)
    
    # Initialize GeoIP Manager
    geoip_manager = GeoIPManager()
    
    # Initialize session state
    if 'scan_results' not in st.session_state:
        st.session_state.scan_results = None
    if 'geo_data' not in st.session_state:
        st.session_state.geo_data = None
    if 'selected_directory' not in st.session_state:
        st.session_state.selected_directory = None
    if 'geoip_available' not in st.session_state:
        st.session_state.geoip_available = False
    
    # GeoIP Database Management Sidebar
    st.sidebar.header("🌍 GeoIP Databases")
    
    # Check database status
    city_exists = geoip_manager.database_exists("city")
    asn_exists = geoip_manager.database_exists("asn")
    
    col1, col2 = st.sidebar.columns(2)
    with col1:
        st.metric("City DB", "✅" if city_exists else "❌")
    with col2:
        st.metric("ASN DB", "✅" if asn_exists else "❌")
    
    # Database management options
    if not (city_exists and asn_exists):
        st.sidebar.warning("GeoIP databases not found!")
        
        if st.sidebar.button("📥 Download GeoIP Databases", type="primary"):
            with st.sidebar:
                success = geoip_manager.download_databases(["city", "asn"])
                if success:
                    st.session_state.geoip_available = True
                    st.rerun()
    else:
        st.sidebar.success("GeoIP databases ready!")
        st.session_state.geoip_available = True
        
        if st.sidebar.button("🔄 Update Databases"):
            with st.sidebar:
                st.info("Downloading latest databases...")
                success = geoip_manager.download_databases(["city", "asn"])
                if success:
                    st.success("Databases updated successfully!")
                    st.rerun()
    
    # File upload section
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
                    findings = scanner.scan_file(tmp_path)
                    # Optimize for large datasets
                    optimized_findings = optimize_large_dataset(findings)
                    st.session_state.scan_results = optimized_findings
                    st.session_state.scanned_files = 1
                
                os.unlink(tmp_path)
    
    else:  # Select Directory
        st.sidebar.subheader("📁 Folder Picker")
        
        # Simple directory input instead of JavaScript picker
        directory_path = st.sidebar.text_input(
            "Enter directory path:",
            value=st.session_state.selected_directory or "",
            placeholder="/path/to/directory"
        )
        
        if st.sidebar.button("📂 Use This Directory", type="primary"):
            if directory_path and os.path.exists(directory_path) and os.path.isdir(directory_path):
                st.session_state.selected_directory = directory_path
                st.sidebar.success(f"Selected: `{directory_path}`")
                st.rerun()
            else:
                st.sidebar.error("Invalid directory path!")
        
        if st.sidebar.button("🗑️ Clear Selection"):
            st.session_state.selected_directory = None
            st.session_state.scan_results = None
            st.rerun()
        
        # Display selected directory
        if st.session_state.selected_directory:
            st.sidebar.success(f"Selected: `{st.session_state.selected_directory}`")
        
        # Scan button
        if st.session_state.selected_directory and st.sidebar.button("🔍 Scan Directory", type="primary"):
            if os.path.exists(st.session_state.selected_directory) and os.path.isdir(st.session_state.selected_directory):
                with st.spinner("Scanning directory for threats..."):
                    findings, scanned_files = scanner.scan_directory(st.session_state.selected_directory)
                    # Optimize for large datasets
                    optimized_findings = optimize_large_dataset(findings)
                    st.session_state.scan_results = optimized_findings
                    st.session_state.scanned_files = scanned_files
            else:
                st.error("Invalid directory path!")
    
    # Handle folder selection from JavaScript
    if 'folder_selected' not in st.session_state:
        st.session_state.folder_selected = False
    
    # JavaScript message handler
    components.html("""
    <script>
    window.addEventListener('message', function(event) {
        if (event.data.type === 'folderSelected') {
            const path = event.data.path;
            window.parent.postMessage({type: 'streamlit:setComponentValue', value: path}, '*');
        }
    });
    </script>
    """, height=0)
    
    # Check for folder selection from frontend
    try:
        folder_path = st.text_input("Selected folder:", key="folder_input", label_visibility="collapsed")
        if folder_path and folder_path != st.session_state.get('last_folder', ''):
            st.session_state.selected_directory = folder_path
            st.session_state.last_folder = folder_path
            st.rerun()
    except:
        pass
    
    # Display results
    if st.session_state.scan_results:
        findings = st.session_state.scan_results
        
        # Summary statistics
        st.header("📊 Scan Summary")
        col1, col2, col3, col4 = st.columns(4)
        
        total_indicators = sum(finding['total_count'] if 'total_count' in finding else len(finding.get('data', [])) 
                              for finding in findings.values())
        total_files = st.session_state.scanned_files
        
        with col1:
            st.metric("Files Scanned", total_files)
        with col2:
            st.metric("Total Indicators Found", total_indicators)
        with col3:
            st.metric("Indicator Types", len(findings))
        with col4:
            if st.session_state.selected_directory:
                st.metric("Scanned Directory", os.path.basename(st.session_state.selected_directory))
        
        # Large dataset warning
        if total_indicators > 10000:
            st.warning(f"⚠️ Large dataset detected: {total_indicators:,} indicators found. Using optimized views for better performance.")
        
        # Overview Dashboard
        st.header("📈 Overview Dashboard")
        
        # Create tabs for different views
        tab1, tab2, tab3, tab4 = st.tabs(["📋 Indicators Overview", "🌍 IP Analysis", "🔍 Detailed Findings", "📊 Statistics"])
        
        with tab1:
            display_indicators_overview(findings)
        
        with tab2:
            display_ip_analysis(findings, geoip_manager)
        
        with tab3:
            display_detailed_findings(findings)
        
        with tab4:
            display_statistics(findings)
        
        # Export results
        st.sidebar.header("💾 Export Results")
        if st.sidebar.button("Export Summary to CSV"):
            export_summary_to_csv(findings)

def display_indicators_overview(findings):
    """Display overview of all indicators"""
    st.subheader("Indicator Summary")
    
    # Group indicators by category for better organization
    categories = {
        'Network': ['ipv4_address', 'ipv6_address', 'domain', 'email_address', 'url'],
        'Cryptocurrency': ['bitcoin_address', 'ethereum_address'],
        'Hashes': ['md5_hash', 'sha1_hash', 'sha256_hash'],
        'Security': ['cve_id'],
        'Malware': ['mimikatz', 'metasploit', 'cobalt_strike', 'empire', 'beacon', 'nishang', 
                   'covenant', 'poshc2', 'sqlmap', 'nikto', 'bloodhound', 'sharphound'],
        'Credential Access': ['sekurlsa_logonpasswords', 'lsass_process', 'procdump', 'pwdump', 
                             'dcsync', 'pass_the_hash'],
        'Lateral Movement': ['psexec', 'wmic_remote', 'winrm', 'wmiexec'],
        'Defense Evasion': ['amsi_bypass', 'uac_bypass', 'process_hollowing', 'etw_bypass', 'sharpblock'],
        'Command Control': ['reverse_shell', 'bind_shell', 'powershell_iex', 'dns_tunneling', 
                           'http_beacon', 'meterpreter']
    }
    
    # Create summary cards by category
    for category, indicators in categories.items():
        st.subheader(f"{category} Indicators")
        cols = st.columns(4)
        indicator_count = 0
        
        for indicator_type in indicators:
            if indicator_type in findings:
                finding_data = findings[indicator_type]
                if finding_data.get('type') == 'summary':
                    count = finding_data['total_count']
                else:
                    count = len(finding_data.get('data', []))
                
                if count > 0:
                    with cols[indicator_count % 4]:
                        st.metric(
                            label=indicator_type.replace('_', ' ').title(),
                            value=f"{count:,}"
                        )
                    indicator_count += 1
        
        if indicator_count == 0:
            st.info(f"No {category.lower()} indicators found")
    
    # Top indicators by count
    st.subheader("Top Indicators Overall")
    indicator_counts = []
    for indicator_type, finding_data in findings.items():
        if finding_data.get('type') == 'summary':
            count = finding_data['total_count']
        else:
            count = len(finding_data.get('data', []))
        
        if count > 0:
            indicator_counts.append((indicator_type, count))
    
    # Sort by count and take top 15
    indicator_counts.sort(key=lambda x: x[1], reverse=True)
    
    if indicator_counts:
        top_indicators_df = pd.DataFrame(indicator_counts[:15], columns=['Indicator', 'Count'])
        fig = px.bar(top_indicators_df, x='Count', y='Indicator', orientation='h',
                    title="Top 15 Indicators by Count")
        st.plotly_chart(fig, use_container_width=True)

def display_ip_analysis(findings, geoip_manager):
    """Display IP analysis with filters"""
    # Check for both IPv4 and IPv6 addresses
    ip_indicators = []
    if 'ipv4_address' in findings:
        ip_indicators.append('ipv4_address')
    if 'ipv6_address' in findings:
        ip_indicators.append('ipv6_address')
    
    if not ip_indicators:
        st.info("No IP addresses found in the scan.")
        return
    
    # Combine all IP data
    all_ip_data = []
    total_ips = 0
    for ip_indicator in ip_indicators:
        ip_data = findings[ip_indicator]
        if ip_data.get('type') == 'summary':
            all_ip_data.extend(ip_data['sample'])
            total_ips += ip_data['total_count']
        else:
            all_ip_data.extend(ip_data.get('data', []))
            total_ips += len(ip_data.get('data', []))
    
    if not all_ip_data:
        st.info("No valid IP addresses found for analysis.")
        return
    
    st.subheader("IP Address Analysis")
    
    # Check if GeoIP is available
    if not st.session_state.geoip_available:
        st.warning("""
        ⚠️ GeoIP analysis requires databases to be downloaded.
        
        Please go to the **🌍 GeoIP Databases** section in the sidebar and click 
        "Download GeoIP Databases" to enable IP geolocation features.
        """)
        
        # Show basic IP analysis without GeoIP
        st.subheader("Basic IP Analysis (Without Geolocation)")
        unique_ips = Counter(match['match'] for match in all_ip_data)
        top_ips_df = pd.DataFrame(unique_ips.most_common(20), columns=['IP Address', 'Count'])
        st.dataframe(top_ips_df, use_container_width=True)
        return
    
    # Initialize GeoIP analyzer
    geo_analyzer = GeoIPAnalyzer(geoip_manager)
    
    # Extract unique IPs from our sample
    unique_ips = set(match['match'] for match in all_ip_data)
    
    # Show progress and get geo information
    with st.spinner(f"Geolocating {len(unique_ips):,} unique IP addresses..."):
        geo_data = []
        successful_lookups = 0
        failed_lookups = 0
        
        for ip in list(unique_ips)[:1000]:  # Limit to 1000 IPs for performance
            geo_info = geo_analyzer.get_ip_info(ip)
            geo_data.append(geo_info)
            
            if geo_info['country'] != 'Unknown':
                successful_lookups += 1
            else:
                failed_lookups += 1
    
    # Close the analyzer to free resources
    geo_analyzer.close()
    
    # Show lookup statistics
    if failed_lookups > 0:
        st.info(f"📍 Geolocation results: {successful_lookups} successful, {failed_lookups} failed (private/IPv6/unknown)")
    
    if geo_data:
        df_geo = pd.DataFrame(geo_data)
        
        # Ensure we have valid country data for filtering
        valid_countries = [country for country in df_geo['country'].unique() if country != 'Unknown']
        
        # Country analysis
        st.subheader("🌍 Country Distribution")
        country_counts = df_geo['country'].value_counts().reset_index()
        country_counts.columns = ['Country', 'Count']
        
        # Filter out 'Unknown' for the chart
        country_counts_chart = country_counts[country_counts['Country'] != 'Unknown']
        
        if not country_counts_chart.empty:
            fig_country = px.pie(country_counts_chart.head(10), values='Count', names='Country',
                               title="Top 10 Countries by IP Count")
            st.plotly_chart(fig_country, use_container_width=True)
            
            # Also show as bar chart for better readability
            fig_country_bar = px.bar(country_counts_chart.head(15), x='Count', y='Country', orientation='h',
                                   title="Top 15 Countries by IP Count")
            st.plotly_chart(fig_country_bar, use_container_width=True)
        else:
            st.info("No country information available for the found IP addresses.")
        
        # ASN analysis
        st.subheader("🖧 ASN Distribution")
        asn_counts = df_geo['asn'].value_counts().reset_index()
        asn_counts.columns = ['ASN', 'Count']
        asn_counts = asn_counts[asn_counts['ASN'] != 'Unknown']
        
        if not asn_counts.empty:
            fig_asn = px.bar(asn_counts.head(15), x='Count', y='ASN', orientation='h',
                           title="Top 15 ASNs by IP Count")
            st.plotly_chart(fig_asn, use_container_width=True)
        else:
            st.info("No ASN information available for the found IP addresses.")
        
        # Interactive filters
        st.subheader("🔍 Drill Down Analysis")
        
        col1, col2 = st.columns(2)
        
        with col1:
            selected_countries = st.multiselect(
                "Filter by Country:",
                options=sorted([c for c in valid_countries if c is not None]),
                default=[],
                help="Select countries to filter IP addresses"
            )
        
        with col2:
            # Get unique ASNs for filtering (excluding 'Unknown' and None values)
            unique_asns = [asn for asn in df_geo['asn'].unique() if asn not in [None, 'Unknown']]
            selected_asns = st.multiselect(
                "Filter by ASN:",
                options=sorted([a for a in unique_asns if a is not None]),
                default=[],
                help="Select Autonomous System Numbers to filter IP addresses"
            )
        
        # Apply filters
        filtered_geo = df_geo.copy()
        if selected_countries:
            filtered_geo = filtered_geo[filtered_geo['country'].isin(selected_countries)]
        if selected_asns:
            filtered_geo = filtered_geo[filtered_geo['asn'].isin(selected_asns)]
        
        # Show filtered results
        if not filtered_geo.empty:
            st.subheader("📋 Filtered IP Details")
            st.dataframe(filtered_geo[['ip', 'country', 'city', 'asn', 'latitude', 'longitude']], use_container_width=True)
            
            # Show related log entries
            st.subheader("📄 Related Log Entries")
            filtered_ips = set(filtered_geo['ip'])
            
            related_entries = []
            for ip_match in all_ip_data:
                if ip_match['match'] in filtered_ips:
                    related_entries.append(ip_match)
            
            if related_entries:
                st.dataframe(pd.DataFrame(related_entries[:100]), use_container_width=True)  # Limit to 100 entries
                if len(related_entries) > 100:
                    st.info(f"Showing first 100 of {len(related_entries):,} related entries")
            else:
                st.info("No log entries match the current filters")
        else:
            st.info("No IP addresses match the current filters")

def display_detailed_findings(findings):
    """Display detailed findings with pagination"""
    st.subheader("Detailed Findings")
    
    # Let user select which indicator to view
    indicator_options = []
    for indicator_type, finding_data in findings.items():
        if finding_data.get('type') == 'summary':
            count = finding_data['total_count']
        else:
            count = len(finding_data.get('data', []))
        
        if count > 0:
            indicator_options.append(f"{indicator_type} ({count:,})")
    
    if not indicator_options:
        st.info("No indicators found to display.")
        return
    
    selected_indicator = st.selectbox("Select indicator to view details:", indicator_options)
    
    if selected_indicator:
        indicator_type = selected_indicator.split(' (')[0]
        finding_data = findings[indicator_type]
        
        if finding_data.get('type') == 'summary':
            st.info(f"📊 Showing sample of 1,000 entries from {finding_data['total_count']:,} total findings")
            data_to_show = finding_data['sample'][:1000]
            st.dataframe(pd.DataFrame(data_to_show), use_container_width=True)
        else:
            st.dataframe(pd.DataFrame(finding_data['data']), use_container_width=True)

def display_statistics(findings):
    """Display comprehensive statistics"""
    st.subheader("📊 Comprehensive Statistics")
    
    # File distribution
    st.subheader("File Distribution")
    all_files = []
    
    for indicator_type, finding_data in findings.items():
        if finding_data.get('type') == 'summary':
            files = list(finding_data['summary_stats']['top_files'].keys())
            all_files.extend(files)
        else:
            files = [match['file'] for match in finding_data.get('data', [])]
            all_files.extend(files)
    
    if all_files:
        file_counts = Counter(all_files)
        top_files_df = pd.DataFrame(file_counts.most_common(10), columns=['File', 'Count'])
        fig_files = px.bar(top_files_df, x='Count', y='File', orientation='h',
                          title="Top 10 Files with Most Indicators")
        st.plotly_chart(fig_files, use_container_width=True)

def export_summary_to_csv(findings):
    """Export summary data to CSV"""
    export_data = []
    
    for indicator_type, finding_data in findings.items():
        if finding_data.get('type') == 'summary':
            count = finding_data['total_count']
            sample_size = len(finding_data.get('sample', []))
            export_data.append({
                'indicator_type': indicator_type,
                'total_count': count,
                'sample_size': sample_size,
                'data_type': 'summary'
            })
        else:
            count = len(finding_data.get('data', []))
            export_data.append({
                'indicator_type': indicator_type,
                'total_count': count,
                'sample_size': count,
                'data_type': 'full'
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