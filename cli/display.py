# cli/display.py - Advanced Display Manager
import time
import json
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass
from enum import Enum

class Colors:
    """Color constants for terminal output"""
    # Standard colors
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    
    # Extended colors
    GREY = '\033[90m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    
    # Background colors
    BG_RED = '\033[101m'
    BG_GREEN = '\033[102m'
    BG_YELLOW = '\033[103m'
    BG_BLUE = '\033[104m'

class DisplayLevel(Enum):
    """Display verbosity levels"""
    MINIMAL = "minimal"
    NORMAL = "normal" 
    VERBOSE = "verbose"
    DEBUG = "debug"

@dataclass
class DisplayTheme:
    """Display theme configuration"""
    success_color: str = Colors.OKGREEN
    error_color: str = Colors.FAIL
    warning_color: str = Colors.WARNING
    info_color: str = Colors.OKCYAN
    highlight_color: str = Colors.BOLD
    device_color: str = Colors.MAGENTA
    vulnerability_color: str = Colors.RED
    exploit_color: str = Colors.YELLOW

class DisplayManager:
    """Advanced display and formatting manager"""
    
    def __init__(self, level: DisplayLevel = DisplayLevel.NORMAL, theme: Optional[DisplayTheme] = None):
        self.colors = Colors()
        self.level = level
        self.theme = theme or DisplayTheme()
        self.show_timestamps = True
        self.show_progress = True
        
    def set_level(self, level: DisplayLevel):
        """Set display verbosity level"""
        self.level = level
    
    def print_success(self, message: str, details: Optional[str] = None):
        """Print success message"""
        timestamp = self._get_timestamp() if self.show_timestamps else ""
        print(f"{timestamp}{self.theme.success_color}✓ {message}{self.colors.ENDC}")
        if details and self.level in [DisplayLevel.VERBOSE, DisplayLevel.DEBUG]:
            print(f"  {self.colors.GREY}{details}{self.colors.ENDC}")
    
    def print_error(self, message: str, details: Optional[str] = None):
        """Print error message"""
        timestamp = self._get_timestamp() if self.show_timestamps else ""
        print(f"{timestamp}{self.theme.error_color}✗ {message}{self.colors.ENDC}")
        if details and self.level in [DisplayLevel.VERBOSE, DisplayLevel.DEBUG]:
            print(f"  {self.colors.GREY}{details}{self.colors.ENDC}")
    
    def print_warning(self, message: str, details: Optional[str] = None):
        """Print warning message"""
        timestamp = self._get_timestamp() if self.show_timestamps else ""
        print(f"{timestamp}{self.theme.warning_color}⚠ {message}{self.colors.ENDC}")
        if details and self.level in [DisplayLevel.VERBOSE, DisplayLevel.DEBUG]:
            print(f"  {self.colors.GREY}{details}{self.colors.ENDC}")
    
    def print_info(self, message: str, details: Optional[str] = None):
        """Print info message"""
        timestamp = self._get_timestamp() if self.show_timestamps else ""
        print(f"{timestamp}{self.theme.info_color}ℹ {message}{self.colors.ENDC}")
        if details and self.level in [DisplayLevel.VERBOSE, DisplayLevel.DEBUG]:
            print(f"  {self.colors.GREY}{details}{self.colors.ENDC}")
    
    def print_device_list(self, devices: List[Dict[str, Any]], title: str = "Discovered Devices"):
        """Print formatted device list"""
        if not devices:
            self.print_info("No devices found")
            return
        
        print(f"\n{self.theme.highlight_color}{title}:{self.colors.ENDC}")
        print("─" * 80)
        
        for i, device in enumerate(devices, 1):
            device_name = device.get('name', 'Unknown Device')
            device_address = device.get('address', 'Unknown')
            rssi = device.get('rssi', 'N/A')
            
            # Color code by signal strength
            if isinstance(rssi, (int, float)):
                if rssi > -50:
                    signal_color = self.colors.OKGREEN
                    signal_icon = "📶"
                elif rssi > -70:
                    signal_color = self.colors.WARNING
                    signal_icon = "📵"
                else:
                    signal_color = self.colors.FAIL
                    signal_icon = "📱"
            else:
                signal_color = self.colors.GREY
                signal_icon = "📱"
            
            print(f"{self.colors.BOLD}[{i:2d}]{self.colors.ENDC} "
                  f"{self.theme.device_color}{device_name[:30]:<30}{self.colors.ENDC} "
                  f"{self.colors.GREY}{device_address}{self.colors.ENDC} "
                  f"{signal_color}{signal_icon} {rssi} dBm{self.colors.ENDC}")
            
            # Show additional info in verbose mode
            if self.level in [DisplayLevel.VERBOSE, DisplayLevel.DEBUG]:
                services = device.get('service_uuids', [])
                if services:
                    service_count = len(services)
                    print(f"    Services: {service_count} advertised")
                
                vendor = device.get('vendor')
                if vendor:
                    print(f"    Vendor: {vendor}")
    
    def print_vulnerability_summary(self, vulnerabilities: List[Dict[str, Any]]):
        """Print vulnerability summary"""
        if not vulnerabilities:
            self.print_info("No vulnerabilities found")
            return
        
        # Count by severity
        severity_counts = {}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'unknown')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        print(f"\n{self.theme.highlight_color}🛡️  Vulnerability Summary:{self.colors.ENDC}")
        print("─" * 50)
        
        severity_colors = {
            'critical': self.colors.BG_RED + self.colors.WHITE,
            'high': self.colors.RED,
            'medium': self.colors.WARNING,
            'low': self.colors.YELLOW,
            'info': self.colors.GREY
        }
        
        for severity, count in severity_counts.items():
            color = severity_colors.get(severity, self.colors.ENDC)
            print(f"{color}{severity.upper()}: {count}{self.colors.ENDC}")
        
        if self.level in [DisplayLevel.VERBOSE, DisplayLevel.DEBUG]:
            print(f"\n{self.theme.highlight_color}Detailed Findings:{self.colors.ENDC}")
            for i, vuln in enumerate(vulnerabilities[:10], 1):  # Show first 10
                vuln_type = vuln.get('vuln_type', 'unknown')
                title = vuln.get('title', 'Unknown Vulnerability')
                confidence = vuln.get('confidence', 0.0)
                
                severity = vuln.get('severity', 'unknown')
                color = severity_colors.get(severity, self.colors.ENDC)
                
                print(f"{color}[{i:2d}] {title}{self.colors.ENDC}")
                print(f"     Type: {vuln_type} | Confidence: {confidence:.1%}")
    
    def print_exploit_results(self, results: List[Dict[str, Any]], exploit_type: str):
        """Print exploit execution results"""
        if not results:
            self.print_info(f"No {exploit_type} exploit results")
            return
        
        successful = [r for r in results if r.get('success', False)]
        
        print(f"\n{self.theme.highlight_color}💥 {exploit_type.title()} Exploit Results:{self.colors.ENDC}")
        print("─" * 60)
        
        print(f"Total attempts: {len(results)}")
        print(f"Successful: {self.colors.OKGREEN}{len(successful)}{self.colors.ENDC}")
        print(f"Failed: {self.colors.FAIL}{len(results) - len(successful)}{self.colors.ENDC}")
        
        if successful and self.level in [DisplayLevel.VERBOSE, DisplayLevel.DEBUG]:
            print(f"\n{self.theme.highlight_color}Successful Exploits:{self.colors.ENDC}")
            for i, result in enumerate(successful, 1):
                exploit_name = result.get('exploit_name', 'Unknown')
                execution_time = result.get('execution_time', 0.0)
                
                print(f"{self.colors.OKGREEN}[{i}] {exploit_name}{self.colors.ENDC}")
                print(f"    Execution time: {execution_time:.2f}s")
                
                # Show additional details
                if 'privileges_gained' in result:
                    privs = result['privileges_gained']
                    if privs:
                        print(f"    Privileges gained: {', '.join(privs)}")
                
                if 'data_extracted' in result:
                    data = result['data_extracted']
                    if data:
                        print(f"    Data extracted: {len(data)} items")
    
    def print_device_intelligence(self, profile: Dict[str, Any]):
        """Pretty-print device intelligence profile with risk and fingerprint info"""
        print(f"\n{self.colors.BOLD}Device Intelligence Report:{self.colors.ENDC}")
        print("─" * 60)
        for k, v in profile.items():
            if k == 'risk_score':
                print(f"{self.colors.WARNING}Risk Score:{self.colors.ENDC} {v}/10")
            elif k == 'security_profile':
                print(f"{self.colors.FAIL}Security Profile:{self.colors.ENDC} {v}")
            else:
                print(f"{self.colors.OKCYAN}{k.replace('_',' ').title()}{self.colors.ENDC}: {v}")
    
    def print_timing_analysis(self, timing_data: Dict[str, Any]):
        """Print timing attack analysis"""
        attack_type = timing_data.get('attack_type', 'unknown')
        precision = timing_data.get('precision_achieved', 'unknown')
        success_rate = timing_data.get('success_rate', 0.0)
        
        print(f"\n{self.theme.highlight_color}⚡ Timing Attack Analysis:{self.colors.ENDC}")
        print("─" * 40)
        
        print(f"Attack Type: {attack_type.replace('_', ' ').title()}")
        print(f"Precision: {precision}")
        print(f"Success Rate: {success_rate:.1%}")
        
        measurements = timing_data.get('timing_measurements', [])
        if measurements and self.level == DisplayLevel.DEBUG:
            avg_time = sum(measurements) / len(measurements)
            print(f"Average Timing: {avg_time:.6f}s")
            print(f"Measurements: {len(measurements)}")
    
    def print_scan_progress(self, current: int, total: int, status: str = ""):
        """Print scan progress"""
        if not self.show_progress:
            return
        
        percentage = (current / total) * 100 if total > 0 else 0
        bar_length = 30
        filled_length = int(bar_length * current // total) if total > 0 else 0
        
        bar = '█' * filled_length + '░' * (bar_length - filled_length)
        
        print(f"\r{self.colors.OKCYAN}[{bar}] {percentage:.1f}% {status}{self.colors.ENDC}", end='', flush=True)
        
        if current >= total:
            print()  # New line when complete
    
    def print_table(self, headers: List[str], rows: List[List[str]], title: Optional[str] = None):
        """Print formatted table"""
        if not rows:
            return
        
        if title:
            print(f"\n{self.theme.highlight_color}{title}:{self.colors.ENDC}")
        
        # Calculate column widths
        col_widths = [len(header) for header in headers]
        for row in rows:
            for i, cell in enumerate(row):
                if i < len(col_widths):
                    col_widths[i] = max(col_widths[i], len(str(cell)))
        
        # Print header
        header_row = " | ".join(f"{header:<{col_widths[i]}}" for i, header in enumerate(headers))
        print(f"{self.colors.BOLD}{header_row}{self.colors.ENDC}")
        print("─" * len(header_row))
        
        # Print rows
        for row in rows:
            formatted_row = " | ".join(f"{str(cell):<{col_widths[i]}}" for i, cell in enumerate(row))
            print(formatted_row)
    
    def print_json(self, data: Dict[str, Any], title: Optional[str] = None, color: bool = True):
        """Print formatted JSON data"""
        if title:
            print(f"\n{self.theme.highlight_color}{title}:{self.colors.ENDC}")
        
        if color and self.level in [DisplayLevel.VERBOSE, DisplayLevel.DEBUG]:
            # Simple JSON coloring
            json_str = json.dumps(data, indent=2, default=str)
            # This is a simplified version - could be enhanced with proper JSON syntax highlighting
            print(f"{self.colors.GREY}{json_str}{self.colors.ENDC}")
        else:
            print(json.dumps(data, indent=2, default=str))
    
    def print_separator(self, char: str = "─", length: int = 60):
        """Print separator line"""
        print(char * length)
    
    def print_header(self, text: str, level: int = 1):
        """Print section header"""
        if level == 1:
            print(f"\n{self.theme.highlight_color}{self.colors.BOLD}{text}{self.colors.ENDC}")
            self.print_separator("═")
        elif level == 2:
            print(f"\n{self.theme.highlight_color}{text}{self.colors.ENDC}")
            self.print_separator("─")
        else:
            print(f"\n{self.colors.BOLD}{text}{self.colors.ENDC}")
    
    def format_bytes(self, data: Union[bytes, bytearray], max_length: int = 16) -> str:
        """Format bytes for display"""
        if not data:
            return ""
        
        hex_str = data[:max_length].hex().upper()
        # Add spaces every 2 characters for readability
        formatted = ' '.join(hex_str[i:i+2] for i in range(0, len(hex_str), 2))
        
        if len(data) > max_length:
            formatted += "..."
        
        return formatted
    
    def format_duration(self, seconds: float) -> str:
        """Format duration for display"""
        if seconds < 1:
            return f"{seconds*1000:.1f}ms"
        elif seconds < 60:
            return f"{seconds:.1f}s"
        elif seconds < 3600:
            minutes = int(seconds // 60)
            secs = seconds % 60
            return f"{minutes}m {secs:.1f}s"
        else:
            hours = int(seconds // 3600)
            minutes = int((seconds % 3600) // 60)
            return f"{hours}h {minutes}m"
    
    def _get_timestamp(self) -> str:
        """Get formatted timestamp"""
        return f"{self.colors.GREY}[{time.strftime('%H:%M:%S')}]{self.colors.ENDC} "
    
    def clear_screen(self):
        """Clear screen"""
        import os
        os.system('clear' if os.name == 'posix' else 'cls')
    
    def print_help(self, commands: Dict[str, Dict[str, str]]):
        """Print help information"""
        print(f"\n{self.theme.highlight_color}{self.colors.BOLD}Available Commands:{self.colors.ENDC}")
        print("─" * 60)
        
        # Group commands by category
        categories = {}
        for cmd, info in commands.items():
            category = info.get('category', 'General')
            if category not in categories:
                categories[category] = []
            categories[category].append((cmd, info))
        
        for category, cmd_list in categories.items():
            print(f"\n{self.colors.BOLD}{category}:{self.colors.ENDC}")
            for cmd, info in cmd_list:
                description = info.get('description', 'No description')
                usage = info.get('usage', cmd)
                print(f"  {self.colors.OKCYAN}{usage:<20}{self.colors.ENDC} {description}")
    
    def confirm_action(self, message: str, default: bool = False) -> bool:
        """Get user confirmation"""
        default_text = "Y/n" if default else "y/N"
        response = input(f"{self.theme.warning_color}⚠ {message} ({default_text}): {self.colors.ENDC}").strip().lower()
        
        if not response:
            return default
        
        return response in ['y', 'yes', 'true', '1']
    
    def print_banner(self):
        """Print BlueForge banner"""
        banner = f"""
{self.colors.HEADER}{self.colors.BOLD}
╔══════════════════════════════════════════════════════════════════════════════════╗
║                           🔒 BLUEFORGE v2.0.0 🔒                                 ║
║                        Advanced BLE Security Research                            ║
║                                                                                  ║
║  🎯 Vulnerability Discovery  💥 Exploit Framework  🔍 Device Analysis            ║
║  ⚡ Timing Attacks          🛡️  Security Testing   📊 Intelligence Gathering     ║
║                                                                                  ║
║                              ⚠️  RESEARCH USE ONLY ⚠️                            ║
╚══════════════════════════════════════════════════════════════════════════════════╝
{self.colors.ENDC}

Type 'help' for available commands or 'scan' to discover devices.
        """
        print(banner)
    
    def print_status_line(self, device_count: int, connected_count: int) -> str:
        """Generate status line for prompt"""
        status = ""
        if device_count > 0:
            status += f"📡{device_count}"
        if connected_count > 0:
            status += f" 🔗{connected_count}"
        
        if status:
            status = f"[{status}] "
        
        return status
    
    def print_session_summary(self, session_data: Dict[str, Any]):
        """Print session summary"""
        print(f"\n{self.theme.highlight_color}📊 Session Summary:{self.colors.ENDC}")
        print("─" * 40)
        
        discovered = session_data.get('discovered_devices', 0)
        connected = session_data.get('connected_devices', 0)
        vulnerabilities = session_data.get('vulnerabilities_found', 0)
        exploits_run = session_data.get('exploits_executed', 0)
        
        print(f"Devices discovered: {discovered}")
        print(f"Connections made: {connected}")
        print(f"Vulnerabilities found: {vulnerabilities}")
        print(f"Exploits executed: {exploits_run}")
        
        if session_data.get('session_duration'):
            duration = self.format_duration(session_data['session_duration'])
            print(f"Session duration: {duration}")
    
    def print_critical_alert(self, message: str):
        """Print critical security alert"""
        print(f"\n{self.colors.BG_RED}{self.colors.WHITE}{self.colors.BOLD}")
        print("═" * 60)
        print(f"🚨 CRITICAL SECURITY ALERT 🚨")
        print("═" * 60)
        print(f"{message}")
        print("═" * 60)
        print(f"{self.colors.ENDC}")
    
    def print_research_note(self, message: str):
        """Print research note"""
        print(f"\n{self.colors.YELLOW}🔬 Research Note:{self.colors.ENDC}")
        print(f"   {message}")
    
    def print_exploit_warning(self, exploit_name: str, risk_level: str):
        """Print exploit execution warning"""
        risk_colors = {
            'low': self.colors.YELLOW,
            'medium': self.colors.WARNING,
            'high': self.colors.RED,
            'critical': self.colors.BG_RED + self.colors.WHITE
        }
        
        color = risk_colors.get(risk_level.lower(), self.colors.WARNING)
        
        print(f"\n{color}⚠️ EXPLOIT WARNING ⚠️{self.colors.ENDC}")
        print(f"Executing: {exploit_name}")
        print(f"Risk Level: {color}{risk_level.upper()}{self.colors.ENDC}")
        print("This may crash or damage the target device.")
    
    def print_connection_status(self, device_address: str, status: str):
        """Print connection status update"""
        status_colors = {
            'connecting': self.colors.YELLOW,
            'connected': self.colors.OKGREEN,
            'disconnected': self.colors.GREY,
            'failed': self.colors.FAIL
        }
        
        color = status_colors.get(status.lower(), self.colors.ENDC)
        status_icon = {
            'connecting': '🔄',
            'connected': '✅',
            'disconnected': '❌',
            'failed': '💥'
        }.get(status.lower(), '📱')
        
        print(f"{color}{status_icon} {device_address} - {status.upper()}{self.colors.ENDC}")
    
    def print_payload_info(self, payload: bytes, payload_type: str, description: str):
        """Print payload information"""
        print(f"\n{self.theme.highlight_color}💾 Payload Information:{self.colors.ENDC}")
        print(f"Type: {payload_type}")
        print(f"Description: {description}")
        print(f"Size: {len(payload)} bytes")
        print(f"Hex: {self.format_bytes(payload, 32)}")
        
        # Show ASCII representation if printable
        try:
            ascii_repr = payload.decode('ascii', errors='ignore')
            if ascii_repr and ascii_repr.isprintable():
                print(f"ASCII: {ascii_repr[:50]}{'...' if len(ascii_repr) > 50 else ''}")
        except:
            pass
    
    def print_fuzzing_history(self, history: List[dict]):
        """Print a table of recent fuzzing sessions for a device"""
        if not history:
            self.print_info("No fuzzing history for this device.")
            return
        print(f"\n{self.theme.highlight_color}🧬 Fuzzing History:{self.colors.ENDC}")
        print("─" * 60)
        headers = ["Session ID", "Char UUID", "Strategy", "Cases", "Crashes", "Time"]
        rows = [
            [h['session_id'], h['char_uuid'], h['strategy'], h['max_cases'], h['crashes_found'], h['session_time']] for h in history
        ]
        self.print_table(headers, rows)
    
    def print_fuzzing_crash_cases(self, crash_cases: List[dict]):
        """Print a summary of crash cases from a fuzzing session"""
        if not crash_cases:
            self.print_info("No crash cases recorded for this session.")
            return
        print(f"\n{self.theme.vulnerability_color}Crash Cases:{self.colors.ENDC}")
        print("─" * 60)
        headers = ["Char UUID", "Crash Type", "Payload (hex)", "Response (hex)"]
        rows = []
        for c in crash_cases:
            payload_hex = c['payload'].hex()[:32] + ("..." if len(c['payload']) > 16 else "")
            response_hex = c['response'].hex()[:32] + ("..." if len(c['response']) > 16 else "")
            rows.append([c['char_uuid'], c['crash_type'], payload_hex, response_hex])
        self.print_table(headers, rows)