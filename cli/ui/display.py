# cli/ui/display.py
from typing import Dict, Any, List

class DisplayManager:
    """Handles all display and formatting logic"""
    
    def __init__(self, colors):
        self.colors = colors
    
    def print_banner(self):
        """Display BlueForge banner"""
        banner = f"""
{self.colors.HEADER}{self.colors.BOLD}
╔══════════════════════════════════════════════════════════════════════════════════╗
║                           BLUEFORGE SECURITY FRAMEWORK                           ║
║                        Advanced BLE Vulnerability Research                       ║
║                                   v2.0.0                                         ║
╚══════════════════════════════════════════════════════════════════════════════════╝
{self.colors.ENDC}
        """
        print(banner)
    
    def print_main_help(self, session):
        """Display main help menu"""
        print(f"\n{self.colors.HEADER}{self.colors.BOLD}╔══════════════════════════════════════════════════════════════════════════════════╗")
        print(f"║                              BLUEFORGE COMMANDS                              ║")
        print(f"╚══════════════════════════════════════════════════════════════════════════════════╝{self.colors.ENDC}")
        
        # Device Discovery & Connection
        print(f"\n{self.colors.BOLD}{self.colors.OKCYAN}📡 DEVICE DISCOVERY & CONNECTION{self.colors.ENDC}")
        print(f"  {self.colors.OKGREEN}scan{self.colors.ENDC}                    🔍 Scan for nearby BLE devices")
        print(f"  {self.colors.OKGREEN}scan-comprehensive{self.colors.ENDC}      🔍 Enhanced scanning with multiple strategies")
        print(f"  {self.colors.OKGREEN}devices{self.colors.ENDC}                 📱 List all discovered devices")
        print(f"  {self.colors.OKGREEN}connect <index>{self.colors.ENDC}         🔗 Connect to a specific device")
        print(f"  {self.colors.OKGREEN}smart-connect <index>{self.colors.ENDC}   🧠 Smart connect using device-specific strategy")
        print(f"  {self.colors.OKGREEN}disconnect [index]{self.colors.ENDC}      📤 Disconnect from device(s)")
        print(f"  {self.colors.OKGREEN}connected{self.colors.ENDC}               🌐 Show all connected devices")
        
        # Device Information & Analysis
        print(f"\n{self.colors.BOLD}{self.colors.WARNING}🔍 DEVICE INFORMATION & ANALYSIS{self.colors.ENDC}")
        print(f"  {self.colors.OKGREEN}info [index]{self.colors.ENDC}            📋 Show basic device information")
        print(f"  {self.colors.OKGREEN}profile [index]{self.colors.ENDC}         🔬 Comprehensive device profiling & analysis")
        print(f"  {self.colors.OKGREEN}services [index]{self.colors.ENDC}        🛠️  List device services & characteristics")
        print(f"  {self.colors.OKGREEN}chars [index]{self.colors.ENDC}           📝 Show detailed characteristic analysis")
        print(f"  {self.colors.OKGREEN}validate [index]{self.colors.ENDC}        ✅ Validate device for vulnerabilities")
        
        # Security Research & Testing
        print(f"\n{self.colors.BOLD}{self.colors.FAIL}🎯 SECURITY RESEARCH & TESTING{self.colors.ENDC}")
        print(f"  {self.colors.OKGREEN}research [index]{self.colors.ENDC}        🔬 Start security research on device")
        print(f"  {self.colors.OKGREEN}fuzz [index]{self.colors.ENDC}            💥 Begin fuzzing attack on device")
        print(f"  {self.colors.OKGREEN}fuzz-config{self.colors.ENDC}             ⚙️  Configure fuzzing profiles and strategies")
        print(f"  {self.colors.OKGREEN}fuzz-help{self.colors.ENDC}               🎯 Show fuzzing help and strategies")
        print(f"  {self.colors.OKGREEN}stats{self.colors.ENDC}                   📈 Show fuzzing & research statistics")
        
        # Advanced Features
        print(f"\n{self.colors.BOLD}{self.colors.OKBLUE}🚀 ADVANCED FEATURES{self.colors.ENDC}")
        print(f"  {self.colors.OKGREEN}profile-batch{self.colors.ENDC}           📊 Batch profile multiple devices")
        print(f"  {self.colors.OKGREEN}export-profiles{self.colors.ENDC}         📤 Export device profiles to file")
        print(f"  {self.colors.OKGREEN}load-targets{self.colors.ENDC}            📥 Load target list from file")
        
        # Debug & Development
        print(f"\n{self.colors.BOLD}{self.colors.OKBLUE}🐛 DEBUG & DEVELOPMENT{self.colors.ENDC}")
        print(f"  {self.colors.OKGREEN}debug-services [index]{self.colors.ENDC}  🔧 Debug service discovery issues")
        print(f"  {self.colors.OKGREEN}debug-connection [index]{self.colors.ENDC} 🔧 Debug connection issues")
        print(f"  {self.colors.OKGREEN}test-payloads{self.colors.ENDC}           🧪 Test payload generation")
        print(f"  {self.colors.OKGREEN}clear{self.colors.ENDC}                   🧹 Clear terminal screen")
        
        # Help & Navigation
        print(f"\n{self.colors.BOLD}{self.colors.HEADER}❓ HELP & NAVIGATION{self.colors.ENDC}")
        print(f"  {self.colors.OKGREEN}help{self.colors.ENDC}                    📚 Show this help message")
        print(f"  {self.colors.OKGREEN}help <command>{self.colors.ENDC}          📖 Show detailed help for specific command")
        print(f"  {self.colors.OKGREEN}status{self.colors.ENDC}                  📊 Show current session status")
        print(f"  {self.colors.OKGREEN}exit / quit{self.colors.ENDC}             👋 Exit BlueForge framework")
        
        print(f"\n{self.colors.HEADER}────────────────────────────────────────────────────────────────────────────────────{self.colors.ENDC}")
        
        # Show context-aware tips
        self._show_context_tips(session)
    
    def print_command_help(self, command: str):
        """Show detailed help for a specific command"""
        
        help_details = {
            'scan': {
                'description': 'Scan for nearby BLE devices using standard discovery',
                'usage': 'scan',
                'examples': ['scan'],
                'notes': ['Scans for 10 seconds by default', 'Use scan-comprehensive for better discovery']
            },
            'scan-comprehensive': {
                'description': 'Enhanced scanning with multiple strategies for better device discovery',
                'usage': 'scan-comprehensive [duration]',
                'examples': ['scan-comprehensive', 'scan-comprehensive 30'],
                'notes': ['Uses passive, active, and extended discovery', 'Better for finding smartphones and privacy-enabled devices']
            },
            'profile': {
                'description': 'Comprehensive device profiling with security analysis',
                'usage': 'profile [device_index]',
                'examples': ['profile 0', 'profile'],
                'notes': ['Shows advertisement analysis, manufacturer info, privacy features', 'Offers optional deep profiling with connection']
            },
            'smart-connect': {
                'description': 'Intelligent connection using device-specific strategies',
                'usage': 'smart-connect <device_index>',
                'examples': ['smart-connect 0', 'smart-connect 5'],
                'notes': ['Adapts connection approach based on device type', 'Better success rate for difficult devices like Flipper Zero']
            },
            'fuzz-config': {
                'description': 'Configure fuzzing profiles and strategies',
                'usage': 'fuzz-config [profile_name]',
                'examples': ['fuzz-config', 'fuzz-config aggressive', 'fuzz-config create custom'],
                'notes': ['Manage fuzzing profiles', 'Create custom configurations', 'Save/load fuzzing strategies']
            },
            'research': {
                'description': 'Start comprehensive security research on target device',
                'usage': 'research [device_index] [profile]',
                'examples': ['research 0', 'research 0 aggressive', 'research'],
                'notes': ['Uses memory corruption research techniques', 'Applies configurable fuzzing profiles']
            },
            'fuzz': {
                'description': 'Start fuzzing attack on device characteristics',
                'usage': 'fuzz [device_index] [strategy/profile]',
                'examples': ['fuzz 0', 'fuzz 0 timing', 'fuzz 0 aggressive'],
                'notes': ['Can use basic strategies or advanced profiles', 'May cause device instability or crashes']
            }
        }
        
        if command not in help_details:
            print(f"{self.colors.FAIL}No detailed help available for '{command}'{self.colors.ENDC}")
            return
        
        details = help_details[command]
        
        print(f"\n{self.colors.BOLD}{self.colors.HEADER}📖 DETAILED HELP: {command.upper()}{self.colors.ENDC}")
        print(f"\n{self.colors.BOLD}Description:{self.colors.ENDC}")
        print(f"  {details['description']}")
        
        print(f"\n{self.colors.BOLD}Usage:{self.colors.ENDC}")
        print(f"  {self.colors.OKCYAN}{details['usage']}{self.colors.ENDC}")
        
        print(f"\n{self.colors.BOLD}Examples:{self.colors.ENDC}")
        for example in details['examples']:
            print(f"  {self.colors.OKGREEN}{example}{self.colors.ENDC}")
        
        if details.get('notes'):
            print(f"\n{self.colors.BOLD}Notes:{self.colors.ENDC}")
            for note in details['notes']:
                print(f"  • {note}")
        
        print()
    
    def print_status(self, session):
        """Show quick status overview"""
        connected_count = len(session.connected_devices)
        discovered_count = len(session.discovered_devices)
        
        print(f"\n{self.colors.BOLD}BLUEFORGE STATUS:{self.colors.ENDC}")
        print(f"  📡 Devices discovered: {discovered_count}")
        print(f"  🔗 Devices connected: {connected_count}")
        
        if connected_count == 1:
            # Show active device info
            active_index = session.get_active_device_index()
            if active_index is not None and active_index < len(session.discovered_devices):
                device = session.discovered_devices[active_index]
                print(f"  🎯 Active device: [{active_index}] {device.name or 'Unknown'} ({device.address})")
                print(f"  💡 Tip: You can use commands without device index (e.g., 'services', 'chars')")
        elif connected_count > 1:
            print(f"  📋 Connected devices:")
            for index in session.connected_devices:
                if index < len(session.discovered_devices):
                    device = session.discovered_devices[index]
                    print(f"    [{index}] {device.name or 'Unknown'}")
            print(f"  💡 Tip: Specify device index for commands (e.g., 'services 0', 'chars 1')")
        else:
            print(f"  💡 Tip: Use 'scan' to discover devices, then 'connect <index>' to connect")
    
    def _show_context_tips(self, session):
        """Show context-aware tips based on session state"""
        if len(session.discovered_devices) == 0:
            print(f"{self.colors.WARNING}💡 Tip: Start with 'scan' to discover nearby BLE devices{self.colors.ENDC}")
        elif len(session.connected_devices) == 0:
            print(f"{self.colors.WARNING}💡 Tip: Use 'profile <index>' to analyze devices before connecting{self.colors.ENDC}")
        elif len(session.connected_devices) == 1:
            print(f"{self.colors.WARNING}💡 Tip: You can omit device index for single connected device{self.colors.ENDC}")
        else:
            print(f"{self.colors.WARNING}💡 Tip: Use 'connected' to see all active connections{self.colors.ENDC}")
    
    def format_device_list(self, devices: List, show_connection_status: bool = True, session=None):
        """Format device list for display"""
        if not devices:
            return "No devices available"
        
        output = []
        for i, device in enumerate(devices):
            # Check if connected
            is_connected = False
            if show_connection_status and session:
                is_connected = any(conn['device'].address == device.address 
                                for conn in session.connected_devices.values())
            
            status = f"{self.colors.OKGREEN}[CONNECTED]{self.colors.ENDC}" if is_connected else ""
            rssi_str = f"RSSI: {device.rssi}" if hasattr(device, 'rssi') and device.rssi else "RSSI: Unknown"
            
            device_line = f"  [{i:2d}] {device.name or 'Unknown'} ({device.address}) - {rssi_str}"
            if status:
                device_line += f" {status}"
            
            output.append(device_line)
        
        return "\n".join(output)
    
    def format_table(self, headers: List[str], rows: List[List[str]], title: str = None):
        """Format data as a simple table"""
        if title:
            print(f"\n{self.colors.BOLD}{title}{self.colors.ENDC}")
        
        # Calculate column widths
        widths = [len(header) for header in headers]
        for row in rows:
            for i, cell in enumerate(row):
                if i < len(widths):
                    widths[i] = max(widths[i], len(str(cell)))
        
        # Print header
        header_line = "  " + " | ".join(header.ljust(widths[i]) for i, header in enumerate(headers))
        print(f"{self.colors.BOLD}{header_line}{self.colors.ENDC}")
        
        # Print separator
        separator = "  " + "-|-".join("-" * width for width in widths)
        print(separator)
        
        # Print rows
        for row in rows:
            row_line = "  " + " | ".join(str(cell).ljust(widths[i]) for i, cell in enumerate(row))
            print(row_line)