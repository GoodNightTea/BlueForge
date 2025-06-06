# cli/blueforge_cli.py
import asyncio
import sys
import os
import json
from typing import List, Dict, Any, Optional
from datetime import datetime
import argparse

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.connection_manager import EnhancedBLEManager, BlueForgeConnectionManager
from core.fuzzing_engine import AdvancedFuzzingEngine, FuzzStrategy
from exploits.memory_research import MemoryCorruptionResearch
from utils.logging import get_logger, set_log_level
from config import config

logger = get_logger(__name__)

class BlueForgeColors:
    """ANSI color codes for terminal output"""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class BlueForgeSession:
    """Manages active BlueForge session state"""
    
    def __init__(self):
        self.ble_manager = EnhancedBLEManager()
        self.fuzzer = AdvancedFuzzingEngine()
        self.researcher = MemoryCorruptionResearch()
        self.discovered_devices = []
        self.connected_devices = {}
        self.session_stats = {
            'scans_performed': 0,
            'devices_tested': 0,
            'vulnerabilities_found': 0,
            'session_start': datetime.now()
        }
class BlueForgeInteractiveCLI:
    """Interactive CLI for BlueForge Security Research Framework"""
    
    def __init__(self):
        self.session = BlueForgeSession()
        self.running = True
        self.colors = BlueForgeColors()
        
    def print_banner(self):
        """Display BlueForge banner"""
        banner = f"""
{self.colors.HEADER}{self.colors.BOLD}
╔══════════════════════════════════════════════════════════════════════════════════╗
║                           BLUEFORGE SECURITY FRAMEWORK                          ║
║                        Advanced BLE Vulnerability Research                      ║
║                                   v2.0.0                                        ║
╚══════════════════════════════════════════════════════════════════════════════════╝
{self.colors.ENDC}
        """
        print(banner)

    def print_prompt(self):
        """Generate command prompt"""
        return f"{self.colors.OKCYAN}blueforge{self.colors.ENDC}> "
    def print_help(self, args: List[str]):
        """Display help information with organized categories"""
        print(f"\n{self.colors.HEADER}{self.colors.BOLD}╔══════════════════════════════════════════════════════════════════════════════════╗")
        print(f"║                              BLUEFORGE COMMANDS                              ║")
        print(f"╚══════════════════════════════════════════════════════════════════════════════════╝{self.colors.ENDC}")
        
        # Device Discovery & Connection
        print(f"\n{self.colors.BOLD}{self.colors.OKCYAN}📡 DEVICE DISCOVERY & CONNECTION{self.colors.ENDC}")
        print(f"  {self.colors.OKGREEN}scan{self.colors.ENDC}                    🔍 Scan for nearby BLE devices")
        print(f"  {self.colors.OKGREEN}devices{self.colors.ENDC}                 📱 List all discovered devices")
        print(f"  {self.colors.OKGREEN}connect <index>{self.colors.ENDC}         🔗 Connect to a specific device")
        print(f"  {self.colors.OKGREEN}disconnect [index]{self.colors.ENDC}      📤 Disconnect from device(s)")
        print(f"  {self.colors.OKGREEN}connected{self.colors.ENDC}               🌐 Show all connected devices")
        
        # Device Information & Analysis
        print(f"\n{self.colors.BOLD}{self.colors.WARNING}🔍 DEVICE INFORMATION & ANALYSIS{self.colors.ENDC}")
        print(f"  {self.colors.OKGREEN}info [index]{self.colors.ENDC}            📋 Show detailed device information")
        print(f"  {self.colors.OKGREEN}services [index]{self.colors.ENDC}        🛠️  List device services & characteristics")
        print(f"  {self.colors.OKGREEN}validate [index]{self.colors.ENDC}        ✅ Validate device for vulnerabilities")
        print(f"  {self.colors.OKGREEN}status{self.colors.ENDC}                  📊 Show current session status")
        
        # Security Research & Testing
        print(f"\n{self.colors.BOLD}{self.colors.FAIL}🎯 SECURITY RESEARCH & TESTING{self.colors.ENDC}")
        print(f"  {self.colors.OKGREEN}research [index]{self.colors.ENDC}        🔬 Start security research on device")
        print(f"  {self.colors.OKGREEN}fuzz [index]{self.colors.ENDC}            💥 Begin fuzzing attack on device")
        print(f"  {self.colors.OKGREEN}stats{self.colors.ENDC}                   📈 Show fuzzing & research statistics")
        
        # Session Management
        print(f"\n{self.colors.BOLD}{self.colors.OKBLUE}⚙️  SESSION MANAGEMENT{self.colors.ENDC}")
        print(f"  {self.colors.OKGREEN}config{self.colors.ENDC}                  🔧 Show current configuration")
        print(f"  {self.colors.OKGREEN}export{self.colors.ENDC}                  💾 Export session data & results")
        print(f"  {self.colors.OKGREEN}clear{self.colors.ENDC}                   🧹 Clear terminal screen")
        print(f"  {self.colors.OKGREEN}debug{self.colors.ENDC}                   🐛 Toggle debug logging mode")
        
        # Help & Navigation
        print(f"\n{self.colors.BOLD}{self.colors.HEADER}❓ HELP & NAVIGATION{self.colors.ENDC}")
        print(f"  {self.colors.OKGREEN}help{self.colors.ENDC}                    📚 Show this help message")
        print(f"  {self.colors.OKGREEN}exit / quit{self.colors.ENDC}             👋 Exit BlueForge framework")
        
        # Usage Tips
        print(f"\n{self.colors.BOLD}{self.colors.OKCYAN}💡 USAGE TIPS{self.colors.ENDC}")
        print(f"  • Commands with {self.colors.WARNING}[index]{self.colors.ENDC} are optional when only one device is connected")
        print(f"  • Commands with {self.colors.FAIL}<index>{self.colors.ENDC} require a device index parameter")
        print(f"  • Use {self.colors.OKGREEN}status{self.colors.ENDC} to see connected devices and their indices")
        print(f"  • Start with {self.colors.OKGREEN}scan{self.colors.ENDC} → {self.colors.OKGREEN}connect <index>{self.colors.ENDC} → {self.colors.OKGREEN}services{self.colors.ENDC} → {self.colors.OKGREEN}fuzz{self.colors.ENDC}")
        
        # Security Warning
        print(f"\n{self.colors.BOLD}{self.colors.FAIL}⚠️  SECURITY WARNING{self.colors.ENDC}")
        print(f"  {self.colors.WARNING}BlueForge is designed for authorized security research only.")
        print(f"  Only test devices you own or have explicit permission to test.")
        print(f"  Unauthorized testing may violate laws and regulations.{self.colors.ENDC}")
        
        print(f"\n{self.colors.HEADER}────────────────────────────────────────────────────────────────────────────────────{self.colors.ENDC}")

    def get_device_from_args_or_active(self, args: List[str]) -> Optional[int]:
        """Get device index from args or return active device if only one connected"""
        if args:
            try:
                return int(args[0])
            except (ValueError, IndexError):
                return None
        
        # If no args and only one device connected, use it
        if len(self.session.connected_devices) == 1:
            return list(self.session.connected_devices.keys())[0]
        
        return None

    def get_active_device_index(self) -> Optional[int]:
        """Get the active device index (if only one connected)"""
        if len(self.session.connected_devices) == 1:
            return list(self.session.connected_devices.keys())[0]
        return None

    async def cmd_info(self, args: List[str]):
        """Show detailed device information"""
        index = self.get_device_from_args_or_active(args)
        
        if index is None:
            if not args and len(self.session.connected_devices) > 1:
                print(f"{self.colors.FAIL}Multiple devices connected. Specify index: info <device_index>{self.colors.ENDC}")
            elif not args and len(self.session.connected_devices) == 0:
                print(f"{self.colors.FAIL}No devices connected. Use 'connect <index>' first{self.colors.ENDC}")
            else:
                print(f"{self.colors.FAIL}Usage: info [device_index]{self.colors.ENDC}")
            return
        
        if index >= len(self.session.discovered_devices):
            print(f"{self.colors.FAIL}Invalid device index{self.colors.ENDC}")
            return
        
        device = self.session.discovered_devices[index]
        is_connected = index in self.session.connected_devices
        
        print(f"\n{self.colors.BOLD}DEVICE INFORMATION:{self.colors.ENDC}")
        print(f"  📱 Index: {index}")
        print(f"  🏷️  Name: {device.name or 'Unknown Device'}")
        print(f"  📍 Address: {device.address}")
        print(f"  📶 RSSI: {getattr(device, 'rssi', 'Unknown')} dBm")
        print(f"  🔗 Status: {'Connected' if is_connected else 'Disconnected'}")
        
        if is_connected:
            conn_info = self.session.connected_devices[index]
            connected_at = conn_info['connected_at'].strftime("%Y-%m-%d %H:%M:%S")
            print(f"  ⏰ Connected since: {connected_at}")
            
            # Get connection manager info
            cm_info = self.session.ble_manager.connection_manager.get_device_report(device.address)
            if cm_info:
                print(f"  🔧 Services: {cm_info['services_count']}")
                print(f"  📝 Characteristics: {cm_info['total_characteristics']}")
                print(f"  🔄 Connection attempts: {cm_info['connection_attempts']}")
                print(f"  💥 Crash count: {cm_info['crash_count']}")

    async def cmd_services(self, args: List[str]):
        """List device services and characteristics"""
        index = self.get_device_from_args_or_active(args)
        
        if index is None:
            if not args and len(self.session.connected_devices) > 1:
                print(f"{self.colors.FAIL}Multiple devices connected. Specify index: services <device_index>{self.colors.ENDC}")
            elif not args and len(self.session.connected_devices) == 0:
                print(f"{self.colors.FAIL}No devices connected. Use 'connect <index>' first{self.colors.ENDC}")
            else:
                print(f"{self.colors.FAIL}Usage: services [device_index]{self.colors.ENDC}")
            return
        
        if index not in self.session.connected_devices:
            print(f"{self.colors.FAIL}Device not connected. Use 'connect {index}' first{self.colors.ENDC}")
            return
        
        device_info = self.session.connected_devices[index]
        device = device_info['device']
        client = device_info['client']
        
        print(f"\n{self.colors.BOLD}SERVICES & CHARACTERISTICS - {device.name or 'Unknown'}:{self.colors.ENDC}")
        
        try:
            services = client.services
            
            for i, service in enumerate(services):
                print(f"\n  [{i:2d}] 🛠️  Service: {self.colors.OKCYAN}{service.uuid}{self.colors.ENDC}")
                print(f"       Description: {service.description}")
                
                for j, char in enumerate(service.characteristics):
                    # Color code by properties
                    props = char.properties
                    if "write" in props:
                        prop_color = self.colors.WARNING  # Writable = interesting for fuzzing
                        prop_icon = "✏️"
                    elif "read" in props:
                        prop_color = self.colors.OKGREEN
                        prop_icon = "👁️"
                    else:
                        prop_color = self.colors.ENDC
                        prop_icon = "🔹"
                    
                    print(f"         [{j:2d}] {prop_icon} {prop_color}{char.uuid}{self.colors.ENDC}")
                    print(f"              Handle: 0x{char.handle:04X}")
                    print(f"              Properties: {', '.join(props)}")
                    
                    # Show descriptors if any
                    if char.descriptors:
                        for desc in char.descriptors:
                            print(f"              📄 Descriptor: {desc.uuid}")
            
            print(f"\n{self.colors.OKGREEN}✓ Found {len(services)} services with {sum(len(s.characteristics) for s in services)} characteristics{self.colors.ENDC}")
            
            # Highlight writable characteristics for fuzzing
            writable_count = 0
            for service in services:
                for char in service.characteristics:
                    if "write" in char.properties:
                        writable_count += 1
            
            if writable_count > 0:
                print(f"{self.colors.WARNING}🎯 {writable_count} writable characteristics found - good targets for fuzzing!{self.colors.ENDC}")
            
        except Exception as e:
            print(f"{self.colors.FAIL}❌ Failed to enumerate services: {e}{self.colors.ENDC}")

    async def cmd_disconnect(self, args: List[str]):
        """Disconnect from a device"""
        index = self.get_device_from_args_or_active(args)
        
        if index is None:
            if not args and len(self.session.connected_devices) > 1:
                print(f"{self.colors.FAIL}Multiple devices connected. Specify index: disconnect <device_index>{self.colors.ENDC}")
            elif not args and len(self.session.connected_devices) == 0:
                print(f"{self.colors.FAIL}No devices connected{self.colors.ENDC}")
            else:
                print(f"{self.colors.FAIL}Usage: disconnect [device_index]{self.colors.ENDC}")
            return
        
        if index not in self.session.connected_devices:
            print(f"{self.colors.FAIL}Device not connected{self.colors.ENDC}")
            return
        
        device_info = self.session.connected_devices[index]
        device = device_info['device']
        
        print(f"{self.colors.OKCYAN}📤 Disconnecting from {device.name or 'Unknown'}...{self.colors.ENDC}")
        
        try:
            success = await self.session.ble_manager.disconnect(device.address)
            if success:
                del self.session.connected_devices[index]
                print(f"{self.colors.OKGREEN}✓ Disconnected successfully{self.colors.ENDC}")
            else:
                print(f"{self.colors.FAIL}❌ Disconnect failed{self.colors.ENDC}")
        except Exception as e:
            print(f"{self.colors.FAIL}❌ Disconnect error: {e}{self.colors.ENDC}")

    async def cmd_validate(self, args: List[str]):
        """Validate device for vulnerabilities"""
        index = self.get_device_from_args_or_active(args)
        
        if index is None:
            if not args and len(self.session.connected_devices) > 1:
                print(f"{self.colors.FAIL}Multiple devices connected. Specify index: validate <device_index>{self.colors.ENDC}")
            elif not args and len(self.session.connected_devices) == 0:
                print(f"{self.colors.FAIL}No devices connected. Use 'connect <index>' first{self.colors.ENDC}")
            else:
                print(f"{self.colors.FAIL}Usage: validate [device_index]{self.colors.ENDC}")
            return
        
        if index not in self.session.connected_devices:
            print(f"{self.colors.FAIL}Device not connected. Use 'connect {index}' first{self.colors.ENDC}")
            return
        
        device_info = self.session.connected_devices[index]
        device = device_info['device']
        
        print(f"{self.colors.OKCYAN}🔍 Validating {device.name or 'Unknown'} for vulnerabilities...{self.colors.ENDC}")
        
        try:
            is_vulnerable = await self.session.researcher.validate_target(device)
            
            if is_vulnerable:
                print(f"{self.colors.WARNING}⚠️  Device appears to have interesting characteristics for research{self.colors.ENDC}")
                print(f"{self.colors.OKGREEN}✅ Device is a good candidate for security testing{self.colors.ENDC}")
            else:
                print(f"{self.colors.OKBLUE}ℹ️  Device has limited attack surface - no writable characteristics found{self.colors.ENDC}")
                
        except Exception as e:
            print(f"{self.colors.FAIL}❌ Validation error: {e}{self.colors.ENDC}")

    def cmd_status(self, args: List[str]):
        """Show quick status overview"""
        connected_count = len(self.session.connected_devices)
        discovered_count = len(self.session.discovered_devices)
        
        print(f"\n{self.colors.BOLD}BLUEFORGE STATUS:{self.colors.ENDC}")
        print(f"  📡 Devices discovered: {discovered_count}")
        print(f"  🔗 Devices connected: {connected_count}")
        
        if connected_count == 1:
            # Show active device info
            active_index = self.get_active_device_index()
            device = self.session.discovered_devices[active_index]
            print(f"  🎯 Active device: [{active_index}] {device.name or 'Unknown'} ({device.address})")
            print(f"  💡 Tip: You can use commands without device index (e.g., 'info', 'services')")
        elif connected_count > 1:
            print(f"  📋 Connected devices:")
            for index in self.session.connected_devices:
                device = self.session.discovered_devices[index]
                print(f"    [{index}] {device.name or 'Unknown'}")
            print(f"  💡 Tip: Specify device index for commands (e.g., 'info 0', 'services 1')")
        else:
            print(f"  💡 Tip: Use 'scan' to discover devices, then 'connect <index>' to connect")

    # Add placeholder methods for missing commands
    async def cmd_scan(self, args: List[str]):
        """Scan for BLE devices"""
        print(f"{self.colors.OKCYAN}🔍 Scanning for BLE devices...{self.colors.ENDC}")
        print(f"{self.colors.WARNING}⚠️  Scan functionality not implemented yet{self.colors.ENDC}")

    def cmd_devices(self, args: List[str]):
        """List discovered devices"""
        print(f"{self.colors.WARNING}⚠️  Devices listing not implemented yet{self.colors.ENDC}")

    async def cmd_connect(self, args: List[str]):
        """Connect to a device"""
        print(f"{self.colors.WARNING}⚠️  Connect functionality not implemented yet{self.colors.ENDC}")

    def cmd_connected(self, args: List[str]):
        """Show connected devices"""
        print(f"{self.colors.WARNING}⚠️  Connected devices listing not implemented yet{self.colors.ENDC}")

    async def cmd_research(self, args: List[str]):
        """Start research on device"""
        print(f"{self.colors.WARNING}⚠️  Research functionality not implemented yet{self.colors.ENDC}")

    async def cmd_fuzz(self, args: List[str]):
        """Start fuzzing device"""
        print(f"{self.colors.WARNING}⚠️  Fuzzing functionality not implemented yet{self.colors.ENDC}")

    def cmd_stats(self, args: List[str]):
        """Show session statistics"""
        print(f"{self.colors.WARNING}⚠️  Statistics not implemented yet{self.colors.ENDC}")

    def cmd_config(self, args: List[str]):
        """Show configuration"""
        print(f"{self.colors.WARNING}⚠️  Configuration display not implemented yet{self.colors.ENDC}")

    def cmd_clear(self, args: List[str]):
        """Clear screen"""
        os.system('clear' if os.name == 'posix' else 'cls')

    def cmd_debug(self, args: List[str]):
        """Toggle debug mode"""
        print(f"{self.colors.WARNING}⚠️  Debug toggle not implemented yet{self.colors.ENDC}")

    def cmd_export(self, args: List[str]):
        """Export session data"""
        print(f"{self.colors.WARNING}⚠️  Export functionality not implemented yet{self.colors.ENDC}")

    async def run_interactive(self):
        """Run interactive CLI mode"""
        self.print_banner()
        
        # Commands dictionary with all the new commands
        commands = {
            'help': self.print_help,
            'scan': self.cmd_scan,
            'devices': self.cmd_devices,
            'info': self.cmd_info,
            'status': self.cmd_status,
            'connect': self.cmd_connect,
            'disconnect': self.cmd_disconnect,
            'connected': self.cmd_connected,
            'services': self.cmd_services,
            'validate': self.cmd_validate,
            'research': self.cmd_research,
            'fuzz': self.cmd_fuzz,
            'stats': self.cmd_stats,
            'config': self.cmd_config,
            'clear': self.cmd_clear,
            'debug': self.cmd_debug,
            'export': self.cmd_export,
            'exit': self.exit_cli,
            'quit': self.exit_cli,
        }
        
        while self.running:
            try:
                user_input = input(self.print_prompt()).strip()
                if not user_input:
                    continue
                
                parts = user_input.split()
                command = parts[0].lower()
                args = parts[1:]
                
                if command in commands:
                    cmd_func = commands[command]
                    if asyncio.iscoroutinefunction(cmd_func):
                        await cmd_func(args)
                    else:
                        cmd_func(args)
                else:
                    print(f"{self.colors.FAIL}Unknown command: {command}. Type 'help' for available commands{self.colors.ENDC}")
                    
            except KeyboardInterrupt:
                print(f"\n{self.colors.WARNING}Use 'exit' to quit BlueForge{self.colors.ENDC}")
            except EOFError:
                self.exit_cli()
                break
            except Exception as e:
                print(f"{self.colors.FAIL}❌ Error: {e}{self.colors.ENDC}")
                logger.error(f"CLI error: {e}", exc_info=True)

    def exit_cli(self):
        """Exit CLI gracefully"""
        self.running = False

async def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(description='BlueForge BLE Security Research Framework')
    parser.add_argument('--version', action='version', version='BlueForge 2.0.0')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    
    args = parser.parse_args()
    
    if args.debug:
        set_log_level('DEBUG')
    
    cli = BlueForgeInteractiveCLI()
    try:
        await cli.run_interactive()
    except KeyboardInterrupt:
        print(f"\n{BlueForgeColors.OKCYAN}👋 Goodbye!{BlueForgeColors.ENDC}")
    finally:
        # Cleanup
        await cli.session.ble_manager.cleanup()

if __name__ == "__main__":
    asyncio.run(main())