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
        
        # Create researcher with shared BLE manager
        self.researcher = MemoryCorruptionResearch(ble_manager=self.ble_manager)
        
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
║                           BLUEFORGE SECURITY FRAMEWORK                           ║
║                        Advanced BLE Vulnerability Research                       ║
║                                   v2.0.0                                         ║
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
        print(f"  {self.colors.OKGREEN}connect <index> [--pair]{self.colors.ENDC}  🔗 Connect to device (optionally with pairing)")
        print(f"  {self.colors.OKGREEN}disconnect [index]{self.colors.ENDC}      📤 Disconnect from device(s)")
        print(f"  {self.colors.OKGREEN}connected{self.colors.ENDC}               🌐 Show all connected devices")
        
        # Device Information & Analysis
        print(f"\n{self.colors.BOLD}{self.colors.WARNING}🔍 DEVICE INFORMATION & ANALYSIS{self.colors.ENDC}")
        print(f"  {self.colors.OKGREEN}info [index]{self.colors.ENDC}            📋 Show detailed device information")
        print(f"  {self.colors.OKGREEN}services [index]{self.colors.ENDC}        🛠️  List device services & characteristics")
        print(f"  {self.colors.OKGREEN}chars [index]{self.colors.ENDC}           📝 Show detailed characteristic analysis")
        print(f"  {self.colors.OKGREEN}validate [index]{self.colors.ENDC}        ✅ Validate device for vulnerabilities")
        print(f"  {self.colors.OKGREEN}status{self.colors.ENDC}                  📊 Show current session status")
        
        # Security Research & Testing
        print(f"\n{self.colors.BOLD}{self.colors.FAIL}🎯 SECURITY RESEARCH & TESTING{self.colors.ENDC}")
        print(f"  {self.colors.OKGREEN}research [index]{self.colors.ENDC}        🔬 Start basic memory corruption research")
        print(f"  {self.colors.OKGREEN}advanced-research [index]{self.colors.ENDC} 🧪 Advanced research with custom parameters")
        print(f"  {self.colors.OKGREEN}fuzz [index]{self.colors.ENDC}            💥 Start comprehensive fuzzing attack")
        print(f"  {self.colors.OKGREEN}stats{self.colors.ENDC}                   📈 Show fuzzing & research statistics")
        
        # Debug & Development
        print(f"\n{self.colors.BOLD}{self.colors.OKBLUE}🐛 DEBUG & DEVELOPMENT{self.colors.ENDC}")
        print(f"  {self.colors.OKGREEN}debug-services [index]{self.colors.ENDC}  🔧 Debug service discovery issues")
        print(f"  {self.colors.OKGREEN}clear{self.colors.ENDC}                   🧹 Clear terminal screen")
      
        # Help & Navigation
        print(f"\n{self.colors.BOLD}{self.colors.HEADER}❓ HELP & NAVIGATION{self.colors.ENDC}")
        print(f"  {self.colors.OKGREEN}help{self.colors.ENDC}                    📚 Show this help message")
        print(f"  {self.colors.OKGREEN}exit / quit{self.colors.ENDC}             👋 Exit BlueForge framework")
        
        print(f"\n{self.colors.HEADER}────────────────────────────────────────────────────────────────────────────────────{self.colors.ENDC}")
 
    def get_device_from_args_or_active(self, args: List[str]) -> Optional[int]:
        """Get device index from args or return active device if only one connected"""
        if args:
            try:
                index = int(args[0])
                if 0 <= index < len(self.session.discovered_devices):
                    return index
                else:
                    print(f"{self.colors.FAIL}Invalid device index. Valid range: 0-{len(self.session.discovered_devices)-1}{self.colors.ENDC}")
                    return None
            except (ValueError, IndexError):
                print(f"{self.colors.FAIL}Invalid device index format{self.colors.ENDC}")
                return None
        
        # If no args and only one device connected, use it
        if len(self.session.connected_devices) == 1:
            return list(self.session.connected_devices.keys())[0]
        
        # If no args and multiple devices connected
        if len(self.session.connected_devices) > 1:
            print(f"{self.colors.WARNING}Multiple devices connected. Please specify device index{self.colors.ENDC}")
            self.cmd_connected([])
        
        return None

    def get_active_device_index(self) -> Optional[int]:
        """Get the active device index (if only one connected)"""
        if len(self.session.connected_devices) == 1:
            return list(self.session.connected_devices.keys())[0]
        return None

    async def cmd_scan(self, args: List[str]):
        """Scan for BLE devices"""
        print(f"{self.colors.OKCYAN}🔍 Scanning for BLE devices...{self.colors.ENDC}")
        
        try:
            devices = await self.session.ble_manager.scan(duration=10)
            
            if not devices:
                print(f"{self.colors.WARNING}No devices found{self.colors.ENDC}")
                return
                
            # Store in session
            self.session.discovered_devices = devices
            
            print(f"{self.colors.OKGREEN}✓ Found {len(devices)} devices:{self.colors.ENDC}")
            
            # Display devices sorted by RSSI
            for i, device in enumerate(devices):
                rssi_str = f"RSSI: {device.rssi}" if hasattr(device, 'rssi') else "RSSI: Unknown"
                device_name = device.name if hasattr(device, 'name') else "Unknown"
                device_addr = device.address if hasattr(device, 'address') else "Unknown"
                print(f"  [{i:2d}] {device_name} ({device_addr}) - {rssi_str}")
                
        except Exception as e:
            print(f"{self.colors.FAIL}❌ Scan failed: {e}{self.colors.ENDC}")

    def cmd_devices(self, args: List[str]):
        """List discovered devices"""
        if not self.session.discovered_devices:
            print(f"{self.colors.WARNING}No devices discovered. Run 'scan' first{self.colors.ENDC}")
            return
        
        print(f"{self.colors.BOLD}Discovered Devices ({len(self.session.discovered_devices)}):{self.colors.ENDC}")
        
        for i, device in enumerate(self.session.discovered_devices):
            # Check if connected
            is_connected = any(conn['device'].address == device.address 
                            for conn in self.session.connected_devices.values())
            
            status = f"{self.colors.OKGREEN}[CONNECTED]{self.colors.ENDC}" if is_connected else ""
            rssi_str = f"RSSI: {device.rssi}" if hasattr(device, 'rssi') else "RSSI: Unknown"
            
            print(f"  [{i:2d}] {device.name} ({device.address}) - {rssi_str} {status}")
   
   
    async def cmd_connect(self, args: List[str]):
        """Connect to a device"""
        if not args:
            print(f"{self.colors.FAIL}Usage: connect <device_index> [--pair]{self.colors.ENDC}")
            return
        
        try:
            device_index = int(args[0])
            enable_pairing = '--pair' in args
            
            if device_index >= len(self.session.discovered_devices):
                print(f"{self.colors.FAIL}Invalid device index{self.colors.ENDC}")
                return
                
            device = self.session.discovered_devices[device_index]
            
            if enable_pairing:
                print(f"{self.colors.OKCYAN}🔗 Connecting to {device.name} with pairing...{self.colors.ENDC}")
            else:
                print(f"{self.colors.OKCYAN}🔗 Connecting to {device.name}...{self.colors.ENDC}")
            
            # Use the shared BLE manager with pairing option
            client = await self.session.ble_manager.connect(device.address, enable_pairing=enable_pairing)
            
            
            if client:
                # Store connection in CLI session (for backward compatibility)
                self.session.connected_devices[device_index] = {
                    'device': device,
                    'client': client,
                    'connected_at': datetime.now()
                }
                print(f"{self.colors.OKGREEN}✓ Successfully connected to {device.address}{self.colors.ENDC}")
            else:
                print(f"{self.colors.FAIL}❌ Failed to connect{self.colors.ENDC}")
                
        except (ValueError, IndexError):
            print(f"{self.colors.FAIL}Invalid device index{self.colors.ENDC}")
        except Exception as e:
            print(f"{self.colors.FAIL}❌ Connection error: {e}{self.colors.ENDC}")
            
    def cmd_connected(self, args: List[str]):
        """Show connected devices"""
        if not self.session.connected_devices:
            print(f"{self.colors.WARNING}No devices currently connected{self.colors.ENDC}")
            return
        
        print(f"{self.colors.OKGREEN}Connected Devices ({len(self.session.connected_devices)}):{self.colors.ENDC}")
        for index, conn_info in self.session.connected_devices.items():
            device = conn_info['device']
            connected_at = conn_info['connected_at'].strftime("%H:%M:%S")
            print(f"  [{index}] {device.name} ({device.address}) - Connected at {connected_at}")

    async def cmd_debug_services(self, args: List[str]):
        """Debug service discovery"""
        index = self.get_device_from_args_or_active(args)
        
        if index is None or index not in self.session.connected_devices:
            print(f"{self.colors.FAIL}No device connected{self.colors.ENDC}")
            return
        
        device_info = self.session.connected_devices[index]
        client = device_info['client']
        
        print(f"{self.colors.OKCYAN}🐛 Debug: Service discovery for {device_info['device'].name}{self.colors.ENDC}")
        
        try:
            print(f"Client connected: {client.is_connected}")
            print(f"Client address: {client.address}")
            
            # Use services property directly (modern bleak API)
            print("Accessing services...")
            services = client.services
            
            # Count services by iterating since len() isn't supported
            service_count = sum(1 for _ in services)
            print(f"Services object type: {type(services)}")
            print(f"Services count: {service_count}")
            
            # Try to iterate
            actual_count = 0
            for service in services:
                actual_count += 1
                print(f"Service {actual_count}: {service.uuid}")
                
                char_count = 0
                for char in service.characteristics:
                    char_count += 1
                    print(f"  Char {char_count}: {char.uuid} - Props: {char.properties}")
            
            print(f"Total services found: {actual_count}")
            
        except Exception as e:
            print(f"{self.colors.FAIL}Debug failed: {e}{self.colors.ENDC}")
            import traceback
            traceback.print_exc()

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

    async def cmd_info(self, args: List[str]):
        """Show detailed device information"""
        index = self.get_device_from_args_or_active(args)
        
        if index is None:
            print(f"{self.colors.FAIL}No device specified. Usage: info [device_index]{self.colors.ENDC}")
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
   
    async def cmd_validate(self, args: List[str]):
        """Validate device for vulnerabilities"""
        index = self.get_device_from_args_or_active(args)
        
        if index is None:
            print(f"{self.colors.FAIL}No device specified or connected{self.colors.ENDC}")
            return
        
        if index >= len(self.session.discovered_devices):
            print(f"{self.colors.FAIL}Invalid device index{self.colors.ENDC}")
            return
        
        device = self.session.discovered_devices[index]
        
        print(f"{self.colors.OKCYAN}🔍 Validating {device.name or 'Unknown'} for vulnerabilities...{self.colors.ENDC}")
        
        try:
            # Check if already connected via CLI
            is_connected_cli = index in self.session.connected_devices
            is_connected_manager = self.session.ble_manager.connection_manager.is_connected(device.address)
            
            if is_connected_cli and is_connected_manager:
                print(f"{self.colors.OKBLUE}ℹ️  Using existing connection to device{self.colors.ENDC}")
            elif is_connected_cli and not is_connected_manager:
                print(f"{self.colors.WARNING}⚠️  CLI shows connected but connection manager doesn't - fixing...{self.colors.ENDC}")
                # Update the connection manager with CLI's connection
                cli_connection = self.session.connected_devices[index]
                # This needs to be fixed in the connection sync
            
            # Validate the device
            is_vulnerable = await self.session.researcher.validate_target(device)
            
            if is_vulnerable:
                print(f"{self.colors.WARNING}⚠️  Device appears to have interesting characteristics for research{self.colors.ENDC}")
                print(f"{self.colors.OKGREEN}✅ Device is a good candidate for security testing{self.colors.ENDC}")
                
                # Show some stats if we have service data
                if hasattr(self.session, 'service_data') and index in self.session.service_data:
                    services_data = self.session.service_data[index]
                    from core.gatt_handler import GATTHandler
                    gatt_handler = GATTHandler()
                    writable = gatt_handler.find_writable_characteristics(services_data)
                    print(f"{self.colors.OKCYAN}📊 Found {len(writable)} writable characteristics{self.colors.ENDC}")
            else:
                print(f"{self.colors.OKBLUE}ℹ️  Device has limited attack surface{self.colors.ENDC}")
                print(f"{self.colors.OKBLUE}💡 No writable characteristics found for research{self.colors.ENDC}")
                    
        except Exception as e:
            print(f"{self.colors.FAIL}❌ Validation error: {e}{self.colors.ENDC}")

    async def cmd_fuzz(self, args: List[str]):
        """Start fuzzing device"""
        index = self.get_device_from_args_or_active(args)
        
        if index is None or index not in self.session.connected_devices:
            print(f"{self.colors.FAIL}No device connected for fuzzing{self.colors.ENDC}")
            return
        
        device_info = self.session.connected_devices[index]
        device = device_info['device']
        client = device_info['client']
        
        # Check if we have service data
        if not hasattr(self.session, 'service_data') or index not in self.session.service_data:
            print(f"{self.colors.WARNING}No service data found. Running service discovery...{self.colors.ENDC}")
            await self.cmd_services([str(index)])
            
            if not hasattr(self.session, 'service_data') or index not in self.session.service_data:
                print(f"{self.colors.FAIL}Service discovery failed. Cannot proceed with fuzzing{self.colors.ENDC}")
                return
        
        # Get ALL characteristics (including read-only for broader attack surface)
        services_data = self.session.service_data[index]
        from core.gatt_handler import GATTHandler
        gatt_handler = GATTHandler()
        
        # Get ALL characteristics, not just writable ones
        all_chars = []
        for service in services_data:
            for char in service['characteristics']:
                all_chars.append({
                    'service_uuid': service['uuid'],
                    'char_uuid': char['uuid'],
                    'handle': char['handle'],
                    'properties': char['properties']
                })
        
        if not all_chars:
            print(f"{self.colors.FAIL}No characteristics found for fuzzing{self.colors.ENDC}")
            return
        
        print(f"\n{self.colors.BOLD}🎯 FUZZING TARGET: {device.name or 'Unknown'}{self.colors.ENDC}")
        print(f"Found {len(all_chars)} characteristics (including read-only)")
        
        # Show available characteristics with property indicators
        print(f"\n{self.colors.OKCYAN}Available targets:{self.colors.ENDC}")
        for i, char in enumerate(all_chars):
            props = char['properties']
            if any(prop in props for prop in ['write', 'write-without-response']):
                prop_icon = "✏️ "
                prop_color = self.colors.OKGREEN
            else:
                prop_icon = "🚫"  # Read-only characteristics
                prop_color = self.colors.WARNING
            
            print(f"  [{i}] {prop_icon} {prop_color}{char['char_uuid']}{self.colors.ENDC} ({', '.join(props)})")
        
        # Ask user to select characteristic or fuzz all
        print(f"\nOptions:")
        print(f"  {self.colors.OKGREEN}[A]{self.colors.ENDC} Fuzz all characteristics")
        print(f"  {self.colors.OKGREEN}[0-{len(all_chars)-1}]{self.colors.ENDC} Fuzz specific characteristic")  # Fixed: use all_chars
        print(f"  {self.colors.OKGREEN}[Q]{self.colors.ENDC} Cancel")
        
        try:
            choice = input(f"\n{self.colors.OKCYAN}Select target: {self.colors.ENDC}").strip().upper()
            
            if choice == 'Q':
                print("Fuzzing cancelled")
                return
            elif choice == 'A':
                # Fuzz all characteristics
                await self._fuzz_all_characteristics(client, device, all_chars)  # Fixed: use all_chars
            else:
                # Fuzz specific characteristic
                char_index = int(choice)
                if 0 <= char_index < len(all_chars):  # Fixed: use all_chars
                    await self._fuzz_single_characteristic(client, device, all_chars[char_index])  # Fixed: use all_chars
                else:
                    print(f"{self.colors.FAIL}Invalid selection{self.colors.ENDC}")
                    
        except (ValueError, KeyboardInterrupt):
            print(f"\n{self.colors.WARNING}Fuzzing cancelled by user{self.colors.ENDC}")

    async def _fuzz_single_characteristic(self, client, device, char_info):
        """Fuzz a single characteristic"""
        char_uuid = char_info['char_uuid']
        
        print(f"\n{self.colors.WARNING}⚠️  STARTING FUZZING ATTACK ⚠️{self.colors.ENDC}")
        print(f"Target: {device.name} - {char_uuid}")
        print(f"This may cause the device to crash or become unresponsive!")
        
        response = input(f"\n{self.colors.FAIL}Continue? (yes/no): {self.colors.ENDC}")
        if response.lower() != 'yes':
            print("Fuzzing cancelled")
            return
        
        from core.fuzzing_engine import AdvancedFuzzingEngine, FuzzStrategy
        
        # Initialize fuzzer
        fuzzer = AdvancedFuzzingEngine()
        
        strategies = [
            (FuzzStrategy.SMART_MUTATION, "Smart Mutation"),
            (FuzzStrategy.TIMING_BASED, "Timing-Based"),
            (FuzzStrategy.PROTOCOL_AWARE, "Protocol-Aware"),
            (FuzzStrategy.BOUNDARY_VALUE, "Boundary Value")
        ]
        
        print(f"\n{self.colors.OKCYAN}Starting comprehensive fuzzing campaign...{self.colors.ENDC}")
        
        all_results = []
        total_crashes = 0
        
        for strategy, strategy_name in strategies:
            print(f"\n{self.colors.BOLD}🔥 Running {strategy_name} fuzzing...{self.colors.ENDC}")
            
            try:
                results = await fuzzer.fuzz_target(client, char_uuid, strategy, max_cases=25)
                all_results.extend(results)
                
                # Count crashes in this strategy
                strategy_crashes = len([r for r in results if r.crashed])
                total_crashes += strategy_crashes
                
                print(f"  ✓ Completed {len(results)} test cases")
                if strategy_crashes > 0:
                    print(f"  💥 Found {strategy_crashes} crashes!")
                else:
                    print(f"  ℹ️  No crashes detected")
                    
            except Exception as e:
                print(f"  ❌ Strategy failed: {e}")
        
        # Generate report
        print(f"\n{self.colors.BOLD}📊 FUZZING REPORT{self.colors.ENDC}")
        print(f"Target characteristic: {char_uuid}")
        print(f"Total test cases: {len(all_results)}")
        print(f"Crashes found: {total_crashes}")
        
        if total_crashes > 0:
            print(f"\n{self.colors.FAIL}💥 VULNERABILITIES DETECTED!{self.colors.ENDC}")
            print(f"Device appears vulnerable to fuzzing attacks")
            
            # Update session stats
            self.session.session_stats['vulnerabilities_found'] += total_crashes
        else:
            print(f"\n{self.colors.OKGREEN}✅ No crashes detected{self.colors.ENDC}")
            print(f"Device appears resilient to basic fuzzing")

    async def _fuzz_all_characteristics(self, client, device, all_chars):  # Fixed parameter name
        """Fuzz all characteristics"""
        print(f"\n{self.colors.WARNING}⚠️  STARTING COMPREHENSIVE FUZZING ⚠️{self.colors.ENDC}")
        print(f"Target: {device.name}")
        print(f"Will fuzz {len(all_chars)} characteristics")  # Fixed: use all_chars
        print(f"This may cause the device to crash or become unresponsive!")
        
        response = input(f"\n{self.colors.FAIL}Continue? (yes/no): {self.colors.ENDC}")
        if response.lower() != 'yes':
            print("Fuzzing cancelled")
            return
        
        total_crashes = 0
        
        for i, char_info in enumerate(all_chars):  # Fixed: use all_chars
            print(f"\n{self.colors.OKCYAN}[{i+1}/{len(all_chars)}] Fuzzing {char_info['char_uuid']}...{self.colors.ENDC}")  # Fixed: use all_chars
            
            await self._fuzz_single_characteristic(client, device, char_info)
            
            # Brief pause between characteristics
            await asyncio.sleep(2)
        
        print(f"\n{self.colors.BOLD}🎯 COMPREHENSIVE FUZZING COMPLETE{self.colors.ENDC}")

    async def cmd_research(self, args: List[str]):
        """Start security research on device"""
        index = self.get_device_from_args_or_active(args)
        
        if index is None:
            print(f"{self.colors.FAIL}No device specified or connected{self.colors.ENDC}")
            return
        
        if index >= len(self.session.discovered_devices):
            print(f"{self.colors.FAIL}Invalid device index{self.colors.ENDC}")
            return
        
        device = self.session.discovered_devices[index]
        
        print(f"\n{self.colors.BOLD}🔬 MEMORY CORRUPTION RESEARCH{self.colors.ENDC}")
        print(f"Target: {device.name or 'Unknown'} ({device.address})")
        print(f"\n{self.colors.WARNING}⚠️  RESEARCH WARNING ⚠️{self.colors.ENDC}")
        print(f"This will perform memory corruption research on the target device.")
        print(f"This is for RESEARCH PURPOSES ONLY on devices you own!")
        print(f"The device may become unresponsive or require reset.")
        
        response = input(f"\n{self.colors.FAIL}Continue with research? (yes/no): {self.colors.ENDC}")
        if response.lower() != 'yes':
            print("Research cancelled")
            return
        
        print(f"\n{self.colors.OKCYAN}🔬 Starting memory corruption research...{self.colors.ENDC}")
        
        try:
            # Execute research
            result = await self.session.researcher.execute(device.address)
            
            if result['success']:
                print(f"\n{self.colors.OKGREEN}✅ Research completed successfully!{self.colors.ENDC}")
                print(f"📊 Tested {result['total_characteristics_tested']} characteristics")
                
                # Count anomalies across all results
                total_anomalies = 0
                for research_result in result['research_results']:
                    if research_result.get('success'):
                        total_anomalies += len(research_result.get('anomalies', []))
                
                if total_anomalies > 0:
                    print(f"{self.colors.WARNING}💥 Found {total_anomalies} anomalies during research!{self.colors.ENDC}")
                    print(f"Device may be vulnerable to memory corruption attacks")
                    
                    # Update session stats
                    self.session.session_stats['vulnerabilities_found'] += total_anomalies
                else:
                    print(f"{self.colors.OKBLUE}ℹ️  No anomalies detected during research{self.colors.ENDC}")
                
                # Update session stats
                self.session.session_stats['devices_tested'] += 1
                
            else:
                print(f"\n{self.colors.FAIL}❌ Research failed: {result.get('error', 'Unknown error')}{self.colors.ENDC}")
                
        except Exception as e:
            print(f"\n{self.colors.FAIL}❌ Research error: {e}{self.colors.ENDC}")

    async def cmd_advanced_research(self, args: List[str]):
        """Advanced research with custom parameters"""
        index = self.get_device_from_args_or_active(args)
        
        if index is None or index not in self.session.connected_devices:
            print(f"{self.colors.FAIL}No device connected for advanced research{self.colors.ENDC}")
            return
        
        device_info = self.session.connected_devices[index]
        device = device_info['device']
        
        print(f"\n{self.colors.BOLD}🔬 ADVANCED MEMORY RESEARCH{self.colors.ENDC}")
        print(f"Target: {device.name or 'Unknown'}")
        
        # Get services if not available
        if not hasattr(self.session, 'service_data') or index not in self.session.service_data:
            print(f"Getting service information...")
            await self.cmd_services([str(index)])
        
        if not hasattr(self.session, 'service_data') or index not in self.session.service_data:
            print(f"{self.colors.FAIL}Could not get service data{self.colors.ENDC}")
            return
        
        # Show available characteristics
        services_data = self.session.service_data[index]
        from core.gatt_handler import GATTHandler
        gatt_handler = GATTHandler()
        writable_chars = gatt_handler.find_writable_characteristics(services_data)
        
        if not writable_chars:
            print(f"{self.colors.FAIL}No writable characteristics available for research{self.colors.ENDC}")
            return
        
        print(f"\nFound {len(writable_chars)} writable characteristics:")
        for i, char in enumerate(writable_chars):
            print(f"  [{i}] {char['char_uuid']}")
        
        try:
            char_choice = input(f"\nSelect characteristic index (0-{len(writable_chars)-1}): ")
            char_index = int(char_choice)
            
            if not 0 <= char_index < len(writable_chars):
                print(f"{self.colors.FAIL}Invalid characteristic index{self.colors.ENDC}")
                return
            
            selected_char = writable_chars[char_index]
            char_uuid = selected_char['char_uuid']
            
            print(f"\n{self.colors.WARNING}⚠️  Starting advanced research on {char_uuid}{self.colors.ENDC}")
            response = input(f"Continue? (yes/no): ")
            if response.lower() != 'yes':
                return
            
            # Perform advanced research on specific characteristic
            result = await self.session.researcher.research_memory_patterns(device.address, char_uuid)
            
            if result['success']:
                print(f"\n{self.colors.OKGREEN}✅ Advanced research completed{self.colors.ENDC}")
                print(f"Patterns tested: {len(result['patterns_tested'])}")
                print(f"Anomalies found: {len(result['anomalies'])}")
                
                if result['anomalies']:
                    print(f"\n{self.colors.WARNING}💥 ANOMALIES DETECTED:{self.colors.ENDC}")
                    for anomaly in result['anomalies']:
                        print(f"  Pattern: {anomaly['pattern']}")
            else:
                print(f"\n{self.colors.FAIL}❌ Research failed: {result.get('error')}{self.colors.ENDC}")
                
        except (ValueError, KeyboardInterrupt):
            print(f"\n{self.colors.WARNING}Research cancelled{self.colors.ENDC}")

    def cmd_stats(self, args: List[str]):
        """Show session statistics"""
        print(f"\n{self.colors.BOLD}SESSION STATISTICS:{self.colors.ENDC}")
        print(f"  📊 Session started: {self.session.session_stats['session_start'].strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  🔍 Scans performed: {self.session.session_stats['scans_performed']}")
        print(f"  🎯 Devices tested: {self.session.session_stats['devices_tested']}")
        print(f"  💥 Vulnerabilities found: {self.session.session_stats['vulnerabilities_found']}")
        
        # Connection manager stats
        cm_stats = self.session.ble_manager.connection_manager.get_statistics()
        print(f"  🔗 Total connections: {cm_stats['total_connections']}")
        print(f"  ✅ Successful connections: {cm_stats['successful_connections']}")
        print(f"  ❌ Failed connections: {cm_stats['failed_connections']}")
        print(f"  💥 Crashes detected: {cm_stats['crashes_detected']}")


    async def cmd_services(self, args: List[str]):
        """List device services and characteristics"""
        index = self.get_device_from_args_or_active(args)
        
        if index is None:
            print(f"{self.colors.FAIL}No device specified or connected{self.colors.ENDC}")
            return
        
        if index not in self.session.connected_devices:
            print(f"{self.colors.FAIL}Device not connected. Use 'connect {index}' first{self.colors.ENDC}")
            return
        
        device_info = self.session.connected_devices[index]
        client = device_info['client']
        device = device_info['device']
        
        print(f"\n{self.colors.BOLD}SERVICES & CHARACTERISTICS - {device.name}:{self.colors.ENDC}")
        
        try:
            # Use the fixed GATT handler
            from core.gatt_handler import GATTHandler
            gatt_handler = GATTHandler()
            
            services_data = await gatt_handler.discover_services(client)
            
            if not services_data:
                print(f"{self.colors.WARNING}No services discovered{self.colors.ENDC}")
                return
            
            total_chars = 0
            writable_count = 0
            
            for i, service in enumerate(services_data):
                print(f"\n  [{i:2d}] 🛠️  Service: {self.colors.OKCYAN}{service['uuid']}{self.colors.ENDC}")
                if service.get('description'):
                    print(f"       Description: {service['description']}")
                
                for j, char in enumerate(service['characteristics']):
                    total_chars += 1
                    
                    # Color code by properties
                    props = char['properties']
                    if any(prop in props for prop in ['write', 'write-without-response']):
                        prop_color = self.colors.WARNING  # Writable = interesting
                        prop_icon = "✏️"
                        writable_count += 1
                    elif "read" in props:
                        prop_color = self.colors.OKGREEN
                        prop_icon = "👁️"
                    elif any(prop in props for prop in ['notify', 'indicate']):
                        prop_color = self.colors.OKBLUE
                        prop_icon = "📡"
                    else:
                        prop_color = self.colors.ENDC
                        prop_icon = "🔹"
                    
                    print(f"         [{j:2d}] {prop_icon} {prop_color}{char['uuid']}{self.colors.ENDC}")
                    print(f"              Handle: 0x{char['handle']:04X}")
                    print(f"              Properties: {', '.join(props)}")
                    
                    # Show descriptors if any
                    if char.get('descriptors'):
                        for k, desc in enumerate(char['descriptors']):
                            print(f"              📄 Descriptor [{k}]: {desc['uuid']} (Handle: 0x{desc['handle']:04X})")
            
            print(f"\n{self.colors.OKGREEN}✓ Found {len(services_data)} services with {total_chars} characteristics{self.colors.ENDC}")
            
            if writable_count > 0:
                print(f"{self.colors.WARNING}🎯 {writable_count} writable characteristics found - excellent targets for fuzzing!{self.colors.ENDC}")
            
            # Store service data in session for later use
            if not hasattr(self.session, 'service_data'):
                self.session.service_data = {}
            self.session.service_data[index] = services_data
                
        except Exception as e:
            print(f"{self.colors.FAIL}❌ Failed to enumerate services: {e}{self.colors.ENDC}")
            logger.error(f"Service enumeration error: {e}", exc_info=True)

    def cmd_chars(self, args: List[str]):
        """Show detailed characteristic information"""
        index = self.get_device_from_args_or_active(args)
        
        if index is None or index not in self.session.connected_devices:
            print(f"{self.colors.FAIL}No device connected{self.colors.ENDC}")
            return
        
        if not hasattr(self.session, 'service_data') or index not in self.session.service_data:
            print(f"{self.colors.WARNING}No service data. Run 'services' first{self.colors.ENDC}")
            return
        
        services_data = self.session.service_data[index]
        
        from core.gatt_handler import GATTHandler
        gatt_handler = GATTHandler()
        
        # Get different types of characteristics
        writable = gatt_handler.find_writable_characteristics(services_data)
        readable = gatt_handler.find_readable_characteristics(services_data)
        notifiable = gatt_handler.find_notifiable_characteristics(services_data)
        
        print(f"\n{self.colors.BOLD}CHARACTERISTIC ANALYSIS:{self.colors.ENDC}")
        
        if writable:
            print(f"\n{self.colors.WARNING}✏️  WRITABLE CHARACTERISTICS ({len(writable)}):{self.colors.ENDC}")
            for i, char in enumerate(writable):
                print(f"  [{i}] {char['char_uuid']} (Handle: 0x{char['handle']:04X})")
                print(f"      Service: {char['service_uuid']}")
                print(f"      Properties: {', '.join(char['properties'])}")
        
        if readable:
            print(f"\n{self.colors.OKGREEN}👁️  READABLE CHARACTERISTICS ({len(readable)}):{self.colors.ENDC}")
            for i, char in enumerate(readable[:5]):  # Show first 5
                print(f"  [{i}] {char['char_uuid']} (Handle: 0x{char['handle']:04X})")
        
        if notifiable:
            print(f"\n{self.colors.OKBLUE}📡 NOTIFIABLE CHARACTERISTICS ({len(notifiable)}):{self.colors.ENDC}")
            for i, char in enumerate(notifiable):
                print(f"  [{i}] {char['char_uuid']} (Handle: 0x{char['handle']:04X})")

    def cmd_clear(self, args: List[str]):
        """Clear screen"""
        os.system('clear' if os.name == 'posix' else 'cls')

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
            print(f"  💡 Tip: You can use commands without device index (e.g., 'services', 'chars')")
        elif connected_count > 1:
            print(f"  📋 Connected devices:")
            for index in self.session.connected_devices:
                device = self.session.discovered_devices[index]
                print(f"    [{index}] {device.name or 'Unknown'}")
            print(f"  💡 Tip: Specify device index for commands (e.g., 'services 0', 'chars 1')")
        else:
            print(f"  💡 Tip: Use 'scan' to discover devices, then 'connect <index>' to connect")

    def exit_cli(self, args: List[str] = None):
        """Exit CLI gracefully"""
        self.running = False

    async def run_interactive(self):
        """Run interactive CLI mode"""
        self.print_banner()
        
        # Commands dictionary with ALL commands
        commands = {
            'help': self.print_help,
            'scan': self.cmd_scan,
            'devices': self.cmd_devices,
            'connect': self.cmd_connect,
            'connected': self.cmd_connected,
            'disconnect': self.cmd_disconnect,  
            'info': self.cmd_info,              
            'services': self.cmd_services,
            'chars': self.cmd_chars,
            'validate': self.cmd_validate,      # Add this
            'research': self.cmd_research,      # Add this
            'advanced-research': self.cmd_advanced_research,
            'fuzz': self.cmd_fuzz,             # Add this
            'stats': self.cmd_stats,           # Add this
            'debug-services': self.cmd_debug_services,
            'status': self.cmd_status,
            'clear': self.cmd_clear,
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