
# cli/commands.py - Comprehensive Command Handler
import asyncio
import time
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import asdict

from core.session_manager import SessionManager
from core.device_intelligence import DeviceIntelligence
from security.vurnerability_scanner import VulnerabilityScanner, ScanIntensity
from security.fuzzing_engine import AdvancedFuzzingEngine, FuzzStrategy
from exploits.memory_corruption import MemoryCorruptionExploit
from exploits.protocol_attacks import ProtocolAttackEngine
from exploits.timing_attacks import TimingExploitEngine
from cli.display import DisplayManager, DisplayLevel
from utils.logging import get_logger

logger = get_logger(__name__)

class CommandHandler:
    """Comprehensive command handler for BlueForge"""
    
    def __init__(self, session: SessionManager, display: DisplayManager):
        self.session = session
        self.display = display
        
        # Initialize analysis engines
        self.device_intelligence = DeviceIntelligence()
        self.vulnerability_scanner = VulnerabilityScanner()
        self.fuzzing_engine = AdvancedFuzzingEngine()
        
        # Initialize exploit engines
        self.memory_exploit = MemoryCorruptionExploit()
        self.protocol_exploit = ProtocolAttackEngine()
        self.timing_exploit = TimingExploitEngine()
        
        # Command registry
        self.commands = self._initialize_commands()
        
        logger.info("Command handler initialized")
    
    def _initialize_commands(self) -> Dict[str, Dict[str, Any]]:
        """Initialize command registry"""
        return {
            # Discovery commands
            'scan': {
                'function': self.cmd_scan,
                'description': 'Discover BLE devices',
                'usage': 'scan [duration]',
                'category': 'Discovery',
                'args': ['duration?']
            },
            'list': {
                'function': self.cmd_list,
                'description': 'List discovered devices',
                'usage': 'list [filter]',
                'category': 'Discovery',
                'args': ['filter?']
            },
            'connect': {
                'function': self.cmd_connect,
                'description': 'Connect to device',
                'usage': 'connect <device_id|address>',
                'category': 'Discovery',
                'args': ['device_id']
            },
            'disconnect': {
                'function': self.cmd_disconnect,
                'description': 'Disconnect from device',
                'usage': 'disconnect <device_id|address>',
                'category': 'Discovery',
                'args': ['device_id']
            },
            
            # Analysis commands
            'analyze': {
                'function': self.cmd_analyze,
                'description': 'Analyze device characteristics',
                'usage': 'analyze <device_id>',
                'category': 'Analysis',
                'args': ['device_id']
            },
            'intelligence': {
                'function': self.cmd_intelligence,
                'description': 'Generate device intelligence report',
                'usage': 'intelligence <device_id>',
                'category': 'Analysis',
                'args': ['device_id']
            },
            'services': {
                'function': self.cmd_services,
                'description': 'Enumerate device services',
                'usage': 'services <device_id>',
                'category': 'Analysis',
                'args': ['device_id']
            },
            
            # Security testing commands
            'vuln-scan': {
                'function': self.cmd_vuln_scan,
                'description': 'Scan for vulnerabilities',
                'usage': 'vuln-scan <device_id> [intensity]',
                'category': 'Security Testing',
                'args': ['device_id', 'intensity?']
            },
            'fuzz': {
                'function': self.cmd_fuzz,
                'description': 'Fuzz device characteristics',
                'usage': 'fuzz <device_id> [strategy] [max_cases]',
                'category': 'Security Testing',
                'args': ['device_id', 'strategy?', 'max_cases?']
            },
            
            # Exploitation commands
            'exploit-memory': {
                'function': self.cmd_exploit_memory,
                'description': 'Execute memory corruption exploits',
                'usage': 'exploit-memory <device_id> [exploit_type]',
                'category': 'Exploitation',
                'args': ['device_id', 'exploit_type?']
            },
            'exploit-protocol': {
                'function': self.cmd_exploit_protocol,
                'description': 'Execute protocol attacks',
                'usage': 'exploit-protocol <device_id> [attack_type]',
                'category': 'Exploitation',
                'args': ['device_id', 'attack_type?']
            },
            'exploit-timing': {
                'function': self.cmd_exploit_timing,
                'description': 'Execute timing attacks',
                'usage': 'exploit-timing <device_id> [attack_type]',
                'category': 'Exploitation',
                'args': ['device_id', 'attack_type?']
            },
            
            # Session management
            'status': {
                'function': self.cmd_status,
                'description': 'Show session status',
                'usage': 'status',
                'category': 'Session',
                'args': []
            },
            'reset': {
                'function': self.cmd_reset,
                'description': 'Reset session data',
                'usage': 'reset [confirm]',
                'category': 'Session',
                'args': ['confirm?']
            },
            'save': {
                'function': self.cmd_save,
                'description': 'Save session data',
                'usage': 'save <filename>',
                'category': 'Session',
                'args': ['filename']
            },
            'load': {
                'function': self.cmd_load,
                'description': 'Load session data',
                'usage': 'load <filename>',
                'category': 'Session',
                'args': ['filename']
            },
            
            # Configuration
            'set': {
                'function': self.cmd_set,
                'description': 'Set configuration option',
                'usage': 'set <option> <value>',
                'category': 'Configuration',
                'args': ['option', 'value']
            },
            'show': {
                'function': self.cmd_show,
                'description': 'Show configuration',
                'usage': 'show [option]',
                'category': 'Configuration',
                'args': ['option?']
            },
            'verbose': {
                'function': self.cmd_verbose,
                'description': 'Toggle verbose output',
                'usage': 'verbose [on|off]',
                'category': 'Configuration',
                'args': ['level?']
            },
            
            # Help and utilities
            'help': {
                'function': self.cmd_help,
                'description': 'Show help information',
                'usage': 'help [command]',
                'category': 'Help',
                'args': ['command?']
            }
        }
    
    async def execute_command(self, command: str, args: List[str]):
        """Execute a command with arguments"""
        if command not in self.commands:
            self.display.print_error(f"Unknown command: {command}")
            self.display.print_info("Type 'help' for available commands")
            return
        
        cmd_info = self.commands[command]
        cmd_function = cmd_info['function']
        
        try:
            await cmd_function(args)
        except Exception as e:
            self.display.print_error(f"Command '{command}' failed: {e}")
            logger.error(f"Command '{command}' failed", exc_info=True)
    
    # Discovery Commands
    async def cmd_scan(self, args: List[str]):
        """Scan for BLE devices"""
        duration = 10  # Default scan duration
        
        if args and args[0].isdigit():
            duration = int(args[0])
            duration = max(5, min(60, duration))  # Clamp between 5-60 seconds
        
        self.display.print_info(f"Scanning for BLE devices ({duration}s)...")
        
        try:
            devices = await self.session.scan_devices(duration)
            
            if devices:
                self.display.print_success(f"Found {len(devices)} devices")
                self.display.print_device_list(devices)
            else:
                self.display.print_warning("No devices found")
                
        except Exception as e:
            self.display.print_error(f"Scan failed: {e}")
    
    async def cmd_list(self, args: List[str]):
        """List discovered devices"""
        devices = self.session.get_discovered_devices()
        
        if not devices:
            self.display.print_info("No devices discovered. Use 'scan' to discover devices.")
            return
        
        # Apply filter if provided
        if args:
            filter_term = args[0].lower()
            devices = [d for d in devices if 
                      filter_term in d.get('name', '').lower() or 
                      filter_term in d.get('address', '').lower()]
        
        self.display.print_device_list(devices, "Discovered Devices")
        
        # Show connection status
        connected_devices = self.session.get_connected_devices()
        if connected_devices:
            connected_addresses = [d['address'] for d in connected_devices]
            self.display.print_info(f"Connected to: {', '.join(connected_addresses)}")
    
    async def cmd_connect(self, args: List[str]):
        """Connect to a device"""
        if not args:
            self.display.print_error("Device ID or address required")
            return
        
        device_identifier = args[0]
        
        # Find device
        device = self._find_device(device_identifier)
        if not device:
            self.display.print_error(f"Device not found: {device_identifier}")
            return
        
        device_name = device.get('name', 'Unknown')
        device_address = device['address']
        
        self.display.print_info(f"Connecting to {device_name} ({device_address})...")
        
        try:
            success = await self.session.connect_device(device_address)
            
            if success:
                self.display.print_success(f"Connected to {device_name}")
                
                # Run initial device analysis
                self.display.print_info("Running device analysis...")
                await self._analyze_connected_device(device_address)
                
            else:
                self.display.print_error(f"Failed to connect to {device_name}")
                
        except Exception as e:
            self.display.print_error(f"Connection failed: {e}")
    
    async def cmd_disconnect(self, args: List[str]):
        """Disconnect from a device"""
        if not args:
            # Disconnect from all
            connected = self.session.get_connected_devices()
            if not connected:
                self.display.print_info("No devices connected")
                return
            
            for device in connected:
                await self.session.disconnect_device(device['address'])
            
            self.display.print_success("Disconnected from all devices")
            return
        
        device_identifier = args[0]
        device = self._find_device(device_identifier)
        
        if not device:
            self.display.print_error(f"Device not found: {device_identifier}")
            return
        
        device_address = device['address']
        device_name = device.get('name', 'Unknown')
        
        try:
            await self.session.disconnect_device(device_address)
            self.display.print_success(f"Disconnected from {device_name}")
        except Exception as e:
            self.display.print_error(f"Disconnect failed: {e}")
    
    # Analysis Commands
    async def cmd_analyze(self, args: List[str]):
        """Analyze device characteristics"""
        if not args:
            self.display.print_error("Device ID required")
            return
        
        device_identifier = args[0]
        client = await self._get_connected_client(device_identifier)
        
        if not client:
            return
        
        self.display.print_info("Analyzing device characteristics...")
        
        try:
            # Get services and characteristics
            services = client.services
            
            if not services:
                self.display.print_warning("No services available")
                return
            
            # Analyze each service
            service_data = []
            total_characteristics = 0
            writable_characteristics = 0
            
            for service in services:
                char_list = []
                for char in service.characteristics:
                    total_characteristics += 1
                    properties = list(char.properties)
                    
                    if 'write' in properties or 'write-without-response' in properties:
                        writable_characteristics += 1
                    
                    char_list.append({
                        'uuid': str(char.uuid),
                        'properties': properties,
                        'handle': char.handle
                    })
                
                service_data.append({
                    'uuid': str(service.uuid),
                    'characteristics': char_list
                })
            
            # Display summary
            self.display.print_header("Device Analysis Results")
            print(f"Services: {len(services)}")
            print(f"Characteristics: {total_characteristics}")
            print(f"Writable: {writable_characteristics}")
            
            # Show detailed service info in verbose mode
            if self.display.level in [DisplayLevel.VERBOSE, DisplayLevel.DEBUG]:
                for service in service_data:
                    self.display.print_header(f"Service: {service['uuid']}", level=2)
                    
                    for char in service['characteristics']:
                        properties_str = ', '.join(char['properties'])
                        print(f"  Characteristic: {char['uuid']}")
                        print(f"    Properties: {properties_str}")
                        print(f"    Handle: 0x{char['handle']:04x}")
                        print()
            
        except Exception as e:
            self.display.print_error(f"Analysis failed: {e}")
    
    async def cmd_intelligence(self, args: List[str]):
        """Generate device intelligence report"""
        if not args:
            self.display.print_error("Device ID required")
            return
        
        device_identifier = args[0]
        device = self._find_device(device_identifier)
        
        if not device:
            self.display.print_error(f"Device not found: {device_identifier}")
            return
        
        self.display.print_info("Generating intelligence report...")
        
        try:
            # Convert device dict to BLEDevice-like object for analysis
            from core.ble_manager import BLEDevice
            ble_device = BLEDevice(
                address=device['address'],
                name=device.get('name'),
                rssi=device.get('rssi'),
                manufacturer_data=device.get('manufacturer_data', {}),
                service_uuids=device.get('service_uuids', [])
            )
            
            # Generate intelligence profile
            profile = self.device_intelligence.analyze_device(ble_device)
            
            # Display results
            profile_dict = asdict(profile)
            self.display.print_device_intelligence(profile_dict)
            
            # Show connection recommendations
            recommendations = self.device_intelligence.get_connection_recommendations(ble_device)
            
            self.display.print_header("Connection Recommendations", level=2)
            print(f"Strategy: {recommendations['strategy'].upper()}")
            print(f"Success Rate: {recommendations['expected_success_rate']}")
            print(f"Timeout: {recommendations['timeout']}s")
            print(f"Max Attempts: {recommendations['attempts']}")
            
            if recommendations['special_considerations']:
                print("\nSpecial Considerations:")
                for consideration in recommendations['special_considerations']:
                    print(f"  ⚠ {consideration}")
            
        except Exception as e:
            self.display.print_error(f"Intelligence analysis failed: {e}")
    
    async def cmd_services(self, args: List[str]):
        """Enumerate device services"""
        if not args:
            self.display.print_error("Device ID required")
            return
        
        device_identifier = args[0]
        client = await self._get_connected_client(device_identifier)
        
        if not client:
            return
        
        self.display.print_info("Enumerating services...")
        
        try:
            services = client.services
            
            if not services:
                self.display.print_warning("No services found")
                return
            
            # Create table data
            table_data = []
            for service in services:
                service_name = self._get_service_name(str(service.uuid))
                char_count = len(service.characteristics)
                
                table_data.append([
                    str(service.uuid),
                    service_name,
                    str(char_count)
                ])
            
            self.display.print_table(
                headers=['UUID', 'Service Name', 'Characteristics'],
                rows=table_data,
                title=f"Services for {client.address}"
            )
            
        except Exception as e:
            self.display.print_error(f"Service enumeration failed: {e}")
    
    # Security Testing Commands
    async def cmd_vuln_scan(self, args: List[str]):
        """Scan for vulnerabilities"""
        if not args:
            self.display.print_error("Device ID required")
            return
        
        device_identifier = args[0]
        client = await self._get_connected_client(device_identifier)
        
        if not client:
            return
        
        # Parse intensity
        intensity = ScanIntensity.MODERATE
        if len(args) > 1:
            intensity_map = {
                'passive': ScanIntensity.PASSIVE,
                'conservative': ScanIntensity.CONSERVATIVE,
                'moderate': ScanIntensity.MODERATE,
                'aggressive': ScanIntensity.AGGRESSIVE,
                'extreme': ScanIntensity.EXTREME
            }
            intensity = intensity_map.get(args[1].lower(), ScanIntensity.MODERATE)
        
        self.display.print_info(f"Starting {intensity.value} vulnerability scan...")
        
        # Confirm for aggressive scans
        if intensity in [ScanIntensity.AGGRESSIVE, ScanIntensity.EXTREME]:
            if not self.display.confirm_action(f"Perform {intensity.value} scan? This may crash the device."):
                self.display.print_info("Scan cancelled")
                return
        
        try:
            # Execute vulnerability scan
            scan_result = await self.vulnerability_scanner.scan_device(
                client, client.address, intensity
            )
            
            # Display results
            self.display.print_header("Vulnerability Scan Results")
            print(f"Scan Duration: {self.display.format_duration(scan_result.scan_duration)}")
            print(f"Total Tests: {scan_result.total_tests}")
            print(f"Scan Intensity: {scan_result.scan_intensity.value.upper()}")
            
            if scan_result.vulnerabilities_found:
                # Convert to display format
                vuln_list = []
                for vuln in scan_result.vulnerabilities_found:
                    vuln_list.append({
                        'severity': vuln.severity.value,
                        'vuln_type': vuln.vuln_type.value,
                        'title': vuln.title,
                        'confidence': vuln.confidence
                    })
                
                self.display.print_vulnerability_summary(vuln_list)
                
                # Store vulnerabilities for exploitation
                self.session.store_vulnerabilities(client.address, scan_result.vulnerabilities_found)
                
            else:
                self.display.print_success("No vulnerabilities detected")
            
            # Show recommendations
            if scan_result.recommendations:
                self.display.print_header("Recommendations", level=2)
                for rec in scan_result.recommendations:
                    print(f"  • {rec}")
            
        except Exception as e:
            self.display.print_error(f"Vulnerability scan failed: {e}")
    
    async def cmd_fuzz(self, args: List[str]):
        """Fuzz device characteristics"""
        if not args:
            self.display.print_error("Device ID required")
            return
        
        device_identifier = args[0]
        client = await self._get_connected_client(device_identifier)
        
        if not client:
            return
        
        # Parse strategy
        strategy = FuzzStrategy.SMART_MUTATION
        if len(args) > 1:
            strategy_map = {
                'random': FuzzStrategy.RANDOM_MUTATION,
                'smart': FuzzStrategy.SMART_MUTATION,
                'protocol': FuzzStrategy.PROTOCOL_AWARE,
                'timing': FuzzStrategy.TIMING_BASED,
                'precision': FuzzStrategy.PRECISION_TIMING,
                'boundary': FuzzStrategy.BOUNDARY_VALUE
            }
            strategy = strategy_map.get(args[1].lower(), FuzzStrategy.SMART_MUTATION)
        
        # Parse max cases
        max_cases = 50
        if len(args) > 2 and args[2].isdigit():
            max_cases = int(args[2])
            max_cases = max(10, min(500, max_cases))  # Clamp between 10-500
        
        self.display.print_info(f"Starting {strategy.value} fuzzing ({max_cases} cases)...")
        
        try:
            # Get writable characteristics
            services = client.services
            writable_chars = []
            
            for service in services:
                for char in service.characteristics:
                    if 'write' in char.properties or 'write-without-response' in char.properties:
                        writable_chars.append(str(char.uuid))
            
            if not writable_chars:
                self.display.print_warning("No writable characteristics found")
                return
            
            # Fuzz each writable characteristic
            all_results = []
            
            for char_uuid in writable_chars[:3]:  # Limit to first 3
                self.display.print_info(f"Fuzzing characteristic: {char_uuid}")
                
                # Execute fuzzing session
                session_result = await self.fuzzing_engine.execute_fuzzing_session(
                    client, char_uuid, strategy, max_cases
                )
                
                all_results.append(session_result)
                
                # Show progress
                crashes_found = session_result.crashes_found
                if crashes_found > 0:
                    self.display.print_warning(f"Found {crashes_found} crashes in {char_uuid}")
            
            # Display summary
            total_crashes = sum(r.crashes_found for r in all_results)
            total_cases = sum(r.total_cases for r in all_results)
            
            self.display.print_header("Fuzzing Results")
            print(f"Total test cases: {total_cases}")
            print(f"Crashes found: {total_crashes}")
            print(f"Characteristics tested: {len(all_results)}")
            
            if total_crashes > 0:
                self.display.print_warning(f"Device stability issues detected!")
            
        except Exception as e:
            self.display.print_error(f"Fuzzing failed: {e}")
    
    # Exploitation Commands
    async def cmd_exploit_memory(self, args: List[str]):
        """Execute memory corruption exploits"""
        if not args:
            self.display.print_error("Device ID required")
            return
        
        device_identifier = args[0]
        client = await self._get_connected_client(device_identifier)
        
        if not client:
            return
        
        # Get stored vulnerabilities
        vulnerabilities = self.session.get_vulnerabilities(client.address)
        memory_vulns = [v for v in vulnerabilities 
                       if v.vuln_type.value in ['buffer_overflow', 'memory_corruption']]
        
        if not memory_vulns:
            self.display.print_warning("No memory corruption vulnerabilities found. Run 'vuln-scan' first.")
            return
        
        # Confirm exploitation
        if not self.display.confirm_action("Execute memory corruption exploits? This may crash the device."):
            self.display.print_info("Exploitation cancelled")
            return
        
        self.display.print_info("Executing memory corruption exploits...")
        
        try:
            results = []
            
            for vulnerability in memory_vulns[:3]:  # Limit to first 3
                # Analyze vulnerability for exploitation
                exploit_vectors = await self.memory_exploit.analyze_vulnerability_for_exploitation(
                    vulnerability, client
                )
                
                if not exploit_vectors:
                    continue
                
                # Execute top exploit vector
                for exploit_vector in exploit_vectors[:2]:  # Try top 2
                    char_uuid = vulnerability.affected_characteristic
                    
                    self.display.print_info(f"Executing {exploit_vector.name}...")
                    
                    result = await self.memory_exploit.execute_exploit(
                        client, char_uuid, exploit_vector
                    )
                    
                    results.append(result)
                    
                    if result.success:
                        self.display.print_success(f"Exploit successful: {exploit_vector.name}")
                        if result.control_achieved:
                            self.display.print_warning("Control achieved!")
                    else:
                        self.display.print_error(f"Exploit failed: {exploit_vector.name}")
            
            # Display results summary
            if results:
                exploit_results = [asdict(r) for r in results]
                self.display.print_exploit_results(exploit_results, "Memory Corruption")
            
        except Exception as e:
            self.display.print_error(f"Memory exploitation failed: {e}")
    
    async def cmd_exploit_protocol(self, args: List[str]):
        """Execute protocol attacks"""
        if not args:
            self.display.print_error("Device ID required")
            return
        
        device_identifier = args[0]
        client = await self._get_connected_client(device_identifier)
        
        if not client:
            return
        
        self.display.print_info("Analyzing protocol attack surface...")
        
        try:
            # Analyze attack surface
            attack_surface = await self.protocol_exploit.analyze_protocol_attack_surface(client)
            
            # Store for reference
            self.protocol_exploit.last_attack_surface = attack_surface
            
            # Get recommended attacks
            recommended_attacks = self.protocol_exploit.get_recommended_attacks(attack_surface)
            
            if not recommended_attacks:
                self.display.print_info("No viable protocol attacks identified")
                return
            
            # Confirm exploitation
            if not self.display.confirm_action("Execute protocol attacks?"):
                self.display.print_info("Attack cancelled")
                return
            
            # Execute attacks
            results = []
            
            for attack_vector in recommended_attacks[:3]:  # Limit to top 3
                self.display.print_info(f"Executing {attack_vector.name}...")
                
                result = await self.protocol_exploit.execute_protocol_attack(
                    client, attack_vector
                )
                
                results.append(result)
                
                if result.success:
                    self.display.print_success(f"Attack successful: {attack_vector.name}")
                    if result.privileges_gained:
                        self.display.print_warning(f"Privileges gained: {', '.join(result.privileges_gained)}")
                else:
                    self.display.print_error(f"Attack failed: {attack_vector.name}")
            
            # Display results
            if results:
                result_dicts = [asdict(r) for r in results]
                self.display.print_exploit_results(result_dicts, "Protocol")
            
        except Exception as e:
            self.display.print_error(f"Protocol attacks failed: {e}")
    
    async def cmd_exploit_timing(self, args: List[str]):
        """Execute timing attacks"""
        if not args:
            self.display.print_error("Device ID required")
            return
        
        device_identifier = args[0]
        client = await self._get_connected_client(device_identifier)
        
        if not client:
            return
        
        # Get timing vulnerabilities
        vulnerabilities = self.session.get_vulnerabilities(client.address)
        timing_vulns = [v for v in vulnerabilities 
                       if v.vuln_type.value in ['race_condition', 'timing_side_channel']]
        
        if not timing_vulns:
            self.display.print_warning("No timing vulnerabilities found. Run 'vuln-scan' first.")
            return
        
        # Confirm exploitation
        if not self.display.confirm_action("Execute timing attacks?"):
            self.display.print_info("Attack cancelled")
            return
        
        self.display.print_info("Executing timing attacks...")
        
        try:
            results = []
            
            for vulnerability in timing_vulns[:2]:  # Limit to first 2
                # Analyze vulnerability for timing attacks
                exploit_vectors = await self.timing_exploit.analyze_timing_vulnerability(
                    vulnerability, client
                )
                
                if not exploit_vectors:
                    continue
                
                # Execute timing exploits
                for exploit_vector in exploit_vectors[:2]:  # Try top 2
                    char_uuid = vulnerability.affected_characteristic
                    
                    self.display.print_info(f"Executing {exploit_vector.name}...")
                    
                    result = await self.timing_exploit.execute_timing_exploit(
                        client, char_uuid, exploit_vector
                    )
                    
                    results.append(result)
                    
                    if result.success:
                        self.display.print_success(f"Timing attack successful: {exploit_vector.name}")
                        if result.objective_accomplished:
                            self.display.print_warning("Objective accomplished!")
                        
                        # Show timing analysis
                        timing_data = {
                            'attack_type': result.attack_type.value,
                            'precision_achieved': result.precision_achieved.value,
                            'success_rate': result.success_rate,
                            'timing_measurements': result.timing_measurements
                        }
                        self.display.print_timing_analysis(timing_data)
                    else:
                        self.display.print_error(f"Timing attack failed: {exploit_vector.name}")
            
            # Display results summary
            if results:
                result_dicts = [asdict(r) for r in results]
                self.display.print_exploit_results(result_dicts, "Timing")
            
        except Exception as e:
            self.display.print_error(f"Timing attacks failed: {e}")
    
    # Session Management Commands
    async def cmd_status(self, args: List[str]):
        """Show session status"""
        discovered = self.session.get_discovered_devices()
        connected = self.session.get_connected_devices()
        
        self.display.print_header("Session Status")
        print(f"Discovered devices: {len(discovered)}")
        print(f"Connected devices: {len(connected)}")
        
        if connected:
            self.display.print_header("Connected Devices", level=2)
            for device in connected:
                device_name = device.get('name', 'Unknown')
                print(f"  • {device_name} ({device['address']})")
                
                # Show vulnerability count
                vulns = self.session.get_vulnerabilities(device['address'])
                if vulns:
                    print(f"    Vulnerabilities: {len(vulns)}")
        
        # Show session statistics
        session_data = self.session.get_session_data()
        if 'statistics' in session_data:
            stats = session_data['statistics']
            self.display.print_header("Statistics", level=2)
            for key, value in stats.items():
                print(f"  {key.replace('_', ' ').title()}: {value}")
    
    async def cmd_reset(self, args: List[str]):
        """Reset session data"""
        if args and args[0].lower() in ['confirm', 'yes', 'y']:
            confirmed = True
        else:
            confirmed = self.display.confirm_action("Reset all session data?")
        
        if confirmed:
            await self.session.reset_session()
            self.display.print_success("Session reset completed")
        else:
            self.display.print_info("Reset cancelled")
    
    async def cmd_save(self, args: List[str]):
        """Save session data"""
        if not args:
            self.display.print_error("Filename required")
            return
        
        filename = args[0]
        if not filename.endswith('.json'):
            filename += '.json'
        
        try:
            await self.session.save_session(filename)
            self.display.print_success(f"Session saved to {filename}")
        except Exception as e:
            self.display.print_error(f"Save failed: {e}")
    
    async def cmd_load(self, args: List[str]):
        """Load session data"""
        if not args:
            self.display.print_error("Filename required")
            return
        
        filename = args[0]
        if not filename.endswith('.json'):
            filename += '.json'
        
        try:
            await self.session.load_session(filename)
            self.display.print_success(f"Session loaded from {filename}")
        except Exception as e:
            self.display.print_error(f"Load failed: {e}")
    
    # Configuration Commands
    async def cmd_set(self, args: List[str]):
        """Set configuration option"""
        if len(args) < 2:
            self.display.print_error("Option and value required")
            return
        
        option = args[0]
        value = args[1]
        
        # Handle display options
        if option == 'display_level':
            level_map = {
                'minimal': DisplayLevel.MINIMAL,
                'normal': DisplayLevel.NORMAL,
                'verbose': DisplayLevel.VERBOSE,
                'debug': DisplayLevel.DEBUG
            }
            if value in level_map:
                self.display.set_level(level_map[value])
                self.display.print_success(f"Display level set to {value}")
            else:
                self.display.print_error(f"Invalid display level: {value}")
        else:
            self.display.print_error(f"Unknown option: {option}")
    
    async def cmd_show(self, args: List[str]):
        """Show configuration"""
        config_info = {
            'display_level': self.display.level.value,
            'show_timestamps': self.display.show_timestamps,
            'show_progress': self.display.show_progress
        }
        
        if args:
            option = args[0]
            if option in config_info:
                print(f"{option}: {config_info[option]}")
            else:
                self.display.print_error(f"Unknown option: {option}")
        else:
            self.display.print_json(config_info, "Configuration")
    
    async def cmd_verbose(self, args: List[str]):
        """Toggle verbose output"""
        if args:
            level = args[0].lower()
            if level in ['on', 'true', '1', 'verbose']:
                self.display.set_level(DisplayLevel.VERBOSE)
                self.display.print_success("Verbose mode enabled")
            else:
                self.display.set_level(DisplayLevel.NORMAL)
                self.display.print_success("Verbose mode disabled")
    
    # Help Commands
    async def cmd_help(self, args: List[str]):
        """Show help information"""
        if args:
            command = args[0]
            if command in self.commands:
                cmd_info = self.commands[command]
                print(f"\n{self.display.colors.BOLD}{cmd_info['usage']}{self.display.colors.ENDC}")
                print(f"{cmd_info['description']}")
                
                if 'args' in cmd_info and cmd_info['args']:
                    print(f"\nArguments:")
                    for arg in cmd_info['args']:
                        required = not arg.endswith('?')
                        arg_name = arg.rstrip('?')
                        status = "required" if required else "optional"
                        print(f"  {arg_name} ({status})")
            else:
                self.display.print_error(f"Unknown command: {command}")
        else:
            self.display.print_help(self.commands)
    
    # Helper Methods
    def _find_device(self, identifier: str) -> Optional[Dict[str, Any]]:
        """Find device by ID or address"""
        devices = self.session.get_discovered_devices()
        
        # Try by index first
        if identifier.isdigit():
            index = int(identifier) - 1
            if 0 <= index < len(devices):
                return devices[index]
        
        # Try by address
        for device in devices:
            if device['address'].lower() == identifier.lower():
                return device
        
        # Try by name (partial match)
        for device in devices:
            name = device.get('name', '')
            if name and identifier.lower() in name.lower():
                return device
        
        return None
    
    async def _get_connected_client(self, device_identifier: str):
        """Get connected client for device"""
        device = self._find_device(device_identifier)
        if not device:
            self.display.print_error(f"Device not found: {device_identifier}")
            return None
        
        device_address = device['address']
        client = self.session.get_client(device_address)
        
        if not client:
            self.display.print_error(f"Device not connected: {device_address}")
            self.display.print_info(f"Use 'connect {device_identifier}' to connect first")
            return None
        
        if not client.is_connected:
            self.display.print_error(f"Device disconnected: {device_address}")
            return None
        
        return client
    
    async def _analyze_connected_device(self, device_address: str):
        """Run initial analysis on newly connected device"""
        try:
            client = self.session.get_client(device_address)
            if not client:
                return
            
            # Basic service enumeration
            services = client.services
            if services:
                self.display.print_info(f"Found {len(services)} services")
            
            # Quick intelligence analysis
            devices = self.session.get_discovered_devices()
            device_data = next((d for d in devices if d['address'] == device_address), None)
            
            if device_data:
                from core.ble_manager import BLEDevice
                ble_device = BLEDevice(
                    address=device_data['address'],
                    name=device_data.get('name'),
                    rssi=device_data.get('rssi'),
                    manufacturer_data=device_data.get('manufacturer_data', {}),
                    service_uuids=device_data.get('service_uuids', [])
                )
                
                profile = self.device_intelligence.analyze_device(ble_device)
                research_potential = profile.research_potential
                
                if research_potential >= 8:
                    self.display.print_success(f"High research potential device ({research_potential}/10)")
                elif research_potential >= 6:
                    self.display.print_info(f"Moderate research potential ({research_potential}/10)")
                else:
                    self.display.print_warning(f"Low research potential ({research_potential}/10)")
            
        except Exception as e:
            logger.debug(f"Initial analysis failed: {e}")
    
    def _get_service_name(self, uuid: str) -> str:
        """Get human-readable service name"""
        service_names = {
            "00001800-0000-1000-8000-00805f9b34fb": "Generic Access",
            "00001801-0000-1000-8000-00805f9b34fb": "Generic Attribute",
            "0000180a-0000-1000-8000-00805f9b34fb": "Device Information",
            "0000180f-0000-1000-8000-00805f9b34fb": "Battery Service",
            "0000180d-0000-1000-8000-00805f9b34fb": "Heart Rate",
            "00001812-0000-1000-8000-00805f9b34fb": "Human Interface Device",
            "0000110b-0000-1000-8000-00805f9b34fb": "Audio Sink",
            "0000110a-0000-1000-8000-00805f9b34fb": "Audio Source",
            "6e400001-b5a3-f393-e0a9-e50e24dcca9e": "Nordic UART Service"
        }
        
        return service_names.get(uuid.lower(), "Custom Service")
    
    def get_command_list(self) -> List[str]:
        """Get list of available commands"""
        return list(self.commands.keys())
    
    def get_command_info(self, command: str) -> Optional[Dict[str, Any]]:
        """Get information about a specific command"""
        return self.commands.get(command)
    
    def get_commands_by_category(self, category: str) -> List[str]:
        """Get commands filtered by category"""
        return [cmd for cmd, info in self.commands.items() 
                if info.get('category', '').lower() == category.lower()]
    
    async def execute_command_batch(self, command_list: List[Tuple[str, List[str]]]):
        """Execute multiple commands in sequence"""
        self.display.print_info(f"Executing batch of {len(command_list)} commands...")
        
        for i, (command, args) in enumerate(command_list, 1):
            self.display.print_info(f"[{i}/{len(command_list)}] Executing: {command} {' '.join(args)}")
            
            try:
                await self.execute_command(command, args)
            except Exception as e:
                self.display.print_error(f"Batch command {i} failed: {e}")
                
                # Ask if should continue
                if not self.display.confirm_action("Continue with remaining commands?"):
                    self.display.print_info("Batch execution cancelled")
                    break
        
        self.display.print_success("Batch execution completed")
    
    def validate_command_args(self, command: str, args: List[str]) -> Tuple[bool, str]:
        """Validate command arguments"""
        if command not in self.commands:
            return False, f"Unknown command: {command}"
        
        cmd_info = self.commands[command]
        expected_args = cmd_info.get('args', [])
        
        # Count required arguments
        required_count = sum(1 for arg in expected_args if not arg.endswith('?'))
        
        if len(args) < required_count:
            return False, f"Command '{command}' requires {required_count} arguments, got {len(args)}"
        
        # Check maximum arguments
        if len(args) > len(expected_args):
            return False, f"Command '{command}' takes at most {len(expected_args)} arguments, got {len(args)}"
        
        return True, "Valid"
    
    async def suggest_next_actions(self, current_context: Dict[str, Any]):
        """Suggest next logical actions based on current context"""
        suggestions = []
        
        discovered_count = len(self.session.get_discovered_devices())
        connected_count = len(self.session.get_connected_devices())
        
        if discovered_count == 0:
            suggestions.append("scan - Discover BLE devices")
        elif connected_count == 0:
            suggestions.append("connect <device_id> - Connect to a discovered device")
        else:
            # Device is connected, suggest analysis/testing
            suggestions.extend([
                "analyze <device_id> - Analyze device characteristics",
                "intelligence <device_id> - Generate intelligence report",
                "vuln-scan <device_id> - Scan for vulnerabilities"
            ])
            
            # Check if vulnerabilities exist for exploitation
            for device in self.session.get_connected_devices():
                vulns = self.session.get_vulnerabilities(device['address'])
                if vulns:
                    suggestions.extend([
                        "exploit-memory <device_id> - Execute memory exploits",
                        "exploit-timing <device_id> - Execute timing attacks"
                    ])
                    break
        
        if suggestions:
            self.display.print_header("Suggested Next Actions", level=2)
            for suggestion in suggestions[:5]:  # Show top 5
                print(f"  • {suggestion}")
    
    def get_completion_suggestions(self, partial_command: str) -> List[str]:
        """Get command completion suggestions"""
        if not partial_command:
            return list(self.commands.keys())
        
        # Find commands that start with the partial command
        matches = [cmd for cmd in self.commands.keys() 
                  if cmd.startswith(partial_command.lower())]
        
        return sorted(matches)