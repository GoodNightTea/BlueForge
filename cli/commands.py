# cli/commands.py - Comprehensive Command Handler
import asyncio
import time
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import asdict

from core.session_manager import SessionManager
from core.device_intelligence import DeviceIntelligence
from security.vurnerability_scanner import VulnerabilityScanner, ScanIntensity
from security.fuzzing_engine import AdvancedFuzzingEngine, FuzzStrategy
from security.fuzzing_db import FuzzingDB
from exploits.memory_corruption import MemoryCorruptionExploit
from exploits.protocol_attacks import ProtocolAttackEngine
from exploits.timing_attacks import TimingExploitEngine
from exploits.sequencer import SequencingEngine, AttackStep, esp32_race_condition_poc
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
        
        # Initialize sequencing engine
        self.sequencer = SequencingEngine()
        
        # Initialize FuzzingDB
        self.fuzzing_db = FuzzingDB()
        
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
            'chars': {
                'function': self.cmd_chars,
                'description': 'List all characteristics for all services',
                'usage': 'chars [device_id]',
                'category': 'Analysis',
                'args': ['device_id?']
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
            'poc-list': {
                'function': self.cmd_poc_list,
                'description': 'List all available PoCs (proof-of-concept exploits)',
                'usage': 'poc-list',
                'category': 'Exploitation',
                'args': []
            },
            'poc-run': {
                'function': self.cmd_poc_run,
                'description': 'Run a specific PoC by name',
                'usage': 'poc-run <poc_name> <device_id>',
                'category': 'Exploitation',
                'args': ['poc_name', 'device_id']
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
            },
            'sequence': {
                'function': self.cmd_sequence,
                'description': 'Run a sequence of attack steps (PoCs, exploits, etc)',
                'usage': 'sequence <device_id>',
                'category': 'Exploitation',
                'args': ['device_id']
            },
            'smart': {
                'function': self.cmd_smart,
                'description': 'Run smart mode (adaptive attacks using previous data)',
                'usage': 'smart <device_id>',
                'category': 'Automation',
                'args': ['device_id']
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
        duration = 10
        if args and args[0].isdigit():
            duration = int(args[0])
            duration = max(5, min(60, duration))
        self.display.print_info(f"Scanning for BLE devices ({duration}s)...")
        try:
            devices = await self.session.scan_for_devices(duration)
            if devices:
                self.display.print_success(f"Found {len(devices)} devices")
                self.display.print_device_list(self.session.discovered_devices_dict)
            else:
                self.display.print_warning("No devices found")
        except Exception as e:
            self.display.print_error(f"Scan failed: {e}")

    async def cmd_list(self, args: List[str]):
        """List discovered devices"""
        devices = self.session.discovered_devices_dict
        if not devices:
            self.display.print_info("No devices discovered. Use 'scan' to discover devices.")
            return
        if args:
            filter_term = args[0].lower()
            devices = [d for d in devices if 
                       filter_term in d.get('name', '').lower() or 
                       filter_term in d.get('address', '').lower()]
        self.display.print_device_list(devices, "Discovered Devices")
        connected_devices = self.session.connected_devices_dict
        if connected_devices:
            connected_addresses = [d['address'] for d in connected_devices]
            self.display.print_info(f"Connected to: {', '.join(connected_addresses)}")

    async def cmd_connect(self, args: List[str]):
        """Connect to a device"""
        if not args:
            self.display.print_error("Device ID or address required")
            return
        device_identifier = args[0]
        device = self._find_device(device_identifier)
        if not device:
            self.display.print_error(f"Device not found: {device_identifier}")
            return
        device_name = device.get('name', 'Unknown')
        device_address = device['address']
        self.display.print_info(f"Connecting to {device_name} ({device_address})...")
        try:
            success = await self.session.connect_by_address(device_address)
            if success:
                self.display.print_success(f"Connected to {device_name}")
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
            self.display.print_error(f"Disconnect failed: {e!r}", details=str(e))
    
    # Analysis Commands
    async def cmd_analyze(self, args: List[str]):
        """Analyze device characteristics"""
        device = self._get_device_for_command(args)
        if not device:
            self.display.print_error("No device specified and multiple/no devices connected.")
            return

        device_identifier = device['address']
        client = self.session.get_ble_client(device_identifier)
        if not client or not client.is_connected:
            self.display.print_error("Device not connected.")
            return

        self.display.print_info("Analyzing device characteristics...")

        try:
            # Bleak services collection: get list
            services = list(getattr(client.services, 'services', {}).values()) if hasattr(client.services, 'services') else list(client.services)
            if not services:
                self.display.print_warning("No services available")
                return

            service_data = []
            total_characteristics = 0
            writable_characteristics = 0

            for service in services:
                char_list = []
                for char in getattr(service, 'characteristics', []):
                    total_characteristics += 1
                    properties = list(getattr(char, 'properties', []))
                    if 'write' in properties or 'write-without-response' in properties:
                        writable_characteristics += 1
                    char_list.append({
                        'uuid': str(char.uuid),
                        'properties': properties,
                        'handle': getattr(char, 'handle', 0)
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
        device = self._get_device_for_command(args)
        if not device:
            self.display.print_error("No device specified and multiple/no devices connected.")
            return

        self.display.print_info("Generating intelligence report...")

        try:
            from core.ble_manager import BLEDevice
            ble_device = BLEDevice(
                address=device['address'],
                name=device.get('name'),
                rssi=device.get('rssi'),
                manufacturer_data=device.get('manufacturer_data', {}),
                service_uuids=device.get('service_uuids', [])
            )
            profile = self.device_intelligence.analyze_device(ble_device)
            profile_dict = asdict(profile)
            # Fix: ensure security_profile is a string
            if hasattr(profile_dict['security_profile'], 'value'):
                profile_dict['security_profile'] = profile_dict['security_profile'].value
            self.display.print_device_intelligence(profile_dict)
            # Show fingerprint if available
            fp = self.fuzzing_db.get_fingerprint(device['address'])
            if fp:
                self.display.print_info(f"Known fingerprint: {fp['fingerprint']} (last seen: {fp['last_seen']})")
            # Show risk score and vendor info
            print(f"\n{self.display.colors.BOLD}Risk Score:{self.display.colors.ENDC} {profile_dict.get('risk_score', 'N/A')}/10")
            if 'vendor' in device and device['vendor']:
                print(f"{self.display.colors.BOLD}Vendor:{self.display.colors.ENDC} {device['vendor']}")
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

    async def cmd_services(self, args: List[str]):
        """Enumerate device services"""
        device = self._get_device_for_command(args)
        if not device:
            self.display.print_error("No device specified and multiple/no devices connected.")
            return

        device_identifier = device['address']
        client = self.session.get_ble_client(device_identifier)
        if not client or not client.is_connected:
            self.display.print_error("Device not connected.")
            return

        self.display.print_info("Enumerating services...")

        try:
            # Bleak services collection: get list
            services = list(getattr(client.services, 'services', {}).values()) if hasattr(client.services, 'services') else list(client.services)
            if not services:
                self.display.print_warning("No services found")
                return

            table_data = []
            for service in services:
                service_name = self._get_service_name(str(service.uuid))
                char_count = len(getattr(service, 'characteristics', []))
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
        device = self._get_device_for_command(args)
        if not device:
            self.display.print_error("No device specified and multiple/no devices connected.")
            return

        device_identifier = device['address']
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

        self.display.print_info(f"Starting {intensity.value} vulnerability scan on {device.get('name', device_identifier)}...")

        # Confirm for aggressive scans
        if intensity in [ScanIntensity.AGGRESSIVE, ScanIntensity.EXTREME]:
            if not self.display.confirm_action(f"Perform {intensity.value} scan? This may crash the device."):
                self.display.print_info("Scan cancelled")
                return

        try:
            # Always use verbose for vuln scan to maximize findings
            scan_result = await self.vulnerability_scanner.scan_device(
                client, client.address, intensity, verbose=True
            ) if 'verbose' in self.vulnerability_scanner.scan_device.__code__.co_varnames else \
                await self.vulnerability_scanner.scan_device(
                    client, client.address, intensity
                )

            self.display.print_header("Vulnerability Scan Results")
            print(f"Scan Duration: {self.display.format_duration(getattr(scan_result, 'scan_duration', 0))}")
            print(f"Total Tests: {getattr(scan_result, 'total_tests', 'N/A')}")
            print(f"Scan Intensity: {getattr(scan_result, 'scan_intensity', intensity).value.upper()}")

            # Show detailed test results if available
            if hasattr(scan_result, 'test_log') and scan_result.test_log:
                print("\nTest Log:")
                headers = ["Result", "Test", "Characteristic", "Service", "Details"]
                rows = []
                for entry in scan_result.test_log:
                    result = entry.get('result','?')
                    color = self.display.colors.OKGREEN if result.lower() == 'pass' else self.display.colors.FAIL
                    rows.append([
                        f"{color}{result}{self.display.colors.ENDC}",
                        entry.get('test','?'),
                        entry.get('characteristic','?'),
                        entry.get('service','?'),
                        entry.get('details','')
                    ])
                self.display.print_table(headers, rows, title="Test Log")

            if hasattr(scan_result, 'tests_conducted') and scan_result.tests_conducted:
                print("\nTest Summary Table:")
                headers = ["Service", "Characteristic", "Test", "Result"]
                rows = []
                for t in scan_result.tests_conducted:
                    result = t.get('result', '?')
                    color = self.display.colors.OKGREEN if result.lower() == 'pass' else self.display.colors.FAIL
                    rows.append([
                        t.get('service', '?'),
                        t.get('characteristic', '?'),
                        t.get('test', '?'),
                        f"{color}{result}{self.display.colors.ENDC}"
                    ])
                self.display.print_table(headers, rows)

            if hasattr(scan_result, 'vulnerabilities_found') and scan_result.vulnerabilities_found:
                vuln_list = []
                for vuln in scan_result.vulnerabilities_found:
                    vuln_list.append({
                        'severity': vuln.severity.value,
                        'vuln_type': vuln.vuln_type.value,
                        'title': vuln.title,
                        'confidence': vuln.confidence
                    })
                self.display.print_vulnerability_summary(vuln_list)
                self.session.store_vulnerabilities(client.address, scan_result.vulnerabilities_found)
            else:
                self.display.print_success("No vulnerabilities detected")

            if hasattr(scan_result, 'recommendations') and scan_result.recommendations:
                self.display.print_header("Recommendations", level=2)
                for rec in scan_result.recommendations:
                    print(f"  • {rec}")

            # --- Run PoC tests for known vulnerabilities ---
            from exploits.sequencer import POC_REGISTRY
            poc_results = []
            for poc in POC_REGISTRY.all():
                if self.display.level in [DisplayLevel.VERBOSE, DisplayLevel.DEBUG]:
                    self.display.print_info(f"Testing PoC: {poc.name} ({poc.description})")
                try:
                    poc_result = await poc.run({'client': client, 'device': device})
                    poc_results.append({
                        'name': poc.name,
                        'cve': poc.cve,
                        'status': poc_result.get('status'),
                        'note': poc_result.get('note', ''),
                        'error': poc_result.get('error', '')
                    })
                except Exception as e:
                    poc_results.append({
                        'name': poc.name,
                        'cve': poc.cve,
                        'status': 'fail',
                        'note': '',
                        'error': str(e)
                    })
            if poc_results:
                self.display.print_header("PoC Vulnerability Test Results", level=2)
                headers = ["PoC", "CVE", "Status", "Note", "Error"]
                rows = [[r['name'], r['cve'], r['status'], r['note'], r['error']] for r in poc_results]
                self.display.print_table(headers, rows, title="PoC Results")
        except Exception as e:
            self.display.print_error(f"Vulnerability scan failed: {e}")

    async def cmd_fuzz(self, args: List[str]):
        """Fuzz device characteristics"""
        device = self._get_device_for_command(args)
        if not device:
            self.display.print_error("No device specified and multiple/no devices connected.")
            return

        device_identifier = device['address']
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

            # --- Device Fingerprinting ---
            fingerprint = f"{device.get('name','')}|{device.get('address','')}|{sorted(writable_chars)}"
            self.fuzzing_db.store_fingerprint(device['address'], device.get('name','Unknown'), fingerprint)
            prev_fp = self.fuzzing_db.get_fingerprint(device['address'])
            if prev_fp:
                self.display.print_info(f"Device fingerprint recognized (last seen: {prev_fp['last_seen']})")
                if self.display.level in [DisplayLevel.VERBOSE, DisplayLevel.DEBUG]:
                    self.display.print_info(f"Fingerprint: {prev_fp['fingerprint']}")

            # Fuzz each writable characteristic
            all_results = []
            session_ids = []

            for char_uuid in writable_chars[:3]:  # Limit to first 3
                self.display.print_info(f"Fuzzing characteristic: {char_uuid}")

                # Execute fuzzing session
                session_result = await self.fuzzing_engine.execute_fuzzing_session(
                    client, char_uuid, strategy, max_cases
                )
                all_results.append(session_result)

                # Log session in DB
                session_id = self.fuzzing_db.log_fuzzing_session(
                    device['address'], char_uuid, strategy.value, max_cases,
                    session_result.crashes_found, session_result.total_cases
                )
                session_ids.append(session_id)

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

            # Show fuzzing history for this device
            history = self.fuzzing_db.get_fuzzing_history(device['address'])
            if history:
                self.display.print_fuzzing_history(history[:5])

            # Show crash cases for the most recent session if any crashes found
            if total_crashes > 0 and session_ids:
                for sid in session_ids:
                    crash_cases = self.fuzzing_db.get_crash_cases(sid)
                    if crash_cases:
                        self.display.print_fuzzing_crash_cases(crash_cases)

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
        discovered = self.session.discovered_devices_dict
        connected = self.session.connected_devices_dict

        self.display.print_header("Session Status")
        print(f"Discovered devices: {len(discovered)}")
        print(f"Connected devices: {len(connected)}")

        if connected:
            self.display.print_header("Connected Devices", level=2)
            for device in connected:
                device_name = device.get('name', 'Unknown')
                print(f"  • {device_name} ({device['address']})")
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
        """Show help information with improved formatting and categorized command list"""
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
            print(f"\n{self.display.colors.BOLD}BlueForge BLE Pentesting Tool - Command Reference{self.display.colors.ENDC}")
            print("─" * 80)
            print(f"{self.display.colors.OKCYAN}Feature List:{self.display.colors.ENDC}")
            print("  • Device scanning, connection, and enumeration")
            print("  • Device intelligence and fingerprinting")
            print("  • Vulnerability scanning with PoC integration")
            print("  • Advanced fuzzing with persistent learning")
            print("  • Exploitation (memory, protocol, timing)")
            print("  • Attack sequencing and smart mode")
            print("  • Session management and reporting")
            print("  • Extensible PoC system (SweynTooth, KNOB, custom 0days)")
            print("  • Adaptive, data-driven attack strategies\n")
            # Categorize commands
            categories = {}
            for name, info in self.commands.items():
                cat = info.get('category', 'Other')
                categories.setdefault(cat, []).append((name, info))
            for cat in sorted(categories.keys()):
                print(f"{self.display.colors.BOLD}{cat} Commands:{self.display.colors.ENDC}")
                for name, info in categories[cat]:
                    print(f"  {self.display.colors.OKGREEN}{name:<15}{self.display.colors.ENDC} - {info['description']}")
                print()
            print("Type 'help <command>' for details on a specific command.")
    
    # Helper Methods
    def _find_device(self, identifier: str) -> Optional[Dict[str, Any]]:
        """Find device by ID or address using session's discovered_devices_dict"""
        devices = self.session.discovered_devices_dict
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
            name = device.get('name', '').session.connected_devices_dict
            if name and identifier.lower() in name.lower():
                return device
        return None
    
    def _get_active_connected_device(self) -> Optional[Dict[str, Any]]:
        """Return the only connected device if only one is connected, else None."""
        connected = self.session.connected_devices_dict
        if len(connected) == 1:
            return connected[0]
        return None

    async def _analyze_connected_device(self, device_address: str):
        """Run quick intelligence analysis on a newly connected device"""
        try:
            client = self.session.get_ble_client(device_address)
            if not client:
                return
            # Use DeviceIntelligence to analyze using live services if possible
            profile = self.device_intelligence.analyze_device_by_address(self.session, device_address)
            research_potential = profile.research_potential
            if research_potential >= 8:
                self.display.print_success(f"High research potential device ({research_potential}/10)")
            elif research_potential >= 6:
                self.display.print_info(f"Moderate research potential ({research_potential}/10)")
            else:
                self.display.print_warning(f"Low research potential ({research_potential}/10)")
        except Exception as e:
            logger.debug(f"Initial analysis failed: {e}")

    async def cmd_chars(self, args: List[str]):
        """List all characteristics for all services of a connected device"""
        device = self._get_device_for_command(args)
        if not device:
            self.display.print_error("No device specified and multiple/no devices connected.")
            return

        device_identifier = device['address']
        client = self.session.get_ble_client(device_identifier)
        if not client or not client.is_connected:
            self.display.print_error("Device not connected.")
            return

        self.display.print_info("Enumerating all characteristics...")

        try:
            # Bleak services collection: get list
            services = list(getattr(client.services, 'services', {}).values()) if hasattr(client.services, 'services') else list(client.services)
            if not services:
                self.display.print_warning("No services found")
                return

            rows = []
            for service in services:
                service_uuid = str(service.uuid)
                for char in getattr(service, 'characteristics', []):
                    char_uuid = str(char.uuid)
                    props = ','.join(getattr(char, 'properties', []))
                    handle = getattr(char, 'handle', 0)
                    rows.append([
                        service_uuid,
                        char_uuid,
                        props,
                        f"0x{handle:04x}"
                    ])
            headers = ["Service UUID", "Characteristic UUID", "Properties", "Handle"]
            self.display.print_table(headers, rows, title="Characteristics")
        except Exception as e:
            self.display.print_error(f"Characteristic enumeration failed: {e}")
    
    def _get_device_for_command(self, args: List[str]) -> Optional[Dict[str, Any]]:
        """
        Helper to get device for commands that operate on a connected device.
        If args is empty and only one device is connected, use it.
        If args is given, use _find_device.
        """
        if args:
            return self._find_device(args[0])
        # No args: try to use the only connected device
        return self._get_active_connected_device()

    async def _get_connected_client(self, device_identifier: str):
        """Get connected client for device using session's get_ble_client"""
        device = self._find_device(device_identifier)
        if not device:
            self.display.print_error(f"Device not found: {device_identifier}")
            return None
        device_address = device['address']
        client = self.session.get_ble_client(device_address)
        if not client:
            self.display.print_error(f"Device not connected: {device_address}")
            self.display.print_info(f"Use 'connect {device_identifier}' to connect first")
            return None
        if not client.is_connected:
            self.display.print_error(f"Device disconnected: {device_address}")
            return None
        return client

    async def cmd_sequence(self, args: List[str]):
        """Run a sequence of attack steps (PoCs, exploits, etc)"""
        device = self._get_device_for_command(args)
        if not device:
            self.display.print_error("No device specified and multiple/no devices connected.")
            return
        device_identifier = device['address']
        client = await self._get_connected_client(device_identifier)
        if not client:
            return
        # Example: Add ESP32 0day PoC to the sequence
        self.sequencer.clear()
        self.sequencer.add_step(AttackStep(
            name="ESP32 Race Condition 0day",
            action=esp32_race_condition_poc,
            description="Trigger race condition for memory corruption on ESP32"
        ))
        # Add more steps as needed...
        context = { 'client': client, 'device': device }
        results = await self.sequencer.execute(context)
        self.display.print_header("Sequencing Results")
        for name, success, result in results:
            color = self.display.colors.OKGREEN if success else self.display.colors.FAIL
            print(f"{color}{name}: {'Success' if success else 'Failed'}{self.display.colors.ENDC}")
            if result:
                print(f"  Details: {result}")

    async def cmd_poc_list(self, args: List[str]):
        """List all available PoCs"""
        from exploits.sequencer import POC_REGISTRY
        pocs = POC_REGISTRY.all()
        headers = ["Name", "CVE", "Severity", "Description", "Tags"]
        rows = [[poc.name, poc.cve, poc.severity, poc.description, ','.join(poc.tags)] for poc in pocs]
        self.display.print_table(headers, rows, title="Available PoCs")

    async def cmd_poc_run(self, args: List[str]):
        """Run a specific PoC by name"""
        if len(args) < 2:
            self.display.print_error("Usage: poc-run <poc_name> <device_id>")
            return
        poc_name, device_id = args[0], args[1]
        from exploits.sequencer import POC_REGISTRY
        poc = POC_REGISTRY.pocs.get(poc_name)
        if not poc:
            self.display.print_error(f"PoC not found: {poc_name}")
            return
        device = self._find_device(device_id)
        if not device:
            self.display.print_error(f"Device not found: {device_id}")
            return
        client = await self._get_connected_client(device['address'])
        if not client:
            return
        self.display.print_info(f"Running PoC: {poc.name} on {device['address']}")
        try:
            result = await poc.run({'client': client, 'device': device})
            self.display.print_json(result, title=f"PoC Result: {poc.name}")
        except Exception as e:
            self.display.print_error(f"PoC execution failed: {e}")

    async def cmd_smart(self, args: List[str]):
        """Run smart mode (adaptive attacks using previous data)"""
        if not args:
            self.display.print_error("Device ID required for smart mode")
            return
        device = self._find_device(args[0])
        if not device:
            self.display.print_error(f"Device not found: {args[0]}")
            return
        client = await self._get_connected_client(device['address'])
        if not client:
            return
        self.display.print_info(f"Running smart mode on {device['address']}")
        # Use previous fuzzing/vuln scan/PoC data to adapt attack order
        history = self.fuzzing_db.get_fuzzing_history(device['address'])
        from exploits.sequencer import POC_REGISTRY
        pocs = POC_REGISTRY.all()
        # Example: prioritize PoCs not previously run or that failed
        already_run = {h['char_uuid'] for h in history}
        smart_pocs = [p for p in pocs if p.name not in already_run]
        if not smart_pocs:
            smart_pocs = pocs  # fallback: run all
        results = []
        for poc in smart_pocs:
            self.display.print_info(f"[Smart] Running PoC: {poc.name}")
            try:
                result = await poc.run({'client': client, 'device': device})
                results.append({'name': poc.name, 'result': result})
            except Exception as e:
                results.append({'name': poc.name, 'result': str(e)})
        self.display.print_json(results, title="Smart Mode Results")