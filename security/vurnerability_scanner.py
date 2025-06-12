# security/vulnerability_scanner.py - Automated Vulnerability Detection Engine
import asyncio
import time
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
from bleak import BleakClient
from security.fuzzing_engine import AdvancedFuzzingEngine, FuzzStrategy, FuzzResult
from utils.logging import get_logger

logger = get_logger(__name__)

class VulnerabilityType(Enum):
    """Types of BLE vulnerabilities"""
    BUFFER_OVERFLOW = "buffer_overflow"
    RACE_CONDITION = "race_condition"
    USE_AFTER_FREE = "use_after_free"
    TIMING_SIDE_CHANNEL = "timing_side_channel"
    PROTOCOL_VIOLATION = "protocol_violation"
    MEMORY_CORRUPTION = "memory_corruption"
    AUTHENTICATION_BYPASS = "authentication_bypass"
    DENIAL_OF_SERVICE = "denial_of_service"
    INFORMATION_DISCLOSURE = "information_disclosure"
    PRIVILEGE_ESCALATION = "privilege_escalation"

class SeverityLevel(Enum):
    """Vulnerability severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class ScanIntensity(Enum):
    """Scanning intensity levels"""
    PASSIVE = "passive"        # Non-intrusive scanning
    CONSERVATIVE = "conservative"  # Light testing
    MODERATE = "moderate"      # Balanced approach
    AGGRESSIVE = "aggressive"  # Thorough testing
    EXTREME = "extreme"        # Maximum testing (may crash devices)

@dataclass
class VulnerabilityFinding:
    """Individual vulnerability finding"""
    vuln_type: VulnerabilityType
    severity: SeverityLevel
    title: str
    description: str
    proof_of_concept: bytes
    affected_characteristic: str
    confidence: float  # 0.0 to 1.0
    cvss_score: Optional[float] = None
    remediation: Optional[str] = None
    references: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ScanResult:
    """Complete vulnerability scan results"""
    target_device: str
    scan_duration: float
    total_tests: int
    vulnerabilities_found: List[VulnerabilityFinding]
    scan_intensity: ScanIntensity
    coverage_report: Dict[str, Any]
    recommendations: List[str] = field(default_factory=list)
    false_positives: int = 0
    scan_timestamp: float = field(default_factory=time.time)

class VulnerabilityScanner:
    """Automated BLE vulnerability detection engine"""
    
    def __init__(self):
        self.logger = get_logger(f"{__name__}.VulnerabilityScanner")
        self.fuzzing_engine = AdvancedFuzzingEngine()
        
        # Vulnerability detection patterns
        self.crash_patterns = self._initialize_crash_patterns()
        self.timing_thresholds = self._initialize_timing_thresholds()
        self.known_vulnerabilities = self._initialize_known_vulnerabilities()
        
        # Scan configuration
        self.scan_config = {
            'timeout_per_test': 5.0,
            'recovery_delay': 2.0,
            'max_consecutive_failures': 5,
            'enable_crash_detection': True,
            'enable_timing_analysis': True,
            'enable_protocol_testing': True,
            'false_positive_filtering': True
        }
    
    def _initialize_crash_patterns(self) -> Dict[str, VulnerabilityType]:
        """Initialize patterns that indicate specific vulnerability types"""
        return {
            # Buffer overflow indicators
            'deadbeef': VulnerabilityType.BUFFER_OVERFLOW,
            '41414141': VulnerabilityType.BUFFER_OVERFLOW,
            'ffffffff': VulnerabilityType.BUFFER_OVERFLOW,
            
            # Memory corruption indicators
            'cafebabe': VulnerabilityType.MEMORY_CORRUPTION,
            '90909090': VulnerabilityType.MEMORY_CORRUPTION,
            'cccccccc': VulnerabilityType.MEMORY_CORRUPTION,
            
            # Timing-based indicators
            'timing_24x14': VulnerabilityType.RACE_CONDITION,
            'precision_timing': VulnerabilityType.TIMING_SIDE_CHANNEL,
            
            # Protocol violation indicators
            'att_violation': VulnerabilityType.PROTOCOL_VIOLATION,
            'gatt_violation': VulnerabilityType.PROTOCOL_VIOLATION,
        }
    
    def _initialize_timing_thresholds(self) -> Dict[str, float]:
        """Initialize timing thresholds for vulnerability detection"""
        return {
            'response_time_anomaly': 0.5,      # Response time deviation threshold
            'timing_variance': 0.1,            # Timing variance threshold
            'race_condition_delay': 0.05,      # Race condition detection delay
            'side_channel_threshold': 0.2      # Side channel detection threshold
        }
    
    def _initialize_known_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Initialize database of known BLE vulnerabilities"""
        return [
            {
                'name': 'Generic Buffer Overflow',
                'cve': 'BlueForge-001',
                'description': 'Buffer overflow in BLE characteristic handling',
                'affected_platforms': ['ARM Cortex-M', 'ESP32', 'nRF52'],
                'test_payload': b'\xDE\xAD\xBE\xEF\xCA\xFE\xBA\xBE',
                'severity': SeverityLevel.CRITICAL
            },
            {
                'name': 'Timing-based Race Condition',
                'cve': 'BlueForge-002',
                'description': 'Race condition in GATT handling with specific timing',
                'affected_platforms': ['ESP32', 'nRF52'],
                'test_payload': b'\x42' * 8,
                'timing_config': {'iterations': 24, 'delay_ms': 14},
                'severity': SeverityLevel.HIGH
            },
            {
                'name': 'Protocol Violation DoS',
                'cve': 'BlueForge-003',
                'description': 'Denial of service via malformed ATT packets',
                'affected_platforms': ['Multiple'],
                'test_payload': b'\xFF' * 100,
                'severity': SeverityLevel.HIGH
            }
        ]
    
    async def scan_device(self, client: BleakClient, device_address: str,
                         intensity: ScanIntensity = ScanIntensity.MODERATE) -> ScanResult:
        """Perform comprehensive vulnerability scan on device"""
        
        scan_start = time.time()
        self.logger.info(f"Starting {intensity.value} vulnerability scan on {device_address}")
        
        # Initialize scan result
        result = ScanResult(
            target_device=device_address,
            scan_duration=0.0,
            total_tests=0,
            vulnerabilities_found=[],
            scan_intensity=intensity,
            coverage_report={}
        )
        
        try:
            # Phase 1: Passive reconnaissance
            await self._passive_reconnaissance(client, device_address, result)
            
            # Phase 2: Service enumeration and analysis
            await self._service_analysis(client, result)
            
            # Phase 3: Known vulnerability testing
            await self._test_known_vulnerabilities(client, result, intensity)
            
            # Phase 4: Fuzzing-based discovery
            if intensity in [ScanIntensity.MODERATE, ScanIntensity.AGGRESSIVE, ScanIntensity.EXTREME]:
                await self._fuzzing_based_discovery(client, result, intensity)
            
            # Phase 5: Timing analysis
            if intensity in [ScanIntensity.AGGRESSIVE, ScanIntensity.EXTREME]:
                await self._timing_vulnerability_analysis(client, result)
            
            # Phase 6: Protocol violation testing
            if intensity == ScanIntensity.EXTREME:
                await self._protocol_violation_testing(client, result)
            
            # Post-processing
            await self._post_process_results(result)
            
        except Exception as e:
            self.logger.error(f"Scan failed: {e}")
            result.recommendations.append(f"Scan incomplete due to error: {e}")
        
        result.scan_duration = time.time() - scan_start
        self.logger.info(f"Scan completed in {result.scan_duration:.1f}s, found {len(result.vulnerabilities_found)} vulnerabilities")
        
        return result
    
    async def _passive_reconnaissance(self, client: BleakClient, device_address: str, 
                                    result: ScanResult):
        """Passive information gathering without device interaction"""
        
        self.logger.info("Phase 1: Passive reconnaissance")
        
        # Analyze device characteristics for vulnerability indicators
        vuln_indicators = []
        
        # Check for privacy indicators
        first_byte = int(device_address.split(':')[0], 16)
        if not (first_byte & 0x02):  # Static MAC
            finding = VulnerabilityFinding(
                vuln_type=VulnerabilityType.INFORMATION_DISCLOSURE,
                severity=SeverityLevel.LOW,
                title="MAC Address Disclosure",
                description="Device uses static MAC address, enabling tracking",
                proof_of_concept=device_address.encode(),
                affected_characteristic="Device Address",
                confidence=0.9,
                remediation="Enable MAC address randomization"
            )
            result.vulnerabilities_found.append(finding)
        
        result.coverage_report['passive_recon'] = {
            'indicators_found': len(vuln_indicators),
            'privacy_analysis': 'completed',
            'vendor_analysis': 'completed'
        }
    
    async def _service_analysis(self, client: BleakClient, result: ScanResult):
        """Analyze GATT services for vulnerabilities"""
        
        self.logger.info("Phase 2: Service analysis")
        
        try:
            services = client.services
            service_list = list(services)
            
            total_characteristics = 0
            writable_characteristics = []
            
            for service in service_list:
                for char in service.characteristics:
                    total_characteristics += 1
                    
                    if 'write' in char.properties or 'write-without-response' in char.properties:
                        writable_characteristics.append({
                            'service': str(service.uuid),
                            'characteristic': str(char.uuid),
                            'properties': char.properties
                        })
            
            # Analyze findings
            if len(writable_characteristics) > 10:
                finding = VulnerabilityFinding(
                    vuln_type=VulnerabilityType.PRIVILEGE_ESCALATION,
                    severity=SeverityLevel.MEDIUM,
                    title="Excessive Writable Characteristics",
                    description=f"Device exposes {len(writable_characteristics)} writable characteristics",
                    proof_of_concept=str(writable_characteristics).encode(),
                    affected_characteristic="Multiple",
                    confidence=0.8,
                    remediation="Implement proper access controls on characteristics"
                )
                result.vulnerabilities_found.append(finding)
            
            # Check for characteristics without proper protection
            for char_info in writable_characteristics:
                if 'write-without-response' in char_info['properties']:
                    finding = VulnerabilityFinding(
                        vuln_type=VulnerabilityType.AUTHENTICATION_BYPASS,
                        severity=SeverityLevel.MEDIUM,
                        title="Write Without Response Enabled",
                        description="Characteristic allows writes without authentication",
                        proof_of_concept=char_info['characteristic'].encode(),
                        affected_characteristic=char_info['characteristic'],
                        confidence=0.7,
                        remediation="Require authentication for write operations"
                    )
                    result.vulnerabilities_found.append(finding)
            
            result.coverage_report['service_analysis'] = {
                'total_services': len(service_list),
                'total_characteristics': total_characteristics,
                'writable_characteristics': len(writable_characteristics),
                'analysis_completed': True
            }
            
        except Exception as e:
            self.logger.error(f"Service analysis failed: {e}")
            result.coverage_report['service_analysis'] = {'error': str(e)}
    
    async def _test_known_vulnerabilities(self, client: BleakClient, result: ScanResult,
                                        intensity: ScanIntensity):
        """Test for known BLE vulnerabilities"""
        
        self.logger.info("Phase 3: Known vulnerability testing")
        
        writable_chars = await self._get_writable_characteristics(client)
        
        if not writable_chars:
            result.coverage_report['known_vuln_testing'] = {'error': 'No writable characteristics found'}
            return
        
        tests_performed = 0
        max_tests = self._get_max_tests_for_intensity(intensity)
        
        for vuln in self.known_vulnerabilities:
            if tests_performed >= max_tests:
                break
            
            for char_uuid in writable_chars[:3]:  # Test first 3 characteristics
                try:
                    self.logger.debug(f"Testing {vuln['name']} on {char_uuid}")
                    
                    crashed = await self._test_vulnerability_payload(
                        client, char_uuid, vuln['test_payload']
                    )
                    
                    if crashed:
                        finding = VulnerabilityFinding(
                            vuln_type=VulnerabilityType.MEMORY_CORRUPTION,
                            severity=vuln['severity'],
                            title=vuln['name'],
                            description=vuln['description'],
                            proof_of_concept=vuln['test_payload'],
                            affected_characteristic=char_uuid,
                            confidence=0.9,
                            cvss_score=self._calculate_cvss_score(vuln['severity']),
                            references=[vuln.get('cve', 'Custom Research')]
                        )
                        result.vulnerabilities_found.append(finding)
                        
                        if vuln['severity'] == SeverityLevel.CRITICAL:
                            self.logger.warning(f"CRITICAL vulnerability found: {vuln['name']}")
                    
                    tests_performed += 1
                    await asyncio.sleep(self.scan_config['recovery_delay'])
                    
                except Exception as e:
                    self.logger.debug(f"Known vuln test failed: {e}")
        
        result.total_tests += tests_performed
        result.coverage_report['known_vuln_testing'] = {
            'vulnerabilities_tested': len(self.known_vulnerabilities),
            'tests_performed': tests_performed,
            'characteristics_tested': min(len(writable_chars), 3)
        }
    
    async def _fuzzing_based_discovery(self, client: BleakClient, result: ScanResult,
                                     intensity: ScanIntensity):
        """Use fuzzing to discover new vulnerabilities"""
        
        self.logger.info("Phase 4: Fuzzing-based discovery")
        
        writable_chars = await self._get_writable_characteristics(client)
        if not writable_chars:
            return
        
        max_cases = self._get_max_tests_for_intensity(intensity)
        strategies = self._get_strategies_for_intensity(intensity)
        
        total_crashes = 0
        
        for strategy in strategies:
            for char_uuid in writable_chars[:2]:  # Limit to first 2 characteristics
                try:
                    self.logger.debug(f"Fuzzing {char_uuid} with {strategy.value} strategy")
                    
                    fuzzing_results = await self.fuzzing_engine.fuzz_target(
                        client, char_uuid, strategy, max_cases // len(strategies)
                    )
                    
                    crashes = [r for r in fuzzing_results if r.crashed]
                    total_crashes += len(crashes)
                    
                    # Convert crashes to vulnerability findings
                    for crash_result in crashes:
                        vuln_type = self._classify_crash_vulnerability(crash_result)
                        severity = self._assess_crash_severity(crash_result)
                        
                        finding = VulnerabilityFinding(
                            vuln_type=vuln_type,
                            severity=severity,
                            title=f"Crash via {strategy.value} fuzzing",
                            description=f"Device crashes when sending specific payload via {strategy.value} fuzzing",
                            proof_of_concept=crash_result.case.payload,
                            affected_characteristic=char_uuid,
                            confidence=0.8,
                            metadata={
                                'strategy': strategy.value,
                                'response_time': crash_result.response_time,
                                'error_message': crash_result.error_message
                            }
                        )
                        result.vulnerabilities_found.append(finding)
                    
                    result.total_tests += len(fuzzing_results)
                    
                except Exception as e:
                    self.logger.debug(f"Fuzzing failed: {e}")
        
        result.coverage_report['fuzzing_discovery'] = {
            'strategies_used': [s.value for s in strategies],
            'total_crashes': total_crashes,
            'characteristics_tested': min(len(writable_chars), 2)
        }
    
    async def _timing_vulnerability_analysis(self, client: BleakClient, result: ScanResult):
        """Analyze for timing-based vulnerabilities"""
        
        self.logger.info("Phase 5: Timing vulnerability analysis")
        
        writable_chars = await self._get_writable_characteristics(client)
        if not writable_chars:
            return
        
        timing_configs = [
            {'payload': b'\xDE\xAD\xBE\xEF\xCA\xFE\xBA\xBE', 'iterations': 24, 'delay_ms': 14, 'description': 'Proven timing pattern'},
            {'payload': b'\x41\x41\x41\x41\x41\x41\x41\x41', 'iterations': 50, 'delay_ms': 10, 'description': 'Aggressive overflow timing'},
            {'payload': b'\x42' * 8, 'iterations': 100, 'delay_ms': 5, 'description': 'Fast race condition'},
        ]
        
        timing_vulnerabilities = 0
        
        for char_uuid in writable_chars[:2]:
            for timing_config in timing_configs:
                try:
                    timing_result = await self.fuzzing_engine.timing_engine.precision_timing_test(
                        client, char_uuid, timing_config['payload'],
                        timing_config['iterations'], timing_config['delay_ms']
                    )
                    
                    if timing_result.fuzz_result.crashed:
                        finding = VulnerabilityFinding(
                            vuln_type=VulnerabilityType.RACE_CONDITION,
                            severity=SeverityLevel.CRITICAL,
                            title="Precision Timing Vulnerability",
                            description=f"Device crashes with precision timing: {timing_config['description']}",
                            proof_of_concept=timing_config['payload'],
                            affected_characteristic=char_uuid,
                            confidence=0.95,
                            metadata={
                                'timing_config': timing_config,
                                'methodology': 'precision_timing',
                                'anomaly_score': timing_result.anomaly_score
                            }
                        )
                        result.vulnerabilities_found.append(finding)
                        timing_vulnerabilities += 1
                        
                        self.logger.warning(f"Timing vulnerability found: {timing_config['description']}")
                    
                    elif timing_result.timing_sensitive:
                        finding = VulnerabilityFinding(
                            vuln_type=VulnerabilityType.TIMING_SIDE_CHANNEL,
                            severity=SeverityLevel.MEDIUM,
                            title="Timing Side Channel",
                            description="Device shows timing sensitivity that may leak information",
                            proof_of_concept=timing_config['payload'],
                            affected_characteristic=char_uuid,
                            confidence=0.7,
                            metadata={
                                'anomaly_score': timing_result.anomaly_score,
                                'response_times': timing_result.response_times
                            }
                        )
                        result.vulnerabilities_found.append(finding)
                    
                    await asyncio.sleep(1)
                    
                except Exception as e:
                    self.logger.debug(f"Timing test failed: {e}")
        
        result.coverage_report['timing_analysis'] = {
            'timing_configs_tested': len(timing_configs),
            'timing_vulnerabilities_found': timing_vulnerabilities,
            'characteristics_tested': min(len(writable_chars), 2)
        }
    
    async def _protocol_violation_testing(self, client: BleakClient, result: ScanResult):
        """Test for protocol violation vulnerabilities"""
        
        self.logger.info("Phase 6: Protocol violation testing")
        
        writable_chars = await self._get_writable_characteristics(client)
        if not writable_chars:
            return
        
        protocol_payloads = [
            b'\xFF' + b'\x00' * 7,                      # Invalid ATT opcode
            b'\x16\x00\x00\x00\x00' + b'\x41' * 100,   # Oversized Prepare Write
            b'\x08\x00\x00\xFF\xFF\x00\x00',           # Invalid handle range
        ]
        
        protocol_crashes = 0
        
        for char_uuid in writable_chars[:1]:
            for payload in protocol_payloads:
                try:
                    crashed = await self._test_vulnerability_payload(client, char_uuid, payload)
                    
                    if crashed:
                        finding = VulnerabilityFinding(
                            vuln_type=VulnerabilityType.PROTOCOL_VIOLATION,
                            severity=SeverityLevel.HIGH,
                            title="Protocol Violation Crash",
                            description="Device crashes when receiving malformed protocol data",
                            proof_of_concept=payload,
                            affected_characteristic=char_uuid,
                            confidence=0.8,
                            remediation="Implement proper input validation for protocol data"
                        )
                        result.vulnerabilities_found.append(finding)
                        protocol_crashes += 1
                    
                    await asyncio.sleep(0.5)
                    
                except Exception as e:
                    self.logger.debug(f"Protocol violation test failed: {e}")
        
        result.coverage_report['protocol_testing'] = {
            'protocol_payloads_tested': len(protocol_payloads),
            'protocol_crashes': protocol_crashes
        }
    
    async def _test_vulnerability_payload(self, client: BleakClient, char_uuid: str, 
                                        payload: bytes) -> bool:
        """Test a single payload for vulnerability"""
        try:
            await client.write_gatt_char(char_uuid, payload, response=False)
            await asyncio.sleep(0.2)
            
            return await self._check_device_crashed(client)
            
        except Exception:
            return True
    
    async def _check_device_crashed(self, client: BleakClient) -> bool:
        """Check if device has crashed"""
        try:
            if not client.is_connected:
                return True
            
            services = client.services
            if not services:
                return True
            
            try:
                await asyncio.wait_for(
                    client.read_gatt_char("00002a00-0000-1000-8000-00805f9b34fb"),
                    timeout=2.0
                )
                return False
            except:
                return False
            
        except Exception:
            return True
    
    async def _get_writable_characteristics(self, client: BleakClient) -> List[str]:
        """Get list of writable characteristic UUIDs"""
        writable_chars = []
        
        try:
            services = client.services
            for service in services:
                for char in service.characteristics:
                    if 'write' in char.properties or 'write-without-response' in char.properties:
                        writable_chars.append(str(char.uuid))
        except Exception as e:
            self.logger.error(f"Failed to get writable characteristics: {e}")
        
        return writable_chars
    
    def _get_max_tests_for_intensity(self, intensity: ScanIntensity) -> int:
        """Get maximum number of tests based on intensity"""
        intensity_limits = {
            ScanIntensity.PASSIVE: 0,
            ScanIntensity.CONSERVATIVE: 10,
            ScanIntensity.MODERATE: 50,
            ScanIntensity.AGGRESSIVE: 100,
            ScanIntensity.EXTREME: 200
        }
        return intensity_limits.get(intensity, 50)
    
    def _get_strategies_for_intensity(self, intensity: ScanIntensity) -> List[FuzzStrategy]:
        """Get fuzzing strategies based on intensity"""
        strategy_map = {
            ScanIntensity.CONSERVATIVE: [FuzzStrategy.BOUNDARY_VALUE],
            ScanIntensity.MODERATE: [FuzzStrategy.SMART_MUTATION, FuzzStrategy.BOUNDARY_VALUE],
            ScanIntensity.AGGRESSIVE: [FuzzStrategy.SMART_MUTATION, FuzzStrategy.TIMING_BASED, FuzzStrategy.PROTOCOL_AWARE],
            ScanIntensity.EXTREME: [FuzzStrategy.SMART_MUTATION, FuzzStrategy.TIMING_BASED, 
                                  FuzzStrategy.PRECISION_TIMING, FuzzStrategy.PROTOCOL_AWARE]
        }
        return strategy_map.get(intensity, [FuzzStrategy.SMART_MUTATION])
    
    def _classify_crash_vulnerability(self, crash_result: FuzzResult) -> VulnerabilityType:
        """Classify crash into vulnerability type"""
        payload_hex = crash_result.case.payload.hex().lower()
        
        for pattern, vuln_type in self.crash_patterns.items():
            if pattern in payload_hex:
                return vuln_type
        
        if crash_result.case.strategy == FuzzStrategy.TIMING_BASED:
            return VulnerabilityType.RACE_CONDITION
        elif crash_result.case.strategy == FuzzStrategy.PROTOCOL_AWARE:
            return VulnerabilityType.PROTOCOL_VIOLATION
        else:
            return VulnerabilityType.BUFFER_OVERFLOW
    
    def _assess_crash_severity(self, crash_result: FuzzResult) -> SeverityLevel:
        """Assess severity of a crash"""
        if crash_result.case.timing_sensitive:
            return SeverityLevel.CRITICAL
        
        if crash_result.case.strategy == FuzzStrategy.PROTOCOL_AWARE:
            return SeverityLevel.HIGH
        
        payload_size = len(crash_result.case.payload)
        if payload_size > 100:
            return SeverityLevel.HIGH
        elif payload_size > 20:
            return SeverityLevel.MEDIUM
        else:
            return SeverityLevel.LOW
    
    def _calculate_cvss_score(self, severity: SeverityLevel) -> float:
        """Calculate CVSS score based on severity"""
        severity_scores = {
            SeverityLevel.CRITICAL: 9.5,
            SeverityLevel.HIGH: 7.5,
            SeverityLevel.MEDIUM: 5.0,
            SeverityLevel.LOW: 2.5,
            SeverityLevel.INFO: 0.0
        }
        return severity_scores.get(severity, 5.0)
    
    async def _post_process_results(self, result: ScanResult):
        """Post-process scan results"""
        
        # Remove duplicate vulnerabilities
        unique_vulns = []
        seen_combinations = set()
        
        for vuln in result.vulnerabilities_found:
            combination = (vuln.vuln_type, vuln.affected_characteristic, vuln.title)
            if combination not in seen_combinations:
                unique_vulns.append(vuln)
                seen_combinations.add(combination)
            else:
                result.false_positives += 1
        
        result.vulnerabilities_found = unique_vulns
        
        # Generate recommendations
        if result.vulnerabilities_found:
            critical_count = sum(1 for v in result.vulnerabilities_found if v.severity == SeverityLevel.CRITICAL)
            high_count = sum(1 for v in result.vulnerabilities_found if v.severity == SeverityLevel.HIGH)
            
            if critical_count > 0:
                result.recommendations.append(f"URGENT: {critical_count} critical vulnerabilities require immediate patching")
            
            if high_count > 0:
                result.recommendations.append(f"High priority: {high_count} high-severity vulnerabilities need attention")
            
            # Specific recommendations
            vuln_types = [v.vuln_type for v in result.vulnerabilities_found]
            if VulnerabilityType.BUFFER_OVERFLOW in vuln_types:
                result.recommendations.append("Implement proper input validation and bounds checking")
            
            if VulnerabilityType.RACE_CONDITION in vuln_types:
                result.recommendations.append("Review timing-sensitive code and implement proper synchronization")
            
            if VulnerabilityType.PROTOCOL_VIOLATION in vuln_types:
                result.recommendations.append("Enhance protocol parsing with robust error handling")
        else:
            result.recommendations.append("No vulnerabilities detected at current scan intensity")
            result.recommendations.append("Consider running more intensive scans for comprehensive coverage")
    
    def generate_report(self, result: ScanResult) -> str:
        """Generate comprehensive vulnerability report"""
        
        critical_vulns = [v for v in result.vulnerabilities_found if v.severity == SeverityLevel.CRITICAL]
        high_vulns = [v for v in result.vulnerabilities_found if v.severity == SeverityLevel.HIGH]
        medium_vulns = [v for v in result.vulnerabilities_found if v.severity == SeverityLevel.MEDIUM]
        low_vulns = [v for v in result.vulnerabilities_found if v.severity == SeverityLevel.LOW]
        
        report = f"""
🛡️  VULNERABILITY SCAN REPORT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📱 Target Device: {result.target_device}
⏱️  Scan Duration: {result.scan_duration:.1f} seconds
🎯 Scan Intensity: {result.scan_intensity.value.upper()}
📊 Total Tests: {result.total_tests}
🕐 Scan Time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(result.scan_timestamp))}

📊 VULNERABILITY SUMMARY:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔴 Critical: {len(critical_vulns)}
🟠 High:     {len(high_vulns)}
🟡 Medium:   {len(medium_vulns)}
🔵 Low:      {len(low_vulns)}
🟢 Info:     {len([v for v in result.vulnerabilities_found if v.severity == SeverityLevel.INFO])}

Total Vulnerabilities: {len(result.vulnerabilities_found)}
False Positives Filtered: {result.false_positives}
"""
        
        # Critical vulnerabilities section
        if critical_vulns:
            report += f"""
🚨 CRITICAL VULNERABILITIES:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"""
            for i, vuln in enumerate(critical_vulns, 1):
                report += f"""
[{i}] {vuln.title}
    Type: {vuln.vuln_type.value.upper()}
    Characteristic: {vuln.affected_characteristic}
    Confidence: {vuln.confidence:.1%}
    CVSS Score: {vuln.cvss_score or 'N/A'}
    Description: {vuln.description}
    PoC Payload: {vuln.proof_of_concept[:16].hex()}{'...' if len(vuln.proof_of_concept) > 16 else ''}
    Remediation: {vuln.remediation or 'Contact security team for mitigation guidance'}
"""
        
        # High vulnerabilities section
        if high_vulns:
            report += f"""
⚠️  HIGH SEVERITY VULNERABILITIES:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"""
            for i, vuln in enumerate(high_vulns, 1):
                report += f"""
[{i}] {vuln.title}
    Type: {vuln.vuln_type.value.upper()}
    Characteristic: {vuln.affected_characteristic}
    Confidence: {vuln.confidence:.1%}
    Description: {vuln.description}
    PoC Payload: {vuln.proof_of_concept[:16].hex()}{'...' if len(vuln.proof_of_concept) > 16 else ''}
"""
        
        # Medium and Low vulnerabilities (summarized)
        if medium_vulns or low_vulns:
            report += f"""
📋 OTHER VULNERABILITIES:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"""
            
            if medium_vulns:
                report += f"\nMedium Severity ({len(medium_vulns)}):"
                for vuln in medium_vulns:
                    report += f"\n  • {vuln.title} ({vuln.vuln_type.value})"
            
            if low_vulns:
                report += f"\nLow Severity ({len(low_vulns)}):"
                for vuln in low_vulns:
                    report += f"\n  • {vuln.title} ({vuln.vuln_type.value})"
        
        # Coverage report
        report += f"""
📊 SCAN COVERAGE:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"""
        
        for phase, coverage in result.coverage_report.items():
            if isinstance(coverage, dict) and 'error' not in coverage:
                report += f"\n✅ {phase.replace('_', ' ').title()}: Completed"
                if phase == 'service_analysis' and 'writable_characteristics' in coverage:
                    report += f" ({coverage['writable_characteristics']} writable characteristics)"
                elif phase == 'known_vuln_testing' and 'tests_performed' in coverage:
                    report += f" ({coverage['tests_performed']} tests)"
                elif phase == 'fuzzing_discovery' and 'total_crashes' in coverage:
                    report += f" ({coverage['total_crashes']} crashes detected)"
            elif isinstance(coverage, dict) and 'error' in coverage:
                report += f"\n❌ {phase.replace('_', ' ').title()}: {coverage['error']}"
        
        # Recommendations
        if result.recommendations:
            report += f"""
💡 RECOMMENDATIONS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"""
            for i, rec in enumerate(result.recommendations, 1):
                report += f"\n{i}. {rec}"
        
        # Technical details for critical findings
        timing_vulns = [v for v in result.vulnerabilities_found if v.vuln_type == VulnerabilityType.RACE_CONDITION]
        if timing_vulns:
            report += f"""
⚡ TIMING VULNERABILITY DETAILS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"""
            for vuln in timing_vulns:
                if 'timing_config' in vuln.metadata:
                    config = vuln.metadata['timing_config']
                    report += f"""
Characteristic: {vuln.affected_characteristic}
Methodology: {config['iterations']} iterations @ {config['delay_ms']}ms
Payload: {vuln.proof_of_concept.hex()}
Anomaly Score: {vuln.metadata.get('anomaly_score', 'N/A')}
"""
        
        report += f"""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
End of Report - BlueForge Vulnerability Scanner v2.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
        
        return report

# Factory function for easy usage
def create_vulnerability_scanner(config: Optional[Dict[str, Any]] = None) -> VulnerabilityScanner:
    """Create and configure vulnerability scanner"""
    scanner = VulnerabilityScanner()
    
    if config:
        scanner.scan_config.update(config)
    
    return scanner