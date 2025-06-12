
# security/fuzzing_engine.py - Comprehensive BLE Fuzzing Engine
import asyncio
import time
import struct
import random
import statistics
from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Callable
from bleak import BleakClient
from utils.logging import get_logger

logger = get_logger(__name__)

class FuzzStrategy(Enum):
    """Fuzzing strategies"""
    RANDOM_MUTATION = "random"
    SMART_MUTATION = "smart"
    PROTOCOL_AWARE = "protocol_aware"
    TIMING_BASED = "timing"
    PRECISION_TIMING = "precision_timing"
    BOUNDARY_VALUE = "boundary"
    STATE_MACHINE = "state_machine"

class VulnerabilityClass(Enum):
    """Classification of discovered vulnerabilities"""
    BUFFER_OVERFLOW = "buffer_overflow"
    RACE_CONDITION = "race_condition"
    USE_AFTER_FREE = "use_after_free"
    TIMING_SIDE_CHANNEL = "timing_side_channel"
    RESOURCE_EXHAUSTION = "resource_exhaustion"
    PROTOCOL_VIOLATION = "protocol_violation"

@dataclass
class FuzzCase:
    """Individual fuzz test case"""
    payload: bytes
    strategy: FuzzStrategy
    iterations: int = 1
    delay_ms: float = 0
    expected_crash: bool = False
    timing_sensitive: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class FuzzResult:
    """Result of a fuzz test case"""
    case: FuzzCase
    success: bool
    crashed: bool
    response_time: float
    anomaly_detected: bool = False
    error_message: Optional[str] = None
    timing_signature: Optional[str] = None

@dataclass
class TimingResult:
    """Enhanced timing analysis result"""
    fuzz_result: FuzzResult
    timing_sensitive: bool
    anomaly_score: float
    response_times: List[float] = field(default_factory=list)
    delay_sequence: List[float] = field(default_factory=list)

@dataclass
class FuzzingSession:
    """Complete fuzzing session results"""
    target_address: str
    target_characteristic: str
    strategy_used: FuzzStrategy
    total_cases: int
    crashes_found: int
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    timing_signatures: List[str] = field(default_factory=list)
    session_duration: float = 0.0
    configuration: Dict[str, Any] = field(default_factory=dict)

class PayloadGenerator:
    """Advanced payload generation for BLE fuzzing"""
    
    def __init__(self):
        self.logger = get_logger(f"{__name__}.PayloadGenerator")
    
    def generate_random_payloads(self, count: int, min_size: int = 1, max_size: int = 512) -> List[bytes]:
        """Generate random byte sequences"""
        payloads = []
        for _ in range(count):
            size = random.randint(min_size, max_size)
            payload = bytes([random.randint(0, 255) for _ in range(size)])
            payloads.append(payload)
        return payloads
    
    def generate_proven_patterns(self) -> List[bytes]:
        """Generate proven vulnerability patterns"""
        return [
            # Proven research patterns
            b'\xDE\xAD\xBE\xEF\xCA\xFE\xBA\xBE',  # Proven pattern
            b'\x41\x41\x41\x41\x41\x41\x41\x41',  # Buffer overflow classic
            b'\x00\x80\x04\x40\x00\x00\x00\x00',  # IRAM base (little endian)
            b'\x00\x00\x04\x40\x00\x00\x00\x00',  # ROM base
            b'\x00\x00\x0D\x40\x00\x00\x00\x00',  # Flash base
            
            # Memory corruption patterns
            b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF',  # Max values
            b'\x00\x00\x00\x00\x00\x00\x00\x00',  # Null bytes
            b'\x90\x90\x90\x90\x90\x90\x90\x90',  # NOP sled
            
            # Format string attacks
            b'%x%x%x%x%x%x%x%x',
            b'%n%n%n%n%n%n%n%n',
            b'%s%s%s%s%s%s%s%s',
            
            # Command injection patterns
            b';cat /etc/passwd',
            b'|id',
            b'`id`',
            b'$(whoami)',
            
            # SQL injection
            b"'; DROP TABLE--",
            b"' OR 1=1--",
            b'" OR 1=1--',
        ]
    
    def generate_integer_overflows(self, bit_width: int = 32) -> List[bytes]:
        """Generate integer overflow payloads"""
        payloads = []
        
        if bit_width == 8:
            values = [0x7F, 0x80, 0xFF, 0x100]
            format_char = 'B'
        elif bit_width == 16:
            values = [0x7FFF, 0x8000, 0xFFFF, 0x10000]
            format_char = 'H'
        elif bit_width == 32:
            values = [0x7FFFFFFF, 0x80000000, 0xFFFFFFFF, 0x100000000]
            format_char = 'I'
        elif bit_width == 64:
            values = [0x7FFFFFFFFFFFFFFF, 0x8000000000000000, 
                    0xFFFFFFFFFFFFFFFF, 0x10000000000000000]
            format_char = 'Q'
        else:
            values = [0x7FFFFFFF, 0x80000000, 0xFFFFFFFF, 0x100000000]
            format_char = 'I'
        
        for value in values:
            max_value = (1 << bit_width) - 1
            clamped_value = value & max_value
            
            try:
                # Little endian
                payloads.append(struct.pack(f'<{format_char}', clamped_value))
                # Big endian
                payloads.append(struct.pack(f'>{format_char}', clamped_value))
            except struct.error:
                pass
        
        return payloads
    
    def generate_boundary_payloads(self) -> List[bytes]:
        """Generate boundary value analysis payloads"""
        boundary_sizes = [0, 1, 2, 4, 8, 16, 20, 32, 64, 128, 255, 256, 512, 1024]
        payloads = []
        
        for size in boundary_sizes:
            if size == 0:
                payloads.append(b'')
            else:
                # Different fill patterns
                payloads.append(b'A' * size)           # ASCII pattern
                payloads.append(b'\x00' * size)        # Null bytes
                payloads.append(b'\xFF' * size)        # Max bytes
                payloads.append(b'\x42' * size)        # Different pattern
        
        return payloads
    
    def generate_protocol_aware_payloads(self) -> List[bytes]:
        """Generate BLE protocol-aware payloads"""
        return [
            # ATT protocol violations
            b'\xFF' + b'\x00' * 7,                     # Invalid ATT opcode
            b'\x16\x00\x00\x00\x00' + b'\x41' * 100,  # Malformed Prepare Write
            b'\x08\x00\x00\xFF\xFF\x00\x00',          # Invalid handle ranges
            b'\x12\x00\x00\x00\x00\x00\x00',          # Execute Write Request
            
            # GATT violations
            b'\x02\x00\x00\x00',                       # Disconnect during operation
            b'\x03\x00\x00\x00',                       # Data while disconnected
            
            # L2CAP violations
            b'\x01\x04\x00\x00',                       # Security req during pairing
            b'\x01\x05\x00\x00',                       # Pairing req while paired
        ]
    
    def generate_timing_payloads(self) -> List[FuzzCase]:
        """Generate timing-based attack cases"""
        cases = []
        base_payload = b'\xDE\xAD\xBE\xEF\xCA\xFE\xBA\xBE'
        
        # Test various timing combinations
        timing_configs = [
            (1, 1),     # 1 iteration, 1ms delay
            (5, 5),     # 5 iterations, 5ms delay
            (10, 10),   # 10 iterations, 10ms delay
            (24, 14),   # Proven timing parameters
            (50, 20),   # Aggressive timing
            (100, 1),   # Many iterations, fast timing
        ]
        
        for iterations, delay_ms in timing_configs:
            cases.append(FuzzCase(
                payload=base_payload,
                strategy=FuzzStrategy.TIMING_BASED,
                iterations=iterations,
                delay_ms=delay_ms,
                timing_sensitive=True,
                metadata={"timing_config": f"{iterations}x{delay_ms}ms"}
            ))
        
        return cases

class TimingEngine:
    """Specialized timing vulnerability analysis engine"""
    
    def __init__(self):
        self.logger = get_logger(f"{__name__}.TimingEngine")
        self.timing_precision_threshold = 0.001  # 1ms precision
    
    async def analyze_timing_sensitivity(self, client: BleakClient, char_uuid: str, 
                                       payload: bytes, iterations: int = 10) -> TimingResult:
        """Analyze if a payload shows timing sensitivity"""
        
        # Baseline measurement
        baseline_times = []
        baseline_payload = b'\x00' * len(payload)
        
        for _ in range(5):
            start_time = time.time()
            try:
                await client.write_gatt_char(char_uuid, baseline_payload, response=False)
            except Exception:
                pass
            baseline_times.append(time.time() - start_time)
            await asyncio.sleep(0.01)
        
        # Test payload timing
        test_times = []
        crashed = False
        exception_occurred = False
        
        for i in range(iterations):
            start_time = time.time()
            try:
                await client.write_gatt_char(char_uuid, payload, response=False)
            except Exception as e:
                exception_occurred = True
                self.logger.debug(f"Exception during timing test {i+1}: {e}")
            
            test_time = time.time() - start_time
            test_times.append(test_time)
            
            # Check for crash
            if not client.is_connected:
                crashed = True
                break
            
            await asyncio.sleep(0.005)
        
        # Analyze timing variance
        timing_sensitive = self._detect_timing_anomaly(baseline_times, test_times)
        anomaly_score = self._calculate_anomaly_score(test_times)
        
        # Create base fuzz result
        fuzz_case = FuzzCase(
            payload=payload,
            strategy=FuzzStrategy.TIMING_BASED,
            timing_sensitive=True,
            iterations=iterations
        )
        
        fuzz_result = FuzzResult(
            case=fuzz_case,
            success=not exception_occurred,
            crashed=crashed or exception_occurred,
            response_time=sum(test_times) / len(test_times) if test_times else 0.0,
            anomaly_detected=timing_sensitive or crashed
        )
        
        return TimingResult(
            fuzz_result=fuzz_result,
            timing_sensitive=timing_sensitive,
            anomaly_score=anomaly_score,
            response_times=test_times
        )
    
    async def precision_timing_test(self, client: BleakClient, char_uuid: str, 
                                  payload: bytes, iterations: int = 24, 
                                  delay_ms: float = 14.0) -> TimingResult:
        """Execute precision timing test with proven methodology"""
        
        self.logger.info(f"Precision timing: {iterations} iterations @ {delay_ms}ms")
        
        success_count = 0
        response_times = []
        
        for i in range(iterations):
            start_time = time.time()
            try:
                await client.write_gatt_char(char_uuid, payload, response=False)
                success_count += 1
            except Exception as e:
                self.logger.debug(f"Precision timing iteration {i+1} failed: {e}")
            
            response_time = time.time() - start_time
            response_times.append(response_time)
            
            # CRITICAL: Precise timing
            await asyncio.sleep(delay_ms / 1000.0)
        
        # Extended monitoring for crashes
        await asyncio.sleep(0.5)
        crashed = await self._extended_crash_monitoring(client, char_uuid, timeout=15)
        
        # Create result
        fuzz_case = FuzzCase(
            payload=payload,
            strategy=FuzzStrategy.PRECISION_TIMING,
            timing_sensitive=True,
            iterations=iterations,
            delay_ms=delay_ms,
            metadata={"precision_timing": True, "methodology": "24x14ms"}
        )
        
        fuzz_result = FuzzResult(
            case=fuzz_case,
            success=success_count > (iterations * 0.7),
            crashed=crashed,
            response_time=sum(response_times) / len(response_times) if response_times else 0.0,
            anomaly_detected=crashed,
            timing_signature="precision_timing_vulnerability" if crashed else None
        )
        
        return TimingResult(
            fuzz_result=fuzz_result,
            timing_sensitive=True,
            anomaly_score=1.0 if crashed else 0.0,
            response_times=response_times
        )
    
    async def race_condition_test(self, client: BleakClient, char_uuid: str, 
                                payload: bytes, delay_ms: float = 1.0) -> TimingResult:
        """Test for race conditions with rapid writes"""
        
        self.logger.info(f"Testing race conditions with {delay_ms}ms delay")
        
        start_time = time.time()
        exception_count = 0
        
        # Rapid-fire writes
        for i in range(20):
            try:
                await client.write_gatt_char(char_uuid, payload, response=False)
            except Exception:
                exception_count += 1
            
            await asyncio.sleep(delay_ms / 1000.0)
        
        total_time = time.time() - start_time
        crashed = await self._check_race_condition_effects(client, char_uuid)
        
        fuzz_case = FuzzCase(
            payload=payload,
            strategy=FuzzStrategy.TIMING_BASED,
            timing_sensitive=True,
            iterations=20,
            delay_ms=delay_ms,
            metadata={"race_condition_test": True}
        )
        
        fuzz_result = FuzzResult(
            case=fuzz_case,
            success=exception_count < 10,
            crashed=crashed,
            response_time=total_time,
            anomaly_detected=crashed or exception_count > 5
        )
        
        return TimingResult(
            fuzz_result=fuzz_result,
            timing_sensitive=True,
            anomaly_score=exception_count / 20.0
        )
    
    def _detect_timing_anomaly(self, baseline_times: List[float], 
                             test_times: List[float]) -> bool:
        """Detect timing anomalies"""
        if len(baseline_times) < 2 or len(test_times) < 2:
            return False
        
        baseline_avg = statistics.mean(baseline_times)
        test_avg = statistics.mean(test_times)
        
        time_ratio = test_avg / baseline_avg if baseline_avg > 0 else 1.0
        test_variance = statistics.variance(test_times)
        
        return time_ratio > 2.0 or test_variance > 0.01
    
    def _calculate_anomaly_score(self, response_times: List[float]) -> float:
        """Calculate anomaly score for response timing"""
        if len(response_times) < 2:
            return 0.0
        
        variance = statistics.variance(response_times)
        mean_time = statistics.mean(response_times)
        
        return min(1.0, variance / (mean_time + 0.001))
    
    async def _extended_crash_monitoring(self, client: BleakClient, char_uuid: str, 
                                       timeout: int = 15) -> bool:
        """Extended monitoring for crashes after precision timing"""
        for i in range(timeout):
            try:
                if not client.is_connected:
                    self.logger.warning(f"Device disconnected after {i}s")
                    return True
                
                # Try to access services
                services = client.services
                if not services:
                    self.logger.warning(f"No services accessible after {i}s")
                    return True
                
                await asyncio.sleep(1)
                
            except Exception as e:
                self.logger.warning(f"Extended monitoring failed at {i}s: {e}")
                return True
        
        return False
    
    async def _check_race_condition_effects(self, client: BleakClient, char_uuid: str) -> bool:
        """Check if race condition had effects on device"""
        try:
            await asyncio.sleep(0.1)
            
            if not client.is_connected:
                return True
            
            # Try to read any characteristic
            services = client.services
            for service in services:
                for char in service.characteristics:
                    if "read" in char.properties:
                        try:
                            await asyncio.wait_for(
                                client.read_gatt_char(char.uuid), 
                                timeout=2.0
                            )
                            return False
                        except asyncio.TimeoutError:
                            return True
                        except Exception:
                            continue
            
            return False
            
        except Exception:
            return True

class AdvancedFuzzingEngine:
    """Main fuzzing engine with all strategies"""
    
    def __init__(self):
        self.logger = get_logger(f"{__name__}.AdvancedFuzzingEngine")
        self.payload_generator = PayloadGenerator()
        self.timing_engine = TimingEngine()
        self.crash_patterns: Dict[str, int] = {}
        
        # Fuzzing configuration
        self.config = {
            'default_strategy': 'smart',
            'max_cases_per_strategy': 50,
            'delay_between_tests': 0.1,
            'crash_detection_timeout': 10,
            'enable_audio_protection': True,
            'recovery_delay_after_crash': 3.0,
            'adaptive_timing': True,
            'verbose_output': False
        }
    
    def update_config(self, **kwargs):
        """Update fuzzing configuration"""
        for key, value in kwargs.items():
            if key in self.config:
                self.config[key] = value
                self.logger.info(f"Updated config: {key} = {value}")
    
    def get_current_config(self) -> Dict[str, Any]:
        """Get current configuration"""
        return self.config.copy()
    
    async def fuzz_target(self, client: BleakClient, char_uuid: str,
                         strategy: FuzzStrategy = FuzzStrategy.SMART_MUTATION,
                         max_cases: int = 100) -> List[FuzzResult]:
        """Main fuzzing interface"""
        
        self.logger.info(f"Starting {strategy.value} fuzzing on {char_uuid}")
        
        # Generate test cases based on strategy
        fuzz_cases = self._generate_fuzz_cases(strategy, max_cases)
        
        # Detect device type for appropriate fuzzing approach
        device_type = await self._detect_device_type(client)
        
        # Adjust approach based on device type
        if device_type == "audio_device":
            max_cases = min(max_cases, 20)
            self.logger.info("Audio device detected - using gentle approach")
        
        results = []
        for i, case in enumerate(fuzz_cases):
            self.logger.debug(f"Executing fuzz case {i+1}/{len(fuzz_cases)}")
            
            try:
                result = await self._execute_fuzz_case(client, char_uuid, case)
                results.append(result)
                
                # Analyze result and apply recovery if needed
                await self._analyze_result(result)
                
                if result.crashed:
                    await asyncio.sleep(self.config['recovery_delay_after_crash'])
                else:
                    await asyncio.sleep(self.config['delay_between_tests'])
                    
            except Exception as e:
                self.logger.error(f"Fuzz case {i+1} failed: {e}")
                error_result = FuzzResult(
                    case=case,
                    success=False,
                    crashed=False,
                    response_time=0.0,
                    error_message=str(e),
                    anomaly_detected=True
                )
                results.append(error_result)
        
        return results
    
    def _generate_fuzz_cases(self, strategy: FuzzStrategy, max_cases: int) -> List[FuzzCase]:
        """Generate fuzz cases based on strategy"""
        cases = []
        
        if strategy == FuzzStrategy.RANDOM_MUTATION:
            payloads = self.payload_generator.generate_random_payloads(max_cases)
            for payload in payloads:
                cases.append(FuzzCase(payload=payload, strategy=strategy))
        
        elif strategy == FuzzStrategy.SMART_MUTATION:
            # Combine multiple payload types
            proven = self.payload_generator.generate_proven_patterns()
            overflows = self.payload_generator.generate_integer_overflows(32)
            protocol = self.payload_generator.generate_protocol_aware_payloads()
            
            all_payloads = (proven + overflows + protocol)[:max_cases]
            for payload in all_payloads:
                cases.append(FuzzCase(payload=payload, strategy=strategy))
        
        elif strategy == FuzzStrategy.TIMING_BASED:
            cases = self.payload_generator.generate_timing_payloads()[:max_cases]
        
        elif strategy == FuzzStrategy.PRECISION_TIMING:
            # Proven timing patterns
            proven_patterns = [
                b'\xDE\xAD\xBE\xEF\xCA\xFE\xBA\xBE',
                b'\x41\x41\x41\x41\x41\x41\x41\x41',
                b'\x00\x80\x04\x40\x00\x00\x00\x00',
            ]
            
            for payload in proven_patterns:
                cases.append(FuzzCase(
                    payload=payload,
                    strategy=strategy,
                    timing_sensitive=True,
                    iterations=24,
                    delay_ms=14,
                    metadata={"precision_timing": True}
                ))
        
        elif strategy == FuzzStrategy.BOUNDARY_VALUE:
            payloads = self.payload_generator.generate_boundary_payloads()
            for payload in payloads[:max_cases]:
                cases.append(FuzzCase(payload=payload, strategy=strategy))
        
        elif strategy == FuzzStrategy.PROTOCOL_AWARE:
            payloads = self.payload_generator.generate_protocol_aware_payloads()
            for payload in payloads:
                cases.append(FuzzCase(payload=payload, strategy=strategy))
        
        return cases[:max_cases]
    
    async def _execute_fuzz_case(self, client: BleakClient, char_uuid: str, 
                               case: FuzzCase) -> FuzzResult:
        """Execute a single fuzz case"""
        start_time = time.time()
        
        if not client.is_connected:
            return FuzzResult(
                case=case,
                success=False,
                crashed=False,
                response_time=0.0,
                error_message="Device not connected",
                anomaly_detected=True
            )
        
        # Handle timing-sensitive cases
        if case.timing_sensitive and case.metadata.get("precision_timing"):
            return await self._execute_precision_timing_case(client, char_uuid, case)
        elif case.timing_sensitive:
            return await self._execute_timing_case(client, char_uuid, case)
        else:
            return await self._execute_standard_case(client, char_uuid, case)
    
    async def _execute_standard_case(self, client: BleakClient, char_uuid: str, 
                                   case: FuzzCase) -> FuzzResult:
        """Execute standard fuzz case"""
        start_time = time.time()
        
        try:
            await client.write_gatt_char(char_uuid, case.payload)
            await asyncio.sleep(0.1)
            
            crashed = await self._check_device_crashed(client)
            response_time = time.time() - start_time
            
            return FuzzResult(
                case=case,
                success=True,
                crashed=crashed,
                response_time=response_time,
                anomaly_detected=crashed
            )
            
        except Exception as e:
            response_time = time.time() - start_time
            return FuzzResult(
                case=case,
                success=False,
                crashed=True,
                response_time=response_time,
                error_message=str(e),
                anomaly_detected=True
            )
    
    async def _execute_timing_case(self, client: BleakClient, char_uuid: str, 
                                 case: FuzzCase) -> FuzzResult:
        """Execute timing-based fuzz case"""
        success_count = 0
        
        for i in range(case.iterations):
            try:
                await client.write_gatt_char(char_uuid, case.payload, response=False)
                success_count += 1
            except Exception:
                pass
            
            await asyncio.sleep(case.delay_ms / 1000.0)
        
        await asyncio.sleep(0.5)
        crashed = await self._check_device_crashed(client)
        
        return FuzzResult(
            case=case,
            success=success_count > (case.iterations * 0.7),
            crashed=crashed,
            response_time=case.delay_ms * case.iterations / 1000.0,
            anomaly_detected=crashed
        )
    
    async def _execute_precision_timing_case(self, client: BleakClient, char_uuid: str, 
                                           case: FuzzCase) -> FuzzResult:
        """Execute precision timing case using timing engine"""
        timing_result = await self.timing_engine.precision_timing_test(
            client, char_uuid, case.payload, case.iterations, case.delay_ms
        )
        
        return timing_result.fuzz_result
    
    async def _check_device_crashed(self, client: BleakClient) -> bool:
        """Check if device crashed with intelligent detection"""
        try:
            if not client.is_connected:
                return False  # Disconnection ≠ crash for consumer devices
            
            # Try to access services
            try:
                services = client.services
                if not services:
                    return True
            except Exception:
                return True
            
            # Try to read a standard characteristic
            try:
                await asyncio.wait_for(
                    client.read_gatt_char("00002a00-0000-1000-8000-00805f9b34fb"),
                    timeout=1.0
                )
                return False
            except asyncio.TimeoutError:
                return False
            except Exception:
                return False
            
        except Exception:
            return True
    
    async def _detect_device_type(self, client: BleakClient) -> str:
        """Detect device type for fuzzing strategy adjustment"""
        try:
            services = client.services
            service_uuids = [str(service.uuid) for service in services]
            
            # Audio device indicators
            audio_services = [
                "0000110b-0000-1000-8000-00805f9b34fb",
                "0000110a-0000-1000-8000-00805f9b34fb",
            ]
            
            if any(uuid in service_uuids for uuid in audio_services):
                return "audio_device"
            
            return "generic_device"
            
        except:
            return "unknown_device"
    
    async def _analyze_result(self, result: FuzzResult):
        """Analyze fuzz result and learn patterns"""
        if result.crashed:
            payload_pattern = result.case.payload[:8].hex()
            self.crash_patterns[payload_pattern] = self.crash_patterns.get(payload_pattern, 0) + 1
            
            self.logger.warning(f"CRASH DETECTED: Payload {payload_pattern} "
                              f"(strategy: {result.case.strategy.value})")
    
    async def execute_fuzzing_session(self, client: BleakClient, char_uuid: str,
                                    strategy: FuzzStrategy = FuzzStrategy.SMART_MUTATION,
                                    max_cases: int = 100) -> FuzzingSession:
        """Execute complete fuzzing session"""
        session_start = time.time()
        
        # Execute fuzzing
        results = await self.fuzz_target(client, char_uuid, strategy, max_cases)
        
        # Analyze results
        crashes = [r for r in results if r.crashed]
        vulnerabilities = self._identify_vulnerabilities(results)
        timing_signatures = [r.timing_signature for r in results if r.timing_signature]
        
        session_duration = time.time() - session_start
        
        return FuzzingSession(
            target_address=getattr(client, 'address', 'unknown'),
            target_characteristic=char_uuid,
            strategy_used=strategy,
            total_cases=len(results),
            crashes_found=len(crashes),
            vulnerabilities=vulnerabilities,
            timing_signatures=timing_signatures,
            session_duration=session_duration,
            configuration=self.config.copy()
        )
    
    def _identify_vulnerabilities(self, results: List[FuzzResult]) -> List[Dict[str, Any]]:
        """Identify potential vulnerabilities from fuzz results"""
        vulnerabilities = []
        
        # Group crashes by payload patterns
        crash_patterns = {}
        for result in results:
            if result.crashed:
                pattern = result.case.payload[:8].hex()
                if pattern not in crash_patterns:
                    crash_patterns[pattern] = []
                crash_patterns[pattern].append(result)
        
        # Analyze crash patterns for vulnerability classification
        for pattern, crash_results in crash_patterns.items():
            vuln_info = {
                'pattern': pattern,
                'crash_count': len(crash_results),
                'vulnerability_class': self._classify_vulnerability(crash_results),
                'confidence': self._calculate_confidence(crash_results),
                'affected_strategies': list(set(r.case.strategy.value for r in crash_results)),
                'sample_payload': crash_results[0].case.payload.hex(),
                'timing_sensitive': any(r.case.timing_sensitive for r in crash_results)
            }
            vulnerabilities.append(vuln_info)
        
        return vulnerabilities
    
    def _classify_vulnerability(self, crash_results: List[FuzzResult]) -> VulnerabilityClass:
        """Classify vulnerability based on crash patterns"""
        # Check for timing-based vulnerabilities
        if any(r.case.timing_sensitive for r in crash_results):
            if any(r.case.strategy == FuzzStrategy.PRECISION_TIMING for r in crash_results):
                return VulnerabilityClass.RACE_CONDITION
            else:
                return VulnerabilityClass.TIMING_SIDE_CHANNEL
        
        # Check for buffer overflow indicators
        buffer_indicators = [b'\x41\x41\x41\x41', b'\xFF\xFF\xFF\xFF']
        for result in crash_results:
            for indicator in buffer_indicators:
                if indicator in result.case.payload:
                    return VulnerabilityClass.BUFFER_OVERFLOW
        
        # Check for protocol violations
        protocol_indicators = [b'\xFF\x00', b'\x16\x00']
        for result in crash_results:
            for indicator in protocol_indicators:
                if result.case.payload.startswith(indicator):
                    return VulnerabilityClass.PROTOCOL_VIOLATION
        
        # Default classification
        return VulnerabilityClass.BUFFER_OVERFLOW
    
    def _calculate_confidence(self, crash_results: List[FuzzResult]) -> str:
        """Calculate confidence level for vulnerability"""
        crash_count = len(crash_results)
        
        if crash_count >= 5:
            return "HIGH"
        elif crash_count >= 2:
            return "MEDIUM"
        else:
            return "LOW"
    
    def get_recommended_strategy(self, device_type: str) -> FuzzStrategy:
        """Get recommended fuzzing strategy for device type"""
        strategy_map = {
            'audio_device': FuzzStrategy.BOUNDARY_VALUE,
            'development': FuzzStrategy.SMART_MUTATION,
            'security': FuzzStrategy.PROTOCOL_AWARE,
            'smartphone': FuzzStrategy.STEALTH,
            'unknown': FuzzStrategy.SMART_MUTATION
        }
        
        return strategy_map.get(device_type, FuzzStrategy.SMART_MUTATION)
    
    def generate_report(self, session: FuzzingSession) -> str:
        """Generate comprehensive fuzzing report"""
        report = f"""
🎯 FUZZING SESSION REPORT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📱 Target: {session.target_address}
🎯 Characteristic: {session.target_characteristic}
⚡ Strategy: {session.strategy_used.value.upper()}
⏱️  Duration: {session.session_duration:.1f}s

📊 RESULTS SUMMARY:
• Total test cases: {session.total_cases}
• Crashes found: {session.crashes_found}
• Vulnerabilities: {len(session.vulnerabilities)}
• Timing signatures: {len(session.timing_signatures)}

"""
        
        if session.vulnerabilities:
            report += "💥 VULNERABILITIES DISCOVERED:\n"
            for i, vuln in enumerate(session.vulnerabilities, 1):
                report += f"  [{i}] {vuln['vulnerability_class'].value.upper()}\n"
                report += f"      Pattern: {vuln['pattern']}\n"
                report += f"      Crashes: {vuln['crash_count']}\n"
                report += f"      Confidence: {vuln['confidence']}\n"
                report += f"      Timing-based: {'Yes' if vuln['timing_sensitive'] else 'No'}\n\n"
        
        if session.timing_signatures:
            report += "⚡ TIMING SIGNATURES:\n"
            for sig in session.timing_signatures:
                report += f"  • {sig}\n"
        
        # Crash patterns analysis
        if self.crash_patterns:
            report += "\n🔍 CRASH PATTERN ANALYSIS:\n"
            sorted_patterns = sorted(self.crash_patterns.items(), 
                                   key=lambda x: x[1], reverse=True)
            for pattern, count in sorted_patterns[:5]:
                report += f"  • {pattern}: {count} occurrences\n"
        
        return report
    
    def reset_session(self):
        """Reset fuzzing session data"""
        self.crash_patterns.clear()
        self.logger.info("Fuzzing session data reset")


# Factory function for easy usage
def create_fuzzing_engine(config: Optional[Dict[str, Any]] = None) -> AdvancedFuzzingEngine:
    """Create and configure fuzzing engine"""
    engine = AdvancedFuzzingEngine()
    
    if config:
        engine.update_config(**config)
    
    return engine