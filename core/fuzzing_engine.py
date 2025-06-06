# core/fuzzing_engine.py
import struct
import asyncio
import random
import time
from enum import Enum
from dataclasses import dataclass
from typing import List, Dict, Any, Optional, Callable
from utils.logging import get_logger
from config import config

logger = get_logger(__name__)

class FuzzTarget(Enum):
    """Types of BLE fuzzing targets"""
    GATT_CHARACTERISTICS = "gatt_char"
    ATT_PROTOCOL = "att_protocol" 
    L2CAP_PACKETS = "l2cap"
    HCI_COMMANDS = "hci"
    PAIRING_PROCESS = "pairing"
    ADVERTISING_DATA = "advertising"

class FuzzStrategy(Enum):
    """Fuzzing strategies"""
    RANDOM_MUTATION = "random"
    SMART_MUTATION = "smart"
    PROTOCOL_AWARE = "protocol_aware"
    STATE_MACHINE = "state_machine"
    TIMING_BASED = "timing"
    BOUNDARY_VALUE = "boundary"

@dataclass
class FuzzCase:
    """Individual fuzz test case"""
    payload: bytes
    strategy: FuzzStrategy
    target: FuzzTarget
    expected_crash: bool = False
    timing_sensitive: bool = False
    iterations: int = 1
    delay_ms: int = 0
    metadata: Dict[str, Any] = None

@dataclass
class FuzzResult:
    """Result of a fuzz test"""
    case: FuzzCase
    success: bool
    crashed: bool
    response_time: float
    error_message: Optional[str] = None
    raw_response: Optional[bytes] = None
    anomaly_detected: bool = False

class PayloadGenerator:
    """Advanced payload generation for BLE fuzzing"""
    
    def __init__(self):
        self.logger = get_logger(f"{__name__}.PayloadGenerator")
    
    def random_bytes(self, min_size: int = 1, max_size: int = 512) -> bytes:
        """Generate random byte sequences"""
        size = random.randint(min_size, max_size)
        return bytes([random.randint(0, 255) for _ in range(size)])
    
    def integer_overflows(self, bit_width: int = 32) -> List[bytes]:
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
            # Default to 32-bit if unsupported width
            values = [0x7FFFFFFF, 0x80000000, 0xFFFFFFFF, 0x100000000]
            format_char = 'I'
        
        for value in values:
            # Clamp value to valid range for the bit width
            max_value = (1 << bit_width) - 1
            clamped_value = value & max_value
            
            # Little endian
            try:
                payloads.append(struct.pack(f'<{format_char}', clamped_value))
            except struct.error:
                # If value is too large, skip it
                pass
            
            # Big endian
            try:
                payloads.append(struct.pack(f'>{format_char}', clamped_value))
            except struct.error:
                # If value is too large, skip it
                pass
        
        return payloads
    
    def hex_patterns(self) -> List[bytes]:
        """Generate common hex attack patterns"""
        patterns = [
            # Your original proven patterns
            b'\xDE\xAD\xBE\xEF\xCA\xFE\xBA\xBE',  # Generic value
            b'\x41\x41\x41\x41\x41\x41\x41\x41',  # Buffer overflow classic
            b'\x00\x00\x00\x00\x00\x00\x00\x00',  # Null bytes
            b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF',  # Max values
            
            # Function pointer targets (inspired by your research)
            b'\x00\x80\x04\x40\x00\x00\x00\x00',  # IRAM base (little endian)
            b'\x00\x00\x04\x40\x00\x00\x00\x00',  # ROM base
            b'\x00\x00\x0D\x40\x00\x00\x00\x00',  # Flash base
            
            # Format string attacks
            b'%x%x%x%x%x%x%x%x',
            b'%n%n%n%n%n%n%n%n',
            
            # SQL injection (for devices with embedded SQL)
            b"'; DROP TABLE--",
            b"' OR 1=1--",
            
            # Command injection
            b';cat /etc/passwd',
            b'|id',
            b'`id`',
        ]
        return patterns
    
    def protocol_aware_gatt(self, characteristic_uuid: str) -> List[bytes]:
        """Generate GATT protocol-aware payloads"""
        payloads = []
        
        # ATT protocol violations (based on research)
        payloads.extend([
            # Invalid ATT opcodes
            b'\xFF' + b'\x00' * 7,
            # Malformed Prepare Write (inspired by your timing discovery)
            b'\x16\x00\x00\x00\x00' + b'\x41' * 100,
            # Invalid handle ranges
            b'\x08\x00\x00\xFF\xFF\x00\x00',
        ])
        
        return payloads
    
    def timing_attack_payloads(self) -> List[FuzzCase]:
        """Generate timing-based attack cases (inspired by your 14ms/24 iteration discovery)"""
        cases = []
        
        # Your proven timing parameters
        base_payload = b'\xDE\xAD\xBE\xEF\xCA\xFE\xBA\xBE'
        
        # Test various timing combinations
        for iterations in [1, 5, 10, 24, 50, 100]:  # 24 was your magic number
            for delay in [1, 5, 10, 14, 20, 50]:     # 14ms was your discovery
                cases.append(FuzzCase(
                    payload=base_payload,
                    strategy=FuzzStrategy.TIMING_BASED,
                    target=FuzzTarget.GATT_CHARACTERISTICS,
                    timing_sensitive=True,
                    iterations=iterations,
                    delay_ms=delay,
                    metadata={"timing_test": True}
                ))
        
        return cases
    
    def state_machine_payloads(self) -> List[bytes]:
        """Generate state machine confusion payloads"""
        # Based on recent research into BLE state machine vulnerabilities
        return [
            # Connection state violations
            b'\x02\x00\x00\x00',  # Disconnect while connecting
            b'\x03\x00\x00\x00',  # Data while disconnected
            
            # Pairing state violations  
            b'\x01\x04\x00\x00',  # Security req during pairing
            b'\x01\x05\x00\x00',  # Pairing req while paired
        ]

class AdvancedFuzzingEngine:
    """Next-generation BLE fuzzing engine"""
    
    def __init__(self):
        self.logger = get_logger(f"{__name__}.AdvancedFuzzingEngine")
        self.payload_generator = PayloadGenerator()
        self.fuzz_results: List[FuzzResult] = []
        self.crash_patterns: Dict[str, int] = {}
        
        # Fuzzing strategies
        self.strategies = {
            FuzzStrategy.RANDOM_MUTATION: self._random_fuzz,
            FuzzStrategy.SMART_MUTATION: self._smart_fuzz,
            FuzzStrategy.PROTOCOL_AWARE: self._protocol_aware_fuzz,
            FuzzStrategy.STATE_MACHINE: self._state_machine_fuzz,
            FuzzStrategy.TIMING_BASED: self._timing_fuzz,
            FuzzStrategy.BOUNDARY_VALUE: self._boundary_fuzz
        }
    
    async def fuzz_target(self, client, target_char: str, 
                         strategy: FuzzStrategy = FuzzStrategy.SMART_MUTATION,
                         max_cases: int = 100) -> List[FuzzResult]:
        """Main fuzzing interface"""
        
        self.logger.info(f"Starting {strategy.value} fuzzing on {target_char}")
        
        # Generate fuzz cases based on strategy
        fuzz_cases = await self._generate_fuzz_cases(strategy, target_char, max_cases)
        
        results = []
        for i, case in enumerate(fuzz_cases):
            self.logger.info(f"Executing fuzz case {i+1}/{len(fuzz_cases)}")
            
            try:
                result = await self._execute_fuzz_case(client, target_char, case)
                results.append(result)
                
                # Analysis and learning
                await self._analyze_result(result)
                
                # Adaptive delay based on previous results
                if result.crashed:
                    await asyncio.sleep(config.device_recovery_delay)
                else:
                    await asyncio.sleep(0.1)
                    
            except Exception as e:
                self.logger.error(f"Fuzz case {i+1} failed: {e}")
                
        self.fuzz_results.extend(results)
        return results
    
    
    async def _generate_fuzz_cases(self, strategy: FuzzStrategy, 
                                target_char: str, max_cases: int) -> List[FuzzCase]:
        """Generate fuzz cases based on strategy"""
        
        cases = []
        
        if strategy == FuzzStrategy.RANDOM_MUTATION:
            for _ in range(max_cases):
                cases.append(FuzzCase(
                    payload=self.payload_generator.random_bytes(),
                    strategy=strategy,
                    target=FuzzTarget.GATT_CHARACTERISTICS
                ))
        
        elif strategy == FuzzStrategy.SMART_MUTATION:
            # Combine multiple payload types intelligently
            hex_payloads = self.payload_generator.hex_patterns()
            overflow_payloads = self.payload_generator.integer_overflows(32)  # Fixed: use 32-bit
            protocol_payloads = self.payload_generator.protocol_aware_gatt(target_char)
            
            all_payloads = hex_payloads + overflow_payloads + protocol_payloads
            
            for payload in all_payloads[:max_cases]:
                cases.append(FuzzCase(
                    payload=payload,
                    strategy=strategy,
                    target=FuzzTarget.GATT_CHARACTERISTICS
                ))
        
        elif strategy == FuzzStrategy.TIMING_BASED:
            cases = self.payload_generator.timing_attack_payloads()[:max_cases]
        
        elif strategy == FuzzStrategy.PROTOCOL_AWARE:
            payloads = self.payload_generator.protocol_aware_gatt(target_char)
            for payload in payloads[:max_cases]:
                cases.append(FuzzCase(
                    payload=payload,
                    strategy=strategy,
                    target=FuzzTarget.GATT_CHARACTERISTICS
                ))
        
        elif strategy == FuzzStrategy.BOUNDARY_VALUE:
            # Generate boundary cases inline
            boundary_sizes = [0, 1, 2, 4, 8, 16, 20, 32, 64, 128, 255, 256, 512]
            for size in boundary_sizes[:max_cases]:
                if size == 0:
                    payload = b''
                else:
                    payload = b'A' * size
                
                cases.append(FuzzCase(
                    payload=payload,
                    strategy=strategy,
                    target=FuzzTarget.GATT_CHARACTERISTICS
                ))
        
        return cases

    async def _execute_fuzz_case(self, client, target_char: str, case: FuzzCase) -> FuzzResult:
        """Execute a single fuzz case"""
        start_time = time.time()
        
        try:
            # Handle timing-sensitive cases
            if case.timing_sensitive:
                for i in range(case.iterations):
                    try:
                        await client.write_gatt_char(target_char, case.payload, response=False)
                    except Exception:
                        try:
                            await client.write_gatt_char(target_char, case.payload, response=True)
                        except Exception:
                            await self._force_write_readonly(client, target_char, case.payload)
                    
                    if case.delay_ms > 0:
                        await asyncio.sleep(case.delay_ms / 1000)
            else:
                try:
                    await client.write_gatt_char(target_char, case.payload)
                except Exception:
                    await self._force_write_readonly(client, target_char, case.payload)
            
            # Monitor for crashes
            crashed = await self._monitor_for_crash(client, target_char)
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

    async def _force_write_readonly(self, client, char_uuid: str, payload: bytes):
        """Force write to read-only characteristics"""
        try:
            await client.write_gatt_char(char_uuid, payload, response=False)
        except Exception:
            try:
                # Low-level approach - find characteristic by UUID
                for svc in client.services:
                    for char in svc.characteristics:
                        if char.uuid == char_uuid:
                            # Try direct handle write
                            if hasattr(client, '_backend'):
                                await client._backend.write_gatt_char(char.handle, payload, False)
                            break
            except Exception as e:
                self.logger.debug(f"Force write failed (expected): {e}")
    
    async def _monitor_for_crash(self, client, target_char: str, timeout: int = 10) -> bool:
        """Monitor for device crashes"""
        for i in range(timeout):
            try:
                await client.read_gatt_char(target_char)
                await asyncio.sleep(1)
            except:
                self.logger.info(f"Device crash detected after {i+1} seconds")
                return True
        
        return False
    
    async def _analyze_result(self, result: FuzzResult):
        """Analyze results and learn patterns"""
        if result.crashed:
            payload_pattern = result.case.payload[:8].hex()
            self.crash_patterns[payload_pattern] = self.crash_patterns.get(payload_pattern, 0) + 1
            
            self.logger.warning(f"CRASH DETECTED: Payload {payload_pattern} "
                              f"(strategy: {result.case.strategy.value})")

    # Strategy implementations
    async def _random_fuzz(self, client, target_char: str, max_cases: int) -> List[FuzzResult]:
        """Random mutation fuzzing"""
        results = []
        for i in range(max_cases):
            payload = self.payload_generator.random_bytes(1, 512)
            case = FuzzCase(
                payload=payload,
                strategy=FuzzStrategy.RANDOM_MUTATION,
                target=FuzzTarget.GATT_CHARACTERISTICS
            )
            result = await self._execute_fuzz_case(client, target_char, case)
            results.append(result)
            await asyncio.sleep(0.1)
        return results

    async def _smart_fuzz(self, client, target_char: str, max_cases: int) -> List[FuzzResult]:
        """Smart mutation combining multiple techniques"""
        results = []
        
        hex_payloads = self.payload_generator.hex_patterns()
        overflow_payloads = self.payload_generator.integer_overflows(32)
        protocol_payloads = self.payload_generator.protocol_aware_gatt(target_char)
        
        all_payloads = (hex_payloads + overflow_payloads + protocol_payloads)[:max_cases]
        
        for payload in all_payloads:
            case = FuzzCase(
                payload=payload,
                strategy=FuzzStrategy.SMART_MUTATION,
                target=FuzzTarget.GATT_CHARACTERISTICS
            )
            result = await self._execute_fuzz_case(client, target_char, case)
            results.append(result)
            await asyncio.sleep(0.1)
        
        return results

    async def _protocol_aware_fuzz(self, client, target_char: str, max_cases: int) -> List[FuzzResult]:
        """Protocol-aware fuzzing"""
        results = []
        payloads = self.payload_generator.protocol_aware_gatt(target_char)
        
        for payload in payloads[:max_cases]:
            case = FuzzCase(
                payload=payload,
                strategy=FuzzStrategy.PROTOCOL_AWARE,
                target=FuzzTarget.GATT_CHARACTERISTICS
            )
            result = await self._execute_fuzz_case(client, target_char, case)
            results.append(result)
            await asyncio.sleep(0.1)
        
        return results

    async def _state_machine_fuzz(self, client, target_char: str, max_cases: int) -> List[FuzzResult]:
        """State machine confusion fuzzing"""
        results = []
        payloads = self.payload_generator.state_machine_payloads()
        
        for payload in payloads[:max_cases]:
            case = FuzzCase(
                payload=payload,
                strategy=FuzzStrategy.STATE_MACHINE,
                target=FuzzTarget.GATT_CHARACTERISTICS
            )
            result = await self._execute_fuzz_case(client, target_char, case)
            results.append(result)
            await asyncio.sleep(0.1)
        
        return results

    async def _timing_fuzz(self, client, target_char: str, max_cases: int) -> List[FuzzResult]:
        """Timing-based fuzzing with race condition detection"""
        results = []
        
        race_detected = await self._detect_race_conditions(client, target_char)
        
        if race_detected:
            self.logger.info("Race condition detected - using aggressive timing")
            timing_cases = self.payload_generator.timing_attack_payloads()[:max_cases]
            for case in timing_cases:
                result = await self._execute_fuzz_case(client, target_char, case)
                results.append(result)
        else:
            self.logger.info("No race conditions detected - using standard timing")
            for i in range(min(max_cases, 10)):
                payload = self.payload_generator.random_bytes(8, 16)
                case = FuzzCase(
                    payload=payload,
                    strategy=FuzzStrategy.TIMING_BASED,
                    target=FuzzTarget.GATT_CHARACTERISTICS,
                    timing_sensitive=False,
                    iterations=1,
                    delay_ms=5
                )
                result = await self._execute_fuzz_case(client, target_char, case)
                results.append(result)
        
        return results

    async def _boundary_fuzz(self, client, target_char: str, max_cases: int) -> List[FuzzResult]:
        """Boundary value analysis fuzzing"""
        results = []
        
        boundary_sizes = [0, 1, 2, 4, 8, 16, 20, 32, 64, 128, 255, 256, 512, 1024]
        
        for size in boundary_sizes[:max_cases]:
            if size == 0:
                payload = b''
            else:
                payload = b'A' * size
            
            case = FuzzCase(
                payload=payload,
                strategy=FuzzStrategy.BOUNDARY_VALUE,
                target=FuzzTarget.GATT_CHARACTERISTICS
            )
            result = await self._execute_fuzz_case(client, target_char, case)
            results.append(result)
            await asyncio.sleep(0.1)
        
        return results

    async def _detect_race_conditions(self, client, target_char: str) -> bool:
        """Detect if target is susceptible to race conditions"""
        try:
            test_payload = b'\x42' * 8
            
            for i in range(5):
                try:
                    await client.write_gatt_char(target_char, test_payload, response=False)
                except:
                    pass
                await asyncio.sleep(0.001)
            
            try:
                await client.read_gatt_char(target_char)
                return False
            except:
                return True
                
        except Exception:
            return False
    
    def generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive fuzzing report"""
        total_cases = len(self.fuzz_results)
        crashes = len([r for r in self.fuzz_results if r.crashed])
        
        return {
            "total_cases": total_cases,
            "crashes_found": crashes,
            "crash_rate": crashes / total_cases if total_cases > 0 else 0,
            "crash_patterns": self.crash_patterns,
            "most_effective_strategy": self._find_most_effective_strategy(),
            "average_response_time": sum(r.response_time for r in self.fuzz_results) / total_cases if total_cases > 0 else 0
        }
    
    def _find_most_effective_strategy(self) -> str:
        """Find which strategy found the most crashes"""
        strategy_crashes = {}
        for result in self.fuzz_results:
            if result.crashed:
                strategy = result.case.strategy.value
                strategy_crashes[strategy] = strategy_crashes.get(strategy, 0) + 1
        
        if strategy_crashes:
            return max(strategy_crashes, key=strategy_crashes.get)
        return "none"