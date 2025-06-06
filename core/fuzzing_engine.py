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
        elif bit_width == 16:
            values = [0x7FFF, 0x8000, 0xFFFF, 0x10000]
        elif bit_width == 32:
            values = [0x7FFFFFFF, 0x80000000, 0xFFFFFFFF, 0x100000000]
        elif bit_width == 64:
            values = [0x7FFFFFFFFFFFFFFF, 0x8000000000000000, 
                     0xFFFFFFFFFFFFFFFF, 0x10000000000000000]
        
        for value in values:
            # Little endian
            try:
                payloads.append(struct.pack(f'<{"BHIQ"[bit_width//16]}', value & ((1 << bit_width) - 1)))
            except struct.error:
                pass
            # Big endian
            try:
                payloads.append(struct.pack(f'>{"BHIQ"[bit_width//16]}', value & ((1 << bit_width) - 1)))
            except struct.error:
                pass
        
        return payloads
    
    def hex_patterns(self) -> List[bytes]:
        """Generate common hex attack patterns"""
        patterns = [
            # Your original proven patterns
            b'\xDE\xAD\xBE\xEF\xCA\xFE\xBA\xBE',  # Your ESP32 discovery!
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
            overflow_payloads = self.payload_generator.integer_overflows(64)  # Your 8-byte discovery
            protocol_payloads = self.payload_generator.protocol_aware_gatt(target_char)
            
            all_payloads = hex_payloads + overflow_payloads + protocol_payloads
            
            for payload in all_payloads[:max_cases]:
                cases.append(FuzzCase(
                    payload=payload,
                    strategy=strategy,
                    target=FuzzTarget.GATT_CHARACTERISTICS
                ))
        
        elif strategy == FuzzStrategy.TIMING_BASED:
            # Your proven timing-based approach
            cases = self.payload_generator.timing_attack_payloads()[:max_cases]
        
        elif strategy == FuzzStrategy.PROTOCOL_AWARE:
            payloads = self.payload_generator.protocol_aware_gatt(target_char)
            for payload in payloads[:max_cases]:
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
            # Handle timing-sensitive cases (your ESP32 methodology)
            if case.timing_sensitive:
                for i in range(case.iterations):
                    await client.write_gatt_char(target_char, case.payload)
                    if case.delay_ms > 0:
                        await asyncio.sleep(case.delay_ms / 1000)
            else:
                await client.write_gatt_char(target_char, case.payload)
            
            # Monitor for crashes (your proven technique)
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
                crashed=True,  # Exception likely means crash
                response_time=response_time,
                error_message=str(e),
                anomaly_detected=True
            )
    
    async def _monitor_for_crash(self, client, target_char: str, timeout: int = 10) -> bool:
        """Monitor for device crashes (your proven method)"""
        for i in range(timeout):
            try:
                # Try to read the characteristic to test responsiveness
                await client.read_gatt_char(target_char)
                await asyncio.sleep(1)
            except:
                self.logger.info(f"Device crash detected after {i+1} seconds")
                return True
        
        return False
    
    async def _analyze_result(self, result: FuzzResult):
        """Analyze results and learn patterns"""
        if result.crashed:
            # Track crash patterns
            payload_pattern = result.case.payload[:8].hex()  # First 8 bytes
            self.crash_patterns[payload_pattern] = self.crash_patterns.get(payload_pattern, 0) + 1
            
            self.logger.warning(f"CRASH DETECTED: Payload {payload_pattern} "
                              f"(strategy: {result.case.strategy.value})")
    
    # Strategy implementations
    async def _random_fuzz(self, client, target_char: str, max_cases: int) -> List[FuzzResult]:
        """Random mutation fuzzing"""
        # Implementation here
        pass
    
    async def _smart_fuzz(self, client, target_char: str, max_cases: int) -> List[FuzzResult]:
        """Smart mutation combining multiple techniques"""
        # Implementation here  
        pass
    
    async def _protocol_aware_fuzz(self, client, target_char: str, max_cases: int) -> List[FuzzResult]:
        """Protocol-aware fuzzing for GATT/ATT violations"""
        # Implementation here
        pass
    
    async def _state_machine_fuzz(self, client, target_char: str, max_cases: int) -> List[FuzzResult]:
        """State machine confusion fuzzing"""
        # Implementation here
        pass
    
    async def _timing_fuzz(self, client, target_char: str, max_cases: int) -> List[FuzzResult]:
        """Timing-based fuzzing (your ESP32 methodology)"""
        # Implementation here
        pass
    
    async def _boundary_fuzz(self, client, target_char: str, max_cases: int) -> List[FuzzResult]:
        """Boundary value analysis fuzzing"""
        # Implementation here
        pass
    
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

# Usage example for your memory research module
class BlueForgeAdvancedFuzzer:
    """High-level interface for BlueForge fuzzing"""
    
    def __init__(self):
        self.engine = AdvancedFuzzingEngine()
        self.logger = get_logger(f"{__name__}.BlueForgeAdvancedFuzzer")
    
    async def comprehensive_fuzz(self, client, target_char: str) -> Dict[str, Any]:
        """Run comprehensive fuzzing campaign"""
        
        all_results = []
        
        # Run multiple strategies
        strategies = [
            FuzzStrategy.SMART_MUTATION,
            FuzzStrategy.TIMING_BASED,    # Your ESP32 methodology
            FuzzStrategy.PROTOCOL_AWARE,
            FuzzStrategy.BOUNDARY_VALUE
        ]
        
        for strategy in strategies:
            self.logger.info(f"Running {strategy.value} fuzzing...")
            results = await self.engine.fuzz_target(client, target_char, strategy, max_cases=25)
            all_results.extend(results)
        
        # Generate comprehensive report
        report = self.engine.generate_report()
        report["detailed_results"] = all_results
        
        return report