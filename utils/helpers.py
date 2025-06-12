
# utils/helpers.py - Utility Functions and Helpers
from utils.logging import get_logger
import re
import struct
import time
from typing import Union, Optional, List, Dict, Any, Tuple
from uuid import UUID

def format_mac_address(address: str, separator: str = ":") -> str:
    """Format MAC address with consistent separator"""
    if not address:
        return ""
    
    # Remove all separators and convert to uppercase
    clean_address = re.sub(r'[:-]', '', address.upper())
    
    # Validate length
    if len(clean_address) != 12:
        return address  # Return original if invalid
    
    # Insert separators every 2 characters
    formatted = separator.join(clean_address[i:i+2] for i in range(0, 12, 2))
    return formatted

def validate_mac_address(address: str) -> bool:
    """Validate MAC address format"""
    if not address:
        return False
    
    # Pattern for MAC address (with : or - separators)
    mac_pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
    return bool(re.match(mac_pattern, address))

def parse_service_uuid(uuid_str: str) -> Tuple[str, str]:
    """Parse service UUID and return UUID and human-readable name"""
    
    # Standard service UUIDs and their names
    standard_services = {
        "1800": "Generic Access",
        "1801": "Generic Attribute", 
        "180a": "Device Information",
        "180f": "Battery Service",
        "180d": "Heart Rate",
        "1812": "Human Interface Device",
        "110b": "Audio Sink",
        "110a": "Audio Source",
        "111e": "Handsfree",
        "1105": "OPP",
        "1106": "FTP",
        "1124": "HID",
        "112f": "Phonebook Access"
    }
    
    try:
        # Handle different UUID formats
        if len(uuid_str) == 4:
            # 16-bit UUID
            service_name = standard_services.get(uuid_str.lower(), "Unknown Service")
            full_uuid = f"0000{uuid_str.lower()}-0000-1000-8000-00805f9b34fb"
        elif len(uuid_str) == 8:
            # 32-bit UUID  
            service_name = "Custom Service"
            full_uuid = f"{uuid_str.lower()}-0000-1000-8000-00805f9b34fb"
        elif len(uuid_str) == 36:
            # Full 128-bit UUID
            full_uuid = uuid_str.lower()
            
            # Check if it's a standard service in 128-bit format
            if uuid_str.lower().startswith("0000") and uuid_str.lower().endswith("-0000-1000-8000-00805f9b34fb"):
                service_id = uuid_str[4:8].lower()
                service_name = standard_services.get(service_id, "Unknown Service")
            else:
                service_name = "Custom Service"
        else:
            # Invalid format
            return uuid_str, "Invalid UUID"
        
        # Validate UUID format
        UUID(full_uuid)
        return full_uuid, service_name
        
    except (ValueError, AttributeError):
        return uuid_str, "Invalid UUID"

def format_bytes_display(data: Union[bytes, bytearray], 
                        max_length: int = 16, 
                        show_ascii: bool = True) -> str:
    """Format bytes for human-readable display"""
    if not data:
        return ""
    
    # Limit data length
    display_data = data[:max_length]
    
    # Convert to hex string with spaces
    hex_str = ' '.join(f'{b:02X}' for b in display_data)
    
    # Add ellipsis if truncated
    if len(data) > max_length:
        hex_str += "..."
    
    if show_ascii:
        # Add ASCII representation
        ascii_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in display_data)
        if len(data) > max_length:
            ascii_str += "..."
        
        return f"{hex_str} | {ascii_str}"
    
    return hex_str

def calculate_signal_strength(rssi: Optional[int]) -> Tuple[str, str]:
    """Calculate signal strength description and quality"""
    if rssi is None:
        return "Unknown", "gray"
    
    if rssi >= -30:
        return "Excellent", "green"
    elif rssi >= -50:
        return "Good", "green"
    elif rssi >= -60:
        return "Fair", "yellow"
    elif rssi >= -70:
        return "Weak", "orange"
    else:
        return "Very Weak", "red"

def format_duration(seconds: float) -> str:
    """Format duration in human-readable format"""
    if seconds < 1:
        return f"{seconds*1000:.0f}ms"
    elif seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = int(seconds // 60)
        secs = seconds % 60
        return f"{minutes}m {secs:.1f}s"
    else:
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        return f"{hours}h {minutes}m"

def format_file_size(size_bytes: int) -> str:
    """Format file size in human-readable format"""
    if size_bytes == 0:
        return "0 B"
    
    units = ["B", "KB", "MB", "GB", "TB"]
    unit_index = 0
    size = float(size_bytes)
    
    while size >= 1024 and unit_index < len(units) - 1:
        size /= 1024
        unit_index += 1
    
    if unit_index == 0:
        return f"{int(size)} {units[unit_index]}"
    else:
        return f"{size:.1f} {units[unit_index]}"

def parse_manufacturer_data(manufacturer_data: Dict[int, bytes]) -> Dict[str, Any]:
    """Parse manufacturer data into readable format"""
    
    # Known manufacturer IDs
    manufacturer_names = {
        0x004C: "Apple Inc.",
        0x0075: "Samsung Electronics", 
        0x00E0: "Google",
        0x0006: "Microsoft",
        0x0590: "Espressif Systems",
        0x004F: "Nordic Semiconductor",
        0x03DA: "Flipper Devices Inc.",
        0x0171: "Skullcandy Inc.",
        0x0087: "Garmin International",
        0x004B: "Tile Inc."
    }
    
    parsed_data = {}
    
    for manufacturer_id, data in manufacturer_data.items():
        manufacturer_name = manufacturer_names.get(manufacturer_id, f"Unknown (0x{manufacturer_id:04X})")
        
        parsed_entry = {
            "manufacturer_id": manufacturer_id,
            "manufacturer_name": manufacturer_name,
            "raw_data": data,
            "hex_data": data.hex().upper(),
            "data_length": len(data)
        }
        
        # Parse specific manufacturer data formats
        if manufacturer_id == 0x004C and len(data) >= 2:
            # Apple manufacturer data parsing
            parsed_entry.update(_parse_apple_manufacturer_data(data))
        elif manufacturer_id == 0x0590 and len(data) >= 1:
            # Espressif (ESP32) data parsing
            parsed_entry.update(_parse_espressif_manufacturer_data(data))
        
        parsed_data[manufacturer_name] = parsed_entry
    
    return parsed_data

def _parse_apple_manufacturer_data(data: bytes) -> Dict[str, Any]:
    """Parse Apple-specific manufacturer data"""
    result = {}
    
    if len(data) >= 2:
        apple_type = struct.unpack('<H', data[:2])[0]
        result["apple_type"] = f"0x{apple_type:04X}"
        
        # Common Apple types
        apple_types = {
            0x02: "iBeacon",
            0x05: "AirDrop",
            0x09: "AirPlay",
            0x10: "Proximity Pairing",
            0x0F: "Handoff"
        }
        
        if apple_type in apple_types:
            result["apple_type_name"] = apple_types[apple_type]
        
        # Parse iBeacon data
        if apple_type == 0x02 and len(data) >= 25:
            try:
                uuid_bytes = data[4:20]
                major = struct.unpack('>H', data[20:22])[0]
                minor = struct.unpack('>H', data[22:24])[0] 
                tx_power = struct.unpack('b', data[24:25])[0]
                
                beacon_uuid = UUID(bytes=uuid_bytes)
                
                result["ibeacon"] = {
                    "uuid": str(beacon_uuid),
                    "major": major,
                    "minor": minor,
                    "tx_power": tx_power
                }
            except:
                pass
    
    return result

def _parse_espressif_manufacturer_data(data: bytes) -> Dict[str, Any]:
    """Parse Espressif (ESP32) manufacturer data"""
    result = {"esp32_data": True}
    
    if len(data) >= 1:
        result["esp32_type"] = data[0]
        
        # Common ESP32 advertising types
        if data[0] == 0x01:
            result["esp32_type_name"] = "ESP32 Beacon"
        elif data[0] == 0x02:
            result["esp32_type_name"] = "ESP32 Device Info"
    
    return result

def extract_device_info_from_name(device_name: str) -> Dict[str, Any]:
    """Extract device information from device name"""
    if not device_name:
        return {}
    
    info = {"original_name": device_name}
    name_lower = device_name.lower()
    
    # Device type detection
    device_types = {
        "audio": ["crusher", "evo", "headphone", "speaker", "audio", "beats", "airpods", 
                 "wireless", "buds", "earphone", "soundlink", "jbl", "sony", "bose"],
        "development": ["esp32", "esp", "arduino", "nordic", "devkit", "development",
                       "nrf", "stm32", "microbit", "module", "board"],
        "smartphone": ["iphone", "ipad", "android", "galaxy", "pixel"],
        "fitness": ["fitbit", "garmin", "polar", "watch", "band", "fitness"],
        "iot": ["beacon", "sensor", "smart", "tile", "tracker"],
        "security": ["flipper", "ubertooth", "hackrf"],
        "gaming": ["controller", "gamepad", "xbox", "playstation", "nintendo"]
    }
    
    detected_types = []
    for device_type, keywords in device_types.items():
        if any(keyword in name_lower for keyword in keywords):
            detected_types.append(device_type)
    
    if detected_types:
        info["detected_types"] = detected_types
        info["primary_type"] = detected_types[0]
    
    # Extract version/model information
    version_match = re.search(r'(\d+)(?:\.(\d+))?', device_name)
    if version_match:
        info["version"] = version_match.group(0)
    
    # Extract brand information
    brand_patterns = {
        "Apple": ["iphone", "ipad", "airpods", "apple"],
        "Samsung": ["galaxy", "samsung"],
        "Google": ["pixel", "google"],
        "Microsoft": ["microsoft", "xbox"],
        "Sony": ["sony"],
        "JBL": ["jbl"],
        "Skullcandy": ["crusher", "skullcandy"],
        "Espressif": ["esp32", "esp"],
        "Nordic": ["nordic", "nrf"],
        "Flipper": ["flipper"]
    }
    
    for brand, patterns in brand_patterns.items():
        if any(pattern in name_lower for pattern in patterns):
            info["brand"] = brand
            break
    
    return info

def is_likely_development_device(device_info: Dict[str, Any]) -> bool:
    """Determine if device is likely a development/research device"""
    
    # Check device name
    name = device_info.get('name', '').lower()
    dev_indicators = ['esp32', 'esp', 'arduino', 'nordic', 'nrf', 'devkit', 
                     'development', 'prototype', 'test', 'debug']
    
    if any(indicator in name for indicator in dev_indicators):
        return True
    
    # Check manufacturer data
    manufacturer_data = device_info.get('manufacturer_data', {})
    
    # Espressif (ESP32) manufacturer ID
    if 0x0590 in manufacturer_data:
        return True
    
    # Nordic Semiconductor 
    if 0x004F in manufacturer_data:
        return True
    
    # Check for custom services (indication of development device)
    service_uuids = device_info.get('service_uuids', [])
    custom_service_count = 0
    
    for uuid in service_uuids:
        # 128-bit UUIDs that don't follow Bluetooth SIG format
        if len(uuid) == 36 and not uuid.lower().endswith('-0000-1000-8000-00805f9b34fb'):
            custom_service_count += 1
    
    # High ratio of custom services suggests development device
    if service_uuids and custom_service_count / len(service_uuids) > 0.5:
        return True
    
    return False

def estimate_device_security_level(device_info: Dict[str, Any]) -> Tuple[str, int]:
    """Estimate device security level (0-10 scale)"""
    
    security_score = 5  # Start with neutral
    
    # Factors that increase security
    if device_info.get('privacy_enabled', False):
        security_score += 2
    
    # Apple devices generally have higher security
    name = device_info.get('name', '').lower()
    if any(apple_term in name for apple_term in ['iphone', 'ipad', 'apple', 'airpods']):
        security_score += 3
    
    # Manufacturer data present (some privacy awareness)
    if device_info.get('manufacturer_data'):
        security_score += 1
    
    # Factors that decrease security  
    if is_likely_development_device(device_info):
        security_score -= 3
    
    # Many advertised services (larger attack surface)
    service_count = len(device_info.get('service_uuids', []))
    if service_count > 5:
        security_score -= 1
    elif service_count > 10:
        security_score -= 2
    
    # No services advertised could indicate either high security or simple device
    if service_count == 0:
        security_score += 1
    
    # Clamp score to 0-10 range
    security_score = max(0, min(10, security_score))
    
    # Convert to security level description
    if security_score >= 8:
        level_desc = "Very High"
    elif security_score >= 6:
        level_desc = "High"
    elif security_score >= 4:
        level_desc = "Medium"
    elif security_score >= 2:
        level_desc = "Low"
    else:
        level_desc = "Very Low"
    
    return level_desc, security_score

def generate_device_fingerprint(device_info: Dict[str, Any]) -> str:
    """Generate a unique fingerprint for device identification"""
    
    fingerprint_components = []
    
    # MAC address (if not randomized)
    address = device_info.get('address', '')
    if address and not _is_randomized_mac(address):
        fingerprint_components.append(f"MAC:{address}")
    
    # Device name
    name = device_info.get('name')
    if name:
        fingerprint_components.append(f"NAME:{name}")
    
    # Manufacturer data
    manufacturer_data = device_info.get('manufacturer_data', {})
    for mfg_id, data in manufacturer_data.items():
        fingerprint_components.append(f"MFG:{mfg_id}:{data.hex()[:8]}")
    
    # Service UUIDs (sorted for consistency)
    service_uuids = sorted(device_info.get('service_uuids', []))
    if service_uuids:
        services_hash = hash(tuple(service_uuids))
        fingerprint_components.append(f"SVC:{services_hash}")
    
    # Combine components
    fingerprint = "|".join(fingerprint_components)
    
    # Generate hash for shorter fingerprint
    import hashlib
    fingerprint_hash = hashlib.md5(fingerprint.encode()).hexdigest()[:12]
    
    return fingerprint_hash.upper()

def _is_randomized_mac(address: str) -> bool:
    """Check if MAC address appears to be randomized"""
    if not address:
        return False
    
    # Get first byte of MAC address
    try:
        first_byte = int(address.split(':')[0], 16)
        # Check if the locally administered bit is set (bit 1 of first octet)
        return bool(first_byte & 0x02)
    except (ValueError, IndexError):
        return False

def sanitize_filename(filename: str) -> str:
    """Sanitize filename for safe file system usage"""
    # Replace invalid characters
    invalid_chars = '<>:"/\\|?*'
    for char in invalid_chars:
        filename = filename.replace(char, '_')
    
    # Replace spaces with underscores
    filename = filename.replace(' ', '_')
    
    # Limit length
    if len(filename) > 200:
        filename = filename[:200]
    
    # Ensure not empty
    if not filename:
        filename = "unnamed"
    
    return filename

def create_session_id() -> str:
    """Create unique session identifier"""
    timestamp = int(time.time())
    import random
    random_part = random.randint(1000, 9999)
    return f"session_{timestamp}_{random_part}"

def validate_exploit_payload(payload: bytes, max_size: int = 1024) -> Tuple[bool, str]:
    """Validate exploit payload for safety"""
    
    if not payload:
        return False, "Empty payload"
    
    if len(payload) > max_size:
        return False, f"Payload too large: {len(payload)} > {max_size}"
    
    # Check for extremely dangerous patterns (this is a simplified check)
    dangerous_patterns = [
        b'\x00' * 100,  # Too many null bytes
        b'\xFF' * 100,  # Too many 0xFF bytes  
    ]
    
    for pattern in dangerous_patterns:
        if pattern in payload:
            return False, "Potentially dangerous payload pattern detected"
    
    return True, "Payload appears safe"

def chunk_data(data: bytes, chunk_size: int = 20) -> List[bytes]:
    """Split data into chunks of specified size"""
    return [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]

def merge_device_info(old_info: Dict[str, Any], new_info: Dict[str, Any]) -> Dict[str, Any]:
    """Merge device information, preserving important data"""
    merged = old_info.copy()
    
    # Update with new information
    for key, value in new_info.items():
        if key == 'service_uuids':
            # Merge service lists
            old_services = set(old_info.get('service_uuids', []))
            new_services = set(value) if value else set()
            merged['service_uuids'] = list(old_services | new_services)
        elif key == 'manufacturer_data':
            # Merge manufacturer data
            old_mfg = old_info.get('manufacturer_data', {})
            old_mfg.update(value if value else {})
            merged['manufacturer_data'] = old_mfg
        elif key == 'rssi':
            # Keep strongest RSSI
            old_rssi = old_info.get('rssi')
            if old_rssi is None or (value is not None and value > old_rssi):
                merged['rssi'] = value
        else:
            # Direct replacement for other fields
            if value is not None:
                merged[key] = value
    
    # Update last seen timestamp
    merged['last_seen'] = time.time()
    
    return merged