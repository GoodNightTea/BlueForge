# core/device_intelligence.py - Device Analysis & Classification
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from enum import Enum
from core.ble_manager import BLEDevice
from utils.logging import get_logger

logger = get_logger(__name__)

class SecurityProfile(Enum):
    """Device security classifications"""
    OPEN = "open"                    # Development devices, test hardware
    MODERATE = "moderate"            # Consumer devices
    STRICT = "strict"               # Security-aware devices
    HARDENED = "hardened"          # Security-focused devices
    UNKNOWN = "unknown"            # Needs analysis

@dataclass
class DeviceProfile:
    """Comprehensive device profile"""
    address: str
    name: Optional[str]
    device_type: str
    vendor: Optional[str]
    security_profile: SecurityProfile
    research_potential: int  # 0-10 scale
    connection_strategy: str
    privacy_enabled: bool
    indicators: List[str]
    warnings: List[str]

class DeviceIntelligence:
    """Advanced device analysis and intelligence gathering"""
    
    def __init__(self):
        self.logger = get_logger(f"{__name__}.DeviceIntelligence")
        
        # Extended vendor database
        self.vendor_database = {
            # Major manufacturers
            0x004C: "Apple Inc.",
            0x0075: "Samsung Electronics",
            0x00E0: "Google",
            0x0006: "Microsoft",
            0x0590: "Espressif Systems",
            0x004F: "Nordic Semiconductor",
            0x03DA: "Flipper Devices Inc.",
            0x0171: "Skullcandy Inc.",
            0x0087: "Garmin International",
            0x004B: "Tile Inc.",
            
            # Audio manufacturers
            0x045E: "Microsoft Audio",
            0x001B: "JBL/Harman",
            0x00A0: "Sony Corporation",
        }
        
        # MAC OUI database for detailed vendor identification
        self.oui_database = {
            'AC233F': 'Apple Inc.',
            '3C2EFF': 'Apple Inc.',
            'F4F5D8': 'Apple Inc.',
            '88E9FE': 'Apple Inc.',
            'BC7E8B': 'Samsung Electronics',
            '5CF370': 'Samsung Electronics',
            '80E127': 'Flipper Devices Inc.',
            '30AEA4': 'ESP32 Dev Board',
            'B4E62D': 'ESP32 Dev Board',
            '3C71BF': 'ESP32 Dev Board',
            '246F28': 'ESP32 Variants',
            'CC50E3': 'Skullcandy Inc.',
            '045217': 'Beats Electronics',
            '2C41A1': 'Sony Audio',
            '001B66': 'JBL/Harman',
        }
        
        # Device classification patterns
        self.classification_patterns = {
            'audio': {
                'keywords': ['crusher', 'headphone', 'speaker', 'audio', 'beats', 'airpods', 
                           'evo', 'wireless', 'buds', 'earphone', 'soundlink', 'jbl',
                           'sony', 'skullcandy', 'bose', 'sennheiser', 'hd 350bt'],
                'security_profile': SecurityProfile.MODERATE,
                'research_potential': 4,
                'connection_strategy': 'gentle'
            },
            'development': {
                'keywords': ['esp32', 'esp', 'arduino', 'nordic', 'devkit', 'development',
                           'nrf', 'stm32', 'microbit', 'module', 'board', 'mcu'],
                'security_profile': SecurityProfile.OPEN,
                'research_potential': 9,
                'connection_strategy': 'aggressive'
            },
            'smartphone': {
                'keywords': ['iphone', 'ipad', 'android', 'galaxy', 'pixel', 'phone'],
                'security_profile': SecurityProfile.STRICT,
                'research_potential': 2,
                'connection_strategy': 'stealth'
            },
            'security': {
                'keywords': ['flipper', 'security', 'pentest', 'hack', 'ubertooth'],
                'security_profile': SecurityProfile.HARDENED,
                'research_potential': 8,
                'connection_strategy': 'stealth'
            },
            'fitness': {
                'keywords': ['fitbit', 'garmin', 'polar', 'watch', 'band', 'fitness'],
                'security_profile': SecurityProfile.MODERATE,
                'research_potential': 5,
                'connection_strategy': 'standard'
            },
            'iot': {
                'keywords': ['beacon', 'sensor', 'smart', 'tile', 'tracker', 'screencast'],
                'security_profile': SecurityProfile.MODERATE,
                'research_potential': 6,
                'connection_strategy': 'standard'
            }
        }
        
        # Standard BLE services for service-based classification
        self.standard_services = {
            # Audio services
            '0000110b-0000-1000-8000-00805f9b34fb': 'audio_sink',
            '0000110a-0000-1000-8000-00805f9b34fb': 'audio_source',
            '0000111e-0000-1000-8000-00805f9b34fb': 'handsfree',
            
            # HID services
            '00001812-0000-1000-8000-00805f9b34fb': 'hid',
            
            # Health services
            '0000180d-0000-1000-8000-00805f9b34fb': 'heart_rate',
            '00001809-0000-1000-8000-00805f9b34fb': 'health_thermometer',
            
            # Generic services
            '0000180f-0000-1000-8000-00805f9b34fb': 'battery',
            '0000180a-0000-1000-8000-00805f9b34fb': 'device_information',
            '00001800-0000-1000-8000-00805f9b34fb': 'generic_access',
            
            # Development/custom services
            '6e400001-b5a3-f393-e0a9-e50e24dcca9e': 'nordic_uart',
            '19b10001-e8f2-537e-4f6c-d104768a1214': 'custom_research'
        }
    
    def analyze_device(self, device: BLEDevice) -> DeviceProfile:
        """Comprehensive device analysis"""
        profile = DeviceProfile(
            address=device.address,
            name=device.name,
            device_type="unknown",
            vendor=None,
            security_profile=SecurityProfile.UNKNOWN,
            research_potential=0,
            connection_strategy="standard",
            privacy_enabled=device.privacy_enabled,
            indicators=[],
            warnings=[]
        )
        
        # Step 1: MAC address analysis
        self._analyze_mac_address(device, profile)
        
        # Step 2: Name-based classification
        self._classify_by_name(device, profile)
        
        # Step 3: Vendor-based classification
        self._classify_by_vendor(device, profile)
        
        # Step 4: Service-based classification (if available)
        self._classify_by_services(device, profile)
        
        # Step 5: Privacy and security analysis
        self._analyze_privacy_features(device, profile)
        
        # Step 6: Research potential assessment
        self._assess_research_potential(device, profile)
        
        return profile
    
    def _analyze_mac_address(self, device: BLEDevice, profile: DeviceProfile):
        """Analyze MAC address for vendor and privacy info"""
        try:
            # Check for randomized MAC (local bit set)
            first_byte = int(device.address.split(':')[0], 16)
            if first_byte & 0x02:
                profile.privacy_enabled = True
                profile.indicators.append("MAC randomization enabled")
                profile.security_profile = SecurityProfile.STRICT
            
            # OUI-based vendor identification
            oui = device.address.replace(':', '')[:6].upper()
            
            for oui_prefix, vendor in self.oui_database.items():
                if oui.startswith(oui_prefix):
                    profile.vendor = vendor
                    profile.indicators.append(f"Vendor identified via MAC OUI: {vendor}")
                    break
            
        except Exception as e:
            self.logger.debug(f"MAC analysis failed: {e}")
    
    def _classify_by_name(self, device: BLEDevice, profile: DeviceProfile):
        """Classify device based on name patterns"""
        if not device.name:
            profile.indicators.append("No device name (potential privacy measure)")
            return
        
        name_lower = device.name.lower()
        
        # Check against classification patterns
        for device_type, patterns in self.classification_patterns.items():
            for keyword in patterns['keywords']:
                if keyword in name_lower:
                    profile.device_type = device_type
                    profile.security_profile = patterns['security_profile']
                    profile.research_potential = patterns['research_potential']
                    profile.connection_strategy = patterns['connection_strategy']
                    profile.indicators.append(f"Classified as {device_type} via name pattern: '{keyword}'")
                    
                    # Add type-specific warnings
                    if device_type == 'smartphone':
                        profile.warnings.append("Smartphone - expect restrictive BLE access")
                    elif device_type == 'security':
                        profile.warnings.append("Security device - may have defensive measures")
                    elif device_type == 'audio':
                        profile.indicators.append("Audio device - use gentle connection approach")
                    
                    return
    
    def _classify_by_vendor(self, device: BLEDevice, profile: DeviceProfile):
        """Refine classification based on vendor"""
        if not profile.vendor:
            return
        
        vendor_lower = profile.vendor.lower()
        
        # Vendor-specific adjustments
        if 'apple' in vendor_lower:
            profile.device_type = 'apple_device'
            profile.security_profile = SecurityProfile.HARDENED
            profile.research_potential = 1
            profile.connection_strategy = 'stealth'
            profile.warnings.append("Apple device - extremely restrictive access")
            
        elif 'espressif' in vendor_lower or 'esp32' in vendor_lower:
            profile.device_type = 'development'
            profile.security_profile = SecurityProfile.OPEN
            profile.research_potential = 9
            profile.connection_strategy = 'aggressive'
            profile.indicators.append("ESP32 device - excellent research target")
            
        elif 'flipper' in vendor_lower:
            profile.device_type = 'security'
            profile.security_profile = SecurityProfile.HARDENED
            profile.research_potential = 7
            profile.connection_strategy = 'stealth'
            profile.warnings.append("Flipper device - has security countermeasures")
            
        elif any(audio_vendor in vendor_lower for audio_vendor in ['skullcandy', 'beats', 'jbl', 'sony']):
            profile.device_type = 'audio'
            profile.security_profile = SecurityProfile.MODERATE
            profile.research_potential = 4
            profile.connection_strategy = 'gentle'
    
    def _classify_by_services(self, device: BLEDevice, profile: DeviceProfile):
        """Classify based on advertised services"""
        if not device.service_uuids:
            return
        
        service_types = []
        custom_services = 0
        
        for service_uuid in device.service_uuids:
            service_uuid_lower = service_uuid.lower()
            
            if service_uuid_lower in self.standard_services:
                service_type = self.standard_services[service_uuid_lower]
                service_types.append(service_type)
                profile.indicators.append(f"Service detected: {service_type}")
            else:
                custom_services += 1
        
        # Service-based classification
        if any(svc in service_types for svc in ['audio_sink', 'audio_source', 'handsfree']):
            if profile.device_type == 'unknown':
                profile.device_type = 'audio'
                profile.security_profile = SecurityProfile.MODERATE
                profile.research_potential = 4
        
        elif 'nordic_uart' in service_types or 'custom_research' in service_types:
            if profile.device_type == 'unknown':
                profile.device_type = 'development'
                profile.security_profile = SecurityProfile.OPEN
                profile.research_potential = 8
                profile.indicators.append("Custom/UART services suggest development device")
        
        elif 'hid' in service_types:
            if profile.device_type == 'unknown':
                profile.device_type = 'input_device'
                profile.security_profile = SecurityProfile.MODERATE
                profile.research_potential = 5
        
        # Custom services indicate research potential
        if custom_services > 0:
            profile.research_potential += min(3, custom_services)
            profile.indicators.append(f"{custom_services} custom services detected")
    
    def _analyze_privacy_features(self, device: BLEDevice, profile: DeviceProfile):
        """Analyze privacy and security features"""
        # MAC randomization already handled in MAC analysis
        
        # Minimal service advertisement (privacy indicator)
        if len(device.service_uuids) == 0:
            profile.indicators.append("No advertised services (high privacy)")
            if profile.security_profile == SecurityProfile.UNKNOWN:
                profile.security_profile = SecurityProfile.STRICT
        
        elif len(device.service_uuids) <= 2:
            # Minimal services (Apple-like behavior)
            basic_services = ['0000180f-0000-1000-8000-00805f9b34fb']  # Battery only
            if any(svc in basic_services for svc in device.service_uuids):
                profile.indicators.append("Minimal service exposure (privacy-conscious)")
        
        # Manufacturer data analysis
        if device.manufacturer_data:
            profile.indicators.append(f"Manufacturer data present: {len(device.manufacturer_data)} entries")
            
            # Apple-specific privacy analysis
            if 0x004C in device.manufacturer_data:
                profile.indicators.append("Apple manufacturer data - privacy protocols active")
                profile.security_profile = SecurityProfile.HARDENED
        else:
            profile.indicators.append("No manufacturer data (potential privacy measure)")
    
    def _assess_research_potential(self, device: BLEDevice, profile: DeviceProfile):
        """Final research potential assessment"""
        # Start with base score from classification
        score = profile.research_potential
        
        # Adjust based on various factors
        
        # Multiple services increase attack surface
        if len(device.service_uuids) > 3:
            score += 2
            profile.indicators.append("Many services exposed - increased attack surface")
        
        # Privacy features reduce research potential
        if profile.privacy_enabled:
            score -= 1
            profile.indicators.append("Privacy features may limit research access")
        
        # Strong RSSI suggests device is nearby and accessible
        if device.rssi and device.rssi > -50:
            score += 1
            profile.indicators.append("Strong signal - good accessibility")
        elif device.rssi and device.rssi < -80:
            score -= 1
            profile.indicators.append("Weak signal - may affect connection stability")
        
        # Vendor-based adjustments
        if profile.vendor:
            if any(dev_vendor in profile.vendor.lower() for dev_vendor in ['espressif', 'nordic', 'esp32']):
                score += 1  # Development vendors
            elif 'apple' in profile.vendor.lower():
                score = min(score, 2)  # Cap Apple devices at low research potential
        
        # Final score clamping and assignment
        profile.research_potential = max(0, min(10, score))
        
        # Generate final recommendations
        if profile.research_potential >= 8:
            profile.indicators.append("HIGH PRIORITY research target")
        elif profile.research_potential >= 6:
            profile.indicators.append("Moderate research interest")
        elif profile.research_potential <= 2:
            profile.indicators.append("Low research priority")
    
    def generate_device_report(self, device: BLEDevice) -> str:
        """Generate comprehensive device intelligence report"""
        profile = self.analyze_device(device)
        
        report = f"""
🔍 DEVICE INTELLIGENCE REPORT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📱 Device: {profile.name or 'Unknown Device'}
📍 Address: {profile.address}
🏭 Vendor: {profile.vendor or 'Unknown'}
🎯 Type: {profile.device_type.upper()}
🔒 Security: {profile.security_profile.value.upper()}
🧪 Research Potential: {profile.research_potential}/10
🔗 Recommended Strategy: {profile.connection_strategy.upper()}
📶 RSSI: {device.rssi} dBm (Signal: {'Strong' if device.rssi and device.rssi > -60 else 'Weak' if device.rssi and device.rssi < -80 else 'Moderate'})

🔍 Analysis Indicators:"""
        
        for indicator in profile.indicators:
            report += f"\n   ✓ {indicator}"
        
        if profile.warnings:
            report += f"\n\n⚠️  Security Warnings:"
            for warning in profile.warnings:
                report += f"\n   ⚠️  {warning}"
        
        if device.service_uuids:
            report += f"\n\n🛠️  Services: {len(device.service_uuids)} advertised"
            for service in device.service_uuids[:5]:  # Show first 5
                service_name = self.standard_services.get(service.lower(), "Custom/Unknown")
                report += f"\n   • {service} ({service_name})"
            
            if len(device.service_uuids) > 5:
                report += f"\n   • ... and {len(device.service_uuids) - 5} more"
        
        return report
    
    def get_connection_recommendations(self, device: BLEDevice) -> Dict[str, Any]:
        """Get specific connection recommendations for device"""
        profile = self.analyze_device(device)
        
        strategy_details = {
            'aggressive': {
                'timeout': 30,
                'attempts': 5,
                'description': 'Maximum effort connection for development devices'
            },
            'standard': {
                'timeout': 15,
                'attempts': 3,
                'description': 'Balanced approach for most devices'
            },
            'gentle': {
                'timeout': 10,
                'attempts': 2,
                'description': 'Careful approach for audio/consumer devices'
            },
            'stealth': {
                'timeout': 20,
                'attempts': 1,
                'description': 'Minimal footprint for security-conscious devices'
            }
        }
        
        strategy_info = strategy_details.get(profile.connection_strategy, strategy_details['standard'])
        
        return {
            'strategy': profile.connection_strategy,
            'timeout': strategy_info['timeout'],
            'attempts': strategy_info['attempts'],
            'description': strategy_info['description'],
            'expected_success_rate': self._estimate_success_rate(profile),
            'special_considerations': profile.warnings,
            'research_value': profile.research_potential
        }
    
    def _estimate_success_rate(self, profile: DeviceProfile) -> str:
        """Estimate connection success rate"""
        if profile.security_profile == SecurityProfile.OPEN:
            return "Very High (90%+)"
        elif profile.security_profile == SecurityProfile.MODERATE:
            return "High (70-90%)"
        elif profile.security_profile == SecurityProfile.STRICT:
            return "Medium (40-70%)"
        elif profile.security_profile == SecurityProfile.HARDENED:
            return "Low (10-40%)"
        else:
            return "Unknown"
    
    def analyze_device_by_address(self, session_manager, device_identifier: str) -> DeviceProfile:
        """
        Analyze device using address or ID.
        If connected, use live services from BLE client.
        Otherwise, use advertised services.
        """
        # Try to find device dict
        device = None
        devices = session_manager.discovered_devices_dict
        # Try by index
        if device_identifier.isdigit():
            idx = int(device_identifier) - 1
            if 0 <= idx < len(devices):
                device = devices[idx]
        # Try by address
        if not device:
            for d in devices:
                if d['address'].lower() == device_identifier.lower():
                    device = d
                    break
        if not device:
            # Try by name
            for d in devices:
                if device_identifier.lower() in (d.get('name') or '').lower():
                    device = d
                    break
        if not device:
            raise ValueError(f"Device not found: {device_identifier}")

        # Try to get live services if connected
        client = session_manager.get_ble_client(device['address'])
        service_uuids = device.get('service_uuids', [])
        if client and getattr(client, 'is_connected', False):
            try:
                # Use live services if available
                if hasattr(client, 'services') and client.services:
                    service_uuids = [str(s.uuid) for s in client.services]
            except Exception:
                pass

        # Build BLEDevice for analysis
        from core.ble_manager import BLEDevice
        ble_device = BLEDevice(
            address=device['address'],
            name=device.get('name'),
            rssi=device.get('rssi'),
            manufacturer_data=device.get('manufacturer_data', {}),
            service_uuids=service_uuids
        )
        return self.analyze_device(ble_device)