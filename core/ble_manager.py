
# core/ble_manager.py - Consolidated BLE Operations
import asyncio
import time
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
from bleak import BleakClient, BleakScanner
from bleak.exc import BleakError
from utils.logging import get_logger

logger = get_logger(__name__)

class ConnectionQuality(Enum):
    """Connection quality assessment"""
    EXCELLENT = "excellent"
    GOOD = "good"
    FAIR = "fair" 
    POOR = "poor"
    FAILED = "failed"

class DeviceStrategy(Enum):
    """Connection strategies"""
    AGGRESSIVE = "aggressive"
    STANDARD = "standard"
    GENTLE = "gentle"
    STEALTH = "stealth"

@dataclass
class BLEDevice:
    """Simplified BLE device representation"""
    address: str
    name: Optional[str] = None
    rssi: Optional[int] = None
    device_type: str = "unknown"
    vendor: Optional[str] = None
    manufacturer_data: Dict[int, bytes] = field(default_factory=dict)
    service_uuids: List[str] = field(default_factory=list)
    privacy_enabled: bool = False
    research_potential: int = 0  # 0-10 scale

@dataclass
class ServiceInfo:
    """GATT service information"""
    uuid: str
    handle: int
    characteristics: List[Dict[str, Any]] = field(default_factory=list)

class BLEManager:
    """Unified BLE operations manager"""
    
    def __init__(self):
        self.logger = get_logger(f"{__name__}.BLEManager")
        self.active_connections: Dict[str, BleakClient] = {}
        self.connection_quality: Dict[str, ConnectionQuality] = {}
        
        # Vendor database for device intelligence
        self.vendor_db = {
            0x004C: "Apple Inc.",
            0x0075: "Samsung Electronics",
            0x00E0: "Google",
            0x0590: "Espressif Systems",
            0x03DA: "Flipper Devices Inc.",
            0x0171: "Skullcandy Inc.",
        }
    
    async def scan(self, duration: int = 10) -> List[BLEDevice]:
        """Scan for BLE devices with enhanced discovery"""
        self.logger.info(f"Starting BLE scan ({duration}s)")
        
        try:
            # Basic Bleak discovery
            devices = await BleakScanner.discover(timeout=duration)
            
            enhanced_devices = []
            for device in devices:
                ble_device = self._create_ble_device(device)
                enhanced_devices.append(ble_device)
            
            self.logger.info(f"Scan completed: {len(enhanced_devices)} devices found")
            return enhanced_devices
            
        except Exception as e:
            self.logger.error(f"Scan failed: {e}")
            return []
    
    def _create_ble_device(self, device) -> BLEDevice:
        """Convert Bleak device to BLEDevice"""
        # Extract basic info
        address = getattr(device, 'address', 'Unknown')
        name = getattr(device, 'name', None)
        
        # Handle deprecated RSSI warning
        rssi = None
        try:
            import warnings
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                rssi = getattr(device, 'rssi', None)
        except:
            rssi = None
        
        # Create device
        ble_device = BLEDevice(
            address=address,
            name=name,
            rssi=rssi
        )
        
        # Basic device classification
        ble_device.device_type = self._classify_device_basic(name, address)
        ble_device.vendor = self._identify_vendor_basic(address)
        ble_device.privacy_enabled = self._is_randomized_mac(address)
        ble_device.research_potential = self._calculate_research_potential_basic(ble_device)
        
        return ble_device
    
    def _classify_device_basic(self, name: Optional[str], address: str) -> str:
        """Basic device classification"""
        if not name:
            return "unknown"
        
        name_lower = name.lower()
        
        # Audio devices
        if any(keyword in name_lower for keyword in ['crusher', 'headphone', 'speaker', 'audio', 'beats']):
            return "audio"
        
        # Development boards
        if any(keyword in name_lower for keyword in ['esp32', 'arduino', 'dev']):
            return "development"
        
        # Smartphones
        if any(keyword in name_lower for keyword in ['iphone', 'android', 'phone']):
            return "smartphone"
        
        # Security tools
        if any(keyword in name_lower for keyword in ['flipper', 'security']):
            return "security"
        
        return "unknown"
    
    def _identify_vendor_basic(self, address: str) -> Optional[str]:
        """Basic vendor identification from MAC OUI"""
        try:
            oui = address.replace(':', '')[:6].upper()
            
            # Check known OUI patterns
            oui_map = {
                'AC233F': 'Apple Inc.',
                'BC7E8B': 'Samsung Electronics',
                '80E127': 'Flipper Devices Inc.',
                '30AEA4': 'ESP32 Dev Board',
                'CC50E3': 'Skullcandy Inc.',
            }
            
            for pattern, vendor in oui_map.items():
                if oui.startswith(pattern):
                    return vendor
            
        except:
            pass
        
        return None
    
    def _is_randomized_mac(self, address: str) -> bool:
        """Check if MAC uses randomization"""
        try:
            first_byte = int(address.split(':')[0], 16)
            return bool(first_byte & 0x02)
        except:
            return False
    
    def _calculate_research_potential_basic(self, device: BLEDevice) -> int:
        """Basic research potential calculation (0-10)"""
        score = 0
        
        # Device type scoring
        type_scores = {
            'development': 9,
            'security': 8,
            'unknown': 5,
            'audio': 4,
            'smartphone': 2,
        }
        score += type_scores.get(device.device_type, 3)
        
        # Privacy reduces research potential
        if device.privacy_enabled:
            score -= 1
        
        return max(0, min(10, score))
    
    async def connect(self, address: str, strategy: DeviceStrategy = DeviceStrategy.STANDARD) -> Optional[BleakClient]:
        """Connect to device with strategy"""
        if address in self.active_connections:
            client = self.active_connections[address]
            if client.is_connected:
                return client
        
        self.logger.info(f"Connecting to {address} using {strategy.value} strategy")
        
        # Strategy-specific settings
        strategy_config = {
            DeviceStrategy.AGGRESSIVE: {'timeout': 30, 'attempts': 5},
            DeviceStrategy.STANDARD: {'timeout': 15, 'attempts': 3},
            DeviceStrategy.GENTLE: {'timeout': 10, 'attempts': 2},
            DeviceStrategy.STEALTH: {'timeout': 20, 'attempts': 1},
        }
        
        config = strategy_config[strategy]
        
        for attempt in range(config['attempts']):
            try:
                client = BleakClient(address, timeout=config['timeout'])
                await client.connect()
                
                if client.is_connected:
                    # Test connection quality
                    quality = await self._assess_connection_quality(client)
                    
                    if quality != ConnectionQuality.FAILED:
                        self.active_connections[address] = client
                        self.connection_quality[address] = quality
                        self.logger.info(f"Connected with {quality.value} quality")
                        return client
                    else:
                        await client.disconnect()
                
            except Exception as e:
                self.logger.debug(f"Connection attempt {attempt + 1} failed: {e}")
                if attempt < config['attempts'] - 1:
                    await asyncio.sleep(2)
        
        self.logger.error(f"Failed to connect to {address}")
        return None
    
    async def _assess_connection_quality(self, client: BleakClient) -> ConnectionQuality:
        """Assess connection quality"""
        try:
            if not client.is_connected:
                return ConnectionQuality.FAILED
            
            # Test service discovery
            services = client.services
            service_count = len(list(services)) if services else 0
            
            if service_count == 0:
                return ConnectionQuality.POOR
            
            # Test characteristic access
            try:
                await asyncio.wait_for(
                    client.read_gatt_char("00002a00-0000-1000-8000-00805f9b34fb"),
                    timeout=2.0
                )
                return ConnectionQuality.EXCELLENT
            except:
                return ConnectionQuality.GOOD
                
        except Exception:
            return ConnectionQuality.FAILED
    
    async def disconnect(self, address: str) -> bool:
        """Disconnect from device"""
        if address not in self.active_connections:
            return True
        
        try:
            client = self.active_connections[address]
            if client.is_connected:
                await client.disconnect()
            
            del self.active_connections[address]
            if address in self.connection_quality:
                del self.connection_quality[address]
            
            self.logger.info(f"Disconnected from {address}")
            return True
            
        except Exception as e:
            self.logger.error(f"Disconnect failed: {e}")
            return False
    
    def is_connected(self, address: str) -> bool:
        """Check if device is connected"""
        if address not in self.active_connections:
            return False
        
        try:
            return self.active_connections[address].is_connected
        except:
            return False
    
    def get_connection(self, address: str) -> Optional[BleakClient]:
        """Get active connection"""
        return self.active_connections.get(address)
    
    async def discover_services(self, client: BleakClient) -> List[ServiceInfo]:
        """Discover GATT services and characteristics"""
        try:
            services = client.services
            service_list = []
            
            for service in services:
                service_info = ServiceInfo(
                    uuid=str(service.uuid).lower(),
                    handle=getattr(service, 'handle', 0)
                )
                
                # Get characteristics
                for char in service.characteristics:
                    char_info = {
                        'uuid': str(char.uuid).lower(),
                        'properties': list(char.properties) if hasattr(char, 'properties') else [],
                        'handle': getattr(char, 'handle', 0)
                    }
                    service_info.characteristics.append(char_info)
                
                service_list.append(service_info)
            
            self.logger.info(f"Discovered {len(service_list)} services")
            return service_list
            
        except Exception as e:
            self.logger.error(f"Service discovery failed: {e}")
            return []
    
    def find_writable_characteristics(self, services: List[ServiceInfo]) -> List[Dict[str, Any]]:
        """Find writable characteristics"""
        writable = []
        
        for service in services:
            for char in service.characteristics:
                if 'write' in char['properties'] or 'write-without-response' in char['properties']:
                    writable.append({
                        'service_uuid': service.uuid,
                        'char_uuid': char['uuid'],
                        'handle': char['handle'],
                        'properties': char['properties']
                    })
        
        return writable
    
    async def cleanup(self):
        """Cleanup all connections"""
        for address in list(self.active_connections.keys()):
            await self.disconnect(address)