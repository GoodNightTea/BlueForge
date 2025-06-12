# core/session_manager.py - State Management
import time
import json
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from core.ble_manager import BLEDevice, BLEManager
from utils.logging import get_logger

logger = get_logger(__name__)

@dataclass
class SessionStats:
    """Session statistics"""
    session_start: datetime
    scans_performed: int = 0
    devices_tested: int = 0
    vulnerabilities_found: int = 0
    connections_made: int = 0
    fuzzing_sessions: int = 0

@dataclass
class ConnectionInfo:
    """Information about an active connection"""
    device: BLEDevice
    connected_at: datetime
    quality: str
    services_discovered: bool = False
    characteristics_tested: int = 0

class SessionManager:
    """Manages BlueForge session state and data"""
    
    def __init__(self):
        self.logger = get_logger(f"{__name__}.SessionManager")
        
        # Core managers
        self.ble_manager = BLEManager()
        
        # Session state
        self.stats = SessionStats(session_start=datetime.now())
        self.discovered_devices: List[BLEDevice] = []
        self.connected_devices: Dict[int, ConnectionInfo] = {}  # index -> connection info
        self.device_profiles: Dict[str, Dict] = {}  # address -> profile data
        self.session_data: Dict[str, Any] = {}
        
        self.logger.info("Session manager initialized")
    

    # Update existing method to return both formats
    async def scan_for_devices(self, duration: int = 10) -> List[BLEDevice]:
        """Scan for BLE devices and update session state"""
        self.logger.info(f"Starting device scan ({duration}s)")
        
        devices = await self.ble_manager.scan(duration)
        
        # Update session state
        self.discovered_devices = devices
        self.stats.scans_performed += 1
        
        self.logger.info(f"Scan completed: {len(devices)} devices discovered")
        
        # Categorize devices for better overview
        categories = self._categorize_devices(devices)
        self.session_data['last_scan_categories'] = categories
        
        return devices

    # Add property accessors for clean interface
    @property
    def discovered_devices_dict(self) -> List[Dict[str, Any]]:
        """Get discovered devices as dictionary list"""
        return [self._device_to_dict(device) for device in self.discovered_devices]

    @property
    def connected_devices_dict(self) -> List[Dict[str, Any]]:
        """Get connected devices as dictionary list"""
        connected = []
        for idx, conn_info in self.connected_devices.items():
            device_dict = self._device_to_dict(conn_info.device)
            device_dict['connected_at'] = conn_info.connected_at
            device_dict['quality'] = conn_info.quality
            connected.append(device_dict)
        return connected

    async def connect_by_address(self, device_address: str) -> bool:
        """Connect to device by address - finds index automatically"""
        for i, device in enumerate(self.discovered_devices):
            if device.address == device_address:
                conn_info = await self.connect_to_device(i)
                return conn_info is not None
        return False

    async def disconnect_by_address(self, device_address: str) -> bool:
        """Disconnect device by address - finds index automatically"""
        for idx, conn_info in self.connected_devices.items():
            if conn_info.device.address == device_address:
                return await self.disconnect_device(idx)
        return False

    def get_ble_client(self, device_address: str):
        """Get BLE client for device address"""
        return self.ble_manager.get_connection(device_address)

    def _device_to_dict(self, device: BLEDevice) -> Dict[str, Any]:
        """Convert BLEDevice to dict representation"""
        return {
            'address': device.address,
            'name': device.name,
            'rssi': device.rssi,
            'device_type': device.device_type,
            'vendor': device.vendor,
            'manufacturer_data': device.manufacturer_data,
            'service_uuids': device.service_uuids,
            'privacy_enabled': device.privacy_enabled,
            'research_potential': device.research_potential
        }

    # Add vulnerability storage (simple implementation)
    def store_vulnerabilities(self, device_address: str, vulnerabilities: List):
        """Store vulnerabilities for device"""
        if 'vulnerabilities' not in self.session_data:
            self.session_data['vulnerabilities'] = {}
        self.session_data['vulnerabilities'][device_address] = vulnerabilities

    def get_vulnerabilities(self, device_address: str) -> List:
        """Get stored vulnerabilities for device"""
        return self.session_data.get('vulnerabilities', {}).get(device_address, [])

    def get_session_data(self) -> Dict[str, Any]:
        """Get session data for compatibility"""
        return {
            'statistics': {
                'scans_performed': self.stats.scans_performed,
                'devices_tested': self.stats.devices_tested,
                'vulnerabilities_found': self.stats.vulnerabilities_found,
                'connections_made': self.stats.connections_made,
                'fuzzing_sessions': self.stats.fuzzing_sessions
            }
        }

    async def reset_session(self):
        """Reset session data"""
        await self.cleanup()
        self.__init__()

    async def save_session(self, filename: str):
        """Save session to file"""
        self.export_session_data(filename)

    async def load_session(self, filename: str):
        """Load session from file"""
        self.import_session_data(filename)

    def _device_to_dict(self, device) -> Dict[str, Any]:
        """Convert BLEDevice to dict for compatibility"""
        return {
            'address': device.address,
            'name': device.name,
            'rssi': device.rssi,
            'device_type': device.device_type,
            'vendor': device.vendor,
            'manufacturer_data': device.manufacturer_data,
            'service_uuids': device.service_uuids,
            'privacy_enabled': device.privacy_enabled,
            'research_potential': device.research_potential
        }

    def _categorize_devices(self, devices: List[BLEDevice]) -> Dict[str, List[BLEDevice]]:
        """Categorize devices by type for organized display"""
        categories = {
            'high_value_targets': [],
            'development_boards': [],
            'audio_devices': [], 
            'smartphones': [],
            'security_tools': [],
            'unknown_devices': []
        }
        
        for device in devices:
            if device.research_potential >= 7:
                categories['high_value_targets'].append(device)
            
            if device.device_type == 'development':
                categories['development_boards'].append(device)
            elif device.device_type == 'audio':
                categories['audio_devices'].append(device)
            elif device.device_type == 'smartphone':
                categories['smartphones'].append(device)
            elif device.device_type == 'security':
                categories['security_tools'].append(device)
            else:
                categories['unknown_devices'].append(device)
        
        return categories
    
    async def connect_to_device(self, device_index: int, 
                               strategy: str = "standard") -> Optional[ConnectionInfo]:
        """Connect to a discovered device"""
        if device_index >= len(self.discovered_devices):
            self.logger.error(f"Invalid device index: {device_index}")
            return None
        
        device = self.discovered_devices[device_index]
        
        # Check if already connected
        if device_index in self.connected_devices:
            existing = self.connected_devices[device_index]
            if self.ble_manager.is_connected(device.address):
                self.logger.info(f"Already connected to {device.address}")
                return existing
            else:
                # Clean up stale connection
                del self.connected_devices[device_index]
        
        # Map strategy string to enum
        from core.ble_manager import DeviceStrategy
        strategy_map = {
            'aggressive': DeviceStrategy.AGGRESSIVE,
            'standard': DeviceStrategy.STANDARD,
            'gentle': DeviceStrategy.GENTLE,
            'stealth': DeviceStrategy.STEALTH
        }
        
        strategy_enum = strategy_map.get(strategy, DeviceStrategy.STANDARD)
        
        # Attempt connection
        client = await self.ble_manager.connect(device.address, strategy_enum)
        
        if client:
            # Create connection info
            quality = self.ble_manager.connection_quality.get(device.address, "unknown")
            connection_info = ConnectionInfo(
                device=device,
                connected_at=datetime.now(),
                quality=quality.value if hasattr(quality, 'value') else str(quality)
            )
            
            self.connected_devices[device_index] = connection_info
            self.stats.connections_made += 1
            
            self.logger.info(f"Successfully connected to {device.name} ({device.address})")
            return connection_info
        else:
            self.logger.error(f"Failed to connect to {device.address}")
            return None
    
    async def disconnect_device(self, device_index: int) -> bool:
        """Disconnect from a device"""
        if device_index not in self.connected_devices:
            self.logger.warning(f"Device index {device_index} not connected")
            return False
        
        connection_info = self.connected_devices[device_index]
        device = connection_info.device
        
        success = await self.ble_manager.disconnect(device.address)
        
        if success:
            del self.connected_devices[device_index]
            self.logger.info(f"Disconnected from {device.name}")
        
        return success
    
    def get_device_from_index(self, device_index: Optional[int]) -> Optional[BLEDevice]:
        """Get device by index with automatic selection logic"""
        # If no index provided and only one device connected, use it
        if device_index is None:
            if len(self.connected_devices) == 1:
                return list(self.connected_devices.values())[0].device
            else:
                return None
        
        # Validate index
        if device_index >= len(self.discovered_devices):
            return None
        
        return self.discovered_devices[device_index]
    
    def get_connection_info(self, device_index: int) -> Optional[ConnectionInfo]:
        """Get connection information for device"""
        return self.connected_devices.get(device_index)
    
    def get_active_connection_index(self) -> Optional[int]:
        """Get index of active device if only one connected"""
        if len(self.connected_devices) == 1:
            return list(self.connected_devices.keys())[0]
        return None
    
    def update_device_profile(self, device_address: str, profile_data: Dict):
        """Update device profile data"""
        self.device_profiles[device_address] = profile_data
        self.logger.debug(f"Updated profile for {device_address}")
    
    def get_device_profile(self, device_address: str) -> Optional[Dict]:
        """Get device profile data"""
        return self.device_profiles.get(device_address)
    
    def get_session_summary(self) -> Dict[str, Any]:
        """Get session summary for display"""
        return {
            'session_start': self.stats.session_start,
            'uptime': datetime.now() - self.stats.session_start,
            'discovered_devices': len(self.discovered_devices),
            'connected_devices': len(self.connected_devices),
            'scans_performed': self.stats.scans_performed,
            'devices_tested': self.stats.devices_tested,
            'vulnerabilities_found': self.stats.vulnerabilities_found,
            'connections_made': self.stats.connections_made,
            'fuzzing_sessions': self.stats.fuzzing_sessions
        }
    
    def export_session_data(self, filename: Optional[str] = None) -> str:
        """Export session data to JSON file"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"blueforge_session_{timestamp}.json"
        
        # Prepare export data
        export_data = {
            'session_info': {
                'start_time': self.stats.session_start.isoformat(),
                'export_time': datetime.now().isoformat(),
                'stats': asdict(self.stats)
            },
            'discovered_devices': [
                {
                    'address': device.address,
                    'name': device.name,
                    'device_type': device.device_type,
                    'vendor': device.vendor,
                    'research_potential': device.research_potential,
                    'privacy_enabled': device.privacy_enabled
                }
                for device in self.discovered_devices
            ],
            'device_profiles': self.device_profiles,
            'session_data': self.session_data
        }
        
        try:
            with open(filename, 'w') as f:
                json.dump(export_data, f, indent=2, default=str)
            
            self.logger.info(f"Session data exported to {filename}")
            return filename
            
        except Exception as e:
            self.logger.error(f"Failed to export session data: {e}")
            raise
    
    def import_session_data(self, filename: str) -> bool:
        """Import session data from JSON file"""
        try:
            with open(filename, 'r') as f:
                data = json.load(f)
            
            # Import discovered devices
            self.discovered_devices = []
            for device_data in data.get('discovered_devices', []):
                device = BLEDevice(
                    address=device_data['address'],
                    name=device_data['name'],
                    device_type=device_data.get('device_type', 'unknown'),
                    vendor=device_data.get('vendor'),
                    research_potential=device_data.get('research_potential', 0),
                    privacy_enabled=device_data.get('privacy_enabled', False)
                )
                self.discovered_devices.append(device)
            
            # Import profiles
            self.device_profiles = data.get('device_profiles', {})
            self.session_data = data.get('session_data', {})
            
            self.logger.info(f"Session data imported from {filename}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to import session data: {e}")
            return False
    
    async def cleanup(self):
        """Cleanup session resources"""
        self.logger.info("Cleaning up session resources")
        
        # Disconnect all devices
        for device_index in list(self.connected_devices.keys()):
            await self.disconnect_device(device_index)
        
        # Cleanup BLE manager
        await self.ble_manager.cleanup()
        
        self.logger.info("Session cleanup completed")