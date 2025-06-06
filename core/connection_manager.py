# core/connection_manager.py
import asyncio
import time
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass, field
from enum import Enum
from bleak import BleakClient, BleakScanner
from bleak.exc import BleakError, BleakDeviceNotFoundError
from utils.logging import get_logger
from config import config

logger = get_logger(__name__)

class ConnectionState(Enum):
    """BLE connection states"""
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    RECONNECTING = "reconnecting"
    FAILED = "failed"
    CRASHED = "crashed"

class DeviceType(Enum):
    """Device type classification"""
    ESP32 = "esp32"
    NRF52 = "nrf52"
    STM32 = "stm32"
    UNKNOWN = "unknown"
    AUDIO_DEVICE = "audio"
    MEDICAL_DEVICE = "medical"
    IOT_DEVICE = "iot"

@dataclass
class ConnectionInfo:
    """Information about a BLE connection"""
    address: str
    name: Optional[str] = None
    device_type: DeviceType = DeviceType.UNKNOWN
    state: ConnectionState = ConnectionState.DISCONNECTED
    client: Optional[BleakClient] = None
    last_seen: float = field(default_factory=time.time)
    connection_attempts: int = 0
    successful_connections: int = 0
    crash_count: int = 0
    services: List[str] = field(default_factory=list)
    characteristics: Dict[str, List[str]] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ConnectionEvent:
    """Connection event for logging/callbacks"""
    address: str
    event_type: str  # connected, disconnected, failed, crashed
    timestamp: float = field(default_factory=time.time)
    details: Dict[str, Any] = field(default_factory=dict)

class BlueForgeConnectionManager:
    """Advanced BLE connection manager for security research"""
    
    def __init__(self, max_connections: int = None):
        self.max_connections = max_connections or config.max_connections
        self.connections: Dict[str, ConnectionInfo] = {}
        self.event_callbacks: List[Callable] = []
        self.auto_reconnect = True
        self.reconnect_delay = 3
        self.max_reconnect_attempts = 5
        
        self.logger = get_logger(f"{__name__}.ConnectionManager")
        
        # Connection statistics
        self.stats = {
            'total_connections': 0,
            'successful_connections': 0,
            'failed_connections': 0,
            'crashes_detected': 0,
            'reconnections': 0
        }
    
    def add_event_callback(self, callback: Callable[[ConnectionEvent], None]):
        """Add callback for connection events"""
        self.event_callbacks.append(callback)
    
    def _emit_event(self, address: str, event_type: str, **details):
        """Emit connection event to callbacks"""
        event = ConnectionEvent(address, event_type, details=details)
        for callback in self.event_callbacks:
            try:
                callback(event)
            except Exception as e:
                self.logger.error(f"Event callback failed: {e}")
    
    async def scan_devices(self, duration: int = 10, 
                          filter_func: Optional[Callable] = None) -> List[Dict[str, Any]]:
        """Enhanced device scanning with classification"""
        self.logger.info(f"Scanning for BLE devices (duration: {duration}s)")
        
        try:
            devices = await BleakScanner.discover(timeout=duration)
            discovered = []
            
            for device in devices:
                device_info = {
                    'address': device.address,
                    'name': device.name,
                    'rssi': device.rssi,
                    'device_type': self._classify_device(device),
                    'metadata': device.metadata if hasattr(device, 'metadata') else {}
                }
                
                # Apply filter if provided
                if filter_func is None or filter_func(device_info):
                    discovered.append(device_info)
            
            self.logger.info(f"Discovered {len(discovered)} devices")
            return discovered
            
        except Exception as e:
            self.logger.error(f"Device scanning failed: {e}")
            return []
    
    def _classify_device(self, device) -> DeviceType:
        """Classify device type based on name and characteristics"""
        if not device.name:
            return DeviceType.UNKNOWN
        
        name_lower = device.name.lower()
        
        # Device classification patterns
        if any(keyword in name_lower for keyword in ['esp32', 'esp']):
            return DeviceType.ESP32
        elif any(keyword in name_lower for keyword in ['nordic', 'nrf']):
            return DeviceType.NRF52
        elif any(keyword in name_lower for keyword in ['stm32', 'stm']):
            return DeviceType.STM32
        elif any(keyword in name_lower for keyword in ['headphone', 'speaker', 'audio', 'crusher', 'beats']):
            return DeviceType.AUDIO_DEVICE
        elif any(keyword in name_lower for keyword in ['health', 'medical', 'pulse', 'heart']):
            return DeviceType.MEDICAL_DEVICE
        elif any(keyword in name_lower for keyword in ['smart', 'iot', 'sensor']):
            return DeviceType.IOT_DEVICE
        
        return DeviceType.UNKNOWN
    
    async def connect(self, address: str, force_reconnect: bool = False) -> Optional[BleakClient]:
        """Connect to a BLE device with advanced error handling"""
        
        # Check if already connected
        if address in self.connections:
            conn_info = self.connections[address]
            if conn_info.state == ConnectionState.CONNECTED and not force_reconnect:
                if conn_info.client and conn_info.client.is_connected:
                    self.logger.info(f"Already connected to {address}")
                    return conn_info.client
                else:
                    # State mismatch, update state
                    conn_info.state = ConnectionState.DISCONNECTED
        
        # Check connection limits
        active_connections = len([c for c in self.connections.values() 
                                if c.state == ConnectionState.CONNECTED])
        if active_connections >= self.max_connections:
            self.logger.warning(f"Max connections ({self.max_connections}) reached")
            return None
        
        # Initialize connection info if needed
        if address not in self.connections:
            self.connections[address] = ConnectionInfo(address=address)
        
        conn_info = self.connections[address]
        conn_info.state = ConnectionState.CONNECTING
        conn_info.connection_attempts += 1
        
        self.logger.info(f"Connecting to {address} (attempt {conn_info.connection_attempts})")
        self._emit_event(address, "connecting", attempt=conn_info.connection_attempts)
        
        try:
            # Create client with timeouts
            client = BleakClient(
                address, 
                timeout=config.connection_timeout,
                disconnected_callback=self._on_disconnected
            )
            
            # Attempt connection
            await client.connect()
            
            # Verify connection
            if not client.is_connected:
                raise BleakError("Connection verification failed")
            
            # Update connection info
            conn_info.client = client
            conn_info.state = ConnectionState.CONNECTED
            conn_info.successful_connections += 1
            conn_info.last_seen = time.time()
            
            # Discover services immediately
            await self._discover_services(conn_info)
            
            # Update statistics
            self.stats['total_connections'] += 1
            self.stats['successful_connections'] += 1
            
            self.logger.info(f"Successfully connected to {address}")
            self._emit_event(address, "connected", 
                           services_count=len(conn_info.services),
                           device_type=conn_info.device_type.value)
            
            return client
            
        except BleakDeviceNotFoundError:
            self.logger.error(f"Device {address} not found")
            conn_info.state = ConnectionState.FAILED
            self.stats['failed_connections'] += 1
            self._emit_event(address, "failed", reason="device_not_found")
            return None
            
        except asyncio.TimeoutError:
            self.logger.error(f"Connection to {address} timed out")
            conn_info.state = ConnectionState.FAILED
            self.stats['failed_connections'] += 1
            self._emit_event(address, "failed", reason="timeout")
            return None
            
        except Exception as e:
            self.logger.error(f"Connection to {address} failed: {e}")
            conn_info.state = ConnectionState.FAILED
            self.stats['failed_connections'] += 1
            self._emit_event(address, "failed", reason=str(e))
            return None
    
    async def _discover_services(self, conn_info: ConnectionInfo):
        """Discover and cache services/characteristics"""
        try:
            if not conn_info.client or not conn_info.client.is_connected:
                return
            
            # Use services property instead of get_services() to avoid deprecation
            services = conn_info.client.services
            
            conn_info.services = []
            conn_info.characteristics = {}
            
            for service in services:
                service_uuid = service.uuid
                conn_info.services.append(service_uuid)
                conn_info.characteristics[service_uuid] = []
                
                for char in service.characteristics:
                    conn_info.characteristics[service_uuid].append({
                        'uuid': char.uuid,
                        'properties': char.properties,
                        'handle': char.handle
                    })
            
            self.logger.info(f"Discovered {len(conn_info.services)} services on {conn_info.address}")
            
        except Exception as e:
            self.logger.error(f"Service discovery failed for {conn_info.address}: {e}")
    
    def _on_disconnected(self, client: BleakClient):
        """Handle unexpected disconnections"""
        # Find the connection by client
        for address, conn_info in self.connections.items():
            if conn_info.client == client:
                self.logger.warning(f"Unexpected disconnection from {address}")
                conn_info.state = ConnectionState.DISCONNECTED
                conn_info.client = None
                self._emit_event(address, "disconnected", unexpected=True)
                
                # Schedule auto-reconnect if enabled
                if self.auto_reconnect and conn_info.connection_attempts < self.max_reconnect_attempts:
                    asyncio.create_task(self._auto_reconnect(address))
                break
    
    async def _auto_reconnect(self, address: str):
        """Automatic reconnection logic"""
        if address not in self.connections:
            return
        
        conn_info = self.connections[address]
        conn_info.state = ConnectionState.RECONNECTING
        
        self.logger.info(f"Auto-reconnecting to {address} in {self.reconnect_delay}s")
        await asyncio.sleep(self.reconnect_delay)
        
        # Attempt reconnection
        client = await self.connect(address)
        if client:
            self.stats['reconnections'] += 1
            self._emit_event(address, "reconnected")
        else:
            self.logger.error(f"Auto-reconnection to {address} failed")
    
    async def disconnect(self, address: str) -> bool:
        """Gracefully disconnect from a device"""
        if address not in self.connections:
            self.logger.warning(f"No connection found for {address}")
            return False
        
        conn_info = self.connections[address]
        
        try:
            if conn_info.client and conn_info.client.is_connected:
                await conn_info.client.disconnect()
            
            conn_info.state = ConnectionState.DISCONNECTED
            conn_info.client = None
            
            self.logger.info(f"Disconnected from {address}")
            self._emit_event(address, "disconnected", graceful=True)
            return True
            
        except Exception as e:
            self.logger.error(f"Disconnect from {address} failed: {e}")
            return False
    
    async def disconnect_all(self):
        """Disconnect from all devices"""
        disconnect_tasks = []
        for address in list(self.connections.keys()):
            disconnect_tasks.append(self.disconnect(address))
        
        await asyncio.gather(*disconnect_tasks, return_exceptions=True)
        self.logger.info("Disconnected from all devices")
    
    def get_connection(self, address: str) -> Optional[ConnectionInfo]:
        """Get connection information"""
        return self.connections.get(address)
    
    def get_connected_devices(self) -> List[str]:
        """Get list of connected device addresses"""
        return [addr for addr, conn in self.connections.items() 
                if conn.state == ConnectionState.CONNECTED]
    
    def is_connected(self, address: str) -> bool:
        """Check if device is connected"""
        if address not in self.connections:
            return False
        
        conn_info = self.connections[address]
        return (conn_info.state == ConnectionState.CONNECTED and 
                conn_info.client and 
                conn_info.client.is_connected)
    
    async def monitor_connection_health(self, address: str) -> bool:
        """Monitor connection health by attempting a simple operation"""
        if not self.is_connected(address):
            return False
        
        conn_info = self.connections[address]
        
        try:
            # Try to read device name or any readable characteristic
            services = conn_info.client.services
            
            # Find a readable characteristic
            for service in services:
                for char in service.characteristics:
                    if "read" in char.properties:
                        try:
                            await conn_info.client.read_gatt_char(char.uuid)
                            conn_info.last_seen = time.time()
                            return True
                        except:
                            continue
            
            # If no readable characteristics, connection might be alive but limited
            conn_info.last_seen = time.time()
            return True
            
        except Exception as e:
            self.logger.warning(f"Connection health check failed for {address}: {e}")
            await self._handle_potential_crash(address)
            return False
    
    async def _handle_potential_crash(self, address: str):
        """Handle potential device crash"""
        if address not in self.connections:
            return
        
        conn_info = self.connections[address]
        conn_info.state = ConnectionState.CRASHED
        conn_info.crash_count += 1
        
        self.stats['crashes_detected'] += 1
        
        self.logger.warning(f"Device {address} appears to have crashed (crash #{conn_info.crash_count})")
        self._emit_event(address, "crashed", crash_count=conn_info.crash_count)
        
        # Force disconnect and wait for recovery
        try:
            if conn_info.client:
                await conn_info.client.disconnect()
        except:
            pass
        
        conn_info.client = None
        conn_info.state = ConnectionState.DISCONNECTED
        
        # Wait for device recovery
        await asyncio.sleep(config.device_recovery_delay)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get connection manager statistics"""
        active_connections = len(self.get_connected_devices())
        
        return {
            **self.stats,
            'active_connections': active_connections,
            'total_tracked_devices': len(self.connections),
            'device_types': {
                device_type.value: len([c for c in self.connections.values() 
                                      if c.device_type == device_type])
                for device_type in DeviceType
            }
        }
    
    def get_device_report(self, address: str) -> Optional[Dict[str, Any]]:
        """Get detailed report for a specific device"""
        if address not in self.connections:
            return None
        
        conn_info = self.connections[address]
        
        return {
            'address': conn_info.address,
            'name': conn_info.name,
            'device_type': conn_info.device_type.value,
            'current_state': conn_info.state.value,
            'connection_attempts': conn_info.connection_attempts,
            'successful_connections': conn_info.successful_connections,
            'crash_count': conn_info.crash_count,
            'last_seen': conn_info.last_seen,
            'services_count': len(conn_info.services),
            'total_characteristics': sum(len(chars) for chars in conn_info.characteristics.values()),
            'services': conn_info.services,
            'characteristics': conn_info.characteristics,
            'metadata': conn_info.metadata
        }

# Enhanced BLE Manager that uses the connection manager
class EnhancedBLEManager:
    """Enhanced BLE manager with advanced connection management"""
    
    def __init__(self):
        self.connection_manager = BlueForgeConnectionManager()
        self.logger = get_logger(f"{__name__}.EnhancedBLEManager")
        
        # Add event logging
        self.connection_manager.add_event_callback(self._log_connection_event)
    
    def _log_connection_event(self, event: ConnectionEvent):
        """Log connection events"""
        self.logger.info(f"Connection event: {event.event_type} for {event.address}")
    
    async def scan(self, duration: int = 10, filter_esp32: bool = False) -> List[Any]:
        """Enhanced scanning with filtering"""
        filter_func = None
        
        if filter_esp32:
            filter_func = lambda device: device['device_type'] == DeviceType.ESP32
        
        devices = await self.connection_manager.scan_devices(duration, filter_func)
        
        # Convert to compatible format for existing code
        class DeviceInfo:
            def __init__(self, data):
                self.address = data['address']
                self.name = data['name']
                self.rssi = data['rssi']
        
        return [DeviceInfo(device) for device in devices]
    
    async def connect(self, address: str) -> Optional[BleakClient]:
        """Enhanced connection with automatic management"""
        return await self.connection_manager.connect(address)
    
    async def disconnect(self, address: str) -> bool:
        """Enhanced disconnection"""
        return await self.connection_manager.disconnect(address)
    
    def get_connected_devices(self) -> List[str]:
        """Get connected devices"""
        return self.connection_manager.get_connected_devices()
    
    def is_connected(self, address: str) -> bool:
        """Check connection status"""
        return self.connection_manager.is_connected(address)
    
    async def cleanup(self):
        """Cleanup all connections"""
        await self.connection_manager.disconnect_all()