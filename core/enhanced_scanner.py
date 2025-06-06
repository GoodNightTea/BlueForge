# core/enhanced_scanner.py
import asyncio
import time
from typing import List, Dict, Optional, Callable
from bleak import BleakScanner
from bleak.backends.scanner import AdvertisementData
from utils.logging import get_logger

logger = get_logger(__name__)

class EnhancedBLEScanner:
    """Advanced BLE scanner with better device discovery"""
    
    def __init__(self):
        self.discovered_devices = {}
        self.scan_filters = {}
        self.passive_scan = True  # Better for discovering more devices
        
    async def comprehensive_scan(self, duration: int = 30, 
                               extended_discovery: bool = True) -> List[Dict]:
        """Comprehensive scanning with multiple strategies"""
        
        logger.info(f"Starting comprehensive BLE scan (duration: {duration}s)")
        
        all_devices = {}
        
        # Strategy 1: Passive scanning (better device discovery)
        logger.info("Phase 1: Passive scanning...")
        passive_devices = await self._passive_scan(duration // 3)
        self._merge_devices(all_devices, passive_devices)
        
        # Strategy 2: Active scanning with service filters
        logger.info("Phase 2: Active scanning with service filters...")
        active_devices = await self._active_scan_with_filters(duration // 3)
        self._merge_devices(all_devices, active_devices)
        
        # Strategy 3: Extended discovery for stubborn devices
        if extended_discovery:
            logger.info("Phase 3: Extended discovery scan...")
            extended_devices = await self._extended_discovery_scan(duration // 3)
            self._merge_devices(all_devices, extended_devices)
        
        logger.info(f"Comprehensive scan complete: {len(all_devices)} unique devices")
        return list(all_devices.values())
    
    async def _passive_scan(self, duration: int) -> Dict[str, Dict]:
        """Passive scanning - better for discovering Android/iOS devices"""
        devices = {}
        
        def detection_callback(device, advertisement_data):
            device_info = self._create_device_info(device, advertisement_data)
            devices[device.address] = device_info
            logger.debug(f"Passive scan found: {device.name or 'Unknown'} ({device.address})")
        
        try:
            scanner = BleakScanner(detection_callback)
            await scanner.start()
            await asyncio.sleep(duration)
            await scanner.stop()
        except Exception as e:
            logger.error(f"Passive scan failed: {e}")
        
        return devices
    
    async def _active_scan_with_filters(self, duration: int) -> Dict[str, Dict]:
        """Active scanning with service UUID filters"""
        devices = {}
        
        # Common service UUIDs that smartphones might advertise
        service_filters = [
            "0000180F-0000-1000-8000-00805F9B34FB",  # Battery Service
            "0000180A-0000-1000-8000-00805F9B34FB",  # Device Information
            "0000181C-0000-1000-8000-00805F9B34FB",  # User Data Service
            "6E400001-B5A3-F393-E0A9-E50E24DCCA9E",  # Nordic UART
        ]
        
        for service_uuid in service_filters:
            try:
                logger.debug(f"Scanning for service: {service_uuid}")
                discovered = await BleakScanner.discover(
                    timeout=duration / len(service_filters),
                    service_uuids=[service_uuid]
                )
                
                for device in discovered:
                    device_info = self._create_device_info(device, None)
                    devices[device.address] = device_info
                    
            except Exception as e:
                logger.debug(f"Service filter scan failed for {service_uuid}: {e}")
        
        return devices
    
    async def _extended_discovery_scan(self, duration: int) -> Dict[str, Dict]:
        """Extended discovery for devices with privacy features"""
        devices = {}
        
        # Multiple short scans can catch devices with MAC rotation
        scan_rounds = 6
        round_duration = duration / scan_rounds
        
        for round_num in range(scan_rounds):
            logger.debug(f"Extended scan round {round_num + 1}/{scan_rounds}")
            
            try:
                discovered = await BleakScanner.discover(timeout=round_duration)
                
                for device in discovered:
                    device_info = self._create_device_info(device, None)
                    devices[device.address] = device_info
                    
                # Small delay between rounds
                await asyncio.sleep(0.5)
                
            except Exception as e:
                logger.debug(f"Extended scan round {round_num + 1} failed: {e}")
        
        return devices
    
    def _create_device_info(self, device, advertisement_data) -> Dict:
        """Create comprehensive device information"""
        
        # Enhanced device classification
        device_type = self._classify_device_advanced(device, advertisement_data)
        
        device_info = {
            'address': device.address,
            'name': device.name or 'Unknown Device',
            'rssi': getattr(device, 'rssi', None),
            'device_type': device_type,
            'manufacturer_data': {},
            'service_data': {},
            'service_uuids': [],
            'local_name': None,
            'tx_power': None,
            'first_seen': time.time(),
            'last_seen': time.time(),
            'scan_count': 1,
        }
        
        # Extract advertisement data if available
        if advertisement_data:
            device_info.update({
                'manufacturer_data': dict(advertisement_data.manufacturer_data),
                'service_data': dict(advertisement_data.service_data),
                'service_uuids': list(advertisement_data.service_uuids),
                'local_name': advertisement_data.local_name,
                'tx_power': advertisement_data.tx_power,
            })
        
        return device_info
    
    def _classify_device_advanced(self, device, advertisement_data) -> str:
        """Advanced device classification for smartphones and other devices"""
        
        if not device.name:
            # Check manufacturer data for identification
            if advertisement_data and advertisement_data.manufacturer_data:
                # Apple devices (Company ID: 0x004C)
                if 0x004C in advertisement_data.manufacturer_data:
                    return "apple_device"
                # Samsung devices (Company ID: 0x0075)
                elif 0x0075 in advertisement_data.manufacturer_data:
                    return "samsung_device"
                # Google devices (Company ID: 0x00E0)
                elif 0x00E0 in advertisement_data.manufacturer_data:
                    return "google_device"
            
            return "unknown_smartphone_candidate"
        
        name_lower = device.name.lower()
        
        # Smartphone identification patterns
        if any(keyword in name_lower for keyword in ['iphone', 'ipad', 'apple']):
            return "apple_device"
        elif any(keyword in name_lower for keyword in ['samsung', 'galaxy', 'sm-']):
            return "samsung_device"
        elif any(keyword in name_lower for keyword in ['pixel', 'android']):
            return "android_device"
        elif any(keyword in name_lower for keyword in ['esp32', 'esp']):
            return "esp32_target"
        elif any(keyword in name_lower for keyword in ['arduino', 'nano']):
            return "microcontroller_target"
        
        return "unknown_device"
    
    def _merge_devices(self, target_dict: Dict, source_dict: Dict):
        """Merge device discoveries, updating existing entries"""
        for address, device_info in source_dict.items():
            if address in target_dict:
                # Update existing device
                target_dict[address]['last_seen'] = device_info['last_seen']
                target_dict[address]['scan_count'] += 1
                
                # Update RSSI if new value is available
                if device_info['rssi'] is not None:
                    target_dict[address]['rssi'] = device_info['rssi']
                
                # Merge additional data
                target_dict[address]['manufacturer_data'].update(device_info['manufacturer_data'])
                target_dict[address]['service_data'].update(device_info['service_data'])
                
                # Merge service UUIDs
                existing_uuids = set(target_dict[address]['service_uuids'])
                new_uuids = set(device_info['service_uuids'])
                target_dict[address]['service_uuids'] = list(existing_uuids | new_uuids)
                
            else:
                target_dict[address] = device_info