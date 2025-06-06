# cli/commands/discovery.py
import asyncio
from datetime import datetime
from .base import BaseCommands

class DiscoveryCommands(BaseCommands):
    """Commands for device discovery and connection management"""
    
    def get_commands(self):
        return {
            'scan': self.cmd_scan,
            'scan-comprehensive': self.cmd_scan_comprehensive,
            'devices': self.cmd_devices,
            'connect': self.cmd_connect,
            'smart-connect': self.cmd_smart_connect,
            'connected': self.cmd_connected,
            'disconnect': self.cmd_disconnect,
        }
    
    async def cmd_scan(self, args):
        """Scan for BLE devices"""
        self.print_info("🔍 Scanning for BLE devices...")
        
        try:
            devices = await self.session.ble_manager.scan(duration=10)
            
            if not devices:
                self.print_warning("No devices found")
                return
                
            self.session.discovered_devices = devices
            self.print_success(f"Found {len(devices)} devices:")
            
            for i, device in enumerate(devices):
                rssi_str = f"RSSI: {device.rssi}" if hasattr(device, 'rssi') else "RSSI: Unknown"
                device_name = device.name if hasattr(device, 'name') else "Unknown"
                device_addr = device.address if hasattr(device, 'address') else "Unknown"
                print(f"  [{i:2d}] {device_name} ({device_addr}) - {rssi_str}")
                
        except Exception as e:
            self.print_error(f"Scan failed: {e}")

    async def cmd_scan_comprehensive(self, args):
        """Comprehensive scanning with enhanced discovery"""
        duration = 30  # Default longer duration
        if args:
            try:
                duration = int(args[0])
            except ValueError:
                self.print_error("Invalid duration. Using default (30s)")
        
        self.print_info(f"🔍 Starting comprehensive BLE scan ({duration}s)...")
        
        try:
            from core.enhanced_scanner import EnhancedBLEScanner
            scanner = EnhancedBLEScanner()
            devices_data = await scanner.comprehensive_scan(duration, extended_discovery=True)
            
            if not devices_data:
                self.print_warning("No devices found")
                return
            
            # Convert to compatible format
            class DeviceInfo:
                def __init__(self, data):
                    self.address = data['address']
                    self.name = data['name']
                    self.rssi = data['rssi']
                    self.device_type = data.get('device_type', 'unknown')
                    self.manufacturer_data = data.get('manufacturer_data', {})
                    self.service_data = data.get('service_data', {})
                    self.service_uuids = data.get('service_uuids', [])
            
            devices = [DeviceInfo(data) for data in devices_data]
            self.session.discovered_devices = devices
            
            self.print_success(f"Comprehensive scan found {len(devices)} devices:")
            
            # Enhanced display with device classification
            for i, device in enumerate(devices):
                device_type_icon = self._get_device_icon(device.device_type)
                rssi_str = f"RSSI: {device.rssi}" if device.rssi else "RSSI: Unknown"
                manufacturer_info = self._get_manufacturer_info(device.manufacturer_data)
                
                print(f"  [{i:2d}] {device_type_icon} {device.name} ({device.address}) - {rssi_str} {manufacturer_info}")
            
            self.session.session_stats['scans_performed'] += 1
            
        except Exception as e:
            self.print_error(f"Comprehensive scan failed: {e}")

    def cmd_devices(self, args):
        """List discovered devices"""
        if not self.session.discovered_devices:
            self.print_warning("No devices discovered. Run 'scan' first")
            return
        
        print(f"{self.colors.BOLD}Discovered Devices ({len(self.session.discovered_devices)}):{self.colors.ENDC}")
        
        for i, device in enumerate(self.session.discovered_devices):
            # Check if connected
            is_connected = any(conn['device'].address == device.address 
                            for conn in self.session.connected_devices.values())
            
            status = f"{self.colors.OKGREEN}[CONNECTED]{self.colors.ENDC}" if is_connected else ""
            rssi_str = f"RSSI: {device.rssi}" if hasattr(device, 'rssi') else "RSSI: Unknown"
            
            print(f"  [{i:2d}] {device.name} ({device.address}) - {rssi_str} {status}")

    async def cmd_connect(self, args):
        """Connect to a device"""
        if not args:
            self.print_error("Usage: connect <device_index>")
            return
        
        try:
            device_index = int(args[0])
            if device_index >= len(self.session.discovered_devices):
                self.print_error("Invalid device index")
                return
                
            device = self.session.discovered_devices[device_index]
            
            self.print_info(f"🔗 Connecting to {device.name} ({device.address})...")
            
            client = await self.session.ble_manager.connect(device.address)
            
            if client:
                self.session.connected_devices[device_index] = {
                    'device': device,
                    'client': client,
                    'connected_at': datetime.now()
                }
                self.print_success(f"Successfully connected to {device.address}")
            else:
                self.print_error("Failed to connect")
                
        except (ValueError, IndexError):
            self.print_error("Invalid device index")
        except Exception as e:
            self.print_error(f"Connection error: {e}")

    async def cmd_smart_connect(self, args):
        """Smart connection using device-specific strategies"""
        index = self.get_device_from_args_or_active(args)
        
        if index is None or index >= len(self.session.discovered_devices):
            self.print_error("Invalid device index")
            return
        
        device = self.session.discovered_devices[index]
        
        # Get device strategy first
        device_dict = {'name': device.name, 'address': device.address}
        from core.device_profiler import DeviceProfiler
        profiler = DeviceProfiler()
        strategy = profiler._suggest_connection_strategy(device_dict)
        
        self.print_info(f"🔗 Smart connecting to {device.name} using '{strategy['approach']}' strategy...")
        
        if strategy['special_considerations']:
            self.print_warning("Special considerations:")
            for consideration in strategy['special_considerations']:
                print(f"    • {consideration}")
        
        # Attempt connection using the profiler's smart connect
        device_dict = {
            'address': device.address,
            'name': device.name,
            'device_type': getattr(device, 'device_type', 'unknown')
        }
        
        client = await profiler._smart_connect(device_dict, strategy['timeout'])
        
        if client:
            self.session.connected_devices[index] = {
                'device': device,
                'client': client,
                'connected_at': datetime.now(),
                'strategy_used': strategy['approach']
            }
            self.print_success(f"Successfully connected using {strategy['approach']} strategy")
        else:
            self.print_error("Connection failed despite optimized strategy")
            if strategy['expected_challenges']:
                self.print_warning("Expected challenges:")
                for challenge in strategy['expected_challenges']:
                    print(f"    • {challenge}")

    def cmd_connected(self, args):
        """Show connected devices"""
        if not self.session.connected_devices:
            self.print_warning("No devices currently connected")
            return
        
        print(f"{self.colors.OKGREEN}Connected Devices ({len(self.session.connected_devices)}):{self.colors.ENDC}")
        for index, conn_info in self.session.connected_devices.items():
            device = conn_info['device']
            connected_at = conn_info['connected_at'].strftime("%H:%M:%S")
            print(f"  [{index}] {device.name} ({device.address}) - Connected at {connected_at}")

    async def cmd_disconnect(self, args):
        """Disconnect from a device"""
        index = self.get_device_from_args_or_active(args)
        
        if index is None:
            if not args and len(self.session.connected_devices) > 1:
                self.print_error("Multiple devices connected. Specify index: disconnect <device_index>")
            elif not args and len(self.session.connected_devices) == 0:
                self.print_error("No devices connected")
            else:
                self.print_error("Usage: disconnect [device_index]")
            return
        
        if index not in self.session.connected_devices:
            self.print_error("Device not connected")
            return
        
        device_info = self.session.connected_devices[index]
        device = device_info['device']
        
        self.print_info(f"📤 Disconnecting from {device.name or 'Unknown'}...")
        
        try:
            success = await self.session.ble_manager.disconnect(device.address)
            if success:
                del self.session.connected_devices[index]
                self.print_success("Disconnected successfully")
            else:
                self.print_error("Disconnect failed")
        except Exception as e:
            self.print_error(f"Disconnect error: {e}")

    def _get_device_icon(self, device_type: str) -> str:
        """Get emoji icon for device type"""
        icons = {
            'apple_device': '🍎',
            'samsung_device': '📱',
            'android_device': '🤖',
            'esp32_target': '🎯',
            'microcontroller_target': '🔧',
            'flipper_device': '🐬',
            'audio_device': '🎵',
            'unknown_smartphone_candidate': '📲',
            'unknown_device': '❓'
        }
        return icons.get(device_type, '📱')

    def _get_manufacturer_info(self, manufacturer_data: dict) -> str:
        """Get brief manufacturer info for display"""
        if not manufacturer_data:
            return ""
        
        known_manufacturers = {
            0x004C: "[Apple]",
            0x0075: "[Samsung]",
            0x00E0: "[Google]",
            0x0590: "[Espressif]",
            0x03DA: "[Flipper]"
        }
        
        for company_id in manufacturer_data:
            if company_id in known_manufacturers:
                return known_manufacturers[company_id]
        
        return f"[Mfg:0x{list(manufacturer_data.keys())[0]:04X}]"