# cli/commands/advanced.py
import time
import json
from .base import BaseCommands

class AdvancedCommands(BaseCommands):
    """Advanced commands for batch operations and data management"""
    
    def get_commands(self):
        return {
            'profile-batch': self.cmd_profile_batch,
            'export-profiles': self.cmd_export_profiles,
            'load-targets': self.cmd_load_targets,
        }
    
    async def cmd_profile_batch(self, args):
        """Batch profile multiple devices"""
        if not self.session.discovered_devices:
            self.print_warning("No devices discovered. Run 'scan' first")
            return
        
        self.print_info(f"🔍 Starting batch profiling of {len(self.session.discovered_devices)} devices...")
        
        from core.device_profiler import DeviceProfiler
        profiler = DeviceProfiler()
        
        high_value_targets = []
        
        for i, device in enumerate(self.session.discovered_devices):
            device_dict = {
                'address': device.address,
                'name': device.name,
                'rssi': getattr(device, 'rssi', None),
                'device_type': getattr(device, 'device_type', 'unknown'),
                'manufacturer_data': getattr(device, 'manufacturer_data', {}),
                'service_data': getattr(device, 'service_data', {}),
                'service_uuids': getattr(device, 'service_uuids', [])
            }
            
            profile = await profiler.profile_device_quick(device_dict)
            research_score = profile.get('research_potential', {}).get('overall_score', 0)
            
            if research_score >= 7:
                high_value_targets.append((i, device, profile))
                print(f"  🎯 [{i}] {device.name or 'Unknown'} - Score: {research_score}/10")
            elif research_score >= 4:
                print(f"  ⚠️  [{i}] {device.name or 'Unknown'} - Score: {research_score}/10")
            else:
                print(f"  ❌ [{i}] {device.name or 'Unknown'} - Score: {research_score}/10")
        
        self.print_success("Batch profiling complete")
        print(f"High-value targets: {len(high_value_targets)}")
        
        if high_value_targets:
            print(f"\n{self.colors.WARNING}Recommended targets for research:{self.colors.ENDC}")
            for i, device, profile in high_value_targets:
                target_type = profile.get('research_potential', {}).get('target_type', 'unknown')
                print(f"  [{i}] {device.name} - {target_type}")

    async def cmd_export_profiles(self, args):
        """Export device profiles to file"""
        if not self.session.discovered_devices:
            self.print_warning("No devices to export. Run 'scan' first")
            return
        
        filename = args[0] if args else f"blueforge_profiles_{int(time.time())}.json"
        
        self.print_info(f"📤 Exporting device profiles to {filename}...")
        
        try:
            from core.device_profiler import DeviceProfiler
            profiler = DeviceProfiler()
            
            export_data = {
                'scan_timestamp': time.time(),
                'total_devices': len(self.session.discovered_devices),
                'profiles': []
            }
            
            for i, device in enumerate(self.session.discovered_devices):
                device_dict = {
                    'address': device.address,
                    'name': device.name,
                    'rssi': getattr(device, 'rssi', None),
                    'device_type': getattr(device, 'device_type', 'unknown'),
                    'manufacturer_data': getattr(device, 'manufacturer_data', {}),
                    'service_data': getattr(device, 'service_data', {}),
                    'service_uuids': getattr(device, 'service_uuids', [])
                }
                
                profile = await profiler.profile_device_quick(device_dict)
                profile['scan_index'] = i
                export_data['profiles'].append(profile)
            
            with open(filename, 'w') as f:
                json.dump(export_data, f, indent=2, default=str)
            
            self.print_success(f"Exported {len(export_data['profiles'])} device profiles to {filename}")
            
        except Exception as e:
            self.print_error(f"Export failed: {e}")

    async def cmd_load_targets(self, args):
        """Load target list from file"""
        if not args:
            self.print_error("Usage: load-targets <filename>")
            return
        
        filename = args[0]
        
        try:
            with open(filename, 'r') as f:
                data = json.load(f)
            
            if 'profiles' in data:
                # Loading exported profiles
                self.print_info(f"📥 Loading device profiles from {filename}...")
                
                loaded_devices = []
                for profile_data in data['profiles']:
                    basic_info = profile_data.get('basic_info', {})
                    
                    class MockDevice:
                        def __init__(self, info):
                            self.address = info.get('address', 'Unknown')
                            self.name = info.get('name', 'Unknown')
                            self.rssi = info.get('rssi', None)
                            self.device_type = info.get('device_type', 'unknown')
                    
                    device = MockDevice(basic_info)
                    loaded_devices.append(device)
                
                self.session.discovered_devices = loaded_devices
                self.print_success(f"Loaded {len(loaded_devices)} devices from profile export")
                
            elif 'targets' in data:
                # Loading target list
                self.print_info(f"📥 Loading target list from {filename}...")
                
                loaded_devices = []
                for target in data['targets']:
                    class MockDevice:
                        def __init__(self, target_info):
                            self.address = target_info.get('address', 'Unknown')
                            self.name = target_info.get('name', 'Unknown')
                            self.rssi = target_info.get('rssi', None)
                            self.device_type = target_info.get('type', 'unknown')
                    
                    device = MockDevice(target)
                    loaded_devices.append(device)
                
                self.session.discovered_devices = loaded_devices
                self.print_success(f"Loaded {len(loaded_devices)} targets from target list")
            
            else:
                self.print_error("Invalid file format. Expected 'profiles' or 'targets' key")
                
        except FileNotFoundError:
            self.print_error(f"File not found: {filename}")
        except json.JSONDecodeError:
            self.print_error(f"Invalid JSON format in {filename}")
        except Exception as e:
            self.print_error(f"Load failed: {e}")