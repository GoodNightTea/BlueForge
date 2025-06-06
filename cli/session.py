# cli/session.py
from datetime import datetime
from typing import Optional, List
from core.connection_manager import EnhancedBLEManager
from core.fuzzing_engine import AdvancedFuzzingEngine
from exploits.memory_research import MemoryCorruptionResearch

class BlueForgeSession:
    """Manages active BlueForge session state"""
    
    def __init__(self):
        self.ble_manager = EnhancedBLEManager()
        self.fuzzer = AdvancedFuzzingEngine()
        
        # Create researcher with shared BLE manager
        self.researcher = MemoryCorruptionResearch(ble_manager=self.ble_manager)
        
        self.discovered_devices = []
        self.connected_devices = {}
        self.session_stats = {
            'scans_performed': 0,
            'devices_tested': 0,
            'vulnerabilities_found': 0,
            'session_start': datetime.now()
        }
    
    def get_device_from_args_or_active(self, args: List[str]) -> Optional[int]:
        """Get device index from args or return active device if only one connected"""
        if args:
            try:
                index = int(args[0])
                if 0 <= index < len(self.discovered_devices):
                    return index
                else:
                    return None
            except (ValueError, IndexError):
                return None
        
        # If no args and only one device connected, use it
        if len(self.connected_devices) == 1:
            return list(self.connected_devices.keys())[0]
        
        return None

    def get_active_device_index(self) -> Optional[int]:
        """Get the active device index (if only one connected)"""
        if len(self.connected_devices) == 1:
            return list(self.connected_devices.keys())[0]
        return None