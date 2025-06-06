# server/api_server.py
import asyncio
import json
from ..exploits.memory_research import EnhancedBLEManager
from ..utils.logging import get_logger

logger = get_logger(__name__)

class BlueForgeAPI:
    def __init__(self):
        self.exploit_esp32 = EnhancedBLEManager()
        self.running = False
    
    async def scan_esp32_targets(self, duration=10):
        """API endpoint: Scan for ESP32 targets"""
        try:
            targets = await self.esp32_exploit.scan_targets(duration)
            return {
                "success": True,
                "targets": [{"name": d.name, "address": d.address, "rssi": d.rssi} for d in targets]
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def exploit_esp32(self, target_address):
        """API endpoint: Exploit ESP32 device"""
        try:
            result = await self.esp32_exploit.execute(target_address)
            return result
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def get_status(self):
        """API endpoint: Get server status"""
        return {
            "success": True,
            "status": "running" if self.running else "stopped",
            "connected_devices": self.esp32_exploit.ble_manager.get_connected_devices()
        }