# main.py - Remove ESP32 specific references
from core.connection_manager import EnhancedBLEManager  # New enhanced version
from exploits.memory_research import MemoryCorruptionResearch  # Generic name!
from config import config
from utils.logging import get_logger

import asyncio
import sys
logger = get_logger(__name__)


class BlueForgeMain:
    def __init__(self):
        self.ble_manager = EnhancedBLEManager()
        self.memory_researcher = MemoryCorruptionResearch()  # Generic!
    
    async def test_framework(self):
        """Test the BlueForge framework"""
        print("""
╔══════════════════════════════════════════════════════════════════════════════════╗
║                    BLUEFORGE MEMORY RESEARCH FRAMEWORK                          ║
║                           RESEARCH USE ONLY                                     ║
╚══════════════════════════════════════════════════════════════════════════════════╝
        """)
        
        # Test BLE scanning
        print("[1/3] Testing BLE scanning...")
        devices = await self.ble_manager.scan(duration=5)
        print(f"[✓] Found {len(devices)} BLE devices")
        
        if not devices:
            print("[⚠] No devices found. Make sure target devices are advertising.")
            return
        
        # Show devices but don't filter for ESP32
        print("\nDiscovered devices:")
        for i, device in enumerate(devices[:5]):  # Show first 5
            print(f"  [{i+1}] {device.name or 'Unknown'} - {device.address}")
        
        # Test target validation
        print("\n[2/3] Testing target validation...")
        target = devices[0]
        print(f"[→] Testing {target.name or 'Unknown'} ({target.address})")
        
        is_valid = await self.memory_researcher.validate_target(target)
        if is_valid:
            print(f"[✓] Target has interesting characteristics for research")
        else:
            print(f"[ℹ] Target doesn't have writable characteristics")
            return
        
        # Test memory research (but warn user!)
        print("\n[3/3] Memory research capability test...")
        print(f"[⚠] WARNING: This is for RESEARCH on devices you OWN ONLY!")
        print(f"[⚠] This may cause the target device to become unresponsive!")
        
        response = input("[?] Continue with research test? (y/N): ")
        if response.lower() != 'y':
            print("[→] Research test skipped")
            return
        
        result = await self.memory_researcher.execute(target.address)
        
        if result['success']:
            print(f"[✓] Memory research completed successfully!")
            print(f"[📊] Tested {result['total_characteristics_tested']} characteristics")
        else:
            print(f"[ℹ] Research completed with issues: {result.get('error', 'Unknown')}")


async def main():
    """Main entry point"""
    blueforge = BlueForgeMain()
    
    if len(sys.argv) > 1:
        if sys.argv[1] == "test":
            await blueforge.test_framework()
        elif sys.argv[1] == "interactive":
            print("Interactive mode not implemented yet")
        else:
            print(f"Unknown command: {sys.argv[1]}")
    else:
        # Default to test mode for now
        await blueforge.test_framework()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[👋] BlueForge terminated by user")
    except Exception as e:
        print(f"[❌] Fatal error: {e}")