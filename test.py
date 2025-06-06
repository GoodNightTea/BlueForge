# test_complete_setup.py
import asyncio
import sys
import os

# Add current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

async def test_blueforge():
    print("🔥 Testing Complete BlueForge Setup 🔥\n")
    
    # Test 1: Basic Imports
    print("[1/5] Testing imports...")
    try:
        from config import config
        from utils.logging import get_logger
        from core.connection_manager import EnhancedBLEManager, BlueForgeConnectionManager
        from core.fuzzing_engine import AdvancedFuzzingEngine
        from exploits.memory_research import MemoryCorruptionResearch
        print("✓ All imports successful")
    except Exception as e:
        print(f"✗ Import failed: {e}")
        return
    
    # Test 2: Initialize Components
    print("\n[2/5] Testing component initialization...")
    try:
        logger = get_logger(__name__)
        ble_manager = EnhancedBLEManager()
        fuzzer = AdvancedFuzzingEngine()
        researcher = MemoryCorruptionResearch()
        print("✓ All components initialized")
    except Exception as e:
        print(f"✗ Initialization failed: {e}")
        return
    
    # Test 3: Quick BLE Scan
    print("\n[3/5] Testing BLE scanning...")
    try:
        devices = await ble_manager.scan(duration=3)
        print(f"✓ BLE scan successful - found {len(devices)} devices")
        if devices:
            for i, device in enumerate(devices[:3]):
                print(f"  [{i+1}] {device.name or 'Unknown'} - {device.address}")
    except Exception as e:
        print(f"✗ BLE scan failed: {e}")
    
    # Test 4: Connection Manager Stats
    print("\n[4/5] Testing connection manager...")
    try:
        stats = ble_manager.connection_manager.get_statistics()
        print(f"✓ Connection manager working - Stats: {stats}")
    except Exception as e:
        print(f"✗ Connection manager failed: {e}")
    
    # Test 5: Fuzzing Engine
    print("\n[5/5] Testing fuzzing engine...")
    try:
        generator = fuzzer.payload_generator
        patterns = generator.hex_patterns()
        print(f"✓ Fuzzing engine working - Generated {len(patterns)} attack patterns")
        print(f"  Sample pattern: {patterns[0].hex()}")
    except Exception as e:
        print(f"✗ Fuzzing engine failed: {e}")
    
    print("\n🎉 BlueForge setup test complete!")
    print("If you see checkmarks above, your framework is ready!")

if __name__ == "__main__":
    asyncio.run(test_blueforge())