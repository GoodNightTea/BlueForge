# test.py - Test your new modular framework
import asyncio
from cli.blueforge_cli import BlueForgeInteractiveCLI

async def test_new_framework():
    print("🔥 Testing New Modular BlueForge Framework 🔥\n")
    
    # Initialize CLI
    cli = BlueForgeInteractiveCLI()
    
    # Test scan
    print("[1/3] Testing scan...")
    await cli.cmd_scan([])
    
    # Test device listing
    print("\n[2/3] Testing device listing...")
    cli.cmd_devices([])
    
    # Test connection (if devices found)
    if cli.session.discovered_devices:
        print(f"\n[3/3] Testing connection to first device...")
        await cli.cmd_connect(["0"])
        
        if cli.session.connected_devices:
            print("✓ Connection successful!")
            
            # Test service discovery
            await cli.cmd_services(["0"])
    
    print("\n🎉 New framework test complete!")

if __name__ == "__main__":
    asyncio.run(test_new_framework())