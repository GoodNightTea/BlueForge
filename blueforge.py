#!/usr/bin/env python3
# blueforge.py - Main launcher
import sys
import os
import asyncio

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from cli.blueforge_cli import main
    
    if __name__ == "__main__":
        asyncio.run(main())
        
except ImportError as e:
    print(f"❌ Import error: {e}")
    print("Make sure you're in the BlueForge directory and have installed dependencies")
    sys.exit(1)
except Exception as e:
    print(f"❌ Error starting BlueForge: {e}")
    sys.exit(1)