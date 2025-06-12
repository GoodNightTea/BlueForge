#!/usr/bin/env python3
# verify_setup.py - BlueForge Installation Verification Script

import sys
import os
import importlib
from pathlib import Path

def check_file_structure():
    """Verify all required files are present"""
    print("🔍 Checking file structure...")
    
    required_files = [
        "blueforge.py",
        "config.py", 
        "requirements.txt",
        "setup.py",
        "README.md",
        ".gitignore"
    ]
    
    required_dirs = [
        "core",
        "security", 
        "exploits",
        "cli",
        "utils"
    ]
    
    missing_files = []
    missing_dirs = []
    
    for file in required_files:
        if not Path(file).exists():
            missing_files.append(file)
    
    for dir in required_dirs:
        if not Path(dir).exists():
            missing_dirs.append(dir)
    
    if missing_files:
        print(f"❌ Missing files: {', '.join(missing_files)}")
        return False
    
    if missing_dirs:
        print(f"❌ Missing directories: {', '.join(missing_dirs)}")
        return False
    
    print("✅ All required files and directories present")
    return True

def check_python_version():
    """Check Python version"""
    print("🐍 Checking Python version...")
    
    if sys.version_info < (3, 8):
        print(f"❌ Python 3.8+ required, found {sys.version}")
        return False
    
    print(f"✅ Python {sys.version.split()[0]}")
    return True

def check_module_imports():
    """Test importing all BlueForge modules"""
    print("📦 Checking module imports...")
    
    modules_to_test = [
        "config",
        "core.ble_manager",
        "core.device_intelligence", 
        "core.session_manager",
        "security.vurnerability_scanner",
        "security.fuzzing_engine",
        "security.payloads",
        "exploits.memory_corruption",
        "exploits.protocol_attacks",
        "exploits.timing_attacks",
        "cli.interface",
        "cli.display",
        "cli.commands",
        "utils.helpers",
        "utils.logging"
    ]
    
    failed_imports = []
    
    for module in modules_to_test:
        try:
            importlib.import_module(module)
            print(f"  ✅ {module}")
        except ImportError as e:
            print(f"  ❌ {module}: {e}")
            failed_imports.append(module)
        except Exception as e:
            print(f"  ⚠️  {module}: {e}")
    
    if failed_imports:
        print(f"\n❌ Failed to import: {', '.join(failed_imports)}")
        return False
    
    print("✅ All modules imported successfully")
    return True

def check_dependencies():
    """Check for required dependencies"""
    print("📚 Checking dependencies...")
    
    required_packages = [
        "bleak",
        "asyncio"
    ]
    
    missing_packages = []
    
    for package in required_packages:
        try:
            importlib.import_module(package)
            print(f"  ✅ {package}")
        except ImportError:
            print(f"  ❌ {package}")
            missing_packages.append(package)
    
    if missing_packages:
        print(f"\n❌ Missing packages: {', '.join(missing_packages)}")
        print("Run: pip install -r requirements.txt")
        return False
    
    print("✅ All required dependencies available")
    return True

def test_basic_functionality():
    """Test basic BlueForge functionality"""
    print("🧪 Testing basic functionality...")
    
    try:
        # Test config loading
        from config import get_config_manager
        config_manager = get_config_manager()
        config = config_manager.get_config()
        print(f"  ✅ Configuration loaded (version: {config.version})")
        
        # Test display manager
        from cli.display import DisplayManager
        display = DisplayManager()
        print("  ✅ Display manager initialized")
        
        # Test device intelligence
        from core.device_intelligence import DeviceIntelligence
        intel = DeviceIntelligence()
        print("  ✅ Device intelligence initialized")
        
        # Test vulnerability scanner
        from security.vurnerability_scanner import VulnerabilityScanner
        scanner = VulnerabilityScanner()
        print("  ✅ Vulnerability scanner initialized")
        
        # Test exploit engines
        from exploits.memory_corruption import MemoryCorruptionExploit
        from exploits.protocol_attacks import ProtocolAttackEngine
        from exploits.timing_attacks import TimingExploitEngine
        
        mem_exploit = MemoryCorruptionExploit()
        proto_exploit = ProtocolAttackEngine()
        timing_exploit = TimingExploitEngine()
        print("  ✅ Exploit engines initialized")
        
        print("✅ Basic functionality test passed")
        return True
        
    except Exception as e:
        print(f"  ❌ Functionality test failed: {e}")
        return False

def main():
    """Main verification function"""
    print("🔒 BlueForge Installation Verification")
    print("=" * 50)
    
    checks = [
        check_python_version,
        check_file_structure,
        check_dependencies,
        check_module_imports,
        test_basic_functionality
    ]
    
    all_passed = True
    
    for check in checks:
        try:
            if not check():
                all_passed = False
        except Exception as e:
            print(f"❌ Check failed with exception: {e}")
            all_passed = False
        print()
    
    print("=" * 50)
    if all_passed:
        print("🎉 All verification checks passed!")
        print("✅ BlueForge is ready to use")
        print("")
        print("🚀 To start BlueForge:")
        print("   python blueforge.py")
        print("")
        print("📚 For help:")
        print("   python blueforge.py --help")
        return 0
    else:
        print("❌ Some verification checks failed")
        print("Please fix the issues above before using BlueForge")
        return 1

if __name__ == "__main__":
    sys.exit(main())