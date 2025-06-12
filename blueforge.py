
#!/usr/bin/env python3
# blueforge.py - BlueForge Main Entry Point
"""
BlueForge v2.0.0 - Advanced BLE Security Research Framework

A comprehensive BLE security testing and exploitation framework designed for 
security researchers, penetration testers, and IoT security professionals.

Features:
- Advanced BLE device discovery and analysis
- Comprehensive vulnerability scanning
- Memory corruption exploit framework
- Protocol-level attack capabilities  
- Precision timing attack engine
- Device intelligence and classification
- Session management and reporting

Usage:
    python blueforge.py [options]

Environment Variables:
    BLUEFORGE_DEBUG=1           Enable debug mode
    BLUEFORGE_VERBOSE=verbose   Set verbosity level
    BLUEFORGE_SCAN_TIMEOUT=15   Override scan timeout
    BLUEFORGE_SCAN_INTENSITY=moderate  Override scan intensity

Authors: BlueForge Security Research Team
License: Research Use Only
"""

import sys
import os
import asyncio
import argparse
import signal
from pathlib import Path
from typing import Optional

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

# Core imports
from config import get_config_manager, setup_logging, apply_env_overrides
from cli.interface import BlueForgeInterface
from utils.logging import get_logger

# Version information
__version__ = "2.1.0"
__author__ = "BlueForge Security Research Team"
__license__ = "Research Use Only"

logger = get_logger(__name__)

def setup_signal_handlers():
    """Setup signal handlers for graceful shutdown"""
    def signal_handler(signum, frame):
        print(f"\n🛑 Received signal {signum}, shutting down gracefully...")
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

def check_platform_requirements():
    """Check platform-specific requirements"""
    issues = []
    
    # Check Python version
    if sys.version_info < (3, 8):
        issues.append("Python 3.8 or higher is required")
    
    # Platform-specific checks
    if sys.platform == "linux":
        # Check if running as root or with CAP_NET_RAW
        if os.geteuid() != 0:
            issues.append("Linux: Consider running as root or with CAP_NET_RAW for full BLE access")
    
    elif sys.platform == "darwin":
        # macOS specific checks
        pass
    
    elif sys.platform == "win32":
        # Windows specific checks
        issues.append("Windows: Ensure Bluetooth adapter supports BLE")
    
    return issues

def print_startup_banner():
    """Print startup banner with system information"""
    banner = f"""
╔══════════════════════════════════════════════════════════════════════════════════╗
║                           🔒 BLUEFORGE v{__version__} 🔒                                 ║
║                        Advanced BLE Security Research                            ║
║                                                                                  ║
║  🎯 Vulnerability Discovery  💥 Exploit Framework  🔍 Device Analysis            ║
║  ⚡ Timing Attacks          🛡️  Security Testing   📊 Intelligence Gathering     ║
║                                                                                  ║
║                              ⚠️  RESEARCH USE ONLY ⚠️                            ║
╚══════════════════════════════════════════════════════════════════════════════════╝

Platform: {sys.platform}
Python: {sys.version.split()[0]}
Working Directory: {os.getcwd()}

"""
    print(banner)

def validate_environment():
    """Validate environment and show warnings"""
    # Check platform requirements
    issues = check_platform_requirements()
    
    if issues:
        print("⚠️  Platform Requirements:")
        for issue in issues:
            print(f"   • {issue}")
        print()
    
    # Validate configuration
    config_manager = get_config_manager()
    config_issues = config_manager.validate_config()
    
    if config_issues:
        print("⚠️  Configuration Issues:")
        for issue in config_issues:
            print(f"   • {issue}")
        print()
    
    return len(issues) == 0 and len(config_issues) == 0

def setup_directories():
    """Setup required directories"""
    directories = [
        "logs",
        "sessions", 
        "reports",
        "exports"
    ]
    
    for directory in directories:
        Path(directory).mkdir(exist_ok=True)

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="BlueForge - Advanced BLE Security Research Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python blueforge.py                    # Start interactive mode
  python blueforge.py --debug            # Start with debug logging
  python blueforge.py --config custom.json  # Use custom config
  python blueforge.py --version          # Show version info

Environment Variables:
  BLUEFORGE_DEBUG=1                      # Enable debug mode
  BLUEFORGE_VERBOSE=verbose              # Set verbosity
  BLUEFORGE_SCAN_TIMEOUT=15              # Override scan timeout
  
For detailed documentation, visit: https://github.com/yourusername/blueforge-main
        """
    )
    
    parser.add_argument(
        '--version', 
        action='version', 
        version=f"BlueForge {__version__}"
    )
    
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug mode with verbose logging'
    )
    
    parser.add_argument(
        '--config',
        type=str,
        metavar='FILE',
        help='Path to configuration file'
    )
    
    parser.add_argument(
        '--no-banner',
        action='store_true',
        help='Suppress startup banner'
    )
    
    parser.add_argument(
        '--check-only',
        action='store_true',
        help='Check requirements and configuration, then exit'
    )
    
    parser.add_argument(
        '--scan-intensity',
        choices=['passive', 'conservative', 'moderate', 'aggressive', 'extreme'],
        help='Override default scan intensity'
    )
    
    parser.add_argument(
        '--verbose',
        choices=['minimal', 'normal', 'verbose', 'debug'],
        help='Set output verbosity level'
    )
    
    return parser.parse_args()

def apply_cli_overrides(args):
    """Apply command line argument overrides"""
    config_manager = get_config_manager()
    
    # Debug mode override
    if args.debug:
        config_manager.update_config('display', 'log_level', 'DEBUG')
        config_manager.config.debug_mode = True
    
    # Verbosity override
    if args.verbose:
        config_manager.update_config('display', 'verbosity_level', args.verbose)
    
    # Scan intensity override
    if args.scan_intensity:
        config_manager.update_config('security', 'default_scan_intensity', args.scan_intensity)

async def main():
    """Main application entry point"""
    try:
        # Parse command line arguments
        args = parse_arguments()
        
        # Setup signal handlers
        setup_signal_handlers()
        
        # Load custom config if specified
        if args.config:
            config_manager = get_config_manager()
            if not config_manager.import_config(args.config):
                print(f"❌ Failed to load config from {args.config}")
                sys.exit(1)
        
        # Apply environment overrides
        apply_env_overrides()
        
        # Apply CLI overrides
        apply_cli_overrides(args)
        
        # Setup logging
        setup_logging()
        
        # Setup directories
        setup_directories()
        
        # Show banner
        if not args.no_banner:
            print_startup_banner()
        
        # Validate environment
        env_valid = validate_environment()
        
        if args.check_only:
            if env_valid:
                print("✅ All checks passed!")
                sys.exit(0)
            else:
                print("❌ Environment validation failed!")
                sys.exit(1)
        
        if not env_valid:
            print("⚠️  Some issues detected, but continuing...")
            print()
        
        # Log startup
        config = get_config_manager().get_config()
        logger.info(f"BlueForge {__version__} starting")
        logger.info(f"Platform: {sys.platform}")
        logger.info(f"Debug mode: {config.debug_mode}")
        logger.info(f"Research mode: {config.research_mode}")
        
        # Show effective configuration summary in debug mode
        if config.debug_mode:
            config_summary = get_config_manager().get_effective_config_summary()
            logger.debug(f"Effective configuration: {config_summary}")
        
        # Initialize and run interface
        interface = BlueForgeInterface()
        await interface.run()
        
    except KeyboardInterrupt:
        print(f"\n👋 BlueForge shutdown requested by user")
        
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        print(f"❌ Fatal error: {e}")
        
        if get_config_manager().get_config().debug_mode:
            import traceback
            traceback.print_exc()
        
        sys.exit(1)
    
    finally:
        # Cleanup
        logger.info("BlueForge shutdown complete")

def cli_entry_point():
    """Entry point for CLI installation"""
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    cli_entry_point()