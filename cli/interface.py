
# cli/interface.py - Main CLI Interface
import asyncio
import sys
import os
from typing import Dict, List, Any, Optional
from core.session_manager import SessionManager
from cli.display import DisplayManager
from cli.commands import CommandHandler
from utils.logging import get_logger

logger = get_logger(__name__)

class BlueForgeInterface:
    """Main interactive CLI interface"""
    
    def __init__(self):
        self.session = SessionManager()
        self.display = DisplayManager()
        self.commands = CommandHandler(self.session, self.display)
        self.running = True
        
        logger.info("BlueForge interface initialized")
    
    def print_banner(self):
        """Display startup banner"""
        banner = f"""
{self.display.colors.HEADER}{self.display.colors.BOLD}
╔══════════════════════════════════════════════════════════════════════════════════╗
║                           🔒 BLUEFORGE v2.0.0 🔒                                 ║
║                        Advanced BLE Security Research                            ║
║                                                                                  ║
║  🎯 Vulnerability Discovery  💥 Exploit Framework  🔍 Device Analysis            ║
║  ⚡ Timing Attacks          🛡️  Security Testing   📊 Intelligence Gathering     ║
║                                                                                  ║
║                              ⚠️  RESEARCH USE ONLY ⚠️                            ║
╚══════════════════════════════════════════════════════════════════════════════════╝
{self.display.colors.ENDC}

Type 'help' for available commands or 'scan' to discover devices.
        """
        print(banner)
    
    def get_prompt(self) -> str:
        """Generate command prompt with status indicators"""
        connected_count = len(self.session.connected_devices)
        discovered_count = len(self.session.discovered_devices)
        
        # Status indicators
        status = ""
        if discovered_count > 0:
            status += f"📡{discovered_count}"
        if connected_count > 0:
            status += f" 🔗{connected_count}"
        
        if status:
            status = f"[{status}] "
        
        return f"{status}{self.display.colors.OKCYAN}blueforge{self.display.colors.ENDC}> "
    
    async def run(self):
        """Main interactive loop"""
        try:
            self.print_banner()
            
            while self.running:
                try:
                    user_input = input(self.get_prompt()).strip()
                    
                    if not user_input:
                        continue
                    
                    # Parse command and arguments
                    parts = user_input.split()
                    command = parts[0].lower()
                    args = parts[1:] if len(parts) > 1 else []
                    
                    # Handle built-in commands
                    if command in ['exit', 'quit']:
                        self.running = False
                        break
                    elif command == 'clear':
                        os.system('clear' if os.name == 'posix' else 'cls')
                        continue
                    
                    # Execute command
                    await self.commands.execute_command(command, args)
                    
                except KeyboardInterrupt:
                    print(f"\n{self.display.colors.WARNING}Use 'exit' to quit{self.display.colors.ENDC}")
                except EOFError:
                    self.running = False
                    break
                except Exception as e:
                    self.display.print_error(f"Command error: {e}")
                    logger.error(f"Command execution failed: {e}", exc_info=True)
        
        finally:
            await self._cleanup()
    
    async def _cleanup(self):
        """Cleanup resources on exit"""
        print(f"\n{self.display.colors.OKCYAN}👋 Cleaning up and exiting...{self.display.colors.ENDC}")
        
        try:
            await self.session.cleanup()
            logger.info("Interface cleanup completed")
        except Exception as e:
            logger.error(f"Cleanup error: {e}")
    
    def handle_exception(self, exc_type, exc_value, exc_traceback):
        """Global exception handler"""
        if issubclass(exc_type, KeyboardInterrupt):
            print(f"\n{self.display.colors.WARNING}Interrupted by user{self.display.colors.ENDC}")
            return
        
        logger.error(f"Unhandled exception: {exc_value}", exc_info=True)
        self.display.print_error(f"Fatal error: {exc_value}")


async def main():
    """Main entry point for CLI"""
    try:
        interface = BlueForgeInterface()
        
        # Set up exception handling
        sys.excepthook = interface.handle_exception
        
        await interface.run()
        
    except Exception as e:
        print(f"Fatal error starting BlueForge: {e}")
        logger.error(f"Startup failed: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())