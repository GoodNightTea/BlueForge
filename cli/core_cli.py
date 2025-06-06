# cli/core_cli.py
import asyncio
import sys
import os
from typing import List, Dict, Any, Optional

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cli.session import BlueForgeSession
from cli.ui.colors import BlueForgeColors
from cli.ui.display import DisplayManager
from cli.commands import (
    DiscoveryCommands, AnalysisCommands, ResearchCommands, 
    AdvancedCommands, DebugCommands
)
from utils.logging import get_logger

logger = get_logger(__name__)

class BlueForgeInteractiveCLI:
    """Modular Interactive CLI for BlueForge Security Research Framework"""
    
    def __init__(self):
        self.session = BlueForgeSession()
        self.running = True
        self.colors = BlueForgeColors()
        self.display = DisplayManager(self.colors)
        
        # Initialize command modules
        self.discovery = DiscoveryCommands(self.session, self.colors)
        self.analysis = AnalysisCommands(self.session, self.colors)
        self.research = ResearchCommands(self.session, self.colors)
        self.advanced = AdvancedCommands(self.session, self.colors)
        self.debug = DebugCommands(self.session, self.colors)
        
    def print_banner(self):
        """Display BlueForge banner"""
        self.display.print_banner()

    def print_prompt(self):
        """Generate command prompt"""
        return f"{self.colors.OKCYAN}blueforge{self.colors.ENDC}> "

    def print_help(self, args: List[str]):
        """Display help information"""
        if args:
            self.display.print_command_help(args[0])
        else:
            self.display.print_main_help(self.session)

    async def run_interactive(self):
        """Run interactive CLI mode"""
        self.print_banner()
        
        # Build commands dictionary from modules
        commands = self._build_commands_dict()
        
        while self.running:
            try:
                user_input = input(self.print_prompt()).strip()
                if not user_input:
                    continue
                
                parts = user_input.split()
                command = parts[0].lower()
                args = parts[1:]
                
                if command in commands:
                    cmd_func = commands[command]
                    if asyncio.iscoroutinefunction(cmd_func):
                        await cmd_func(args)
                    else:
                        cmd_func(args)
                else:
                    print(f"{self.colors.FAIL}Unknown command: {command}. Type 'help' for available commands{self.colors.ENDC}")
                    
            except KeyboardInterrupt:
                print(f"\n{self.colors.WARNING}Use 'exit' to quit BlueForge{self.colors.ENDC}")
            except EOFError:
                self.exit_cli()
                break
            except Exception as e:
                print(f"{self.colors.FAIL}❌ Error: {e}{self.colors.ENDC}")
                logger.error(f"CLI error: {e}", exc_info=True)

    def _build_commands_dict(self) -> Dict[str, Any]:
        """Build commands dictionary from all command modules"""
        commands = {}
        
        # Basic commands
        commands.update({
            'help': self.print_help,
            'exit': self.exit_cli,
            'quit': self.exit_cli,
            'clear': self._cmd_clear,
            'status': self._cmd_status,
        })
        
        # Discovery commands
        commands.update(self.discovery.get_commands())
        
        # Analysis commands  
        commands.update(self.analysis.get_commands())
        
        # Research commands
        commands.update(self.research.get_commands())
        
        # Advanced commands
        commands.update(self.advanced.get_commands())
        
        # Debug commands
        commands.update(self.debug.get_commands())
        
        return commands

    def _cmd_clear(self, args: List[str]):
        """Clear screen"""
        os.system('clear' if os.name == 'posix' else 'cls')

    def _cmd_status(self, args: List[str]):
        """Show quick status overview"""
        self.display.print_status(self.session)

    def exit_cli(self, args: List[str] = None):
        """Exit CLI gracefully"""
        print(f"\n{self.colors.OKCYAN}👋 Cleaning up connections...{self.colors.ENDC}")
        self.running = False