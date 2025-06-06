# cli/commands/base.py
from abc import ABC, abstractmethod
from typing import Dict, Any, List
from utils.logging import get_logger

class BaseCommands(ABC):
    """Base class for command modules"""
    
    def __init__(self, session, colors):
        self.session = session
        self.colors = colors
        self.logger = get_logger(f"{__name__}.{self.__class__.__name__}")
    
    @abstractmethod
    def get_commands(self) -> Dict[str, Any]:
        """Return dictionary of commands provided by this module"""
        pass
    
    def get_device_from_args_or_active(self, args: List[str]):
        """Helper to get device index"""
        return self.session.get_device_from_args_or_active(args)
    
    def print_error(self, message: str):
        """Print error message with consistent formatting"""
        print(f"{self.colors.FAIL}❌ {message}{self.colors.ENDC}")
    
    def print_success(self, message: str):
        """Print success message with consistent formatting"""
        print(f"{self.colors.OKGREEN}✓ {message}{self.colors.ENDC}")
    
    def print_warning(self, message: str):
        """Print warning message with consistent formatting"""
        print(f"{self.colors.WARNING}⚠️  {message}{self.colors.ENDC}")
    
    def print_info(self, message: str):
        """Print info message with consistent formatting"""
        print(f"{self.colors.OKCYAN}{message}{self.colors.ENDC}")