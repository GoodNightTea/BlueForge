# cli/ui/colors.py
class BlueForgeColors:
    """ANSI color codes for terminal output"""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    
    @classmethod
    def disable_colors(cls):
        """Disable all colors for non-terminal output"""
        cls.HEADER = ''
        cls.OKBLUE = ''
        cls.OKCYAN = ''
        cls.OKGREEN = ''
        cls.WARNING = ''
        cls.FAIL = ''
        cls.ENDC = ''
        cls.BOLD = ''
        cls.UNDERLINE = ''
    
    def success(self, text: str) -> str:
        """Format text as success message"""
        return f"{self.OKGREEN}✓ {text}{self.ENDC}"
    
    def error(self, text: str) -> str:
        """Format text as error message"""
        return f"{self.FAIL}❌ {text}{self.ENDC}"
    
    def warning(self, text: str) -> str:
        """Format text as warning message"""
        return f"{self.WARNING}⚠️  {text}{self.ENDC}"
    
    def info(self, text: str) -> str:
        """Format text as info message"""
        return f"{self.OKCYAN}{text}{self.ENDC}"
    
    def header(self, text: str) -> str:
        """Format text as header"""
        return f"{self.BOLD}{self.HEADER}{text}{self.ENDC}"