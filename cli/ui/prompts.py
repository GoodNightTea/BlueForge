# cli/ui/prompts.py
from typing import Optional, List, Callable

class PromptManager:
    """Handles user input prompts and validation"""
    
    def __init__(self, colors):
        self.colors = colors
    
    def confirm(self, message: str, default: bool = False) -> bool:
        """Show a yes/no confirmation prompt"""
        default_hint = " (Y/n)" if default else " (y/N)"
        
        try:
            response = input(f"{self.colors.WARNING}{message}{default_hint}: {self.colors.ENDC}").strip().lower()
            
            if not response:
                return default
            
            return response in ['y', 'yes', 'true', '1']
            
        except (KeyboardInterrupt, EOFError):
            return False
    
    def input_text(self, message: str, default: str = None, validator: Callable = None) -> Optional[str]:
        """Get text input with optional validation"""
        default_hint = f" (default: {default})" if default else ""
        
        try:
            response = input(f"{self.colors.OKCYAN}{message}{default_hint}: {self.colors.ENDC}").strip()
            
            if not response and default:
                response = default
            
            if validator and not validator(response):
                print(f"{self.colors.FAIL}Invalid input{self.colors.ENDC}")
                return None
            
            return response
            
        except (KeyboardInterrupt, EOFError):
            return None
    
    def input_number(self, message: str, min_val: int = None, max_val: int = None, default: int = None) -> Optional[int]:
        """Get numeric input with optional range validation"""
        default_hint = f" (default: {default})" if default is not None else ""
        range_hint = ""
        
        if min_val is not None and max_val is not None:
            range_hint = f" ({min_val}-{max_val})"
        elif min_val is not None:
            range_hint = f" (min: {min_val})"
        elif max_val is not None:
            range_hint = f" (max: {max_val})"
        
        try:
            response = input(f"{self.colors.OKCYAN}{message}{range_hint}{default_hint}: {self.colors.ENDC}").strip()
            
            if not response and default is not None:
                return default
            
            try:
                value = int(response)
                
                if min_val is not None and value < min_val:
                    print(f"{self.colors.FAIL}Value too small (minimum: {min_val}){self.colors.ENDC}")
                    return None
                
                if max_val is not None and value > max_val:
                    print(f"{self.colors.FAIL}Value too large (maximum: {max_val}){self.colors.ENDC}")
                    return None
                
                return value
                
            except ValueError:
                print(f"{self.colors.FAIL}Invalid number format{self.colors.ENDC}")
                return None
                
        except (KeyboardInterrupt, EOFError):
            return None
    
    def select_from_list(self, message: str, options: List[str], allow_multiple: bool = False) -> Optional[List[int]]:
        """Show a selection prompt from a list of options"""
        
        print(f"\n{self.colors.BOLD}{message}{self.colors.ENDC}")
        for i, option in enumerate(options):
            print(f"  [{i}] {option}")
        
        selection_type = "selections (comma-separated)" if allow_multiple else "selection"
        
        try:
            response = input(f"\nEnter {selection_type}: ").strip()
            
            if not response:
                return None
            
            try:
                if allow_multiple:
                    indices = [int(x.strip()) for x in response.split(',')]
                else:
                    indices = [int(response)]
                
                # Validate indices
                valid_indices = []
                for idx in indices:
                    if 0 <= idx < len(options):
                        valid_indices.append(idx)
                    else:
                        print(f"{self.colors.WARNING}Invalid index: {idx}{self.colors.ENDC}")
                
                return valid_indices if valid_indices else None
                
            except ValueError:
                print(f"{self.colors.FAIL}Invalid selection format{self.colors.ENDC}")
                return None
                
        except (KeyboardInterrupt, EOFError):
            return None
    
    def warning_prompt(self, message: str, action: str = "continue") -> bool:
        """Show a warning prompt requiring explicit confirmation"""
        print(f"\n{self.colors.WARNING}⚠️  WARNING ⚠️{self.colors.ENDC}")
        print(f"{self.colors.WARNING}{message}{self.colors.ENDC}")
        
        try:
            response = input(f"\n{self.colors.FAIL}Type 'yes' to {action}: {self.colors.ENDC}").strip().lower()
            return response == 'yes'
            
        except (KeyboardInterrupt, EOFError):
            return False
    
    def progress_indicator(self, current: int, total: int, message: str = "Progress"):
        """Show a simple progress indicator"""
        percentage = (current / total) * 100 if total > 0 else 0
        bar_length = 40
        filled_length = int(bar_length * current // total) if total > 0 else 0
        
        bar = '█' * filled_length + '-' * (bar_length - filled_length)
        
        print(f"\r{self.colors.OKCYAN}{message}: |{bar}| {percentage:.1f}% ({current}/{total}){self.colors.ENDC}", end='')
        
        if current >= total:
            print()  # New line when complete