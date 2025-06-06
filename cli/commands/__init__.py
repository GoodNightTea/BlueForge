# cli/commands/__init__.py
from .discovery import DiscoveryCommands
from .analysis import AnalysisCommands
from .research import ResearchCommands
from .advanced import AdvancedCommands
from .debug import DebugCommands

__all__ = [
    'DiscoveryCommands', 'AnalysisCommands', 'ResearchCommands',
    'AdvancedCommands', 'DebugCommands'
]