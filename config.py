
# config.py - Configuration Management
import os
import json
import logging
from typing import Dict, Any, Optional
from dataclasses import dataclass, asdict
from pathlib import Path

@dataclass
class BLEConfig:
    """BLE scanning and connection configuration"""
    scan_timeout: int = 10
    connection_timeout: int = 20
    connection_attempts: int = 3
    service_discovery_timeout: int = 10
    characteristic_read_timeout: int = 5
    enable_advertisements: bool = True
    scan_duplicates: bool = False

@dataclass
class SecurityConfig:
    """Security testing configuration"""
    default_scan_intensity: str = "moderate"
    max_vulnerability_tests: int = 100
    fuzzing_timeout: int = 300
    exploit_timeout: int = 60
    enable_crash_detection: bool = True
    auto_recovery_delay: float = 2.0
    max_consecutive_failures: int = 5

@dataclass
class ExploitConfig:
    """Exploitation framework configuration"""
    memory_exploit_enabled: bool = True
    protocol_exploit_enabled: bool = True
    timing_exploit_enabled: bool = True
    auto_calibration: bool = True
    precision_timing_enabled: bool = True
    max_exploit_attempts: int = 3
    require_confirmation: bool = True

@dataclass
class DisplayConfig:
    """Display and output configuration"""
    color_output: bool = True
    show_timestamps: bool = True
    show_progress: bool = True
    verbosity_level: str = "normal"
    log_level: str = "INFO"
    output_format: str = "console"

@dataclass
class SessionConfig:
    """Session management configuration"""
    auto_save: bool = False
    auto_save_interval: int = 300  # seconds
    session_directory: str = "./sessions"
    max_session_history: int = 10
    compress_sessions: bool = True

@dataclass
class BlueForgeConfig:
    """Main BlueForge configuration"""
    ble: BLEConfig
    security: SecurityConfig
    exploits: ExploitConfig
    display: DisplayConfig
    session: SessionConfig
    
    # Application metadata
    version: str = "2.0.0"
    debug_mode: bool = False
    research_mode: bool = True

class ConfigManager:
    """Configuration management system"""
    
    def __init__(self, config_file: Optional[str] = None):
        self.config_file = config_file or self._get_default_config_path()
        self.config = self._load_default_config()
        
        # Create config directory if needed
        config_dir = Path(self.config_file).parent
        config_dir.mkdir(parents=True, exist_ok=True)
        
        # Load existing config
        self.load_config()
    
    def _get_default_config_path(self) -> str:
        """Get default configuration file path"""
        home_dir = Path.home()
        config_dir = home_dir / ".blueforge"
        config_dir.mkdir(exist_ok=True)
        return str(config_dir / "config.json")
    
    def _load_default_config(self) -> BlueForgeConfig:
        """Load default configuration"""
        return BlueForgeConfig(
            ble=BLEConfig(),
            security=SecurityConfig(),
            exploits=ExploitConfig(),
            display=DisplayConfig(),
            session=SessionConfig()
        )
    
    def load_config(self) -> bool:
        """Load configuration from file"""
        try:
            if not os.path.exists(self.config_file):
                # Create default config file
                self.save_config()
                return True
            
            with open(self.config_file, 'r') as f:
                data = json.load(f)
            
            # Update config with loaded data
            self._update_config_from_dict(data)
            return True
            
        except Exception as e:
            print(f"Warning: Failed to load config from {self.config_file}: {e}")
            print("Using default configuration")
            return False
    
    def save_config(self) -> bool:
        """Save configuration to file"""
        try:
            config_dict = asdict(self.config)
            
            with open(self.config_file, 'w') as f:
                json.dump(config_dict, f, indent=2)
            
            return True
            
        except Exception as e:
            print(f"Warning: Failed to save config to {self.config_file}: {e}")
            return False
    
    def _update_config_from_dict(self, data: Dict[str, Any]):
        """Update configuration from dictionary"""
        
        # Update BLE config
        if 'ble' in data:
            ble_data = data['ble']
            for key, value in ble_data.items():
                if hasattr(self.config.ble, key):
                    setattr(self.config.ble, key, value)
        
        # Update Security config
        if 'security' in data:
            security_data = data['security']
            for key, value in security_data.items():
                if hasattr(self.config.security, key):
                    setattr(self.config.security, key, value)
        
        # Update Exploits config
        if 'exploits' in data:
            exploits_data = data['exploits']
            for key, value in exploits_data.items():
                if hasattr(self.config.exploits, key):
                    setattr(self.config.exploits, key, value)
        
        # Update Display config
        if 'display' in data:
            display_data = data['display']
            for key, value in display_data.items():
                if hasattr(self.config.display, key):
                    setattr(self.config.display, key, value)
        
        # Update Session config
        if 'session' in data:
            session_data = data['session']
            for key, value in session_data.items():
                if hasattr(self.config.session, key):
                    setattr(self.config.session, key, value)
        
        # Update main config
        for key in ['version', 'debug_mode', 'research_mode']:
            if key in data:
                setattr(self.config, key, data[key])
    
    def get_config(self) -> BlueForgeConfig:
        """Get current configuration"""
        return self.config
    
    def update_config(self, section: str, key: str, value: Any) -> bool:
        """Update a specific configuration value"""
        try:
            section_obj = getattr(self.config, section)
            if hasattr(section_obj, key):
                setattr(section_obj, key, value)
                return True
            else:
                print(f"Warning: Unknown config key: {section}.{key}")
                return False
        except AttributeError:
            print(f"Warning: Unknown config section: {section}")
            return False
    
    def get_config_value(self, section: str, key: str) -> Any:
        """Get a specific configuration value"""
        try:
            section_obj = getattr(self.config, section)
            return getattr(section_obj, key)
        except AttributeError:
            return None
    
    def setup_logging(self):
        """Setup logging based on configuration"""
        log_level = getattr(logging, self.config.display.log_level.upper(), logging.INFO)
        
        # Create logs directory
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        
        # Configure logging
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_dir / "blueforge.log"),
                logging.StreamHandler() if self.config.debug_mode else logging.NullHandler()
            ]
        )
    
    def validate_config(self) -> list[str]:
        """Validate configuration and return list of issues"""
        issues = []
        
        # Validate BLE config
        if self.config.ble.scan_timeout < 5:
            issues.append("BLE scan timeout should be at least 5 seconds")
        
        if self.config.ble.connection_timeout < 10:
            issues.append("BLE connection timeout should be at least 10 seconds")
        
        # Validate Security config
        valid_intensities = ["passive", "conservative", "moderate", "aggressive", "extreme"]
        if self.config.security.default_scan_intensity not in valid_intensities:
            issues.append(f"Invalid scan intensity: {self.config.security.default_scan_intensity}")
        
        # Validate Display config
        valid_verbosity = ["minimal", "normal", "verbose", "debug"]
        if self.config.display.verbosity_level not in valid_verbosity:
            issues.append(f"Invalid verbosity level: {self.config.display.verbosity_level}")
        
        valid_log_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if self.config.display.log_level.upper() not in valid_log_levels:
            issues.append(f"Invalid log level: {self.config.display.log_level}")
        
        # Validate Session config
        session_dir = Path(self.config.session.session_directory)
        try:
            session_dir.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            issues.append(f"Cannot create session directory: {e}")
        
        return issues
    
    def reset_to_defaults(self):
        """Reset configuration to defaults"""
        self.config = self._load_default_config()
    
    def export_config(self, file_path: str) -> bool:
        """Export configuration to a specific file"""
        try:
            config_dict = asdict(self.config)
            
            with open(file_path, 'w') as f:
                json.dump(config_dict, f, indent=2)
            
            return True
            
        except Exception as e:
            print(f"Failed to export config to {file_path}: {e}")
            return False
    
    def import_config(self, file_path: str) -> bool:
        """Import configuration from a specific file"""
        try:
            if not os.path.exists(file_path):
                print(f"Config file not found: {file_path}")
                return False
            
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            # Validate before importing
            backup_config = self.config
            self._update_config_from_dict(data)
            
            issues = self.validate_config()
            if issues:
                print("Configuration validation failed:")
                for issue in issues:
                    print(f"  - {issue}")
                
                # Restore backup
                self.config = backup_config
                return False
            
            return True
            
        except Exception as e:
            print(f"Failed to import config from {file_path}: {e}")
            return False
    
    def get_effective_config_summary(self) -> Dict[str, Any]:
        """Get summary of effective configuration"""
        return {
            "config_file": self.config_file,
            "version": self.config.version,
            "debug_mode": self.config.debug_mode,
            "research_mode": self.config.research_mode,
            "ble": {
                "scan_timeout": self.config.ble.scan_timeout,
                "connection_timeout": self.config.ble.connection_timeout,
                "connection_attempts": self.config.ble.connection_attempts
            },
            "security": {
                "default_scan_intensity": self.config.security.default_scan_intensity,
                "max_vulnerability_tests": self.config.security.max_vulnerability_tests,
                "enable_crash_detection": self.config.security.enable_crash_detection
            },
            "exploits": {
                "memory_exploit_enabled": self.config.exploits.memory_exploit_enabled,
                "protocol_exploit_enabled": self.config.exploits.protocol_exploit_enabled,
                "timing_exploit_enabled": self.config.exploits.timing_exploit_enabled,
                "require_confirmation": self.config.exploits.require_confirmation
            },
            "display": {
                "verbosity_level": self.config.display.verbosity_level,
                "color_output": self.config.display.color_output,
                "show_timestamps": self.config.display.show_timestamps
            }
        }

# Global configuration instance
_config_manager = None

def get_config_manager() -> ConfigManager:
    """Get global configuration manager instance"""
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigManager()
    return _config_manager

def get_config() -> BlueForgeConfig:
    """Get current configuration"""
    return get_config_manager().get_config()

def setup_logging():
    """Setup logging from configuration"""
    get_config_manager().setup_logging()

# Environment variable overrides
def apply_env_overrides():
    """Apply configuration overrides from environment variables"""
    config_manager = get_config_manager()
    
    # BLE overrides
    if os.getenv('BLUEFORGE_SCAN_TIMEOUT'):
        try:
            timeout = int(os.getenv('BLUEFORGE_SCAN_TIMEOUT'))
            config_manager.update_config('ble', 'scan_timeout', timeout)
        except ValueError:
            pass
    
    # Security overrides
    if os.getenv('BLUEFORGE_SCAN_INTENSITY'):
        intensity = os.getenv('BLUEFORGE_SCAN_INTENSITY').lower()
        if intensity in ["passive", "conservative", "moderate", "aggressive", "extreme"]:
            config_manager.update_config('security', 'default_scan_intensity', intensity)
    
    # Debug mode override
    if os.getenv('BLUEFORGE_DEBUG') in ['1', 'true', 'True', 'TRUE']:
        config_manager.config.debug_mode = True
    
    # Verbosity override
    if os.getenv('BLUEFORGE_VERBOSE'):
        verbosity = os.getenv('BLUEFORGE_VERBOSE').lower()
        if verbosity in ["minimal", "normal", "verbose", "debug"]:
            config_manager.update_config('display', 'verbosity_level', verbosity)

# Initialize configuration on import
apply_env_overrides()