# config.py - Make it generic
class BlueForgeConfig:
    def __init__(self):
        # Server configuration
        self.server_socket = "/tmp/blueforge_server.sock"
        self.default_scan_timeout = 10
        self.connection_timeout = 30
        self.max_connections = 10
        self.connection_timeout = 30
        
        # Generic fuzzing configuration
        self.default_fuzz_iterations = 5
        self.default_fuzz_delay = 5  # Optimal timing discovered through research
        self.max_fuzz_payload_size = 1024
        
        # Research targets (generic)
        self.target_characteristics = [
            "19b10001-e8f2-537e-4f6c-d104768a1214",  # Generic service char 1
            "19b10002-e8f2-537e-4f6c-d104768a1214",  # Generic service char 2  
            "19b10003-e8f2-537e-4f6c-d104768a1214",  # Generic service char 3
            "19b10004-e8f2-537e-4f6c-d104768a1214",  # Generic service char 4
        ]
        
        # Memory analysis settings
        self.memory_scan_base = 0x40000000  # Generic ARM Cortex base
        self.memory_scan_range = (-10, 10)  # Generic scan range
        
        # Logging
        self.log_level = "INFO"
        self.crash_detection_timeout = 15
        self.device_recovery_delay = 3

    def load_from_file(self, config_file):
        """Load configuration from JSON file"""
        try:
            import os
            import json
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    data = json.load(f)
                    
                for key, value in data.items():
                    if hasattr(self, key):
                        setattr(self, key, value)
                        
                print(f"Configuration loaded from {config_file}")
            else:
                print(f"Config file {config_file} not found, using defaults")
        except Exception as e:
            print(f"Failed to load config from {config_file}: {e}")
    
    @classmethod
    def load(cls, config_file=None):
        """Load configuration from file or use defaults"""
        instance = cls()
        if config_file:
            instance.load_from_file(config_file)
        return instance


# Create global config instance
config = BlueForgeConfig.load()