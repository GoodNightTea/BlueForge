# core/configurable_fuzzing.py
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Callable
from enum import Enum
import json
import asyncio
import copy
from utils.logging import get_logger
from core.fuzzing_engine import AdvancedFuzzingEngine, FuzzStrategy, FuzzTarget

logger = get_logger(__name__)

@dataclass
class FuzzingProfile:
    """Configurable fuzzing profile"""
    name: str
    description: str
    
    # Payload configuration
    payload_types: List[str] = field(default_factory=lambda: ["random", "overflow", "format_string"])
    payload_sizes: List[int] = field(default_factory=lambda: [8, 16, 32, 64, 128])
    custom_payloads: List[bytes] = field(default_factory=list)
    
    # Timing configuration
    iterations_per_test: int = 5
    delay_between_tests: float = 0.1
    delay_between_characteristics: float = 2.0
    
    # Strategy configuration
    strategies: List[str] = field(default_factory=lambda: ["smart_mutation", "timing_based"])
    max_cases_per_strategy: int = 50
    
    # Target configuration
    target_characteristics: List[str] = field(default_factory=list)
    only_writable: bool = True
    skip_standard_services: bool = True
    
    # Safety configuration
    crash_detection_timeout: int = 10
    max_crashes_before_stop: int = 3
    recovery_delay_after_crash: float = 5.0
    
    # Advanced configuration
    adaptive_timing: bool = True
    payload_mutation_rate: float = 0.1
    enable_feedback_learning: bool = True

class ConfigurableFuzzingEngine:
    """Highly configurable fuzzing engine that wraps AdvancedFuzzingEngine"""
    
    def __init__(self):
        self.profiles = {}
        self.current_profile = None
        self.base_engine = AdvancedFuzzingEngine()
        self.logger = get_logger(f"{__name__}.ConfigurableFuzzingEngine")
        self.load_default_profiles()
        
    def load_default_profiles(self):
        """Load default fuzzing profiles"""
        
        # Aggressive research profile
        aggressive = FuzzingProfile(
            name="aggressive_research",
            description="Aggressive fuzzing for research targets",
            payload_types=["random", "overflow", "format_string", "protocol_violation"],
            payload_sizes=[8, 16, 32, 64, 128, 256, 512],
            iterations_per_test=24,  # Your proven iteration count
            delay_between_tests=0.014,  # Your proven timing
            strategies=["smart_mutation", "timing_based", "protocol_aware", "boundary_value"],
            max_cases_per_strategy=100
        )
        
        # Conservative testing profile
        conservative = FuzzingProfile(
            name="conservative_testing",
            description="Conservative fuzzing for production devices",
            payload_types=["boundary_value", "null_bytes"],
            payload_sizes=[8, 16, 32],
            iterations_per_test=3,
            delay_between_tests=0.5,
            strategies=["boundary_value"],
            max_cases_per_strategy=20,
            max_crashes_before_stop=1
        )
        
        # Smartphone-specific profile
        smartphone = FuzzingProfile(
            name="smartphone_research",
            description="Specialized fuzzing for smartphone BLE stacks",
            payload_types=["apple_continuity", "android_specific", "overflow"],
            iterations_per_test=10,
            delay_between_tests=0.1,
            strategies=["state_machine", "timing_based"],
            skip_standard_services=False,  # Include standard services
            adaptive_timing=True
        )
        
        # ESP32 specific profile based on your research
        esp32 = FuzzingProfile(
            name="esp32_target",
            description="Optimized profile for ESP32 devices based on research",
            payload_types=["overflow", "format_string", "memory_corruption"],
            payload_sizes=[8, 16, 32, 64],
            iterations_per_test=24,  # Your discovered magic number
            delay_between_tests=0.014,  # Your discovered timing
            strategies=["smart_mutation", "timing_based", "protocol_aware"],
            max_cases_per_strategy=150,
            crash_detection_timeout=15,
            recovery_delay_after_crash=3.0
        )
        
        self.profiles = {
            "aggressive": aggressive,
            "conservative": conservative,
            "smartphone": smartphone,
            "esp32": esp32
        }
        
        self.current_profile = aggressive
    
    def create_custom_profile(self, name: str, base_profile: str = "aggressive") -> FuzzingProfile:
        """Create a custom fuzzing profile based on an existing one"""
        if base_profile not in self.profiles:
            raise ValueError(f"Base profile '{base_profile}' not found")
        
        # Deep copy the base profile
        new_profile = copy.deepcopy(self.profiles[base_profile])
        new_profile.name = name
        new_profile.description = f"Custom profile based on {base_profile}"
        
        self.profiles[name] = new_profile
        return new_profile
    
    def configure_profile(self, profile_name: str, **kwargs):
        """Configure a fuzzing profile with specific parameters"""
        if profile_name not in self.profiles:
            raise ValueError(f"Profile '{profile_name}' not found")
        
        profile = self.profiles[profile_name]
        
        for key, value in kwargs.items():
            if hasattr(profile, key):
                setattr(profile, key, value)
                self.logger.info(f"Updated {profile_name}.{key} = {value}")
            else:
                self.logger.warning(f"Unknown profile parameter: {key}")
    
    async def fuzz_with_profile(self, client, target_char: str, profile_name: str = None) -> Dict[str, Any]:
        """Execute fuzzing using a specific profile"""
        
        if profile_name and profile_name in self.profiles:
            profile = self.profiles[profile_name]
        else:
            profile = self.current_profile
        
        self.logger.info(f"Starting fuzzing with profile: {profile.name}")
        
        results = {
            'profile_used': profile.name,
            'total_strategies': len(profile.strategies),
            'strategy_results': {},
            'overall_crashes': 0,
            'total_cases': 0
        }
        
        for strategy_name in profile.strategies:
            try:
                # Convert string strategy name to enum
                strategy_map = {
                    'random_mutation': FuzzStrategy.RANDOM_MUTATION,
                    'smart_mutation': FuzzStrategy.SMART_MUTATION,
                    'protocol_aware': FuzzStrategy.PROTOCOL_AWARE,
                    'state_machine': FuzzStrategy.STATE_MACHINE,
                    'timing_based': FuzzStrategy.TIMING_BASED,
                    'boundary_value': FuzzStrategy.BOUNDARY_VALUE
                }
                
                if strategy_name not in strategy_map:
                    self.logger.warning(f"Unknown strategy: {strategy_name}")
                    continue
                
                strategy_enum = strategy_map[strategy_name]
                
                self.logger.info(f"Executing strategy: {strategy_name}")
                
                # Apply profile settings to the base engine
                self._apply_profile_to_engine(profile)
                
                # Execute fuzzing with the strategy
                strategy_results = await self.base_engine.fuzz_target(
                    client, 
                    target_char, 
                    strategy_enum, 
                    profile.max_cases_per_strategy
                )
                
                # Analyze strategy results
                crashes_in_strategy = len([r for r in strategy_results if r.crashed])
                results['strategy_results'][strategy_name] = {
                    'cases_executed': len(strategy_results),
                    'crashes_found': crashes_in_strategy,
                    'success_rate': len([r for r in strategy_results if r.success]) / len(strategy_results) if strategy_results else 0
                }
                
                results['overall_crashes'] += crashes_in_strategy
                results['total_cases'] += len(strategy_results)
                
                # Check if we should stop due to too many crashes
                if crashes_in_strategy >= profile.max_crashes_before_stop:
                    self.logger.warning(f"Stopping fuzzing - too many crashes ({crashes_in_strategy})")
                    break
                
                # Recovery delay between strategies
                if crashes_in_strategy > 0:
                    await asyncio.sleep(profile.recovery_delay_after_crash)
                else:
                    await asyncio.sleep(profile.delay_between_characteristics)
                
            except Exception as e:
                self.logger.error(f"Strategy {strategy_name} failed: {e}")
                results['strategy_results'][strategy_name] = {
                    'error': str(e),
                    'cases_executed': 0,
                    'crashes_found': 0
                }
        
        return results
    
    def _apply_profile_to_engine(self, profile: FuzzingProfile):
        """Apply profile settings to the base fuzzing engine"""
        # This would configure the base engine with profile settings
        # For now, we'll store the profile for reference
        self.base_engine.current_profile = profile
    
    def save_profile(self, profile_name: str, filename: str):
        """Save a fuzzing profile to file"""
        if profile_name not in self.profiles:
            raise ValueError(f"Profile '{profile_name}' not found")
        
        profile = self.profiles[profile_name]
        
        # Convert to JSON-serializable format
        profile_data = {
            'name': profile.name,
            'description': profile.description,
            'payload_types': profile.payload_types,
            'payload_sizes': profile.payload_sizes,
            'custom_payloads': [p.hex() for p in profile.custom_payloads],
            'iterations_per_test': profile.iterations_per_test,
            'delay_between_tests': profile.delay_between_tests,
            'delay_between_characteristics': profile.delay_between_characteristics,
            'strategies': profile.strategies,
            'max_cases_per_strategy': profile.max_cases_per_strategy,
            'target_characteristics': profile.target_characteristics,
            'only_writable': profile.only_writable,
            'skip_standard_services': profile.skip_standard_services,
            'crash_detection_timeout': profile.crash_detection_timeout,
            'max_crashes_before_stop': profile.max_crashes_before_stop,
            'recovery_delay_after_crash': profile.recovery_delay_after_crash,
            'adaptive_timing': profile.adaptive_timing,
            'payload_mutation_rate': profile.payload_mutation_rate,
            'enable_feedback_learning': profile.enable_feedback_learning
        }
        
        with open(filename, 'w') as f:
            json.dump(profile_data, f, indent=2)
        
        self.logger.info(f"Profile '{profile_name}' saved to {filename}")
    
    def load_profile(self, filename: str) -> str:
        """Load a fuzzing profile from file"""
        try:
            with open(filename, 'r') as f:
                profile_data = json.load(f)
            
            # Convert back from JSON format
            profile = FuzzingProfile(
                name=profile_data['name'],
                description=profile_data['description'],
                payload_types=profile_data['payload_types'],
                payload_sizes=profile_data['payload_sizes'],
                custom_payloads=[bytes.fromhex(p) for p in profile_data['custom_payloads']],
                iterations_per_test=profile_data['iterations_per_test'],
                delay_between_tests=profile_data['delay_between_tests'],
                delay_between_characteristics=profile_data['delay_between_characteristics'],
                strategies=profile_data['strategies'],
                max_cases_per_strategy=profile_data['max_cases_per_strategy'],
                target_characteristics=profile_data['target_characteristics'],
                only_writable=profile_data['only_writable'],
                skip_standard_services=profile_data['skip_standard_services'],
                crash_detection_timeout=profile_data['crash_detection_timeout'],
                max_crashes_before_stop=profile_data['max_crashes_before_stop'],
                recovery_delay_after_crash=profile_data['recovery_delay_after_crash'],
                adaptive_timing=profile_data['adaptive_timing'],
                payload_mutation_rate=profile_data['payload_mutation_rate'],
                enable_feedback_learning=profile_data['enable_feedback_learning']
            )
            
            self.profiles[profile.name] = profile
            self.logger.info(f"Profile '{profile.name}' loaded from {filename}")
            return profile.name
            
        except Exception as e:
            self.logger.error(f"Failed to load profile from {filename}: {e}")
            raise
    
    def get_profile_names(self) -> List[str]:
        """Get list of available profile names"""
        return list(self.profiles.keys())
    
    def get_profile_info(self, profile_name: str) -> Dict[str, Any]:
        """Get detailed information about a profile"""
        if profile_name not in self.profiles:
            return None
        
        profile = self.profiles[profile_name]
        return {
            'name': profile.name,
            'description': profile.description,
            'strategies': profile.strategies,
            'max_cases_per_strategy': profile.max_cases_per_strategy,
            'iterations_per_test': profile.iterations_per_test,
            'delay_between_tests': profile.delay_between_tests,
            'payload_types': profile.payload_types,
            'crash_detection_timeout': profile.crash_detection_timeout
        }