# cli/commands/research.py
import asyncio
import time
import json
from datetime import datetime
from .base import BaseCommands

class ResearchCommands(BaseCommands):
    """Commands for security research and fuzzing"""
    
    def get_commands(self):
        return {
            'research': self.cmd_research,
            'fuzz': self.cmd_fuzz,
            'fuzz-config': self.cmd_fuzz_config,
            'fuzz-help': self.cmd_fuzz_help,
            'stats': self.cmd_stats,
        }
    
    async def cmd_research(self, args):
        """Start comprehensive security research on device"""
        index = self.get_device_from_args_or_active(args)
        
        if index is None or index >= len(self.session.discovered_devices):
            self.print_error("Invalid device index")
            return
        
        device = self.session.discovered_devices[index]
        
        # Check if device is connected
        if index not in self.session.connected_devices:
            self.print_warning("Device not connected. Attempting smart connection...")
            # Import discovery commands to use smart connect
            from .discovery import DiscoveryCommands
            discovery = DiscoveryCommands(self.session, self.colors)
            await discovery.cmd_smart_connect([str(index)])
            
            if index not in self.session.connected_devices:
                self.print_error("Failed to connect to device")
                return
        
        device_info = self.session.connected_devices[index]
        
        print(f"{self.colors.WARNING}🔬 Starting comprehensive security research on {device.name or 'Unknown'}{self.colors.ENDC}")
        print(f"{self.colors.WARNING}⚠️  This will perform various security tests and may cause device instability!{self.colors.ENDC}")
        
        response = input(f"{self.colors.WARNING}Continue with research? (y/N): {self.colors.ENDC}")
        if response.lower() != 'y':
            print("Research cancelled")
            return
        
        try:
            # Step 1: Device profiling
            print(f"\n{self.colors.OKCYAN}[1/4] 📊 Device profiling...{self.colors.ENDC}")
            from core.device_profiler import DeviceProfiler
            profiler = DeviceProfiler()
            
            device_dict = {
                'address': device.address,
                'name': device.name,
                'rssi': getattr(device, 'rssi', None),
                'device_type': getattr(device, 'device_type', 'unknown'),
                'manufacturer_data': getattr(device, 'manufacturer_data', {}),
                'service_data': getattr(device, 'service_data', {}),
                'service_uuids': getattr(device, 'service_uuids', [])
            }
            
            deep_profile = await profiler.profile_device_deep(device_dict)
            research_score = deep_profile.get('research_potential', {}).get('overall_score', 0)
            
            print(f"Research potential: {research_score}/10")
            
            # Step 2: Service discovery and analysis
            print(f"\n{self.colors.OKCYAN}[2/4] 🛠️  Service analysis...{self.colors.ENDC}")
            if not hasattr(self.session, 'service_data') or index not in self.session.service_data:
                from .analysis import AnalysisCommands
                analysis = AnalysisCommands(self.session, self.colors)
                await analysis.cmd_services([str(index)])
            
            # Step 3: Memory research
            print(f"\n{self.colors.OKCYAN}[3/4] 🧬 Memory corruption research...{self.colors.ENDC}")
            
            memory_results = await self.session.researcher.execute(device.address)
            
            if memory_results['success']:
                self.print_success("Memory research completed")
                anomalies = sum(len(result.get('anomalies', [])) for result in memory_results.get('research_results', []))
                if anomalies > 0:
                    self.print_warning(f"Found {anomalies} potential anomalies")
            else:
                self.print_error(f"Memory research failed: {memory_results.get('error', 'Unknown error')}")
            
            # Step 4: Targeted fuzzing (if high research potential)
            if research_score >= 6:
                print(f"\n{self.colors.OKCYAN}[4/4] 💥 Targeted fuzzing...{self.colors.ENDC}")
                
                # Choose appropriate profile based on device type
                device_type = getattr(device, 'device_type', 'unknown').lower()
                if 'esp32' in device_type:
                    profile = 'esp32'
                elif any(keyword in device_type for keyword in ['apple', 'samsung', 'android']):
                    profile = 'smartphone'
                else:
                    profile = 'conservative'
                
                print(f"Using fuzzing profile: {profile}")
                await self.cmd_fuzz([str(index), profile])
            else:
                print(f"\n{self.colors.OKCYAN}[4/4] ⏭️  Skipping fuzzing (low research potential){self.colors.ENDC}")
            
            # Research summary
            print(f"\n{self.colors.BOLD}🔬 RESEARCH SUMMARY{self.colors.ENDC}")
            print(f"Device: {device.name or 'Unknown'} ({device.address})")
            print(f"Research Score: {research_score}/10")
            print(f"Memory Research: {'✓ Completed' if memory_results['success'] else '❌ Failed'}")
            
            self.session.session_stats['devices_tested'] += 1
            
        except Exception as e:
            self.print_error(f"Research failed: {e}")
            self.logger.error(f"Research error: {e}", exc_info=True)

    async def cmd_fuzz(self, args):
        """Start fuzzing device with configurable profiles or basic fuzzing"""
        index = self.get_device_from_args_or_active(args)
        
        if index is None or index not in self.session.connected_devices:
            self.print_error("No device connected")
            return
        
        device_info = self.session.connected_devices[index]
        device = device_info['device']
        client = device_info['client']
        
        # Try to use configurable fuzzing engine first
        use_basic_fuzzing = False
        try:
            from core.configurable_fuzzing import ConfigurableFuzzingEngine
            if not hasattr(self.session, 'fuzz_engine'):
                self.session.fuzz_engine = ConfigurableFuzzingEngine()
            
            engine = self.session.fuzz_engine
            profile_name = args[1] if len(args) > 1 else engine.current_profile.name
            
            if profile_name not in engine.profiles:
                self.print_warning(f"Profile '{profile_name}' not found. Using default 'aggressive'")
                profile_name = 'aggressive'
            
        except (ImportError, ModuleNotFoundError, AttributeError) as e:
            self.print_warning(f"Configurable fuzzing not available: {e}")
            self.print_info("🎯 Using basic fuzzing engine...")
            use_basic_fuzzing = True
            
            from core.fuzzing_engine import AdvancedFuzzingEngine, FuzzStrategy
            if not hasattr(self.session, 'basic_fuzz_engine'):
                self.session.basic_fuzz_engine = AdvancedFuzzingEngine()
            
            basic_engine = self.session.basic_fuzz_engine
            
            strategy_map = {
                'random': FuzzStrategy.RANDOM_MUTATION,
                'smart': FuzzStrategy.SMART_MUTATION,
                'timing': FuzzStrategy.TIMING_BASED,
                'protocol': FuzzStrategy.PROTOCOL_AWARE,
                'boundary': FuzzStrategy.BOUNDARY_VALUE,
                'state': FuzzStrategy.STATE_MACHINE
            }
            
            strategy_name = args[1] if len(args) > 1 else 'smart'
            fuzzing_strategy = strategy_map.get(strategy_name, FuzzStrategy.SMART_MUTATION)
        
        print(f"{self.colors.WARNING}⚠️  WARNING: Starting fuzzing on {device.name or 'Unknown'}{self.colors.ENDC}")
        print(f"{self.colors.WARNING}⚠️  This may cause device instability or crashes!{self.colors.ENDC}")
        
        if use_basic_fuzzing:
            print(f"Strategy: {fuzzing_strategy.value}")
            print(f"Available strategies: {', '.join(strategy_map.keys())}")
        else:
            print(f"Profile: {profile_name}")
        
        response = input(f"{self.colors.WARNING}Continue? (y/N): {self.colors.ENDC}")
        if response.lower() != 'y':
            print("Fuzzing cancelled")
            return
        
        # Get writable characteristics
        if not hasattr(self.session, 'service_data') or index not in self.session.service_data:
            self.print_warning("No service data. Running services discovery...")
            from .analysis import AnalysisCommands
            analysis = AnalysisCommands(self.session, self.colors)
            await analysis.cmd_services([str(index)])
        
        if not hasattr(self.session, 'service_data') or index not in self.session.service_data:
            self.print_error("Failed to discover services")
            return
        
        services_data = self.session.service_data[index]
        from core.gatt_handler import GATTHandler
        gatt_handler = GATTHandler()
        writable_chars = gatt_handler.find_writable_characteristics(services_data)
        
        if not writable_chars:
            self.print_warning("No writable characteristics found for fuzzing")
            return
        
        self.print_info(f"🎯 Starting fuzzing on {len(writable_chars)} characteristics...")
        
        # Execute fuzzing based on engine type
        if use_basic_fuzzing:
            total_results = await self._execute_basic_fuzzing(
                basic_engine, client, writable_chars, fuzzing_strategy
            )
        else:
            total_results = await self._execute_configurable_fuzzing(
                engine, client, writable_chars, profile_name
            )
        
        # Summary
        self._display_fuzzing_summary(total_results)

    async def cmd_fuzz_config(self, args):
        """Configure fuzzing profiles and strategies"""
        try:
            from core.configurable_fuzzing import ConfigurableFuzzingEngine
        except ImportError:
            self.print_error("Configurable fuzzing engine not available")
            return
        
        if not hasattr(self.session, 'fuzz_engine'):
            self.session.fuzz_engine = ConfigurableFuzzingEngine()
        
        engine = self.session.fuzz_engine
        
        if not args:
            # Show current profiles
            print(f"\n{self.colors.BOLD}Available Fuzzing Profiles:{self.colors.ENDC}")
            for name in engine.get_profile_names():
                current = "→ " if name == engine.current_profile.name else "  "
                profile_info = engine.get_profile_info(name)
                print(f"{current}{self.colors.OKGREEN}{name}{self.colors.ENDC}: {profile_info['description']}")
            
            print(f"\n{self.colors.BOLD}Commands:{self.colors.ENDC}")
            print(f"  {self.colors.OKCYAN}fuzz-config show <profile>{self.colors.ENDC}     - Show profile details")
            print(f"  {self.colors.OKCYAN}fuzz-config use <profile>{self.colors.ENDC}      - Switch to profile")
            print(f"  {self.colors.OKCYAN}fuzz-config create <name>{self.colors.ENDC}     - Create custom profile")
            print(f"  {self.colors.OKCYAN}fuzz-config save <profile> <file>{self.colors.ENDC} - Save profile to file")
            print(f"  {self.colors.OKCYAN}fuzz-config load <file>{self.colors.ENDC}       - Load profile from file")
            return
        
        command = args[0].lower()
        
        if command == "show" and len(args) > 1:
            profile_name = args[1]
            profile_info = engine.get_profile_info(profile_name)
            if profile_info:
                print(f"\n{self.colors.BOLD}Profile: {profile_info['name']}{self.colors.ENDC}")
                print(f"Description: {profile_info['description']}")
                print(f"Payload Types: {', '.join(profile_info['payload_types'])}")
                print(f"Strategies: {', '.join(profile_info['strategies'])}")
                print(f"Iterations per Test: {profile_info['iterations_per_test']}")
                print(f"Delay Between Tests: {profile_info['delay_between_tests']}s")
                print(f"Max Cases per Strategy: {profile_info['max_cases_per_strategy']}")
                print(f"Crash Detection Timeout: {profile_info['crash_detection_timeout']}s")
            else:
                self.print_error(f"Profile '{profile_name}' not found")
        
        elif command == "use" and len(args) > 1:
            profile_name = args[1]
            if profile_name in engine.profiles:
                engine.current_profile = engine.profiles[profile_name]
                self.print_success(f"Switched to profile: {profile_name}")
            else:
                self.print_error(f"Profile '{profile_name}' not found")
        
        elif command == "create" and len(args) > 1:
            profile_name = args[1]
            base_profile = args[2] if len(args) > 2 else "aggressive"
            try:
                engine.create_custom_profile(profile_name, base_profile)
                self.print_success(f"Created custom profile: {profile_name}")
                print(f"Based on: {base_profile}")
            except ValueError as e:
                self.print_error(f"Failed to create profile: {e}")
        
        elif command == "save" and len(args) > 2:
            profile_name = args[1]
            filename = args[2]
            try:
                engine.save_profile(profile_name, filename)
                self.print_success(f"Profile '{profile_name}' saved to {filename}")
            except Exception as e:
                self.print_error(f"Failed to save profile: {e}")
        
        elif command == "load" and len(args) > 1:
            filename = args[1]
            try:
                profile_name = engine.load_profile(filename)
                self.print_success(f"Profile '{profile_name}' loaded from {filename}")
            except Exception as e:
                self.print_error(f"Failed to load profile: {e}")
        
        else:
            self.print_error(f"Unknown fuzz-config command: {command}")
            print(f"Available commands: show, use, create, save, load")

    def cmd_fuzz_help(self, args):
        """Show fuzzing help and available strategies"""
        print(f"\n{self.colors.BOLD}🎯 BLUEFORGE FUZZING HELP{self.colors.ENDC}")
        
        print(f"\n{self.colors.BOLD}Basic Fuzzing Strategies:{self.colors.ENDC}")
        print(f"  {self.colors.OKGREEN}smart{self.colors.ENDC}     - Intelligent payload combination (recommended)")
        print(f"  {self.colors.OKGREEN}random{self.colors.ENDC}    - Random mutation fuzzing")
        print(f"  {self.colors.OKGREEN}timing{self.colors.ENDC}    - Timing-based race condition testing")
        print(f"  {self.colors.OKGREEN}protocol{self.colors.ENDC}  - BLE protocol violation testing")
        print(f"  {self.colors.OKGREEN}boundary{self.colors.ENDC}  - Boundary value analysis")
        print(f"  {self.colors.OKGREEN}state{self.colors.ENDC}     - State machine confusion testing")
        
        print(f"\n{self.colors.BOLD}Usage Examples:{self.colors.ENDC}")
        print(f"  {self.colors.OKCYAN}fuzz{self.colors.ENDC}                 - Use default strategy (smart)")
        print(f"  {self.colors.OKCYAN}fuzz timing{self.colors.ENDC}          - Use timing-based fuzzing")
        print(f"  {self.colors.OKCYAN}fuzz 0 protocol{self.colors.ENDC}      - Fuzz device 0 with protocol strategy")
        
        print(f"\n{self.colors.BOLD}Configurable Profiles (if available):{self.colors.ENDC}")
        print(f"  {self.colors.OKGREEN}aggressive{self.colors.ENDC}   - High-intensity research fuzzing")
        print(f"  {self.colors.OKGREEN}conservative{self.colors.ENDC} - Safe testing for production devices")
        print(f"  {self.colors.OKGREEN}esp32{self.colors.ENDC}        - Optimized for ESP32 targets")
        print(f"  {self.colors.OKGREEN}smartphone{self.colors.ENDC}   - Specialized for mobile devices")

    def cmd_stats(self, args):
        """Show session statistics"""
        print(f"\n{self.colors.BOLD}SESSION STATISTICS:{self.colors.ENDC}")
        print(f"  📊 Session started: {self.session.session_stats['session_start'].strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  🔍 Scans performed: {self.session.session_stats['scans_performed']}")
        print(f"  🎯 Devices tested: {self.session.session_stats['devices_tested']}")
        print(f"  💥 Vulnerabilities found: {self.session.session_stats['vulnerabilities_found']}")
        
        # Connection manager stats
        cm_stats = self.session.ble_manager.connection_manager.get_statistics()
        print(f"  🔗 Total connections: {cm_stats['total_connections']}")
        print(f"  ✅ Successful connections: {cm_stats['successful_connections']}")
        print(f"  ❌ Failed connections: {cm_stats['failed_connections']}")
        print(f"  💥 Crashes detected: {cm_stats['crashes_detected']}")

    async def _execute_basic_fuzzing(self, basic_engine, client, writable_chars, strategy):
        """Execute basic fuzzing using AdvancedFuzzingEngine"""
        from core.fuzzing_engine import FuzzStrategy
        total_results = []
        
        for i, char_info in enumerate(writable_chars):
            char_uuid = char_info['char_uuid']
            print(f"\n[{i+1}/{len(writable_chars)}] Fuzzing characteristic: {char_uuid}")
            print(f"  Handle: 0x{char_info['handle']:04X}")
            print(f"  Properties: {', '.join(char_info['properties'])}")
            
            try:
                print(f"  Strategy: {strategy.value}")
                
                max_cases = {
                    FuzzStrategy.RANDOM_MUTATION: 50,
                    FuzzStrategy.SMART_MUTATION: 75,
                    FuzzStrategy.TIMING_BASED: 30,
                    FuzzStrategy.PROTOCOL_AWARE: 25,
                    FuzzStrategy.BOUNDARY_VALUE: 15,
                    FuzzStrategy.STATE_MACHINE: 20
                }.get(strategy, 50)
                
                print(f"  Max test cases: {max_cases}")
                
                fuzz_results = await basic_engine.fuzz_target(client, char_uuid, strategy, max_cases)
                
                crashes = len([r for r in fuzz_results if r.crashed])
                successes = len([r for r in fuzz_results if r.success])
                errors = len([r for r in fuzz_results if not r.success])
                
                result_summary = {
                    'characteristic': char_uuid,
                    'strategy': strategy.value,
                    'total_cases': len(fuzz_results),
                    'crashes': crashes,
                    'successes': successes,
                    'errors': errors,
                    'crash_rate': (crashes / len(fuzz_results) * 100) if fuzz_results else 0,
                    'raw_results': fuzz_results
                }
                
                total_results.append(result_summary)
                
                if crashes > 0:
                    print(f"  {self.colors.FAIL}💥 Found {crashes} crashes!{self.colors.ENDC}")
                    self.session.session_stats['vulnerabilities_found'] += crashes
                    
                    crash_patterns = {}
                    for result in fuzz_results:
                        if result.crashed:
                            pattern = result.case.payload[:8].hex()
                            crash_patterns[pattern] = crash_patterns.get(pattern, 0) + 1
                    
                    print(f"  {self.colors.WARNING}Crash patterns:{self.colors.ENDC}")
                    for pattern, count in crash_patterns.items():
                        print(f"    {pattern}: {count} times")
                else:
                    print(f"  {self.colors.OKGREEN}✓ No crashes detected{self.colors.ENDC}")
                
                print(f"  Cases: {len(fuzz_results)}, Success: {successes}, Errors: {errors}")
                
                if crashes > 0:
                    from config import config
                    print(f"  Waiting {config.device_recovery_delay}s for device recovery...")
                    await asyncio.sleep(config.device_recovery_delay)
                else:
                    await asyncio.sleep(1)
                    
            except Exception as e:
                self.print_error(f"Fuzzing failed: {e}")
                total_results.append({
                    'characteristic': char_uuid,
                    'strategy': strategy.value,
                    'total_cases': 0,
                    'crashes': 0,
                    'successes': 0,
                    'errors': 1,
                    'crash_rate': 0,
                    'error': str(e)
                })
        
        return total_results

    async def _execute_configurable_fuzzing(self, engine, client, writable_chars, profile_name):
        """Execute configurable fuzzing using ConfigurableFuzzingEngine"""
        total_results = []
        
        for i, char_info in enumerate(writable_chars):
            char_uuid = char_info['char_uuid']
            print(f"\n[{i+1}/{len(writable_chars)}] Fuzzing characteristic: {char_uuid}")
            
            try:
                results = await engine.fuzz_with_profile(client, char_uuid, profile_name)
                total_results.append({
                    'characteristic': char_uuid,
                    'profile': profile_name,
                    'overall_crashes': results['overall_crashes'],
                    'total_cases': results['total_cases'],
                    'strategy_results': results['strategy_results']
                })
                
                crashes = results['overall_crashes']
                if crashes > 0:
                    print(f"  {self.colors.FAIL}💥 Found {crashes} crashes!{self.colors.ENDC}")
                    self.session.session_stats['vulnerabilities_found'] += crashes
                else:
                    print(f"  {self.colors.OKGREEN}✓ No crashes detected{self.colors.ENDC}")
                    
            except Exception as e:
                self.print_error(f"Fuzzing failed: {e}")
                total_results.append({
                    'characteristic': char_uuid,
                    'profile': profile_name,
                    'overall_crashes': 0,
                    'total_cases': 0,
                    'error': str(e)
                })
        
        return total_results

    def _display_fuzzing_summary(self, total_results):
        """Display comprehensive fuzzing summary"""
        print(f"\n{self.colors.BOLD}🎯 FUZZING COMPLETE{self.colors.ENDC}")
        
        if not total_results:
            self.print_warning("No results to display")
            return
        
        total_crashes = 0
        total_cases = 0
        characteristics_tested = len(total_results)
        characteristics_with_crashes = 0
        
        for result in total_results:
            if 'overall_crashes' in result:  # Configurable fuzzing
                total_crashes += result['overall_crashes']
                total_cases += result['total_cases']
                if result['overall_crashes'] > 0:
                    characteristics_with_crashes += 1
            elif 'crashes' in result:  # Basic fuzzing
                total_crashes += result['crashes']
                total_cases += result['total_cases']
                if result['crashes'] > 0:
                    characteristics_with_crashes += 1
        
        print(f"Characteristics tested: {characteristics_tested}")
        print(f"Total test cases: {total_cases}")
        print(f"Total crashes found: {total_crashes}")
        print(f"Characteristics with crashes: {characteristics_with_crashes}")
        
        if total_cases > 0:
            crash_rate = (total_crashes / total_cases * 100)
            print(f"Overall crash rate: {crash_rate:.1f}%")
            
            if crash_rate > 10:
                print(f"{self.colors.FAIL}🚨 HIGH CRASH RATE - Significant vulnerabilities detected!{self.colors.ENDC}")
            elif crash_rate > 5:
                print(f"{self.colors.WARNING}⚠️  MODERATE CRASH RATE - Some vulnerabilities found{self.colors.ENDC}")
            elif crash_rate > 0:
                print(f"{self.colors.WARNING}💡 LOW CRASH RATE - Minor issues detected{self.colors.ENDC}")
            else:
                print(f"{self.colors.OKGREEN}✅ NO CRASHES - Device appears stable{self.colors.ENDC}")
        
        # Save results option
        response = input(f"\n{self.colors.OKCYAN}Save detailed results to file? (y/N): {self.colors.ENDC}")
        if response.lower() == 'y':
            self._save_fuzzing_results(total_results)

    def _save_fuzzing_results(self, results):
        """Save fuzzing results to file"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"blueforge_fuzz_results_{timestamp}.json"
            
            output_data = {
                'timestamp': timestamp,
                'total_results': len(results),
                'summary': {
                    'total_crashes': sum(r.get('crashes', r.get('overall_crashes', 0)) for r in results),
                    'total_cases': sum(r.get('total_cases', 0) for r in results),
                    'characteristics_tested': len(results)
                },
                'detailed_results': results
            }
            
            with open(filename, 'w') as f:
                json.dump(output_data, f, indent=2, default=str)
            
            self.print_success(f"Results saved to {filename}")
            
        except Exception as e:
            self.print_error(f"Failed to save results: {e}")