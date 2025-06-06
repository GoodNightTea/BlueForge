# cli/commands/debug.py
from .base import BaseCommands

class DebugCommands(BaseCommands):
    """Debug and development commands"""
    
    def get_commands(self):
        return {
            'debug-services': self.cmd_debug_services,
            'debug-connection': self.cmd_debug_connection,
            'test-payloads': self.cmd_test_payloads,
        }
    
    async def cmd_debug_services(self, args):
        """Debug service discovery"""
        index = self.get_device_from_args_or_active(args)
        
        if index is None or index not in self.session.connected_devices:
            self.print_error("No device connected")
            return
        
        device_info = self.session.connected_devices[index]
        client = device_info['client']
        
        self.print_info(f"🐛 Debug: Service discovery for {device_info['device'].name}")
        
        try:
            print(f"Client connected: {client.is_connected}")
            print(f"Client address: {client.address}")
            
            print("Accessing services...")
            services = client.services
            
            service_count = sum(1 for _ in services)
            print(f"Services object type: {type(services)}")
            print(f"Services count: {service_count}")
            
            actual_count = 0
            for service in services:
                actual_count += 1
                print(f"Service {actual_count}: {service.uuid}")
                
                char_count = 0
                for char in service.characteristics:
                    char_count += 1
                    print(f"  Char {char_count}: {char.uuid} - Props: {char.properties}")
            
            print(f"Total services found: {actual_count}")
            
        except Exception as e:
            self.print_error(f"Debug failed: {e}")
            import traceback
            traceback.print_exc()

    async def cmd_debug_connection(self, args):
        """Debug connection issues with specific device"""
        index = self.get_device_from_args_or_active(args)
        
        if index is None or index >= len(self.session.discovered_devices):
            self.print_error("Invalid device index")
            return
        
        device = self.session.discovered_devices[index]
        self.print_info(f"🔧 Debug connection to {device.name} ({device.address})")
        
        from core.device_profiler import DeviceProfiler
        profiler = DeviceProfiler()
        
        device_dict = {
            'name': device.name, 
            'address': device.address, 
            'device_type': getattr(device, 'device_type', 'unknown')
        }
        strategy = profiler._suggest_connection_strategy(device_dict)
        
        print(f"Suggested strategy: {strategy['approach']}")
        print(f"Timeout: {strategy['timeout']}s")
        print(f"Retry attempts: {strategy['retry_attempts']}")
        
        if strategy['special_considerations']:
            print("Special considerations:")
            for consideration in strategy['special_considerations']:
                print(f"  • {consideration}")
        
        if strategy['expected_challenges']:
            print("Expected challenges:")
            for challenge in strategy['expected_challenges']:
                print(f"  • {challenge}")

    def cmd_test_payloads(self, args):
        """Test payload generation"""
        self.print_info("🧪 Testing payload generation...")
        
        from core.fuzzing_engine import PayloadGenerator
        generator = PayloadGenerator()
        
        print(f"\n{self.colors.BOLD}Sample hex patterns:{self.colors.ENDC}")
        patterns = generator.hex_patterns()
        for i, pattern in enumerate(patterns[:5]):
            print(f"  [{i}] {pattern.hex()}")
        
        print(f"\n{self.colors.BOLD}Sample integer overflows (32-bit):{self.colors.ENDC}")
        overflows = generator.integer_overflows(32)
        for i, overflow in enumerate(overflows[:3]):
            print(f"  [{i}] {overflow.hex()}")
        
        print(f"\n{self.colors.BOLD}Timing attack cases:{self.colors.ENDC}")
        timing_cases = generator.timing_attack_payloads()
        for i, case in enumerate(timing_cases[:3]):
            print(f"  [{i}] {case.payload.hex()} - {case.iterations} iterations, {case.delay_ms}ms delay")
        
        print(f"\n{self.colors.BOLD}State machine payloads:{self.colors.ENDC}")
        state_payloads = generator.state_machine_payloads()
        for i, payload in enumerate(state_payloads):
            print(f"  [{i}] {payload.hex()}")
        
        print(f"\n{self.colors.BOLD}Random samples:{self.colors.ENDC}")
        for i in range(3):
            random_payload = generator.random_bytes(8, 16)
            print(f"  [{i}] {random_payload.hex()}")