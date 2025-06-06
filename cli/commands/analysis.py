# cli/commands/analysis.py
import asyncio
from .base import BaseCommands

class AnalysisCommands(BaseCommands):
    """Commands for device analysis and information gathering"""
    
    def get_commands(self):
        return {
            'info': self.cmd_info,
            'profile': self.cmd_profile,
            'services': self.cmd_services,
            'chars': self.cmd_chars,
            'validate': self.cmd_validate,
        }
    
    async def cmd_info(self, args):
        """Show detailed device information"""
        index = self.get_device_from_args_or_active(args)
        
        if index is None:
            self.print_error("No device specified. Usage: info [device_index]")
            return
        
        if index >= len(self.session.discovered_devices):
            self.print_error("Invalid device index")
            return
        
        device = self.session.discovered_devices[index]
        is_connected = index in self.session.connected_devices
        
        print(f"\n{self.colors.BOLD}DEVICE INFORMATION:{self.colors.ENDC}")
        print(f"  📱 Index: {index}")
        print(f"  🏷️  Name: {device.name or 'Unknown Device'}")
        print(f"  📍 Address: {device.address}")
        print(f"  📶 RSSI: {getattr(device, 'rssi', 'Unknown')} dBm")
        print(f"  🔗 Status: {'Connected' if is_connected else 'Disconnected'}")
        
        if is_connected:
            conn_info = self.session.connected_devices[index]
            connected_at = conn_info['connected_at'].strftime("%Y-%m-%d %H:%M:%S")
            print(f"  ⏰ Connected since: {connected_at}")

    async def cmd_profile(self, args):
        """Profile a device with detailed information"""
        index = self.get_device_from_args_or_active(args)
        
        if index is None or index >= len(self.session.discovered_devices):
            self.print_error("Invalid device index")
            return
        
        device = self.session.discovered_devices[index]
        self.print_info(f"🔍 Profiling {device.name or 'Unknown'} ({device.address})...")
        
        # Convert device to dict format for profiler
        device_dict = {
            'address': device.address,
            'name': device.name,
            'rssi': getattr(device, 'rssi', None),
            'device_type': getattr(device, 'device_type', 'unknown'),
            'manufacturer_data': getattr(device, 'manufacturer_data', {}),
            'service_data': getattr(device, 'service_data', {}),
            'service_uuids': getattr(device, 'service_uuids', []),
            'local_name': getattr(device, 'local_name', None),
            'tx_power': getattr(device, 'tx_power', None)
        }
        
        from core.device_profiler import DeviceProfiler
        profiler = DeviceProfiler()
        
        # Quick profile first
        quick_profile = await profiler.profile_device_quick(device_dict)
        self._display_device_profile(quick_profile, detailed=False)
        
        # Ask for deep profile
        response = input(f"{self.colors.WARNING}Attempt connection for deep profile? (y/N): {self.colors.ENDC}")
        if response.lower() == 'y':
            deep_profile = await profiler.profile_device_deep(device_dict)
            self._display_device_profile(deep_profile, detailed=True)

    async def cmd_services(self, args):
        """List device services and characteristics"""
        index = self.get_device_from_args_or_active(args)
        
        if index is None:
            self.print_error("No device specified or connected")
            return
        
        if index not in self.session.connected_devices:
            self.print_error(f"Device not connected. Use 'connect {index}' first")
            return
        
        device_info = self.session.connected_devices[index]
        client = device_info['client']
        device = device_info['device']
        
        print(f"\n{self.colors.BOLD}SERVICES & CHARACTERISTICS - {device.name}:{self.colors.ENDC}")
        
        try:
            from core.gatt_handler import GATTHandler
            gatt_handler = GATTHandler()
            
            services_data = await gatt_handler.discover_services(client)
            
            if not services_data:
                self.print_warning("No services discovered")
                return
            
            total_chars = 0
            writable_count = 0
            
            for i, service in enumerate(services_data):
                print(f"\n  [{i:2d}] 🛠️  Service: {self.colors.OKCYAN}{service['uuid']}{self.colors.ENDC}")
                if service.get('description'):
                    print(f"       Description: {service['description']}")
                
                for j, char in enumerate(service['characteristics']):
                    total_chars += 1
                    
                    # Color code by properties
                    props = char['properties']
                    if any(prop in props for prop in ['write', 'write-without-response']):
                        prop_color = self.colors.WARNING
                        prop_icon = "✏️"
                        writable_count += 1
                    elif "read" in props:
                        prop_color = self.colors.OKGREEN
                        prop_icon = "👁️"
                    elif any(prop in props for prop in ['notify', 'indicate']):
                        prop_color = self.colors.OKBLUE
                        prop_icon = "📡"
                    else:
                        prop_color = self.colors.ENDC
                        prop_icon = "🔹"
                    
                    print(f"         [{j:2d}] {prop_icon} {prop_color}{char['uuid']}{self.colors.ENDC}")
                    print(f"              Handle: 0x{char['handle']:04X}")
                    print(f"              Properties: {', '.join(props)}")
                    
                    if char.get('descriptors'):
                        for k, desc in enumerate(char['descriptors']):
                            print(f"              📄 Descriptor [{k}]: {desc['uuid']} (Handle: 0x{desc['handle']:04X})")
            
            self.print_success(f"Found {len(services_data)} services with {total_chars} characteristics")
            
            if writable_count > 0:
                self.print_warning(f"🎯 {writable_count} writable characteristics found - excellent targets for fuzzing!")
            
            # Store service data in session for later use
            if not hasattr(self.session, 'service_data'):
                self.session.service_data = {}
            self.session.service_data[index] = services_data
                
        except Exception as e:
            self.print_error(f"Failed to enumerate services: {e}")

    def cmd_chars(self, args):
        """Show detailed characteristic information"""
        index = self.get_device_from_args_or_active(args)
        
        if index is None or index not in self.session.connected_devices:
            self.print_error("No device connected")
            return
        
        if not hasattr(self.session, 'service_data') or index not in self.session.service_data:
            self.print_warning("No service data. Run 'services' first")
            return
        
        services_data = self.session.service_data[index]
        
        from core.gatt_handler import GATTHandler
        gatt_handler = GATTHandler()
        
        # Get different types of characteristics
        writable = gatt_handler.find_writable_characteristics(services_data)
        readable = gatt_handler.find_readable_characteristics(services_data)
        notifiable = gatt_handler.find_notifiable_characteristics(services_data)
        
        print(f"\n{self.colors.BOLD}CHARACTERISTIC ANALYSIS:{self.colors.ENDC}")
        
        if writable:
            print(f"\n{self.colors.WARNING}✏️  WRITABLE CHARACTERISTICS ({len(writable)}):{self.colors.ENDC}")
            for i, char in enumerate(writable):
                print(f"  [{i}] {char['char_uuid']} (Handle: 0x{char['handle']:04X})")
                print(f"      Service: {char['service_uuid']}")
                print(f"      Properties: {', '.join(char['properties'])}")
        
        if readable:
            print(f"\n{self.colors.OKGREEN}👁️  READABLE CHARACTERISTICS ({len(readable)}):{self.colors.ENDC}")
            for i, char in enumerate(readable[:5]):
                print(f"  [{i}] {char['char_uuid']} (Handle: 0x{char['handle']:04X})")
        
        if notifiable:
            print(f"\n{self.colors.OKBLUE}📡 NOTIFIABLE CHARACTERISTICS ({len(notifiable)}):{self.colors.ENDC}")
            for i, char in enumerate(notifiable):
                print(f"  [{i}] {char['char_uuid']} (Handle: 0x{char['handle']:04X})")

    async def cmd_validate(self, args):
        """Validate device for vulnerabilities"""
        index = self.get_device_from_args_or_active(args)
        
        if index is None:
            self.print_error("No device specified or connected")
            return
        
        if index >= len(self.session.discovered_devices):
            self.print_error("Invalid device index")
            return
        
        device = self.session.discovered_devices[index]
        
        self.print_info(f"🔍 Validating {device.name or 'Unknown'} for vulnerabilities...")
        
        try:
            is_vulnerable = await self.session.researcher.validate_target(device)
            
            if is_vulnerable:
                self.print_warning("Device appears to have interesting characteristics for research")
                self.print_success("Device is a good candidate for security testing")
                
                if hasattr(self.session, 'service_data') and index in self.session.service_data:
                    services_data = self.session.service_data[index]
                    from core.gatt_handler import GATTHandler
                    gatt_handler = GATTHandler()
                    writable = gatt_handler.find_writable_characteristics(services_data)
                    self.print_info(f"📊 Found {len(writable)} writable characteristics")
            else:
                self.print_info("Device has limited attack surface")
                self.print_info("💡 No writable characteristics found for research")
                    
        except Exception as e:
            self.print_error(f"Validation error: {e}")

    def _display_device_profile(self, profile, detailed=False):
        """Display device profile information"""
        basic = profile['basic_info']
        print(f"\n{self.colors.BOLD}📱 DEVICE PROFILE - {basic['name']}{self.colors.ENDC}")
        print(f"  Address: {basic['address']}")
        print(f"  Type: {basic['device_type']}")
        print(f"  RSSI: {basic['rssi']} dBm")
        
        # Research potential
        research = profile.get('research_potential', {})
        score = research.get('overall_score', 0)
        if score >= 7:
            score_color = self.colors.OKGREEN
            score_icon = "🎯"
        elif score >= 4:
            score_color = self.colors.WARNING
            score_icon = "⚠️"
        else:
            score_color = self.colors.FAIL
            score_icon = "❌"
        
        print(f"  {score_icon} Research Score: {score_color}{score}/10{self.colors.ENDC}")
        
        # Privacy features
        privacy = profile.get('privacy_features', {})
        if privacy.get('mac_randomization'):
            print(f"  🔒 Privacy: {self.colors.WARNING}MAC Randomization Enabled{self.colors.ENDC}")
        
        # Manufacturer info
        manufacturer = profile.get('manufacturer_info', {})
        if manufacturer.get('manufacturers'):
            for mfg in manufacturer['manufacturers']:
                print(f"  🏭 Manufacturer: {mfg['company_name']}")
        
        # Connection strategy
        strategy = profile.get('connection_strategy', {})
        print(f"  🔗 Connection Strategy: {strategy.get('approach', 'unknown')}")
        
        if detailed and 'services_analysis' in profile:
            services = profile['services_analysis']
            print(f"\n{self.colors.BOLD}🛠️  SERVICE ANALYSIS:{self.colors.ENDC}")
            print(f"  Services: {services.get('total_services', 0)}")
            print(f"  Characteristics: {services.get('total_characteristics', 0)}")
            print(f"  Writable: {len(services.get('writable_characteristics', []))}")
            
            vulnerabilities = profile.get('vulnerability_assessment', {})
            risk = vulnerabilities.get('risk_level', 'unknown')
            risk_color = self.colors.FAIL if risk == 'high' else self.colors.WARNING if risk == 'medium' else self.colors.OKGREEN
            print(f"  Risk Level: {risk_color}{risk.upper()}{self.colors.ENDC}")