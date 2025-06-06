# core/device_profiler.py
import asyncio
import struct
from typing import Dict, List, Optional, Any
from bleak import BleakClient
from bleak.exc import BleakError
from utils.logging import get_logger

logger = get_logger(__name__)

class DeviceProfiler:
    """Advanced device profiling and information gathering"""
    
    def __init__(self):
        self.device_profiles = {}
        self.known_manufacturers = {
            0x004C: "Apple Inc.",
            0x0075: "Samsung Electronics Co. Ltd.",
            0x00E0: "Google",
            0x0006: "Microsoft",
            0x0087: "Garmin International",
            0x004F: "Nordic Semiconductor ASA",
            0x0590: "Espressif Systems",
            0x03DA: "Flipper Devices Inc"
        }
        
        self.known_services = {
            "0000180F-0000-1000-8000-00805F9B34FB": "Battery Service",
            "0000180A-0000-1000-8000-00805F9B34FB": "Device Information Service",
            "00001800-0000-1000-8000-00805F9B34FB": "Generic Access",
            "00001801-0000-1000-8000-00805F9B34FB": "Generic Attribute",
            "0000181C-0000-1000-8000-00805F9B34FB": "User Data Service",
            "6E400001-B5A3-F393-E0A9-E50E24DCCA9E": "Nordic UART Service",
            "19B10001-E8F2-537E-4F6C-D104768A1214": "Custom Service (Research Target)",
        }
    
    async def profile_device_quick(self, device_info: Dict) -> Dict[str, Any]:
        """Quick profiling without connection - analyze advertisement data"""
        
        profile = {
            'basic_info': {
                'address': device_info['address'],
                'name': device_info['name'],
                'rssi': device_info['rssi'],
                'device_type': device_info.get('device_type', 'unknown')
            },
            'advertisement_analysis': {},
            'manufacturer_info': {},
            'privacy_features': {},
            'research_potential': {},
            'connection_strategy': {}
        }
        
        # Analyze advertisement data
        profile['advertisement_analysis'] = self._analyze_advertisement_data(device_info)
        
        # Analyze manufacturer data
        if device_info.get('manufacturer_data'):
            profile['manufacturer_info'] = self._analyze_manufacturer_data(
                device_info['manufacturer_data']
            )
        
        # Detect privacy features
        profile['privacy_features'] = self._detect_privacy_features(device_info)
        
        # Assess research potential
        profile['research_potential'] = self._assess_research_potential(device_info)
        
        # Suggest connection strategy
        profile['connection_strategy'] = self._suggest_connection_strategy(device_info)
        
        return profile
    
    async def profile_device_deep(self, device_info: Dict, 
                                 connection_timeout: int = 10) -> Dict[str, Any]:
        """Deep profiling with temporary connection"""
        
        # Start with quick profile
        profile = await self.profile_device_quick(device_info)
        
        address = device_info['address']
        logger.info(f"Starting deep profile of {device_info['name']} ({address})")
        
        # Attempt connection with appropriate strategy
        connection_success = False
        connection_error = None
        
        try:
            client = await self._smart_connect(device_info, connection_timeout)
            if client:
                connection_success = True
                
                # Gather deep information
                profile['connection_info'] = await self._analyze_connection(client)
                profile['services_analysis'] = await self._analyze_services_deep(client)
                profile['security_analysis'] = await self._analyze_security_features(client)
                profile['vulnerability_assessment'] = await self._assess_vulnerabilities(client)
                
                # Disconnect cleanly
                await client.disconnect()
                
        except Exception as e:
            connection_error = str(e)
            logger.warning(f"Deep profiling failed for {address}: {e}")
        
        profile['connection_result'] = {
            'success': connection_success,
            'error': connection_error,
            'timestamp': asyncio.get_event_loop().time()
        }
        
        return profile
    
    def _analyze_advertisement_data(self, device_info: Dict) -> Dict[str, Any]:
        """Analyze BLE advertisement data for insights"""
        
        analysis = {
            'has_local_name': bool(device_info.get('local_name')),
            'has_manufacturer_data': bool(device_info.get('manufacturer_data')),
            'has_service_data': bool(device_info.get('service_data')),
            'advertised_services': device_info.get('service_uuids', []),
            'tx_power': device_info.get('tx_power'),
            'advertisement_flags': []
        }
        
        # Analyze service UUIDs
        if analysis['advertised_services']:
            analysis['known_services'] = []
            analysis['custom_services'] = []
            
            for service_uuid in analysis['advertised_services']:
                service_uuid_str = str(service_uuid).upper()
                if service_uuid_str in self.known_services:
                    analysis['known_services'].append({
                        'uuid': service_uuid_str,
                        'name': self.known_services[service_uuid_str]
                    })
                else:
                    analysis['custom_services'].append(service_uuid_str)
        
        return analysis
    
    def _analyze_manufacturer_data(self, manufacturer_data: Dict) -> Dict[str, Any]:
        """Analyze manufacturer-specific data"""
        
        analysis = {
            'manufacturers': [],
            'apple_analysis': {},
            'samsung_analysis': {},
            'esp32_analysis': {},
            'flipper_analysis': {}
        }
        
        for company_id, data in manufacturer_data.items():
            manufacturer_info = {
                'company_id': company_id,
                'company_name': self.known_manufacturers.get(company_id, f"Unknown (0x{company_id:04X})"),
                'data_length': len(data),
                'raw_data': data.hex() if isinstance(data, bytes) else str(data)
            }
            
            # Company-specific analysis
            if company_id == 0x004C:  # Apple
                manufacturer_info['apple_details'] = self._analyze_apple_data(data)
                analysis['apple_analysis'] = manufacturer_info['apple_details']
            elif company_id == 0x0075:  # Samsung
                manufacturer_info['samsung_details'] = self._analyze_samsung_data(data)
                analysis['samsung_analysis'] = manufacturer_info['samsung_details']
            elif company_id == 0x0590:  # Espressif (ESP32)
                manufacturer_info['esp32_details'] = self._analyze_esp32_data(data)
                analysis['esp32_analysis'] = manufacturer_info['esp32_details']
            elif company_id == 0x03DA:  # Flipper Devices
                manufacturer_info['flipper_details'] = self._analyze_flipper_data(data)
                analysis['flipper_analysis'] = manufacturer_info['flipper_details']
            
            analysis['manufacturers'].append(manufacturer_info)
        
        return analysis
    
    def _analyze_apple_data(self, data: bytes) -> Dict[str, Any]:
        """Analyze Apple-specific manufacturer data"""
        
        if len(data) < 2:
            return {'error': 'Insufficient data'}
        
        apple_type = data[0]
        apple_subtype = data[1] if len(data) > 1 else None
        
        analysis = {
            'type': apple_type,
            'subtype': apple_subtype,
            'data_hex': data.hex(),
            'interpretation': {}
        }
        
        # Apple continuity message types
        if apple_type == 0x01:
            analysis['interpretation']['type'] = 'iBeacon'
        elif apple_type == 0x02:
            analysis['interpretation']['type'] = 'AirDrop'
        elif apple_type == 0x03:
            analysis['interpretation']['type'] = 'AirPrint'
        elif apple_type == 0x05:
            analysis['interpretation']['type'] = 'AirPlay'
        elif apple_type == 0x07:
            analysis['interpretation']['type'] = 'Proximity Pairing'
        elif apple_type == 0x08:
            analysis['interpretation']['type'] = 'Hey Siri'
        elif apple_type == 0x09:
            analysis['interpretation']['type'] = 'AirPods'
        elif apple_type == 0x0A:
            analysis['interpretation']['type'] = 'Handoff'
        elif apple_type == 0x0C:
            analysis['interpretation']['type'] = 'WiFi Password Sharing'
        elif apple_type == 0x10:
            analysis['interpretation']['type'] = 'Nearby Action'
        elif apple_type == 0x12:
            analysis['interpretation']['type'] = 'FindMy'
        else:
            analysis['interpretation']['type'] = f'Unknown Apple Type (0x{apple_type:02X})'
        
        return analysis
    
    def _analyze_flipper_data(self, data: bytes) -> Dict[str, Any]:
        """Analyze Flipper Zero specific data"""
        
        return {
            'device_type': 'Flipper Zero',
            'data_hex': data.hex(),
            'security_note': 'Flipper devices often have strict BLE security implementations',
            'connection_difficulty': 'high',
            'research_value': 'moderate - educational device with known security features'
        }
    
    def _detect_privacy_features(self, device_info: Dict) -> Dict[str, Any]:
        """Detect privacy and security features"""
        
        features = {
            'mac_randomization': False,
            'privacy_level': 'unknown',
            'trackable': True,
            'security_indicators': []
        }
        
        address = device_info['address']
        
        # Check for MAC randomization (local address bit)
        if address:
            mac_bytes = address.replace(':', '').replace('-', '')
            if len(mac_bytes) >= 2:
                first_byte = int(mac_bytes[0:2], 16)
                if first_byte & 0x02:  # Local address bit set
                    features['mac_randomization'] = True
                    features['privacy_level'] = 'high'
                    features['trackable'] = False
                    features['security_indicators'].append('MAC randomization enabled')
        
        # Check for Apple privacy features
        if device_info.get('manufacturer_data', {}).get(0x004C):
            features['security_indicators'].append('Apple privacy protocols')
            features['privacy_level'] = 'very_high'
        
        # Check for minimal advertisement data (privacy indicator)
        if not device_info.get('name') or device_info['name'].startswith(('Unknown', '')):
            features['security_indicators'].append('Minimal advertisement data')
        
        return features
    
    def _assess_research_potential(self, device_info: Dict) -> Dict[str, Any]:
        """Assess device's potential for security research"""
        
        assessment = {
            'overall_score': 0,
            'factors': {},
            'recommendations': [],
            'difficulty_level': 'unknown',
            'target_type': 'unknown'
        }
        
        score = 0
        
        # Device type scoring
        device_type = device_info.get('device_type', '').lower()
        if 'esp32' in device_type:
            score += 9
            assessment['factors']['esp32_target'] = 'High value research target'
            assessment['target_type'] = 'microcontroller'
            assessment['difficulty_level'] = 'medium'
        elif 'arduino' in device_type or 'microcontroller' in device_type:
            score += 8
            assessment['factors']['microcontroller'] = 'Good research target'
            assessment['target_type'] = 'microcontroller'
            assessment['difficulty_level'] = 'medium'
        elif 'apple' in device_type:
            score += 3
            assessment['factors']['apple_device'] = 'Limited research potential due to security'
            assessment['target_type'] = 'smartphone'
            assessment['difficulty_level'] = 'very_high'
        elif 'samsung' in device_type:
            score += 4
            assessment['factors']['samsung_device'] = 'Moderate research potential'
            assessment['target_type'] = 'smart_device'
            assessment['difficulty_level'] = 'high'
        elif 'flipper' in device_info.get('name', '').lower():
            score += 6
            assessment['factors']['flipper_device'] = 'Educational device with known security'
            assessment['target_type'] = 'security_tool'
            assessment['difficulty_level'] = 'high'
        
        # Service-based scoring
        services = device_info.get('service_uuids', [])
        for service in services:
            if 'nordic' in str(service).lower():
                score += 5
                assessment['factors']['nordic_uart'] = 'UART service suggests custom firmware'
            elif any(custom in str(service) for custom in ['19b1', 'custom']):
                score += 7
                assessment['factors']['custom_services'] = 'Custom services indicate research potential'
        
        # Privacy features (inverse scoring)
        privacy = self._detect_privacy_features(device_info)
        if privacy['mac_randomization']:
            score -= 2
            assessment['factors']['privacy_protection'] = 'MAC randomization reduces research potential'
        
        assessment['overall_score'] = max(0, min(10, score))
        
        # Generate recommendations
        if assessment['overall_score'] >= 7:
            assessment['recommendations'].append('High priority research target')
            assessment['recommendations'].append('Attempt comprehensive fuzzing')
        elif assessment['overall_score'] >= 4:
            assessment['recommendations'].append('Moderate research interest')
            assessment['recommendations'].append('Start with conservative testing')
        else:
            assessment['recommendations'].append('Low research priority')
            assessment['recommendations'].append('Basic information gathering only')
        
        return assessment
    
    def _suggest_connection_strategy(self, device_info: Dict) -> Dict[str, Any]:
        """Suggest optimal connection strategy for device"""
        
        strategy = {
            'approach': 'standard',
            'timeout': 10,
            'retry_attempts': 3,
            'special_considerations': [],
            'expected_challenges': []
        }
        
        device_name = device_info.get('name', '').lower()
        device_type = device_info.get('device_type', '').lower()
        
        # Flipper Zero specific strategy
        if 'flipper' in device_name:
            strategy.update({
                'approach': 'conservative',
                'timeout': 15,
                'retry_attempts': 1,
                'special_considerations': [
                    'Flipper has strict BLE security',
                    'May require specific pairing process',
                    'Connection attempts may be logged by device'
                ],
                'expected_challenges': [
                    'Connection may be rejected',
                    'Limited service discovery',
                    'Write operations may fail'
                ]
            })
        
        # Apple device strategy
        elif 'apple' in device_type:
            strategy.update({
                'approach': 'minimal',
                'timeout': 5,
                'retry_attempts': 1,
                'special_considerations': [
                    'Apple devices have strong privacy protections',
                    'Limited advertisement data',
                    'Connection may require authorization'
                ],
                'expected_challenges': [
                    'Service discovery limitations',
                    'Authentication requirements',
                    'Minimal exposed functionality'
                ]
            })
        
        # ESP32 strategy
        elif 'esp32' in device_type:
            strategy.update({
                'approach': 'aggressive',
                'timeout': 10,
                'retry_attempts': 5,
                'special_considerations': [
                    'ESP32 devices often have custom firmware',
                    'May support extensive service discovery',
                    'Good target for research'
                ],
                'expected_challenges': [
                    'Custom protocol implementations',
                    'Potential for crashes during testing',
                    'May require device recovery time'
                ]
            })
        
        return strategy
    
    async def _smart_connect(self, device_info: Dict, timeout: int) -> Optional[BleakClient]:
        """Smart connection using device-specific strategy"""
        
        strategy = self._suggest_connection_strategy(device_info)
        address = device_info['address']
        
        for attempt in range(strategy['retry_attempts']):
            try:
                logger.info(f"Connection attempt {attempt + 1}/{strategy['retry_attempts']} to {address}")
                
                client = BleakClient(address, timeout=strategy['timeout'])
                await client.connect()
                
                if client.is_connected:
                    logger.info(f"Successfully connected to {address}")
                    return client
                    
            except Exception as e:
                logger.debug(f"Connection attempt {attempt + 1} failed: {e}")
                if attempt < strategy['retry_attempts'] - 1:
                    await asyncio.sleep(2)  # Wait between attempts
        
        logger.warning(f"All connection attempts failed for {address}")
        return None
    
    async def _analyze_connection(self, client: BleakClient) -> Dict[str, Any]:
        """Analyze connection-specific information"""
        
        return {
            'is_connected': client.is_connected,
            'address': client.address,
            'mtu_size': getattr(client, 'mtu_size', None),
            'connection_interval': None,  # Would need lower-level access
            'connection_latency': None,
            'supervision_timeout': None
        }
    
    async def _analyze_services_deep(self, client: BleakClient) -> Dict[str, Any]:
        """Deep analysis of device services and characteristics"""
        
        analysis = {
            'total_services': 0,
            'total_characteristics': 0,
            'writable_characteristics': [],
            'readable_characteristics': [],
            'notifiable_characteristics': [],
            'custom_services': [],
            'standard_services': [],
            'security_implications': []
        }
        
        try:
            services = client.services
            analysis['total_services'] = len(services)
            
            for service in services:
                service_info = {
                    'uuid': service.uuid,
                    'handle': service.handle,
                    'characteristics': []
                }
                
                # Classify service
                if str(service.uuid).upper() in self.known_services:
                    service_info['type'] = 'standard'
                    service_info['name'] = self.known_services[str(service.uuid).upper()]
                    analysis['standard_services'].append(service_info)
                else:
                    service_info['type'] = 'custom'
                    analysis['custom_services'].append(service_info)
                
                # Analyze characteristics
                for char in service.characteristics:
                    analysis['total_characteristics'] += 1
                    
                    char_info = {
                        'uuid': char.uuid,
                        'handle': char.handle,
                        'properties': char.properties
                    }
                    
                    # Categorize by capabilities
                    if 'write' in char.properties or 'write-without-response' in char.properties:
                        analysis['writable_characteristics'].append(char_info)
                    
                    if 'read' in char.properties:
                        analysis['readable_characteristics'].append(char_info)
                    
                    if 'notify' in char.properties or 'indicate' in char.properties:
                        analysis['notifiable_characteristics'].append(char_info)
                    
                    service_info['characteristics'].append(char_info)
            
            # Security analysis
            if len(analysis['writable_characteristics']) > 5:
                analysis['security_implications'].append('Many writable characteristics - high attack surface')
            
            if len(analysis['custom_services']) > 0:
                analysis['security_implications'].append('Custom services may have vulnerabilities')
            
        except Exception as e:
            analysis['error'] = str(e)
        
        return analysis
    
    async def _analyze_security_features(self, client: BleakClient) -> Dict[str, Any]:
        """Analyze security features and protections"""
        
        return {
            'encryption_required': None,  # Would need to test writes
            'authentication_required': None,
            'authorization_levels': [],
            'security_mode': 'unknown',
            'bonding_required': None
        }
    
    async def _assess_vulnerabilities(self, client: BleakClient) -> Dict[str, Any]:
        """Assess potential vulnerabilities"""
        
        vulnerabilities = {
            'potential_issues': [],
            'risk_level': 'low',
            'recommended_tests': []
        }
        
        try:
            services = client.services
            writable_count = 0
            custom_services = 0
            
            for service in services:
                if str(service.uuid).upper() not in self.known_services:
                    custom_services += 1
                
                for char in service.characteristics:
                    if 'write' in char.properties or 'write-without-response' in char.properties:
                        writable_count += 1
            
            # Risk assessment
            if writable_count > 10:
                vulnerabilities['potential_issues'].append('High number of writable characteristics')
                vulnerabilities['risk_level'] = 'high'
                vulnerabilities['recommended_tests'].append('Buffer overflow testing')
                vulnerabilities['recommended_tests'].append('Format string testing')
            
            if custom_services > 3:
                vulnerabilities['potential_issues'].append('Multiple custom services')
                vulnerabilities['recommended_tests'].append('Protocol fuzzing')
            
            if writable_count > 0:
                vulnerabilities['recommended_tests'].append('Input validation testing')
            
        except Exception as e:
            vulnerabilities['error'] = str(e)
        
        return vulnerabilities