# core/gatt_handler.py
import asyncio
from bleak.exc import BleakError
from utils.logging import get_logger

logger = get_logger(__name__)

class GATTHandler:
    def __init__(self):
        pass
    
    async def read_characteristic(self, client, characteristic_uuid):
        """Read a GATT characteristic"""
        try:
            value = await client.read_gatt_char(characteristic_uuid)
            logger.debug(f"Read characteristic {characteristic_uuid}: {value.hex()}")
            return value
        except Exception as e:
            logger.error(f"Failed to read characteristic {characteristic_uuid}: {e}")
            return None
    
    async def write_characteristic(self, client, characteristic_uuid, data, with_response=True):
        """Write to a GATT characteristic"""
        try:
            await client.write_gatt_char(characteristic_uuid, data, response=with_response)
            logger.debug(f"Wrote to characteristic {characteristic_uuid}: {data.hex()}")
            return True
        except Exception as e:
            logger.error(f"Failed to write characteristic {characteristic_uuid}: {e}")
            return False
    
    async def discover_services(self, client):
        """Discover all GATT services and characteristics"""
        try:
            # Use the services property directly (no need to call get_services())
            logger.info("Performing service discovery...")
            services = client.services
            
            # Count services by iterating
            services_count = sum(1 for _ in services)
            logger.info(f"Discovered {services_count} services")
            
            service_data = []
            for service in services:
                service_info = {
                    'uuid': service.uuid,
                    'handle': service.handle,
                    'description': service.description,
                    'characteristics': []
                }
                
                for char in service.characteristics:
                    char_info = {
                        'uuid': char.uuid,
                        'properties': char.properties,
                        'handle': char.handle,
                        'descriptors': []
                    }
                    
                    # Add descriptors if any
                    for desc in char.descriptors:
                        desc_info = {
                            'uuid': desc.uuid,
                            'handle': desc.handle
                        }
                        char_info['descriptors'].append(desc_info)
                    
                    service_info['characteristics'].append(char_info)
                
                service_data.append(service_info)
            
            total_chars = sum(len(s['characteristics']) for s in service_data)
            logger.info(f"Service discovery complete: {len(service_data)} services, {total_chars} characteristics")
            
            return service_data
            
        except Exception as e:
            logger.error(f"Service discovery failed: {e}")
            logger.error(f"Client connected: {client.is_connected if hasattr(client, 'is_connected') else 'Unknown'}")
            return []
    
    async def enable_notifications(self, client, characteristic_uuid, callback):
        """Enable notifications on a characteristic"""
        try:
            await client.start_notify(characteristic_uuid, callback)
            logger.info(f"Enabled notifications for {characteristic_uuid}")
            return True
        except Exception as e:
            logger.error(f"Failed to enable notifications for {characteristic_uuid}: {e}")
            return False
    
    async def disable_notifications(self, client, characteristic_uuid):
        """Disable notifications on a characteristic"""
        try:
            await client.stop_notify(characteristic_uuid)
            logger.info(f"Disabled notifications for {characteristic_uuid}")
            return True
        except Exception as e:
            logger.error(f"Failed to disable notifications for {characteristic_uuid}: {e}")
            return False
    
    def find_writable_characteristics(self, services_data):
        """Find all writable characteristics from service data"""
        writable_chars = []
        
        for service in services_data:
            for char in service['characteristics']:
                if 'write' in char['properties'] or 'write-without-response' in char['properties']:
                    writable_chars.append({
                        'service_uuid': service['uuid'],
                        'char_uuid': char['uuid'],
                        'handle': char['handle'],
                        'properties': char['properties']
                    })
        
        return writable_chars
    
    def find_readable_characteristics(self, services_data):
        """Find all readable characteristics from service data"""
        readable_chars = []
        
        for service in services_data:
            for char in service['characteristics']:
                if 'read' in char['properties']:
                    readable_chars.append({
                        'service_uuid': service['uuid'],
                        'char_uuid': char['uuid'],
                        'handle': char['handle'],
                        'properties': char['properties']
                    })
        
        return readable_chars
    
    def find_notifiable_characteristics(self, services_data):
        """Find all characteristics that support notifications"""
        notifiable_chars = []
        
        for service in services_data:
            for char in service['characteristics']:
                if 'notify' in char['properties'] or 'indicate' in char['properties']:
                    notifiable_chars.append({
                        'service_uuid': service['uuid'],
                        'char_uuid': char['uuid'],
                        'handle': char['handle'],
                        'properties': char['properties']
                    })
        
        return notifiable_chars