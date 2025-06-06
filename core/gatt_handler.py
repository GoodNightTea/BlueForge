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
            services = await client.get_services()
            logger.info(f"Discovered {len(services)} services")
            
            service_data = []
            for service in services:
                service_info = {
                    'uuid': service.uuid,
                    'characteristics': []
                }
                
                for char in service.characteristics:
                    char_info = {
                        'uuid': char.uuid,
                        'properties': char.properties,
                        'handle': char.handle
                    }
                    service_info['characteristics'].append(char_info)
                
                service_data.append(service_info)
            
            return service_data
            
        except Exception as e:
            logger.error(f"Service discovery failed: {e}")
            return []