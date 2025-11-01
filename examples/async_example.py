#!/usr/bin/env python3
"""
Example: Using the fmd_api v2 Device and FmdClient APIs

This example demonstrates both the high-level Device API and low-level FmdClient API
for interacting with an FMD server.

Usage:
    python async_example.py --url https://fmd.example.com --id device-id --password secret
"""

import asyncio
import argparse
import logging
from pathlib import Path

# High-level API
from fmd_api import Device

# Low-level API (optional, for advanced use)
from fmd_api import FmdClient, FmdCommands, Location


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
log = logging.getLogger(__name__)


async def high_level_example(base_url: str, device_id: str, password: str):
    """
    Demonstrates the high-level Device API (recommended for most use cases).
    
    The Device API provides an intuitive, object-oriented interface for
    common device operations.
    """
    log.info("=== High-level Device API Example ===")
    
    # Create and authenticate device
    log.info("Authenticating...")
    device = await Device.create(base_url, device_id, password)
    log.info("✓ Authentication successful")
    
    # Get current location
    log.info("\n1. Getting current location...")
    location = await device.get_location()
    if location:
        log.info(f"   Device location:")
        log.info(f"   - Coordinates: {location.latitude}, {location.longitude}")
        log.info(f"   - Provider: {location.provider}")
        log.info(f"   - Battery: {location.battery}%")
        log.info(f"   - Timestamp: {location.timestamp}")
        if location.accuracy:
            log.info(f"   - Accuracy: {location.accuracy}m")
        if location.speed:
            log.info(f"   - Speed: {location.speed} m/s ({location.speed * 3.6:.1f} km/h)")
        if location.heading:
            log.info(f"   - Heading: {location.heading}°")
    else:
        log.warning("   No location data available")
    
    # Get location history
    log.info("\n2. Getting location history (last 5 locations)...")
    history = await device.get_history(limit=5)
    log.info(f"   Retrieved {len(history)} locations:")
    for i, loc in enumerate(history, 1):
        log.info(f"   {i}. {loc.timestamp}: ({loc.latitude}, {loc.longitude}) - Battery: {loc.battery}%")
    
    # Access cached location
    log.info("\n3. Using cached location (no API call)...")
    cached = device.last_known_location
    if cached:
        log.info(f"   Cached location: {cached.latitude}, {cached.longitude}")
    
    # Device control examples (commented out to avoid triggering actual commands)
    log.info("\n4. Device control commands (examples - not executed):")
    log.info("   # await device.play_sound()         # Make device ring")
    log.info("   # await device.lock()               # Lock device screen")
    log.info("   # await device.take_front_photo()   # Take selfie")
    log.info("   # await device.take_rear_photo()    # Take photo")
    
    # Example: Request a new location update
    log.info("\n5. Requesting new location update (commented out):")
    log.info("   # await device.client.request_location('gps')")
    log.info("   # await asyncio.sleep(30)  # Wait for device to respond")
    log.info("   # location = await device.get_location()")
    
    # Fetch pictures (if any)
    log.info("\n6. Fetching pictures (limited to 2)...")
    pictures = await device.fetch_pictures(limit=2)
    if pictures:
        log.info(f"   Found {len(pictures)} pictures")
        output_dir = Path("photos")
        output_dir.mkdir(exist_ok=True)
        
        for i, picture in enumerate(pictures, 1):
            output_path = output_dir / f"photo_{i}.jpg"
            await device.download_photo(picture, str(output_path))
            log.info(f"   ✓ Saved to {output_path} ({len(picture.data)} bytes)")
    else:
        log.info("   No pictures found")


async def low_level_example(base_url: str, device_id: str, password: str):
    """
    Demonstrates the low-level FmdClient API (for advanced use cases).
    
    The FmdClient API provides direct access to FMD server operations and is
    similar to the v1 FmdApi interface.
    """
    log.info("\n\n=== Low-level FmdClient API Example ===")
    
    # Create and authenticate client
    log.info("Authenticating...")
    client = await FmdClient.create(base_url, device_id, password)
    log.info("✓ Authentication successful")
    
    # Get location blobs (encrypted data from server)
    log.info("\n1. Getting encrypted location blobs...")
    location_blobs = await client.get_locations(num=3)
    log.info(f"   Retrieved {len(location_blobs)} encrypted blobs")
    
    # Decrypt and parse locations
    log.info("\n2. Decrypting and parsing locations...")
    import json
    for i, blob in enumerate(location_blobs, 1):
        try:
            # Decrypt blob
            decrypted_bytes = client.decrypt_data_blob(blob)
            
            # Parse JSON
            location_data = json.loads(decrypted_bytes)
            
            # Option 1: Access as dictionary
            lat = location_data['lat']
            lon = location_data['lon']
            battery = location_data['bat']
            
            # Option 2: Convert to Location object (recommended)
            location = Location.from_dict(location_data)
            
            log.info(f"   {i}. Location: {location.latitude}, {location.longitude} (Battery: {location.battery}%)")
            
        except Exception as e:
            log.error(f"   Failed to decrypt location {i}: {e}")
    
    # Send commands using constants
    log.info("\n3. Sending commands (examples - not executed):")
    log.info(f"   # await client.send_command(FmdCommands.RING)")
    log.info(f"   # await client.send_command(FmdCommands.LOCATE_GPS)")
    log.info(f"   # await client.send_command(FmdCommands.CAMERA_FRONT)")
    
    # Convenience methods
    log.info("\n4. Using convenience methods (examples - not executed):")
    log.info("   # await client.play_sound()")
    log.info("   # await client.lock_device()")
    log.info("   # await client.request_location('gps')")
    log.info("   # await client.take_picture('front')")
    log.info("   # await client.toggle_bluetooth(True)")
    log.info("   # await client.set_ringer_mode('vibrate')")
    
    # Export data
    log.info("\n5. Exporting data (commented out):")
    log.info("   # await client.export_data_zip('export.zip')")


async def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="FMD API v2 examples - High-level Device and Low-level Client APIs"
    )
    parser.add_argument('--url', required=True, help='FMD server URL')
    parser.add_argument('--id', required=True, help='Device ID')
    parser.add_argument('--password', required=True, help='Device password')
    parser.add_argument(
        '--api',
        choices=['high', 'low', 'both'],
        default='both',
        help='Which API to demonstrate (default: both)'
    )
    
    args = parser.parse_args()
    
    try:
        if args.api in ['high', 'both']:
            await high_level_example(args.url, args.id, args.password)
        
        if args.api in ['low', 'both']:
            await low_level_example(args.url, args.id, args.password)
        
        log.info("\n✓ Examples completed successfully")
        
    except Exception as e:
        log.error(f"Error: {e}", exc_info=True)
        return 1
    
    return 0


if __name__ == '__main__':
    exit_code = asyncio.run(main())
    exit(exit_code)
