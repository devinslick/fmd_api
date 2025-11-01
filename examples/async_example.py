"""Minimal async example of using fmd_api v2."""
import asyncio
import logging
from fmd_api import Device

# Configure logging to see what's happening
logging.basicConfig(level=logging.INFO)


async def main():
    # Replace with your FMD server details
    SERVER_URL = "https://fmd.example.com"
    DEVICE_ID = "your-device-id"
    PASSWORD = "your-password"
    
    # Create and authenticate device
    print("Authenticating...")
    device = await Device.create(SERVER_URL, DEVICE_ID, PASSWORD)
    print("✓ Authenticated successfully")
    
    # Get current location
    print("\nFetching current location...")
    location = await device.get_location()
    if location:
        print(f"✓ Location: ({location.latitude}, {location.longitude})")
        print(f"  Battery: {location.battery}%")
        print(f"  Provider: {location.provider}")
        print(f"  Timestamp: {location.time}")
        if location.speed:
            print(f"  Speed: {location.speed:.2f} m/s")
    else:
        print("✗ No location data available")
    
    # Get location history
    print("\nFetching location history (last 5)...")
    history = await device.get_history(count=5)
    print(f"✓ Retrieved {len(history)} location(s)")
    for i, loc in enumerate(history, 1):
        print(f"  {i}. {loc.time} - ({loc.latitude}, {loc.longitude})")
    
    # Request a new location update
    print("\nRequesting GPS location update...")
    await device.refresh(provider="gps")
    print("✓ Location update requested (device will update when online)")
    
    # Send ring command
    print("\nMaking device ring...")
    await device.play_sound()
    print("✓ Ring command sent")
    
    # For more advanced operations, access the client directly
    print("\nEnabling Bluetooth...")
    await device.client.toggle_bluetooth(True)
    print("✓ Bluetooth enable command sent")
    
    print("\n✓ All operations completed successfully")


if __name__ == "__main__":
    asyncio.run(main())
