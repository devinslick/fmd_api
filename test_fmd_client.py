import asyncio
from fmd_api import FmdClient

async def main():
    async with FmdClient('https://fmd.devinslick.com') as client:
        print('Session open:', client._session is not None)
    print('Session closed:', client._session is None)

if __name__ == "__main__":
    asyncio.run(main())