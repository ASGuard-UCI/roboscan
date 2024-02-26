#! /usr/bin/env python3

import asyncio
from datetime import datetime
import argparse
import ipaddress
import textwrap
import aiohttp


async def http_code(ip, port, timeout=5):
    async with aiohttp.ClientSession(
            loop=asyncio.get_event_loop(),
            timeout=aiohttp.ClientTimeout(total=timeout)) as client:
        try:
            full_host = 'http://' + str(ip) + ':' + str(port)
            async with client.get(full_host) as response:
                response = await client.get(full_host)
                return ip, port, response.status
        except:
            pass

    return ip, port, None


def _parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--ports", type=str, default=None,
                        help="List of ports, seperated using \",\"")
    parser.add_argument("address", nargs="+", help="List of addresses")
    args = parser.parse_args()

    targets = []
    for address in args.address:
        try:
            ipaddress.ip_address(address)
        except ValueError:
            raise ValueError(f"Invalid ip address: {address}")
        targets.append(address)

    if args.ports is not None:
        ports = set()
        for p in args.ports.split(","):
            try:
                port = int(p)
                assert 0 < port < 65536
            except:
                raise ValueError(f"Invalid port: {p}")
            ports.add(port)
        ports = sorted(list(ports))
    else:
        ports = [11311]

    return targets, ports


def main():
    targets, ports = _parse_args()
    # Add Banner
    print("-" * 50)
    print(textwrap.fill("Scanning addresses: " +
          ", ".join(targets), subsequent_indent="\t"))
    print(textwrap.fill("Scanning ports: " +
          ", ".join([str(p) for p in ports]), subsequent_indent="\t"))

    loop = asyncio.get_event_loop()
    tasks = []

    start_time = datetime.now()
    print("Scanning started at: " + str(start_time))
    for target in targets:
        for port in ports:
            tasks.append(asyncio.ensure_future(http_code(target, port)))
    loop.run_until_complete(asyncio.gather(*tasks))

    end_time = datetime.now()
    print("Scanning ended at: " + str(end_time))
    print("Elapsed: " + str(end_time - start_time))
    print("-" * 50)

    for task in tasks:
        ip, port, code = task.result()
        print(str(ip) + ":" + str(port) + " code: " + str(code))


if __name__ == "__main__":
    main()
