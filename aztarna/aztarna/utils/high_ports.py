#! /usr/bin/env python3

from datetime import datetime
import argparse
import ipaddress
import textwrap
from getpass import getpass

import asyncio
import aionmap

sudo_passwd = None

async def scan_host_ports(ip, ports):
    global sudo_passwd
    if sudo_passwd is None:
        sudo_passwd = getpass()

    scanner = aionmap.PortScanner()
    scan_result = await scanner.scan(ip, ports, '-sS -n -Pn', sudo=True,
                                sudo_passwd=sudo_passwd)
    if not scan_result.hosts:
        return ip, []
    open_ports = [port for port, _ in scan_result.hosts[0].get_open_ports()]
    return ip, open_ports


async def high_port_check(ip, random_ports, rosport="11311"):
    # Scan ros port separately to avoid blocking due to scanning to other ports
    _, ports1 = await scan_host_ports(ip, rosport)
    _, ports2 = await scan_host_ports(ip, random_ports)
    return ip, ports1 + ports2


def _parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--ports", type=str, default="11311",
                        help="List of ports, seperated using \",\"")
    parser.add_argument("--rosport", action="store_true",
                        help="Probe ros port (11311) first.")
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
        ports = [58243, 42345]

    return targets, ports, args.rosport


def main():
    targets, ports, rosport = _parse_args()

    # Add Banner
    print("-" * 50)
    print(textwrap.fill("Scanning addresses: " +
          ", ".join(targets), subsequent_indent="\t"))
    if rosport:
        print(textwrap.fill("Scanning ROS port 11311"))
    print(textwrap.fill("Scanning ports: " +
          ", ".join([str(p) for p in ports]), subsequent_indent="\t"))

    loop = asyncio.get_event_loop()
    tasks = []

    start_time = datetime.now()
    print("Scanning started at: " + str(start_time))
    for target in targets:
        if rosport:
            tasks.append(asyncio.ensure_future(
                high_port_check(target, ports)))
        else:
            tasks.append(asyncio.ensure_future(
                scan_host_ports(target, ports)))
    loop.run_until_complete(asyncio.gather(*tasks))

    end_time = datetime.now()
    print("Scanning ended at: " + str(end_time))
    print("Elapsed: " + str(end_time - start_time))
    print("-" * 50)

    for task in tasks:
        ip, open_ports = task.result()
        print(ip, "open_ports:", open_ports)



if __name__ == "__main__":
    main()
