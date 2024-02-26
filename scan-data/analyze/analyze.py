#! /usr/bin/env python3

import os
import json
import yaml
import re
from typing import Iterable


from aiohttp_xmlrpc.client import ServerProxy
from collections import Counter, defaultdict
from pprint import pprint
import aiohttp
import asyncio
import geoip2.database
import requests

script_path = os.path.realpath(os.path.dirname(__file__))


class SetEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, set):
            return list(obj)
        return json.JSONEncoder.default(self, obj)


class GeoLoc:
    geoip_city_db = os.path.realpath(os.path.join(
        script_path, "..", "..", "dataset-vis/GeoLite2-City.mmdb"))
    geoip_asn_db = os.path.realpath(os.path.join(
        script_path, "..", "..", "dataset-vis/GeoLite2-ASN.mmdb"))

    def __init__(self):
        self.geoip_city_reader = geoip2.database.Reader(self.geoip_city_db)
        self.geoip_asn_reader = geoip2.database.Reader(self.geoip_asn_db)

    def locate(self, ip):
        city = self.geoip_city_reader.city(ip)
        asn = self.geoip_asn_reader.asn(ip)
        location_data = {
            "ip": ip,
            "city": city.city.name,
            "country": city.country.name,
            "latitude": city.location.latitude,
            "longitude": city.location.longitude,
            "asn": asn.autonomous_system_number,
            "asn-name": asn.autonomous_system_organization,
        }
        return location_data


class Host:
    def __init__(self, scan_result: dict):
        self.ip = scan_result["address"]
        self.port = scan_result["port"]

        self.hostnames = set(n["address"] for n in scan_result["nodes"])
        self.nodes = set(n["name"] for n in scan_result["nodes"])

        self.topics = set()
        self.services = set()

        self.params = scan_result["params"]
        self.geo = scan_result["geo"]

        self.process_nodes(scan_result["nodes"])
        self.process_comm(scan_result["communications"])

    def process_nodes(self, nodes):
        for n in nodes:
            self.topics.update(self._topic(t) for t in n["published_topics"])
            self.topics.update(self._topic(t) for t in n["subscribed_topics"])
            self.services.update(n["services"])

    def process_comm(self, comms):
        for comm in comms:
            self.topics.add(self._topic(comm["topic"]))

    def _topic(self, topic_str: str):
        # http://wiki.ros.org/ROS/Concepts#Names.Valid_Names
        m = re.match("^/?([A-z][A-z0-9_/]*)\(Type: (\S+)\)$", topic_str)
        if m:
            topic, _type = m.groups()
            return "/" + topic, _type
        else:
            raise ValueError(f"Fail to parse topic str: {topic_str}")


class RuleMatch:
    def __init__(self, rule_file: str = None, geo_rule_file: str = None):
        if rule_file is None:
            rule_file = os.path.join(script_path, "ros1.yaml")
        self.rule_file = rule_file
        with open(self.rule_file, "r") as f:
            self.rules = yaml.safe_load(f)

        if geo_rule_file is None:
            geo_rule_file = os.path.join(script_path, "geo.yaml")
        self.geo_rule_file = geo_rule_file
        with open(self.geo_rule_file, "r") as f:
            self.geo_rules = yaml.safe_load(f)

    def match(self, host: Host, sanity_check=False):
        labels = defaultdict(set)
        # Determine the host type based on rules
        for rule in self.rules:
            items = self.get_field(host, rule["field"])
            ismatch = self.pattern_match(
                items, rule["matchtype"], rule["pattern"])
            if ismatch:
                for k, v in rule["labels"].items():
                    labels[k].add(v)

        # Also match geolocation types: university, country, etc.
        for rule in self.geo_rules:
            items = self.get_field(host, rule["field"])
            ismatch = self.pattern_match(
                items, rule["matchtype"], rule["pattern"])
            if ismatch:
                for k, v in rule["labels"].items():
                    labels[k].add(v)
        
        if sanity_check:
            self._sanity_check(host, labels)

        return labels

    def _sanity_check(self, host: Host, labels):
        if len(labels["geo"]) == 0:
            print(f"unknown asn {host.geo['asn']}, {host.geo['asn-name']}")
        elif len(labels["geo"]) > 1:
            print(f"more than one geo: {list(labels['geo'])}")

    def pattern_match(self, items: Iterable, matchtype: str,
                      pattern: str) -> True:
        # Match items with pattern. Case insensitive to minimize false negative.
        if matchtype == "full":
            return any(item.lower() == pattern.lower() for item in items)
        elif matchtype == "regex":
            return any(bool(re.search(pattern.lower(), item.lower())) for item in items)
        else:
            raise ValueError(f"Unknown matchtype {matchtype}")
        return False

    def get_field(self, host: Host, field: str) -> Iterable:
        if field == "node name":
            return host.nodes
        elif field == "topic name":
            return [topic for topic, _type in host.topics]
        elif field == "topic type":
            return [_type for topic, _type in host.topics]
        elif field == "service name":
            return host.services
        elif field == "param name":
            #  def extract_param_names(params: dict, pname: str, paramnames: list):
                #  for k, v in params.items():
                    #  pname += f'/{k}'
                    #  paramnames.append(pname)
                    #  if isinstance(v, dict):
                        #  extract_param_names(v, pname, paramnames)
            #  paramnames = []
            #  extract_param_names(host.params, "", paramnames)
            #  return paramnames
            # For the consideration of performance
            return host.params.keys()
        elif field == "hostname":
            return host.hostnames
        elif field == "asn":
            return [str(host.geo["asn"])]
        elif field == "asn-name":
            return [host.geo["asn-name"]]
        else:
            raise ValueError(f"Unknown field {field}")


#  # Collect fail reasons
#  failures = [r["nonHostDescription"] for r in results if not r["isHost"]]
#  failures = Counter(failures)
#  pprint(failures)

#  # Try XMLRPC to http error hosts
#  http_code_failures = [r['address'] for r in results if not r["isHost"] and "Host replies" in r["nonHostDescription"]]
#  async def probe_host_system(address, port=11311):
    #  async with aiohttp.ClientSession(loop=asyncio.get_event_loop(),
                                     #  timeout=aiohttp.ClientTimeout(5)) as client:
        #  full_host = 'http://' + str(address) + ':' + str(port)
        #  ros_master_client = ServerProxy(full_host, loop=asyncio.get_event_loop(), client=client)
        #  try:
            #  code, msg, val = await ros_master_client.getSystemState('')
            #  if code == 1:
                #  return address, port, val
        #  except Exception as e:
            #  print(e)
            #  pass
        #  return address, port, None
#  async def xmlrpc_test():
    #  return await asyncio.gather(*[probe_host_system(ip) for ip in http_code_failures[:10]])
#  xmlrpc_results = asyncio.run(xmlrpc_test())
#  for ip, port, val in xmlrpc_results:
    #  if val is not None:
        #  print(str(ip) + ":" + str(port) + " has getSystemState()")
    #  else:
        #  print(str(ip) + ":" + str(port))


def main():
    ruleMatch = RuleMatch()
    geoloc = GeoLoc()

    for filename in ["09252023.json", "20231025-1615.json"]:
        #  filename = "20231025-1615.json"
        infile = os.path.join(script_path, "..", filename)
        insuccessfile = os.path.join(script_path, "..", "success" + filename)

        if os.path.isfile(insuccessfile):
            with open(insuccessfile, "r") as f:
                successes = json.load(f)

        else:
            with open(infile, "r") as f:
                results = json.load(f)
            successes = [r for r in results if r["isHost"]]
            for s in successes:
                s["geo"] = geoloc.locate(s["address"])
            with open(insuccessfile, "w") as f:
                json.dump(successes, f, indent=2)

        print(f"{len(successes)} hosts are detected in {filename}")

        host_labels = {}
        for s in successes:
            h = Host(s)
            labels = ruleMatch.match(h, sanity_check=True)
            host_labels[h.ip] = labels

        outfile = os.path.join(script_path, "out" + filename)
        with open(outfile, "w") as f:
            json.dump(host_labels, f, cls=SetEncoder, indent=2)

        # Get statistics
        label_stat = defaultdict(Counter)
        for _, labels in host_labels.items():
            for l, v in labels.items():
                for label in v:
                    label_stat[l][label] += 1
        pprint(dict(label_stat))


    # TODO: Draw geo-location


if __name__ == "__main__":
    main()

