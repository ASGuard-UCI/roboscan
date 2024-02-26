#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
ROS Scanner module.

:author Alias Robotics SL (https://aliasrobotics.com)
"""
import asyncio
import aiohttp
import logging
import re
from aiohttp_xmlrpc.client import ServerProxy
from aztarna.ros.commons import CommunicationROS
from aztarna.commons import RobotAdapter
from aztarna.ros.helpers import HelpersROS
from aztarna.ros.ros.helpers import Node, Topic, Service
from aztarna.ros.ros.helpers import ROSHost
from aztarna.utils.high_ports import high_port_check, scan_host_ports
from aztarna.utils.http_code import http_code
import sys
from ipaddress import IPv4Address
import json

class ROSScanner(RobotAdapter):
    """
    ROSScanner class, an extension of BaseScanner for ROS.
    """
    def __init__(self):
        super().__init__()

        self.timeout = aiohttp.ClientTimeout(total=3)
        self.hosts = []

        self.logger = logging.getLogger(__name__)

    async def analyze_node(self, address, port):
        """
        Perform checks on the target host, and then scan it only if it passes the check

        :param address: address of the ROS master
        :param port: port of the ROS master
        """
        ros_host = ROSHost(address, port)
        self.hosts.append(ros_host)

        #  # Check if the host responds to every port
        #  random_ports = [58243]
        #  #  random_ports = [58243, 42345]
        #  _, open_ports = await scan_host_ports(ros_host.address, random_ports)
        #  #  if port not in open_ports:
            #  #  ros_host.isHost = False
            #  #  ros_host.nonHostDescription = str(port) + " is closed."
            #  #  return
        #  #  elif len(open_ports) > 1:
            #  #  ros_host.isHost = False
            #  #  ros_host.nonHostDescription = "Host replies to any port."
            #  #  return
        #  if open_ports:
            #  ros_host.isHost = False
            #  ros_host.nonHostDescription = "Host replies to any port."
            #  return

        # Check if the host responds http get with 501 error code
        _, _, code = await http_code(ros_host.address, ros_host.port)
        if code != 501:
            ros_host.isHost = False
            if code is None:
                ros_host.nonHostDescription = "Fail to start http get to host."
            else:
                ros_host.nonHostDescription = "Host replies " + str(code) + \
                    " to http get."
            return

        await self.probe_host_system(ros_host)


    async def probe_host_system(self, ros_host: ROSHost):
        """
        Scan a node and gather all its data including topics, services and Communications.

        :param ros_host: ROS host
        """
        async with aiohttp.ClientSession(loop=asyncio.get_event_loop(), timeout=self.timeout) as client:
            full_host = 'http://' + str(ros_host.address) + ':' + str(ros_host.port)
            ros_master_client = ServerProxy(full_host, loop=asyncio.get_event_loop(), client=client)
            async with self.semaphore:
                try:
                    await self.collect_from_host_system(ros_host, ros_master_client)

                except Exception as e:
                    self.logger.error('[-] Error connecting to host ' + \
                            str(ros_host.address) + ':' + str(ros_host.port) + \
                            ' -> ' + str(e) + '\n\tNot a ROS host')
                    ros_host.isHost = False
                    ros_host.nonHostDescription = "Error connecting to host."


    async def collect_from_host_system(self, ros_host: ROSHost,
                                       ros_master_client: ServerProxy):
        """
        Scan a node and gather all its data including topics, services and Communications.

        :param ros_host: ROS host
        :param ros_master_client: aiohttp xmlrpc client
        """
        code, msg, val = await ros_master_client.getSystemState('')
        if code == 1:
            if self.extended:
                publishers_array = val[0]
                subscribers_array = val[1]
                services_array = val[2]
                # In order to analyze the nodes topics are needed
                found_topics = await self.analyze_topic_types(ros_master_client)

                # Extract nodes
                self.extract_nodes(publishers_array, found_topics, 'pub', ros_host)
                self.extract_nodes(subscribers_array, found_topics, 'sub', ros_host)
                # Extract services
                self.extract_services(services_array, ros_host)

                # Extract communications
                for topic_name, topic_type in found_topics.items():
                    current_topic = Topic(topic_name, topic_type)
                    comm = CommunicationROS(current_topic)
                    for node in ros_host.nodes:
                        if next((x for x in node.published_topics
                                 if x.name == current_topic.name), None) is not None:
                            comm.publishers.append(node)
                        if next((x for x in node.subscribed_topics
                                 if x.name == current_topic.name), None) is not None:
                            comm.subscribers.append(node)
                    ros_host.communications.append(comm)

                # Extract parameters
                await self.extract_parameters(ros_master_client, ros_host)

                # Extract address and port from xmlrpc uri for each node
                await self.set_xmlrpcuri_node(ros_master_client, ros_host)

            self.logger.warning('[+] ROS Host found at {}:{}'.format(
                    ros_host.address, ros_host.port))
        else:
            ros_host.isHost = False
            ros_host.nonHostDescription = "Error getting system state."
            self.logger.critical('[-] Error getting system state. Probably not a ROS Master')


    def extract_nodes(self, source_array, topics, pub_or_sub, host):
        """
        From all the data ROS Master returns, extract just the node info.

        :param source_array: A multiple level array containing data from the the ROS system state
        :param topics: A list of all topics found in the ROS system
        :param pub_or_sub: A boolean to separate publisher and subscriber nodes
        :param host: Current ROS host
        """
        source_lines = list(map(HelpersROS.process_line, list(filter(lambda x: (list(x)) is not None, source_array))))
        for source_line in source_lines:
            for node_name in source_line[1]:  # source_line[1] == nodes from a topic, is a list
                node = self.get_create_node(node_name, host)
                topic_name = source_line[0]
                topic_type = topics[topic_name]
                topic = Topic(topic_name, topic_type)
                if topic not in node.published_topics and pub_or_sub == 'pub':
                    node.published_topics.append(topic)
                if topic not in node.subscribed_topics and pub_or_sub == 'sub':
                    node.subscribed_topics.append(topic)

    @staticmethod
    def get_create_node(node_name, host):
        """
        Generate new :class:`aztarna.ros.helpers.Node` objects, and if they exist just return them.

        :param node_name: The name of the node to create or return
        :param host: Current ROS host
        :return: The newly created node or an existing that matches :attr:`node_name`
        """
        node_name_attrs = [o.name for o in host.nodes]
        if node_name not in node_name_attrs:
            ret_node = Node(node_name)
            host.nodes.append(ret_node)
        else:
            ret_node = next((x for x in host.nodes if x.name == node_name), None)

        return ret_node

    async def set_xmlrpcuri_node(self, ros_master_client, host):
        """
        Once all node data is collected, set the xml.

        :param ros_master_client: xml-rpc object for the ROS Master Client
        """
        for node in host.nodes:
            uri = await ros_master_client.lookupNode('', node.name)
            if uri[2] != '':
                regexp = re.compile(r'http://(?P<host>\S+):(?P<port>[0-9]{1,5})')
                uri_groups = regexp.search(uri[2])
                node.address = uri_groups.group('host')
                node.port = uri_groups.group('port')

    @staticmethod
    async def analyze_topic_types(ros_master_client):
        """
        Extract topic from ROS Master and disassemble them into topic name and topic type.

        :param ros_master_client:  xml-rpc object for the ROS Master Client
        :return: A dictionary of topics. Key is the topic name and value the topic type
        """
        topic_types = await ros_master_client.getTopicTypes('')
        topics = {}
        for topic_type_element in topic_types[2]:
            topic_name = topic_type_element[0]
            topic_type = topic_type_element[1]
            topics[topic_name] = topic_type
        return topics

    def extract_services(self, source_array, host):
        """
        Extract the services from the ROS system state.

        :param source_array: A multiple level array containing data from the the ROS system state
        :param host: Current ROS host
        """
        service_lines = list(map(HelpersROS.process_line, list(filter(lambda x: (list(x)) is not None, source_array))))
        for service_line in service_lines:
            for node_name in service_line[1]:
                node = self.get_create_node(node_name, host)
                node.services.append(Service(service_line[0]))

    async def extract_parameters(self, ros_master_client: ServerProxy, host: ROSHost):
        code, msg, val = await ros_master_client.getParam("", "/")
        if code == 1:
            host.params = val

    async def scan_network(self):
        """
        Scan the provided network (from args) searching for ROS nodes.
        """
        try:
            results = []
            for port in self.ports:
                for address in self.host_list:
                    results.append(self.analyze_node(address, port))

            for result in await asyncio.gather(*results):
                pass

        except ValueError as e:
            self.logger.error('Invalid address entered')
            raise e

    def scan(self):
        """
        Call to :meth:`aztarna.ros.scanner.scan_network` asynchronously
        """
        asyncio.get_event_loop().run_until_complete(self.scan_network())

    async def scan_pipe(self):
        tasks = []
        async for line in RobotAdapter.stream_as_generator(asyncio.get_event_loop(), sys.stdin):
            # TODO: Save input addresses to a file
            str_line = (line.decode()).rstrip('\n')
            for port in self.ports:
                tasks.append(asyncio.ensure_future(
                    self.analyze_node(str_line, port)))
        await asyncio.wait(tasks, loop=asyncio.get_event_loop())
        print(len([h for h in self.hosts if h.isHost]), "ROS hosts are detected.")

    def scan_pipe_main(self):
        asyncio.get_event_loop().run_until_complete(self.scan_pipe())

    def print_results(self):
        """
        Print the information of a ROS system.
        """

        for host in self.hosts:
            if not host.isHost:
                print(host, "is not host, reason:", host.nonHostDescription)
                continue

            print(host)

            for node in host.nodes:
                print('\nNode: ' + str(node))
                print('\n\t Published topics:')
                for topic in node.published_topics:
                    print('\t\t * ' + str(topic))
                print('\n\t Subscribed topics:')
                for topic in node.subscribed_topics:
                    print('\t\t * ' + str(topic))
                print('\n\t Services:')
                for service in node.services:
                    print('\t\t * ' + str(service))

            print('\nCommunications: ')
            for i in range(len(host.communications)):
                comm = host.communications[i]
                print('\n\t Communication ' + str(i) + ':')
                print('\t\t - Topic: ' + str(comm.topic))
                print('\t\t - Publishers:')
                for node in comm.publishers:
                    print('\t\t\t' + str(node))
                print('\t\t - Subscribers:')
                for node in comm.subscribers:
                    print('\t\t\t' + str(node))
            print('\n\n')

    def write_to_file(self, out_file):
        """
        Write the information of a ROS system into the provided file.

        :param out_file: The file where to write the results
        """

        def json_func(o):
            if hasattr(o, "toJSON"):
                return o.toJSON()
            else:
                return o.__dict__

        with open(out_file, 'w') as file:
            json.dump(self.hosts, file, default=json_func, indent=2)
