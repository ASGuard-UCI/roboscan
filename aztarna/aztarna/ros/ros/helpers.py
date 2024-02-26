#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
ROS Scanner helper module.

:author Alias Robotics SL (https://aliasrobotics.com)
"""
from aztarna.ros.commons import BaseNodeROS, BaseNodeROS, BaseServiceROS, BaseHostROS
import json

class ROSHost(BaseHostROS):
    """
    Class for keeping all the attributes of a ROS Node.Extends:class:`aztarna.commons.BaseHostROS`
    """
    def __init__(self, address, port):
        super().__init__()
        self.address = address
        self.port = port
        self.communications = []
        self.params = {}

    def __repr__(self):
        if len(self.nodes) == 0:
            return "Address: {}".format(self.address)
        return "Address: {}, Nodes: {}".format(self.address, self.nodes)

class Node(BaseNodeROS):
    """
    Node class, an extension of the BaseNodeROS
    """
    def __init__(self, name):
        super().__init__()
        self.name = name
        self.published_topics = []
        self.subscribed_topics = []
        self.services = []

    def __str__(self):
        return '{} XMLRPCUri: http://{}:{}'.format(self.name, self.address, self.port)

    def __repr__(self) -> str:
        return self.__str__()

class Topic(BaseNodeROS):
    """
    Topic class, an extension of BaseNodeROS
    """
    def __init__(self, name, topic_type):
        super().__init__()
        self.name = name
        self.type = topic_type

    def __str__(self):
        return self.name + '(Type: ' + self.type + ')'

    def __repr__(self) -> str:
        return self.__str__()

    def toJSON(self):
        return self.__str__()

class Service(BaseServiceROS):
    """
    Service class, an extension of BaseServiceROS
    """
    def __init__(self, name):
        super().__init__()
        self.name = name

    def __str__(self):
        return '{}'.format(self.name)

    def __repr__(self) -> str:
        return self.__str__()

    def toJSON(self):
        return self.name
