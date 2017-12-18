#
#  Copyright 2017 "OVS Performance" Authors
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#
#  Files name:
#    traffic_generator.py
#
#  Description:
#    Hopeless attempt to make a common traffic generator API (object) so its
#    transparent to the test script which physical traffic generator you use,
#    i.e. Xena tester, T-Rex, trafgen, moongen, or even IXIA.
#
#  Author:
#    Eelco Chaudron
#
#  Initial Created:
#    7 March 2017
#
#  Notes:
#    Note that this is a work in progress trying to extract the Xena
#    integration from the OVS Performance script.
#

#
# Base class and traffic generator imports
#
from traffic_generator_base import TrafficFlowType
from traffic_generator_trex import TRex
from traffic_generator_xena import XenaNetworks


#
# Enum import
#
from enum import Enum


#
# Type of traffic generator
#
class TrafficGeneratorType(Enum):
    xena           = 1
    trex           = 2
    trafen         = 3
    moongen        = 4
    trafgen_dut_vm = 5

    @staticmethod
    def new_traffic_object(traffic_generator_type, **kwargs):
        if traffic_generator_type == TrafficGeneratorType.xena:
            return XenaNetworks(**kwargs)

        elif traffic_generator_type == TrafficGeneratorType.trex:
            return TRex(**kwargs)
        else:
            return None


#
# CLASS Traffic Generator
#
class TrafficGenerator():
    def __init__(self, traffic_generator_type, **kwargs):

        self.auto_connect = kwargs.pop("auto_connect", True)

        if not type(traffic_generator_type) is TrafficGeneratorType:
            raise ValueError("Invalid traffic generator type passed!")

        self.__traffic_generator_type = traffic_generator_type
        self.__traffic_generator = TrafficGeneratorType. \
            new_traffic_object(traffic_generator_type, **kwargs)
        #
        # Try to connect if auto connect is enabled
        #
        if self.auto_connect:
            self.__traffic_generator.connect()

    def __str__(self):
        return "TG: type = {}, ".format(self.__traffic_generator_type) + \
            self.__traffic_generator.__str__()

    def connect(self):
        return self.__traffic_generator.connect()

    def disconnect(self):
        return self.__traffic_generator.disconnect()

    def is_connected(self):
        return self.__traffic_generator.is_connected()

    def reserve_port(self, port_name):
        return self.__traffic_generator.reserve_port(port_name)

    def release_port(self, port_name):
        return self.__traffic_generator.release_port(port_name)

    def clear_statistics(self, port_name):
        self.__traffic_generator.clear_statistics(port_name)

    def take_tx_statistics_snapshot(self, port_name):
        self.__traffic_generator.take_tx_statistics_snapshot(port_name)

    def take_rx_statistics_snapshot(self, port_name):
        self.__traffic_generator.take_rx_statistics_snapshot(port_name)

    def take_statistics_snapshot(self, port_name):
        self.__traffic_generator.take_tx_statistics_snapshot(port_name)
        self.__traffic_generator.take_rx_statistics_snapshot(port_name)

    def get_tx_statistics_snapshots(self, port_name):
        return self.__traffic_generator.get_tx_statistics_snapshots(port_name)

    def get_rx_statistics_snapshots(self, port_name):
        return self.__traffic_generator.get_rx_statistics_snapshots(port_name)

    def start_traffic(self, port_name):
        return self.__traffic_generator.start_traffic(port_name)

    def stop_traffic(self, port_name):
        return self.__traffic_generator.stop_traffic(port_name)

    def unconfigure_traffic_stream(self, port_name):
        return self.__traffic_generator. \
            configure_traffic_stream(port_name, TrafficFlowType.none, 0, 0)

    def configure_traffic_stream(self, port_name, traffic_flows,
                                 nr_of_flows, packet_size, **kwargs):
        return self.__traffic_generator.configure_traffic_stream(port_name,
                                                                 traffic_flows,
                                                                 nr_of_flows,
                                                                 packet_size,
                                                                 **kwargs)

    def next_traffic_stream(self, port_name):
        return self.__traffic_generator. \
            next_traffic_stream(port_name)

    def get_port_limits(self, port_name):
        return self.__traffic_generator. \
            get_port_limits(port_name)
