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
#    traffic_generator_base.py
#
#  Description:
#    Base class definitions
#
#  Author:
#    Eelco Chaudron
#
#  Initial Created:
#    7 March 2017
#
#  Notes:
#

#
# Enum import
#
from enum import Enum


#
# Type of traffic generator
#
class TrafficFlowType(Enum):
    none = 0
    l2_mac = 1
    l3_ipv4 = 2
    l4_udp = 3
    vxlan_l2_mac = 4
    vxlan_l3_ipv4 = 5
    nfv_mobile = 6


#
# Traffic Generator Port
#
class TrafficGeneratorPort(object):
    def __init__(self, port_name):
        self.port_name = port_name

    def __str__(self):
        return "TrafficGeneratorPor[{0}]".format(self.port_name)

    def clear_statistics(self):
        return

    def take_tx_statistics_snapshot(self):
        return

    def take_rx_statistics_snapshot(self):
        return

    def get_tx_statistics_snapshots(self):
        return None

    def get_rx_statistics_snapshots(self):
        return None

    def start_traffic(self):
        return False

    def stop_traffic(self):
        return False

    def configure_traffic_stream(self, traffic_flows, nr_of_flows,
                                 packet_size, **kwargs):
        return False

    def next_traffic_stream(self):
        return False


#
# Base class for all traffic generator clients
#
class TrafficGeneratorChassis(object):
    def __init__(self, **kwargs):
        self.hostname = kwargs.pop("hostname", "")
        self.port_data = dict()

    def __str__(self):
        return "port_data = {0}".format(self.port_data)

    def connect(self):
        #
        # Connect and log into the tester
        #
        return False

    def disconnect(self):
        #
        # Log out and disconnect from the tester
        #
        return False

    def is_connected(self):
        #
        # Are we connected and logged into the tester
        #
        return False

    def reserve_port(self, port_name, port_data):
        #
        # Add a port to the list of ports to use, note that the idea
        # is that we will be consistent. i.e. when a connection is
        # restored, we should try to re-add the ports assigned.
        #
        if port_name in self.port_data or port_data is None:
            return False

        self.port_data[port_name] = port_data
        return True

    def release_port(self, port_name):
        #
        # Remove a port from the ports to use
        #
        if port_name not in self.port_data:
            return False

        del(self.port_data[port_name])
        self.port_data.pop(port_name, None)
        return True

    def clear_statistics(self, port_name):
        #
        # Clear all port statistics:
        # - Clear port related counters if tester support this
        # - Clear snapshot statics buffers
        #
        if port_name not in self.port_data:
            return

    def take_tx_statistics_snapshot(self, port_name):
        #
        # Take a snapshot of the port's current tx statistics
        #
        if port_name not in self.port_data:
            return

    def take_rx_statistics_snapshot(self, port_name):
        #
        # Take a snapshot of the port's current rx statistics
        #
        if port_name not in self.port_data:
            return

    def get_tx_statistics_snapshots(self, port_name):
        #
        # Get dictionary of all tx port statistics
        #
        if port_name not in self.port_data:
            return

    def get_rx_statistics_snapshots(self, port_name):
        #
        # Get dictionary of all rx port statistics
        #
        if port_name not in self.port_data:
            return

    def start_traffic(self, port_name):
        #
        # Start traffic generation according to previous configuration
        #
        return False

    def stop_traffic(self, port_name):
        #
        # Stop traffic generation
        #
        return False

    def configure_traffic_stream(self, port_name, traffic_flows,
                                 nr_of_flows, packet_size, **kwargs):
        #
        # Configure a specific traffic stream on the port, only one can be
        # configured on a port.
        #
        return False

    def next_traffic_stream(self, port_name):
        #
        # Enable next traffic stream.
        #
        return False
