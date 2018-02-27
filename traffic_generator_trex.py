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
#    traffic_generator_trex.py
#
#  Description:
#    T-Rex traffic generator abstraction
#
#  Author:
#    Eelco Chaudron
#
#  Initial Created:
#    31 August 2017
#
#  Notes:
#

#
# Imports
#
import os
import logging
import netaddr
import time


#
# External traffic generators
#
from traffic_generator_base import TrafficGeneratorChassis, \
                                   TrafficGeneratorPort, \
                                   TrafficFlowType

#
# Import TRex static traffic library, in addition tell it where to find the
# dependent external libraries
#
os.environ['TREX_STL_EXT_PATH'] = os.path.normpath(os.path.join(
    os.path.dirname(os.path.realpath(__file__)),
    "./trex_stl_lib/external_libs/"))

from trex_stl_lib.api import STLClient, STLError, STLPktBuilder, STLStream, STLTXCont, STLVmFixIpv4, STLVmFlowVar, STLVmWrFlowVar


#
# Imports from Scapy
#
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import UDP, IP, Ether


#
# TRex port class
#
class _TRexPort(TrafficGeneratorPort):
    def __init__(self, port_name, trex_client):
        #
        # The TRex client APIs have one single object, i.e. no specific port
        # class. So we pass on the object used for manipulating the ports.
        #
        super(_TRexPort, self).__init__(port_name)
        self.__traffic_flows = TrafficFlowType.none
        self.__trex_client = trex_client
        self.__trex_port = int(port_name)
        self.__trex_rx_stats = dict()
        self.__trex_tx_stats = dict()
        self.__alternate_stream_sets = []
        self.__active_alternate_stream = 0
        #
        # To make sure receive counters work, enable promiscuous mode
        # when reserving the port.
        #
        self.clear_statistics()
        self.__trex_client.set_port_attr(ports=self.__trex_port,
                                         promiscuous=True)

    def _div_round_up(self, a, b):
        return (a + (-a % b)) / b

    def _mac_2_int(self, mac_str):
        return int(mac_str.translate(None, ":"), 16)

    def clear_statistics(self):
        self.__trex_client.clear_stats(ports=[self.__trex_port])
        self.__trex_rx_stats = dict()
        self.__trex_tx_stats = dict()
        return

    def take_tx_statistics_snapshot(self):
        self.__trex_tx_stats[time.time()] = self.__trex_client.get_stats(
            ports=[self.__trex_port])[self.__trex_port]
        return

    def take_rx_statistics_snapshot(self):
        self.__trex_rx_stats[time.time()] = self.__trex_client.get_stats(
            ports=[self.__trex_port])[self.__trex_port]
        return

    def get_tx_statistics_snapshots(self):
        stats = dict()
        for timestamp, item in list(self.__trex_tx_stats.items()):
            stats[timestamp] = {'pt_total': {'packets': item['opackets'],
                                             'bytes': item['obytes'],
                                             'errors': item['oerrors'],
                                             'pps': item['tx_pps'],
                                             'bps': item['tx_bps'],
                                             'line_util': item['tx_util']}}
        return stats

    def get_rx_statistics_snapshots(self):
        stats = dict()
        for timestamp, item in list(self.__trex_rx_stats.items()):
            stats[timestamp] = {'pr_total': {'packets': item['ipackets'],
                                             'bytes': item['ibytes'],
                                             'errors': item['ierrors'],
                                             'pps': item['rx_pps'],
                                             'bps': item['rx_bps'],
                                             'line_util': item['rx_util']}}
        return stats

    def start_traffic(self):
        self.clear_statistics()
        self.__trex_client.set_port_attr(ports=self.__trex_port,
                                         promiscuous=True)
        self.__trex_client.start(ports=[self.__trex_port])
        return True

    def stop_traffic(self):
        self.__trex_client.stop(ports=[self.__trex_port])
        return True

    def _delete_traffic_stream_config(self):
        self.__traffic_flows = TrafficFlowType.none
        self.__trex_client.reset(ports=[self.__trex_port])

        self.__streams = dict()
        self.__alternate_stream_sets = []

    def configure_traffic_stream(self, traffic_flows, nr_of_flows,
                                 packet_size, **kwargs):

        flow_percentage = kwargs.pop("percentage", 1000000) / 10000
        trex_dst_mac = kwargs.pop("traffic_dst_mac", '00:00:02:00:00:00')
        trex_src_mac = kwargs.pop("traffic_src_mac", '00:00:01:00:00:00')
        l2_macs = kwargs.pop("l2_macs", 1)

        #
        # The packet size passed here assumes it includes the checksum, however
        # the TRex packet size does not. Adjust the size to correct this.
        #
        packet_size -= 4

        if traffic_flows == TrafficFlowType.none or \
           self.__traffic_flows != TrafficFlowType.none:
            #
            # We need either a cleanup, or a cleanup before we configure
            # a new traffic flow type
            #
            self._delete_traffic_stream_config()

        if traffic_flows == TrafficFlowType.l2_mac or \
           traffic_flows == TrafficFlowType.l3_ipv4 or \
           traffic_flows == TrafficFlowType.nfv_mobile:

            #
            # Max flows due to IPv4 address limit, and addresses used for tests
            #
            if nr_of_flows > 0x00ffffff:
                raise ValueError("To many flows requested, max {} supported!".
                                 format(0x00ffffff))

            L2 = Ether(src=trex_src_mac,
                       dst=trex_dst_mac)
            L3 = IP(src="1.0.0.0",
                    dst="2.0.0.0")
            L4 = UDP(chksum=0)

            #if (len(str(L2/L3/L4)) + 4) > packet_size:  # +4 for Ethernet CRC
            #    raise ValueError("Packet size ({} bytes) to small for"
            #                     "requested packet ({} bytes)!".
            #                     format(packet_size, len(L2/L3/L4) + 4))

            if traffic_flows == TrafficFlowType.l2_mac:
                src_base = self._mac_2_int(trex_src_mac) & 0xff000000
                dst_base = self._mac_2_int(trex_dst_mac) & 0xff000000
                vm = [
                    # Source MAC address
                    STLVmFlowVar(name="src",
                                 min_value=src_base,
                                 max_value=src_base + nr_of_flows - 1,
                                 size=4, op="inc"),
                    STLVmWrFlowVar(fv_name="src", pkt_offset=8),

                    # Destination MAC address
                    STLVmFlowVar(name="dst",
                                 min_value=dst_base,
                                 max_value=dst_base + nr_of_flows - 1,
                                 size=4, op="inc"),
                    STLVmWrFlowVar(fv_name="dst", pkt_offset=2)
                ]

            elif traffic_flows == TrafficFlowType.l3_ipv4:

                src_end = str(netaddr.IPAddress(
                    int(netaddr.IPAddress('1.0.0.0')) +
                    nr_of_flows - 1))
                dst_end = str(netaddr.IPAddress(
                    int(netaddr.IPAddress('2.0.0.0')) +
                    nr_of_flows - 1))

                vm = [
                    # Source IPv4 address
                    STLVmFlowVar(name="src", min_value="1.0.0.0",
                                 max_value=src_end, size=4, op="inc"),
                    STLVmWrFlowVar(fv_name="src", pkt_offset="IP.src"),

                    # Destination IPv4 address
                    STLVmFlowVar(name="dst", min_value="2.0.0.0",
                                 max_value=dst_end, size=4, op="inc"),
                    STLVmWrFlowVar(fv_name="dst", pkt_offset="IP.dst"),

                    # Checksum
                    STLVmFixIpv4(offset="IP")
                ]
            elif traffic_flows == TrafficFlowType.nfv_mobile:

                src_end = str(netaddr.IPAddress(
                    int(netaddr.IPAddress('1.0.0.0')) +
                    nr_of_flows - 1))
                dst_end = str(netaddr.IPAddress(
                    int(netaddr.IPAddress('2.0.0.0')) +
                    nr_of_flows - 1))

                vm = [
                    # Source MAC address
                    STLVmFlowVar(name="srcm",
                                 min_value=0x01000001,
                                 max_value=0x01000001 + l2_macs - 1,
                                 size=4, op="inc"),
                    STLVmWrFlowVar(fv_name="srcm", pkt_offset=8),

                    # Destination MAC address
                    STLVmFlowVar(name="dstm",
                                 min_value=0x02000000,
                                 max_value=0x02000000 + l2_macs - 1,
                                 size=4, op="inc"),
                    STLVmWrFlowVar(fv_name="dstm", pkt_offset=2),

                    # Source IPv4 address
                    STLVmFlowVar(name="src", min_value="1.0.0.0",
                                 max_value=src_end, size=4, op="inc"),
                    STLVmWrFlowVar(fv_name="src", pkt_offset="IP.src"),

                    # Destination IPv4 address
                    STLVmFlowVar(name="dst", min_value="2.0.0.0",
                                 max_value=dst_end, size=4, op="inc"),
                    STLVmWrFlowVar(fv_name="dst", pkt_offset="IP.dst"),

                    # Checksum
                    STLVmFixIpv4(offset="IP")
                ]

            else:
                raise ValueError("Unsupported traffic type for T-Rex tester!!!")

            if traffic_flows == TrafficFlowType.nfv_mobile:
                stream_percentage = flow_percentage / 2
            else:
                stream_percentage = flow_percentage

            headers = L2/L3/L4
            padding = max(0, (packet_size - len(headers))) * 'e'
            packet = headers/padding

            trex_packet = STLPktBuilder(pkt=packet, vm=vm)

            trex_stream = STLStream(packet=trex_packet,
                                    mode=STLTXCont(percentage=stream_percentage))

            self.__trex_client.add_streams(trex_stream,
                                           ports=[self.__trex_port])

            #
            # For nfv_mobile we still need to setup the alternating streams.
            #
            if traffic_flows == TrafficFlowType.nfv_mobile:
                alternate_flows = kwargs.pop("alternate_flows", 200000)
                stream_percentage = flow_percentage / 2

                self.__active_alternate_stream = 0
                #
                # Keep the flows the same as for the Xena version, so the
                # traffic scripts using this do not have to differentiate
                # between traffic generator types.
                #
                # The Xena uses streams and every stream can generate 64K
                # flows. To Find the flow start we need the number of base
                # flows rounded of the next 64K (stream) and use the next one.
                #
                # For the individual iterations of the flow set they also
                # need to start at a 64K boundary.
                #
                start_stream_id = self._div_round_up(nr_of_flows, 0x10000) + 1
                for alternate_flow_sets in range(0, 3):
                    flow_start = start_stream_id * 0x10000

                    src_start = str(netaddr.IPAddress(
                        int(netaddr.IPAddress('1.0.0.0')) +
                        flow_start))
                    src_end = str(netaddr.IPAddress(
                        int(netaddr.IPAddress('1.0.0.0')) +
                        flow_start +
                        alternate_flows - 1))
                    dst_start = str(netaddr.IPAddress(
                        int(netaddr.IPAddress('2.0.0.0')) +
                        flow_start))
                    dst_end = str(netaddr.IPAddress(
                        int(netaddr.IPAddress('2.0.0.0')) +
                        flow_start +
                        alternate_flows - 1))

                    vm = [
                        # Source MAC address
                        STLVmFlowVar(name="srcm",
                                     min_value=0x01000001,
                                     max_value=0x01000001 + l2_macs - 1,
                                     size=4, op="inc"),
                        STLVmWrFlowVar(fv_name="srcm", pkt_offset=8),

                        # Destination MAC address
                        STLVmFlowVar(name="dstm",
                                     min_value=0x02000000,
                                     max_value=0x02000000 + l2_macs - 1,
                                     size=4, op="inc"),
                        STLVmWrFlowVar(fv_name="dstm", pkt_offset=2),

                        # Source IPv4 address
                        STLVmFlowVar(name="src", min_value=src_start,
                                     max_value=src_end, size=4, op="inc"),
                        STLVmWrFlowVar(fv_name="src", pkt_offset="IP.src"),

                        # Destination IPv4 address
                        STLVmFlowVar(name="dst", min_value=dst_start,
                                     max_value=dst_end, size=4, op="inc"),
                        STLVmWrFlowVar(fv_name="dst", pkt_offset="IP.dst"),

                        # Checksum
                        STLVmFixIpv4(offset="IP")
                    ]
                    trex_packet = STLPktBuilder(pkt=packet, vm=vm)

                    stream = STLStream(packet=trex_packet,
                                       mode=STLTXCont(percentage=stream_percentage),
                                       start_paused=False
                                       if alternate_flow_sets == 0 else True)

                    self.__alternate_stream_sets.append(
                        self.__trex_client.add_streams(stream,
                                                       ports=[self.__trex_port]))

                    start_stream_id += self._div_round_up(alternate_flows, 0x10000)

            self.__traffic_flows = traffic_flows
            return True
        elif traffic_flows == TrafficFlowType.none:
            self.__traffic_flows = traffic_flows
            return True
        else:
            raise ValueError("Unsupported traffic flow passed for T-Rex tester!")

        self.__traffic_flows = TrafficFlowType.none
        return False

    def next_traffic_stream(self):
        if self.__traffic_flows != TrafficFlowType.nfv_mobile or \
           len(self.__alternate_stream_sets) < 2:
            return False

        old_alternate_stream = self.__active_alternate_stream
        self.__active_alternate_stream = (self.__active_alternate_stream + 1) \
            % len(self.__alternate_stream_sets)

        self.__trex_client.resume_streams(self.__trex_port,
                                          [self.__alternate_stream_sets[
                                              self.__active_alternate_stream]])

        self.__trex_client.pause_streams(self.__trex_port,
                                         [self.__alternate_stream_sets[
                                             old_alternate_stream]])

        return True

    def get_port_limits(self):
        #
        # Return a dictionary for all limits per traffic type.
        # For now we only implement the NFV mobile one.
        #
        return {TrafficFlowType.nfv_mobile: {
            "MAX_L2_MACS": 1000000,
            "MAX_FLOWS": 0xFFFFFF}}

#
# TRex chassis class
#
class TRex(TrafficGeneratorChassis):
    def __init__(self, **kwargs):
        super(TRex, self).__init__(**kwargs)
        self.hostname = kwargs.pop("hostname", "localhost")
        self.__trex_client = STLClient(server=self.hostname)

    def _verify_port_action(self, port_name):
        if self.is_connected() and self._verify_port_string(port_name) and \
           port_name in self.port_data:
            return(True)
        return (False)

    def _verify_port_string(self, port_name):
        try:
            if int(port_name) < 0:
                return False

        except ValueError:
            return False

        return True

    def connect(self):
        if not self.is_connected():
            self.__trex_client.connect()

        return self.is_connected()

    def disconnect(self):
        if self.is_connected:
            for port in list(self.port_data.keys()):
                self.port_data[port] = self.release_port(port)
            self.__trex_client.disconnect()
        return True

    def is_connected(self):
        return self.__trex_client.is_connected()

    def reserve_port(self, port_name):
        if not self._verify_port_string(port_name):
            return False

        try:
            self.__trex_client.acquire(ports=[int(port_name)], force=True)
        except STLError:
            return False

        try:
            self.__trex_client.reset(ports=[int(port_name)])
        except STLError:
            self.__trex_client.release(ports=[int(port_name)])
            return False

        tport = _TRexPort(port_name, self.__trex_client)

        if tport is None:
            return False

        return super(TRex, self).reserve_port(port_name, tport)

    def release_port(self, port_name):
        if not self._verify_port_string(port_name) or \
           port_name not in self.port_data:
            return False

        try:
            self.__trex_client.release(ports=[port_name])
        except STLError:
            pass

        return super(TRex, self).release_port(port_name)

    #
    # FIXME: All the port specific functions should be re factored to use the
    #        base class so the shared code in _xena and _trex can be removed.
    #
    def clear_statistics(self, port_name):
        if self._verify_port_action(port_name):
            self.port_data[port_name].clear_statistics()

    def take_tx_statistics_snapshot(self, port_name):
        if self._verify_port_action(port_name):
            self.port_data[port_name].take_tx_statistics_snapshot()

    def take_rx_statistics_snapshot(self, port_name):
        if self._verify_port_action(port_name):
            self.port_data[port_name].take_rx_statistics_snapshot()

    def get_tx_statistics_snapshots(self, port_name):
        if self._verify_port_action(port_name):
            return self.port_data[port_name].get_tx_statistics_snapshots()
        return None

    def get_rx_statistics_snapshots(self, port_name):
        if self._verify_port_action(port_name):
            return self.port_data[port_name].get_rx_statistics_snapshots()
        return None

    def start_traffic(self, port_name):
        if self._verify_port_action(port_name):
            return self.port_data[port_name].start_traffic()
        return False

    def stop_traffic(self, port_name):
        if self._verify_port_action(port_name):
            return self.port_data[port_name].stop_traffic()
        return False

    def configure_traffic_stream(self, port_name, traffic_flows,
                                 nr_of_flows, packet_size, **kwargs):
        if self._verify_port_action(port_name):
            return self.port_data[port_name].configure_traffic_stream(traffic_flows,
                                                                      nr_of_flows,
                                                                      packet_size,
                                                                      **kwargs)
        return False

    def next_traffic_stream(self, port_name):
        if self._verify_port_action(port_name):
            return self.port_data[port_name].next_traffic_stream()
        return False

    def get_port_limits(self, port_name):
        if self._verify_port_action(port_name):
            return self.port_data[port_name].get_port_limits()
        return dict()
