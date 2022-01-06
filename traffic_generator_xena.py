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
#    traffic_generator_xena.py
#
#  Description:
#    Xena abstraction
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
# Imports
#
import logging

#
# Import for Hexadecimal representation of binary data
# in Python2 and Python3
#
import binascii

#
# External traffic generators
#
from traffic_generator_base import TrafficGeneratorChassis, \
    TrafficGeneratorPort, \
    TrafficFlowType


#
# Imports from XenaLib
#
from xenalib.XenaSocket import XenaSocket
from xenalib.XenaManager import XenaManager


#
# Imports from Scapy
#
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

#
# Remove VXLAN for now, as Scapy needed for T-Rex has no VXLAN support.
#
from scapy.all import UDP, IP, Ether, VXLAN  # noqa: E402


#
# Xena Networks traffic generator Port class
#
class _XenaNetworksPort(TrafficGeneratorPort):

    def __init__(self, port_name, xport):
        super(_XenaNetworksPort, self).__init__(port_name)
        self.__xport = xport
        self.__xport.set_pause_frames_off()
        self.__traffic_flows = TrafficFlowType.none
        self.__streams = dict()
        self.__alternate_stream_sets = []
        self.__active_alternate_stream = 0

    def _div_round_up(self, a, b):
        return (a + (-a % b)) / b

    def _int_2_mac(self, mac_int):
        mac_hex = "{:012x}".format(mac_int)
        return ":".join(mac_hex[i:i+2] for i in range(0, len(mac_hex), 2)) \
            # noqa: E226

    def _mac_2_int(self, mac_str):
        return int(mac_str.replace(":", ""), 16)

    def clear_statistics(self):
        self.__xport.clear_all_rx_stats()
        self.__xport.clear_all_tx_stats()

    def take_tx_statistics_snapshot(self):
        self.__xport.grab_all_tx_stats()

    def take_rx_statistics_snapshot(self):
        self.__xport.grab_all_rx_stats()

    def get_tx_statistics_snapshots(self):
        return self.__xport.dump_all_tx_stats()

    def get_rx_statistics_snapshots(self):
        return self.__xport.dump_all_rx_stats()

    def start_traffic(self):
        return self.__xport.start_traffic()

    def stop_traffic(self):
        return self.__xport.stop_traffic()

    def _delete_traffic_stream_config(self):
        self.__traffic_flows = TrafficFlowType.none
        for stream in list(self.__streams.keys()):
            self.__xport.del_stream(stream)

        self.__streams = dict()
        self.__alternate_stream_sets = []

    def _configure_xena_stream(self, stream_id, traffic_flows, offset,
                               nr_of_flows, packet_size, stream_percentage,
                               suppress, **kwargs):

        tunnel_dst_mac = kwargs.pop("tunnel_dst_mac", None)
        traffic_dst_mac = kwargs.pop("traffic_dst_mac", '00:00:02:00:00:00')
        traffic_src_mac = kwargs.pop("traffic_src_mac", '00:00:01:00:00:00')
        random_payload = kwargs.pop("random_payload", False)

        if traffic_flows == TrafficFlowType.l2_mac:
            src_mac = (self._mac_2_int(traffic_src_mac) & 0xffffff000000) + \
                      (offset * 0x010000)
            dst_mac = (self._mac_2_int(traffic_dst_mac) & 0xffffff000000) + \
                      (offset * 0x010000)
            src_mac = self._int_2_mac(src_mac)
            dst_mac = self._int_2_mac(dst_mac)
            L2 = Ether(src=src_mac, dst=dst_mac)
            L3 = IP(src="1.0.0.0", dst="2.0.0.0")
            L4 = UDP(chksum=0)
        elif (traffic_flows == TrafficFlowType.l3_ipv4
              or traffic_flows == TrafficFlowType.nfv_mobile):
            L2 = Ether(src=traffic_src_mac, dst=traffic_dst_mac)
            L3 = IP(src="1.{}.0.0".format(offset),
                    dst="2.{}.0.0".format(offset))
            L4 = UDP(chksum=0)
        elif traffic_flows == TrafficFlowType.l4_udp:
            L2 = Ether(src=traffic_src_mac, dst=traffic_dst_mac)
            L3 = IP(src="1.0.0.1", dst="2.0.0.1")
            L4 = UDP(sport=offset, dport=offset, chksum=0)
        elif traffic_flows == TrafficFlowType.vxlan_l3_ipv4:
            #
            # Error out here for now, as we have a Scapy version dependency
            # which does not include the VXLAN().
            #
            raise ValueError("VXLAN currently not supported for Xena tester!!")
            if tunnel_dst_mac is None:
                L2 = Ether(src="00:00:00:00:00:01", dst="00:00:00:00:00:02")
            else:
                L2 = Ether(src="00:00:00:00:00:01", dst=tunnel_dst_mac)
            L3 = IP(src="3.1.1.2", dst="3.1.1.1")
            L4 = UDP(sport=32768, dport=4789, chksum=0) / \
                VXLAN(vni=69, NextProtocol=0, flags='Instance') / \
                Ether(src=traffic_src_mac, dst=traffic_dst_mac) / \
                IP(src="1.{}.0.0".format(offset),
                   dst="2.{}.0.0".format(offset)) / UDP(chksum=0)
        else:
            raise ValueError("Unsupported traffic type for Xena tester!!!")

        if (len(L2 / L3 / L4) + 4) > packet_size:  # +4 for Ethernet CRC
            raise ValueError("Packet size ({} bytes) too small for requested "
                             "packet ({} bytes)!".
                             format(packet_size, len(L2 / L3 / L4) + 4))
        #
        # The hex codec has been discarded in Python 3.x.
        # Use binascii instead(it is Python2 and Python3 compatible):
        #
        packet_hex = '0x' + \
            binascii.hexlify(bytes(L2 / L3 / L4)).decode('ascii')

        new_stream = self.__xport.add_stream(stream_id)
        if new_stream is None:
            return False

        if suppress:
            new_stream.set_stream_suppress()
        else:
            new_stream.set_stream_on()
        new_stream.disable_packet_limit()
        new_stream.set_rate_fraction(fraction=stream_percentage)
        new_stream.set_packet_header(packet_hex)
        new_stream.set_packet_length_fixed(packet_size, 1518)
        if random_payload:
            new_stream.set_packet_payload_prbs('0x00')
        else:
            new_stream.set_packet_payload_incrementing('0x00')
        new_stream.set_packet_protocol('ETHERNET', 'IP')
        new_stream.disable_test_payload_id()
        new_stream.set_frame_csum_on()

        if traffic_flows == TrafficFlowType.l2_mac:
            m1_new_stream = new_stream.add_modifier()
            if m1_new_stream is None:
                self.__xport.del_stream(stream_id)
                return False
            m1_new_stream.set_modifier(4, 0xffff0000, 'inc', 1)
            m1_new_stream.set_modifier_range(0, 1, nr_of_flows - 1)
            m2_new_stream = new_stream.add_modifier()
            if m2_new_stream is None:
                self.__xport.del_stream(stream_id)
                return False
            m2_new_stream.set_modifier(10, 0xffff0000, 'inc', 1)
            m2_new_stream.set_modifier_range(0, 1, nr_of_flows - 1)

        elif (traffic_flows == TrafficFlowType.l3_ipv4
              or traffic_flows == TrafficFlowType.nfv_mobile):
            m1_new_stream = new_stream.add_modifier()
            if m1_new_stream is None:
                self.__xport.del_stream(stream_id)
                return False
            m1_new_stream.set_modifier(28, 0xffffff00, 'inc', 1)
            m1_new_stream.set_modifier_range(0, 1, nr_of_flows - 1)
            m2_new_stream = new_stream.add_modifier()
            if m2_new_stream is None:
                self.__xport.del_stream(stream_id)
                return False
            m2_new_stream.set_modifier(32, 0xffffff00, 'inc', 1)
            m2_new_stream.set_modifier_range(0, 1, nr_of_flows - 1)

        elif traffic_flows == TrafficFlowType.l4_udp:
            m1_new_stream = new_stream.add_modifier()
            if m1_new_stream is None:
                self.__xport.del_stream(stream_id)
                return False
            m1_new_stream.set_modifier(34, 0xffff0000, 'inc', 1)
            m1_new_stream.set_modifier_range(0, 1, nr_of_flows - 1)
            m2_new_stream = new_stream.add_modifier()
            if m2_new_stream is None:
                self.__xport.del_stream(stream_id)
                return False
            m2_new_stream.set_modifier(36, 0xffff0000, 'inc', 1)
            m2_new_stream.set_modifier_range(0, 1, nr_of_flows - 1)

        elif traffic_flows == TrafficFlowType.vxlan_l3_ipv4:
            m1_new_stream = new_stream.add_modifier()
            if m1_new_stream is None:
                self.__xport.del_stream(stream_id)
                return False
            m1_new_stream.set_modifier(78, 0xffffff00, 'inc', 1)
            m1_new_stream.set_modifier_range(0, 1, nr_of_flows - 1)
            m2_new_stream = new_stream.add_modifier()
            if m2_new_stream is None:
                self.__xport.del_stream(stream_id)
                return False
            m2_new_stream.set_modifier(82, 0xffffff00, 'inc', 1)
            m2_new_stream.set_modifier_range(0, 1, nr_of_flows - 1)
            #
            # TODO: The above modifiers are causing packets with
            #       checksum errors to be send, as the inner IP
            #       checksum is not calculated!
            #

        self.__streams[stream_id] = new_stream
        return True

    def configure_traffic_stream(self, traffic_flows, nr_of_flows,
                                 packet_size, **kwargs):

        flow_percentage = kwargs.pop("percentage", 1000000)
        l2_macs = kwargs.pop("l2_macs", 1)

        if l2_macs > 1 and traffic_flows == TrafficFlowType.nfv_mobile:
            raise ValueError("Xena only supports a single l2_mac!!!")

        if traffic_flows == TrafficFlowType.none or \
           self.__traffic_flows != TrafficFlowType.none:
            #
            # We need either a cleanup, or a cleanup before we configure
            # a new traffic flow type
            #
            self._delete_traffic_stream_config()

        if traffic_flows == TrafficFlowType.l2_mac or \
           traffic_flows == TrafficFlowType.l3_ipv4 or \
           traffic_flows == TrafficFlowType.l4_udp or \
           traffic_flows == TrafficFlowType.vxlan_l3_ipv4 or \
           traffic_flows == TrafficFlowType.nfv_mobile:

            self.__traffic_flows = traffic_flows
            #
            # Fow NFV mobile flows 50% of the flow percentage
            # should be for the alternating flows.
            #
            if traffic_flows == TrafficFlowType.nfv_mobile:
                alternate_flow_percentage = flow_percentage * 50 / 100
                flow_percentage -= alternate_flow_percentage

            #
            # For Xena the maximum number of streams varies per blade.
            # Unfortunately there is no API to get the supported number, so
            # for now we use the minimum supported value, i.e. 32
            #
            # NOTE: If we ever need to support more than 256, more codes need
            #       updating as 3rd digit for address encoding (IPv4 and MAC)
            #       is based on the stream ID.
            #

            if nr_of_flows > (32 * 0x10000):
                raise ValueError(
                    "Xena has only two 32 streams with 16bit counters!!!")

            #
            # Max flows due to IPv4 address limit, and addresses used for tests
            #
            if nr_of_flows > 0x00ffffff:
                raise ValueError("To many flows requested, max {} supported!".
                                 format(0x00ffffff))

            if traffic_flows == TrafficFlowType.l4_udp and \
               nr_of_flows > 0xffff:
                raise ValueError(
                    "To many L4 flows requested, max {} supported!".format(
                        0xffff))

            #
            #
            # If the number of flows up into streams, each having 0x10000
            # flows.
            #
            # TODO: We need to optimize this because the last stream might have
            #       a low number of flows, causing the percentage to be small,
            #       which in turn might end up in less packets being sends for
            #       these flows...
            #

            flows_to_do = nr_of_flows
            #
            # Explicit typecast to int to avoid the following error:
            # TypeError: 'float' object cannot be interpreted as an integer
            #
            for stream in range(
                    1, int(self._div_round_up(nr_of_flows, 0x10000)) + 1):

                if flows_to_do > 0x10000:
                    flows_this_run = 0x10000
                else:
                    flows_this_run = flows_to_do
                flows_to_do -= flows_this_run

                stream_percentage = (flow_percentage * flows_this_run
                                     / nr_of_flows)
                if not self._configure_xena_stream(stream, traffic_flows,
                                                   stream - 1, flows_this_run,
                                                   packet_size,
                                                   stream_percentage,
                                                   False, **kwargs):
                    self._delete_traffic_stream_config()
                    return False

            if traffic_flows == TrafficFlowType.nfv_mobile:
                alternate_flows = kwargs.pop("alternate_flows", 200000)
                #
                # For NFV mobile we need another 3 sets of traffic streams,
                # to alternately run on request.
                #
                if (3 * self._div_round_up(alternate_flows, 0x10000)) + \
                   len(self.__streams) > 32:
                    self._delete_traffic_stream_config()
                    return False

                self.__active_alternate_stream = 0
                for alternate_flow_sets in range(0, 3):
                    flows_to_do = alternate_flows
                    stream_id_start = len(self.__streams) + 1
                    self.__alternate_stream_sets.append(
                        list(range(stream_id_start,
                                   stream_id_start
                                   + self._div_round_up(alternate_flows,
                                                        0x10000))))
                    if alternate_flow_sets == 0:
                        suppress = False
                    else:
                        suppress = True

                    for stream in range(stream_id_start,
                                        stream_id_start
                                        + self._div_round_up(alternate_flows,
                                                             0x10000)):
                        if flows_to_do > 0x10000:
                            flows_this_run = 0x10000
                        else:
                            flows_this_run = flows_to_do

                        flows_to_do -= flows_this_run
                        stream_percentage = alternate_flow_percentage \
                            * flows_this_run / alternate_flows

                        if not self._configure_xena_stream(
                                stream,
                                traffic_flows,
                                stream - 1,
                                flows_this_run,
                                packet_size,
                                stream_percentage,
                                suppress,
                                random_payload=kwargs.pop(
                                    "random_payload", False)
                        ):
                            self._delete_traffic_stream_config()
                            return False

            return True

        elif traffic_flows == TrafficFlowType.none:
            return True
        else:
            raise ValueError(
                "Unsupported traffic flow passed for Xena Networks tester!")

        return False

    def next_traffic_stream(self):

        if self.__traffic_flows != TrafficFlowType.nfv_mobile or \
           len(self.__alternate_stream_sets) < 2:
            return False

        #
        # We should first stop the old stream, and than start the new one,
        # but Xena is rather slow doing this leaving our average bandwidth
        # way lower than the configured value.
        #
        # for stream in self.__alternate_stream_sets[
        #         self.__active_alternate_stream]:
        #    self.__streams[stream].set_stream_suppress()
        #

        old_streams = self.__alternate_stream_sets[
            self.__active_alternate_stream]

        self.__active_alternate_stream = ((self.__active_alternate_stream + 1)
                                          % len(self.__alternate_stream_sets))

        for stream in self.__alternate_stream_sets[
                self.__active_alternate_stream]:
            self.__streams[stream].set_stream_on()

        for stream in old_streams:
            self.__streams[stream].set_stream_suppress()

        return True

    def get_port_limits(self):
        #
        # Return a dictionary for all limits per traffic type.
        # For now we only implement the NFV mobile one.
        #
        return {TrafficFlowType.nfv_mobile: {
            "MAX_L2_MACS": 1,
            "MAX_FLOWS": 0xFFFFFF}}


#
# Xena Networks traffic generator class
#
class XenaNetworks(TrafficGeneratorChassis):

    def __init__(self, **kwargs):
        super(XenaNetworks, self).__init__(**kwargs)

        self.hostname = kwargs.pop("hostname", "localhost")
        self.username = kwargs.pop("username", "test")
        self.password = kwargs.pop("password", "xena")

        self.__xena_socket = XenaSocket(self.hostname)
        self.__xena_manager = None

    def _verify_port_action(self, port_name):
        if self.is_connected() and self._verify_port_string(port_name) and \
           port_name in self.port_data:
            return(True)
        return (False)

    def _verify_port_string(self, port_name):
        xport = port_name.split(',')
        if len(xport) != 2:
            return False

        for number in xport:
            try:
                if int(number) < 0:
                    return False

            except ValueError:
                return False

        return True

    def connect(self):
        if not self.is_connected():
            self.__xena_socket.connect()
            self.__xena_manager = XenaManager(self.__xena_socket,
                                              self.username,
                                              password=self.password)

            if self.__xena_manager is not None:
                #
                # Re-add previously configured ports
                #
                for port in list(self.port_data.keys()):
                    self.port_data[port] = self._reserve_port(port)

        return self.is_connected()

    def disconnect(self):
        del(self.__xena_manager)
        self.__xena_socket.disconnect()
        self.__xena_socket = None
        return False

    def is_connected(self):
        if self.__xena_socket.is_connected() and \
           self.__xena_manager is not None:
            return True

        return False

    def _reserve_port(self, port_name):
        if not self._verify_port_string(port_name):
            return False

        xport = self.__xena_manager.add_port(port_name.split(',')[0],
                                             port_name.split(',')[1])
        if xport is None:
            return None

        return _XenaNetworksPort(port_name, xport)

    def reserve_port(self, port_name):
        xport = self._reserve_port(port_name)
        if xport is None:
            return False
        return super(XenaNetworks, self).reserve_port(port_name, xport)

    def release_port(self, port_name):
        if not self._verify_port_string(port_name) or \
           port_name not in self.port_data:
            return False

        self.__xena_manager.remove_port(port_name.split(',')[0],
                                        port_name.split(',')[1])

        return super(XenaNetworks, self).release_port(port_name)

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
            return self.port_data[port_name].configure_traffic_stream(
                traffic_flows, nr_of_flows, packet_size, **kwargs)
        return False

    def next_traffic_stream(self, port_name):
        if self._verify_port_action(port_name):
            return self.port_data[port_name].next_traffic_stream()
        return False

    def get_port_limits(self, port_name):
        if self._verify_port_action(port_name):
            return self.port_data[port_name].get_port_limits()
        return dict()
