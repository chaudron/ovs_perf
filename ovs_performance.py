#!/usr/bin/python
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
#    ovs_performance.py
#
#  Description:
#    Simple script to run the OVS performance tests
#
#  Author:
#    Eelco Chaudron
#
#  Initial Created:
#    17 January 2017
#
#  Notes:
#    - Install the spur python module
#        dnf install python-spur
#    - Install the XenaPythonLib from https://github.com/fleitner/XenaPythonLib
#        cd XenaPythonLib/
#        sudo python setup.py install
#    - Install natsort and enum modules
#        pip install natsort enum34
#    - Install matplotlib
#        dnf install python-matplotlib
#    - Install latest Scapy
#        pip install scapy
#    - Install netaddr
#        pip install netaddr
#
#  Example:
#
#
# TODOs:
#   - Add tunnel test cases (Geneve and VXLAN)
#   - Add check after test to see all OF flows got packets (i.e. n_packets != 0)
#   - Add option to stop trying more packet sizes once maximum performance
#     of link is reached (i.e. two consecutive runs @ wire speed)
#   - Test to determine maximum throughput without dropping packets
#   - Add option to maximize traffic rate (PPS, and/or % based on port speed)
#   - Add some VLAN test cases
#   - Add a Bi-directional PVP test [phy0-vf0-VM-vf1-phy1]
#   - Add option to run traffic part multiple(3) times to calculate deviation,
#     and add error bars to the graphs
#

#
# Imports
#
import argparse
import csv
import datetime
import inspect
import os
import logging
import numpy as np
import re
import spur
import sys
import time

#
# Imports from simpel shell API
#
from dut_ssh_shell import DutSshShell

#
# Import general traffic_generator library
#
from traffic_generator_base import TrafficFlowType
from traffic_generator import TrafficGenerator, TrafficGeneratorType

#
# Imports from Matplot, by default disable the tk interface
#
import matplotlib
matplotlib.use('Agg')

#
# Imports from natural sort
#
from natsort import natsorted

#
# Imports from distutils
#
from distutils.version import StrictVersion

# In Python 2, raw_input() returns a string, and input() tries
# to run the input as a Python expression.
# Since getting a string was almost always what we wanted,
# Python 3 does that with input()
# The following line checks the Python version being used to
# stick to raw_input() for Python2 and input() for Python3
if sys.version_info[0] == 3:
    raw_input = input


#
# Default configuration
#
DEFAULT_TESTER_TYPE               = 'xena'
DEFAULT_TESTER_SERVER_ADDRESS     = ''
DEFAULT_TESTER_INTERFACE          = ''
DEFAULT_SECOND_TESTER_INTERFACE   = ''
DEFAULT_DUT_ADDRESS               = ''
DEFAULT_DUT_LOGIN_USER            = 'root'
DEFAULT_DUT_LOGIN_PASSWORD        = 'root'
DEFAULT_DUT_VM_ADDRESS            = ''
DEFAULT_DUT_SECOND_VM_ADDRESS     = ''
DEFAULT_DUT_VM_NIC_PCI_ADDRESS    = ''
DEFAULT_DUT_VM_LOGIN_USER         = 'root'
DEFAULT_DUT_VM_LOGIN_PASSWORD     = 'root'
DEFAULT_PHYSICAL_INTERFACE        = ''
DEFAULT_SECOND_PHYSICAL_INTERFACE = ''
DEFAULT_PACKET_LIST               = '64, 128, 256, 512, 768, 1024, 1514'
DEFAULT_VIRTUAL_INTERFACE         = ''
DEFAULT_SECOND_VIRTUAL_INTERFACE  = ''
DEFAULT_RUN_TIME                  = 20
DEFAULT_STREAM_LIST               = '10, 1000, 10000, 100000, 1000000'
DEFAULT_BRIDGE_NAME               = 'ovs_pvp_br0'
DEFAULT_WARM_UP_TIMEOUT           = 360
DEFAULT_DST_MAC_ADDRESS           = '00:00:02:00:00:00'
DEFAULT_SRC_MAC_ADDRESS           = '00:00:01:00:00:00'


#
# Run simple traffic test Virtual to Virtual
#
def test_v2v(nr_of_flows, packet_sizes):

    v2v_tx_results = list()
    v2v_rx_results = list()
    cpu_results = list()

    for packet_size in packet_sizes:

        ##################################################
        lprint("- [TEST: {0}(flows={1}, packet_size={2})] START".
               format(inspect.currentframe().f_code.co_name,
                      nr_of_flows, packet_size))

        ##################################################
        lprint("  * Create OVS OpenFlow rules...")

        create_ovs_of_rules(nr_of_flows,
                            of_interfaces[config.virtual_interface],
                            of_interfaces[config.second_virtual_interface])

        ##################################################
        lprint("  * Start packet receiver on second VM...")
        start_traffic_rx_on_vm(config.dut_second_vm_address,
                               config.dut_second_vm_nic_pci)

        ##################################################
        lprint("  * Start CPU monitoring on DUT...")
        start_cpu_monitoring()

        ##################################################
        lprint("  * Start packet generation for {0} seconds...".format(config.run_time))
        start_traffic_tx_on_vm(config.dut_vm_address,
                               nr_of_flows, packet_size)
        time.sleep(config.run_time)

        ##################################################
        lprint("  * Stop CPU monitoring on DUT...")
        stop_cpu_monitoring()

        ##################################################
        lprint("  * Stopping packet stream on VM1...")
        stop_traffic_tx_on_vm(config.dut_vm_address)

        ##################################################
        lprint("  * Stop packet receiver on VM2...")
        stop_traffic_rx_on_vm(config.dut_second_vm_address)

        ##################################################
        lprint("  * Gathering statistics...")

        of_dump_port_to_logfile(config.bridge_name)

        vm_pkts_sec = get_traffic_rx_stats_from_vm(config.dut_second_vm_address)
        vm_tx_pkts_sec = get_traffic_tx_stats_from_vm(config.dut_vm_address)

        lprint("    - Transmit rate on VM: {:,} pps".format(vm_tx_pkts_sec))
        lprint("  ! Result, average: {:,} pps".format(vm_pkts_sec))

        cpu_results.append(get_cpu_monitoring_stats())
        v2v_tx_results.append(vm_tx_pkts_sec)
        v2v_rx_results.append(vm_pkts_sec)

        ##################################################
        lprint("  * Restoring state for next test...")
        # dut_shell.dut_exec('sh -c "ovs-ofctl del-flows {0} && ovs-appctl dpctl/del-flows"'.\
        #                    format(config.bridge_name),
        #                    die_on_error=True)

        ##################################################
        lprint("- [TEST: {0}(flows={1}, packet_size={2})] END".
               format(inspect.currentframe().f_code.co_name,
                      nr_of_flows, packet_size))

    flow_str = get_flow_type_short()
    flow_file_str = get_flow_type_name()

    create_multiple_graph(packet_sizes, {'Send Rate': v2v_tx_results,
                                         'Receive Rate': v2v_rx_results},
                          "Packet size", "Packets/second",
                          "Virtual to Virtual with {} {} flows".format(nr_of_flows, flow_str),
                          "test_v2v_{}_{}".format(nr_of_flows, flow_file_str), None,
                          cpu_utilization={'Receive Rate': cpu_results})

    create_multiple_graph(packet_sizes, {'Send Rate': v2v_tx_results,
                                         'Receive Rate': v2v_rx_results},
                          "Packet size", "Packets/second",
                          "Virtual to Virtual with {} {} flows".format(nr_of_flows, flow_str),
                          "test_v2v_{}_{}_ref".format(nr_of_flows, flow_file_str),
                          [phy_speed], cpu_utilization={'Receive Rate': cpu_results})

    return v2v_rx_results, cpu_results


#
# Run simple traffic test Physical to VM back to Physical
#
def test_p2v2p(nr_of_flows, packet_sizes):

    p2v2p_results = list()
    cpu_results = list()
    warm_up_error_continue = 0

    for packet_size in packet_sizes:

        ##################################################
        lprint("- [TEST: {0}(flows={1}, packet_size={2})] START".
               format(inspect.currentframe().f_code.co_name,
                      nr_of_flows, packet_size))

        ##################################################
        lprint("  * Create OVS OpenFlow rules...")

        create_ovs_bidirectional_of_rules(nr_of_flows,
                                          of_interfaces[config.physical_interface],
                                          of_interfaces[config.virtual_interface])

        ##################################################
        lprint("  * Initializing packet generation...")
        tester.configure_traffic_stream(config.tester_interface,
                                        get_traffic_generator_flow(),
                                        nr_of_flows, packet_size,
                                        traffic_dst_mac=config.dst_mac_address,
                                        traffic_src_mac=config.src_mac_address)

        ##################################################
        if config.warm_up:
            lprint("  * Doing flow table warm-up...")
            start_vm_time = datetime.datetime.now()
            start_traffic_loop_on_vm(config.dut_vm_address,
                                     config.dut_vm_nic_pci)

            tester.start_traffic(config.tester_interface)

            warm_up_error_continue = warm_up_verify(nr_of_flows * 2,
                                        config.warm_up_timeout)

            if not warm_up_error_continue:
                tester.stop_traffic(config.tester_interface)

        ##################################################
        lprint("  * Clear all statistics...")
        tester.clear_statistics(config.tester_interface)

        pp_tx_start, pp_tx_drop_start, pp_rx_start, pp_rx_drop_start \
            = get_of_port_packet_stats(of_interfaces[config.physical_interface])
        vp_tx_start, vp_tx_drop_start, vp_rx_start, vp_rx_drop_start \
            = get_of_port_packet_stats(of_interfaces[config.virtual_interface])

        ##################################################
        if not config.warm_up or warm_up_error_continue:
            lprint("  * Start packet receiver on VM...")
            start_traffic_loop_on_vm(config.dut_vm_address,
                                     config.dut_vm_nic_pci)
            warm_up_time = 0
        else:
            # warm_up_time is the total time it takes from the start of the
            # VM at warm-up till we would normally start the loop back VM.
            # This values is used to remove warm-up statistics.
            warm_up_time = int(np.ceil((datetime.datetime.now() -
                                        start_vm_time).total_seconds()))
            lprint("  * Determine warm op time, {} seconds...".
                   format(warm_up_time))

        ##################################################
        lprint("  * Start CPU monitoring on DUT...")
        start_cpu_monitoring()

        ##################################################
        lprint("  * Start packet generation for {0} seconds...".format(config.run_time))
        tester.start_traffic(config.tester_interface)
        for i in range(1, config.run_time):
            time.sleep(1)
            tester.take_rx_statistics_snapshot(config.tester_interface)

        ##################################################
        lprint("  * Stop CPU monitoring on DUT...")
        stop_cpu_monitoring()

        ##################################################
        lprint("  * Stopping packet stream...")
        tester.stop_traffic(config.tester_interface)
        time.sleep(1)

        ##################################################
        lprint("  * Stop packet receiver on VM...")
        stop_traffic_loop_on_vm(config.dut_vm_address)

        ##################################################
        lprint("  * Gathering statistics...")

        tester.take_statistics_snapshot(config.tester_interface)

        full_tx_stats = tester.get_tx_statistics_snapshots(config.tester_interface)
        full_rx_stats = tester.get_rx_statistics_snapshots(config.tester_interface)
        slogger.debug(" full_tx_stats={}".format(full_tx_stats))
        slogger.debug(" full_rx_stats={}".format(full_rx_stats))

        pp_tx_end, pp_tx_drop_end, pp_rx_end, pp_rx_drop_end \
            = get_of_port_packet_stats(of_interfaces[config.physical_interface])
        vp_tx_end, vp_tx_drop_end, vp_rx_end, vp_rx_drop_end \
            = get_of_port_packet_stats(of_interfaces[config.virtual_interface])

        pp_rx = pp_rx_end - pp_rx_start
        pp_tx = pp_tx_end - pp_tx_start
        pp_rx_drop = pp_rx_drop_end - pp_rx_drop_start
        pp_tx_drop = pp_tx_drop_end - pp_tx_drop_start

        vp_rx = vp_rx_end - vp_rx_start
        vp_tx = vp_tx_end - vp_tx_start
        vp_rx_drop = vp_rx_drop_end - vp_rx_drop_start
        vp_tx_drop = vp_tx_drop_end - vp_tx_drop_start

        vm_pkts_sec = get_traffic_rx_stats_from_vm(config.dut_vm_address,
                                                   skip_samples=warm_up_time)

        packets_tx = full_tx_stats[sorted(full_tx_stats.keys())[-1]]['pt_total']['packets']
        packets_rx = full_rx_stats[sorted(full_rx_stats.keys())[-1]]['pr_total']['packets']

        lprint("    - Packets send by Tester      : {:-20,}".format(packets_tx))

        lprint("    - Packets received by physical: {:-20,} [Lost {:,}, Drop {:,}]".
               format(pp_rx, packets_tx - pp_rx, pp_rx_drop))

        lprint("    - Packets received by virtual : {:-20,} [Lost {:,}, Drop {:,}]".
               format(vp_tx, pp_rx - vp_tx, vp_tx_drop))

        lprint("    - Packets send by virtual     : {:-20,} [Lost {:,}, Drop {:,}]".
               format(vp_rx, vp_tx - vp_rx, vp_rx_drop))

        lprint("    - Packets send by physical    : {:-20,} [Lost {:,}, Drop {:,}]".
               format(pp_tx, vp_rx - pp_tx, pp_tx_drop))

        lprint("    - Packets received by Tester  : {:-20,} [Lost {:,}]".
               format(packets_rx, pp_tx - packets_rx))

        lprint("    - Receive rate on VM: {:,} pps".format(vm_pkts_sec))

        rx_pkts_sec = get_packets_per_second_from_traffic_generator_rx_stats(full_rx_stats)
        lprint("  ! Result, average: {:,} pps".format(rx_pkts_sec))

        p2v2p_results.append(rx_pkts_sec)
        cpu_results.append(get_cpu_monitoring_stats())

        ##################################################
        lprint("  * Restoring state for next test...")
        tester.unconfigure_traffic_stream(config.tester_interface)

        # dut_shell.dut_exec('sh -c "ovs-ofctl del-flows {0} && ovs-appctl dpctl/del-flows"'.\
        #                    format(config.bridge_name),
        #                    die_on_error=True)

        ##################################################
        lprint("- [TEST: {0}(flows={1}, packet_size={2})] END".
               format(inspect.currentframe().f_code.co_name,
                      nr_of_flows, packet_size))

    create_single_graph(packet_sizes, p2v2p_results,
                        "Packet size", "Packets/second",
                        "Physical to Virtual back to Physical with {} {} flows".
                        format(nr_of_flows,  get_flow_type_short()),
                        "test_p2v2p_{}_{}".format(nr_of_flows,
                                                  get_flow_type_name()),
                        phy_speed,
                        cpu_utilization=cpu_results)

    return p2v2p_results, cpu_results


#
# Run simple traffic test Physical to VM
#
def test_p2v(nr_of_flows, packet_sizes):

    p2v_results = list()
    cpu_results = list()

    for packet_size in packet_sizes:

        ##################################################
        lprint("- [TEST: {0}(flows={1}, packet_size={2})] START".
               format(inspect.currentframe().f_code.co_name,
                      nr_of_flows, packet_size))

        ##################################################
        lprint("  * Create OVS OpenFlow rules...")
        create_ovs_of_rules(nr_of_flows,
                            of_interfaces[config.physical_interface],
                            of_interfaces[config.virtual_interface])

        ##################################################
        lprint("  * Initializing packet generation...")
        tester.configure_traffic_stream(config.tester_interface,
                                        get_traffic_generator_flow(),
                                        nr_of_flows, packet_size,
                                        traffic_dst_mac=config.dst_mac_address,
                                        traffic_src_mac=config.src_mac_address)

        ##################################################
        if config.warm_up:
            lprint("  * Doing flow table warm-up...")
            tester.start_traffic(config.tester_interface)
            warm_up_verify(nr_of_flows, config.warm_up_timeout)
            tester.stop_traffic(config.tester_interface)

        ##################################################
        lprint("  * Clear all statistics...")
        tester.clear_statistics(config.tester_interface)

        pp_rx_start \
            = get_of_port_packet_stats(of_interfaces[config.physical_interface])[2]
        vp_tx_start, vp_tx_drop_start \
            = get_of_port_packet_stats(of_interfaces[config.virtual_interface])[0:2]

        ##################################################
        lprint("  * Start packet receiver on VM...")
        start_traffic_rx_on_vm(config.dut_vm_address,
                               config.dut_vm_nic_pci)

        ##################################################
        lprint("  * Start CPU monitoring on DUT...")
        start_cpu_monitoring()

        ##################################################
        lprint("  * Start packet generation for {0} seconds...".format(config.run_time))
        tester.start_traffic(config.tester_interface)
        for i in range(1, config.run_time):
            time.sleep(1)

        ##################################################
        lprint("  * Stop CPU monitoring on DUT...")
        stop_cpu_monitoring()

        ##################################################
        lprint("  * Stopping packet stream...")
        tester.stop_traffic(config.tester_interface)
        time.sleep(1)

        ##################################################
        lprint("  * Stop packet receiver on VM...")
        stop_traffic_rx_on_vm(config.dut_vm_address)

        ##################################################
        lprint("  * Gathering statistics...")

        tester.take_tx_statistics_snapshot(config.tester_interface)
        full_tx_stats = tester.get_tx_statistics_snapshots(config.tester_interface)
        slogger.debug(" full_tx_stats={}".format(full_tx_stats))

        pp_rx_end \
            = get_of_port_packet_stats(of_interfaces[config.physical_interface])[2]
        vp_tx_end, vp_tx_drop_end \
            = get_of_port_packet_stats(of_interfaces[config.virtual_interface])[0:2]
        pp_rx = pp_rx_end - pp_rx_start
        vp_tx = vp_tx_end - vp_tx_start
        vp_tx_drop = vp_tx_drop_end - vp_tx_drop_start

        vm_pkts_sec = get_traffic_rx_stats_from_vm(config.dut_vm_address)

        packets_tx = full_tx_stats[sorted(full_tx_stats.keys())[-1]]['pt_total']['packets']

        lprint("    - Packets send by Tester {:,}".format(packets_tx))

        lprint("    - Packets received by physical port {:,} [Lost {:,}]".
               format(pp_rx, packets_tx - pp_rx))

        lprint("    - Packets received by virtual port {:,} [Lost {:,}]".
               format(vp_tx, pp_rx - vp_tx))

        lprint("    - Packets dropped by virtual port {:,}".
               format(vp_tx_drop))

        lprint("  ! Result, average: {:,} pps".format(vm_pkts_sec))

        p2v_results.append(vm_pkts_sec)
        cpu_results.append(get_cpu_monitoring_stats())

        ##################################################
        lprint("  * Restoring state for next test...")
        tester.unconfigure_traffic_stream(config.tester_interface)

        # dut_shell.dut_exec('sh -c "ovs-ofctl del-flows {0} && ovs-appctl dpctl/del-flows"'.\
        #                    format(config.bridge_name),
        #                    die_on_error=True)

        ##################################################
        lprint("- [TEST: {0}(flows={1}, packet_size={2})] END".
               format(inspect.currentframe().f_code.co_name,
                      nr_of_flows, packet_size))

    create_single_graph(packet_sizes, p2v_results,
                        "Packet size", "Packets/second",
                        "Physical to Virtual with {} {} flows".
                        format(nr_of_flows, get_flow_type_short()),
                        "test_p2v_{}_{}".
                        format(nr_of_flows, get_flow_type_name()),
                        phy_speed, cpu_utilization=cpu_results)

    return p2v_results, cpu_results


#
# Run simple traffic test Physical to Physical
#
def test_p2p(nr_of_flows, packet_sizes):

    p2p_results = list()
    cpu_results = list()

    for packet_size in packet_sizes:

        ##################################################
        lprint("- [TEST: {0}(flows={1}, packet_size={2})] START".
               format(inspect.currentframe().f_code.co_name,
                      nr_of_flows, packet_size))

        ##################################################
        lprint("  * Create OVS OpenFlow rules...")

        create_ovs_of_rules(nr_of_flows,
                            of_interfaces[config.physical_interface],
                            of_interfaces[config.second_physical_interface])

        ##################################################
        lprint("  * Initializing packet generation...")
        tester.configure_traffic_stream(config.tester_interface,
                                        get_traffic_generator_flow(),
                                        nr_of_flows, packet_size,
                                        traffic_dst_mac=config.dst_mac_address,
                                        traffic_src_mac=config.src_mac_address)

        ##################################################
        if config.warm_up:
            lprint("  * Doing flow table warm-up...")
            tester.start_traffic(config.tester_interface)
            warm_up_verify(nr_of_flows, config.warm_up_timeout)
            tester.stop_traffic(config.tester_interface)

        ##################################################
        lprint("  * Clear all statistics...")
        tester.clear_statistics(config.tester_interface)
        tester.clear_statistics(config.second_tester_interface)

        pp_tx_start, pp_tx_drop_start, pp_rx_start, pp_rx_drop_start \
            = get_of_port_packet_stats(of_interfaces[config.physical_interface])
        rpp_tx_start, rpp_tx_drop_start, rpp_rx_start, rpp_rx_drop_start \
            = get_of_port_packet_stats(of_interfaces[config.second_physical_interface])

        ##################################################
        lprint("  * Start CPU monitoring on DUT...")
        start_cpu_monitoring()

        ##################################################
        lprint("  * Start packet generation for {0} seconds...".format(config.run_time))
        tester.start_traffic(config.tester_interface)
        for i in range(1, config.run_time):
            time.sleep(1)
            tester.take_rx_statistics_snapshot(config.second_tester_interface)

        ##################################################
        lprint("  * Stop CPU monitoring on DUT...")
        stop_cpu_monitoring()

        ##################################################
        lprint("  * Stopping packet stream...")
        tester.stop_traffic(config.tester_interface)
        time.sleep(1)

        ##################################################
        lprint("  * Gathering statistics...")

        tester.take_tx_statistics_snapshot(config.tester_interface)
        tester.take_rx_statistics_snapshot(config.second_tester_interface)

        full_tx_stats = tester.get_tx_statistics_snapshots(config.tester_interface)
        full_rx_stats = tester.get_rx_statistics_snapshots(config.second_tester_interface)
        slogger.debug(" full_tx_stats={}".format(full_tx_stats))
        slogger.debug(" full_rx_stats={}".format(full_rx_stats))

        pp_tx_end, pp_tx_drop_end, pp_rx_end, pp_rx_drop_end \
            = get_of_port_packet_stats(of_interfaces[config.physical_interface])
        rpp_tx_end, rpp_tx_drop_end, rpp_rx_end, rpp_rx_drop_end \
            = get_of_port_packet_stats(of_interfaces[config.second_physical_interface])

        pp_rx = pp_rx_end - pp_rx_start
        pp_rx_drop = pp_rx_drop_end - pp_rx_drop_start

        rpp_tx = rpp_tx_end - rpp_tx_start
        rpp_tx_drop = rpp_tx_drop_end - rpp_tx_drop_start

        packets_tx = full_tx_stats[sorted(full_tx_stats.keys())[-1]]['pt_total']['packets']
        packets_rx = full_rx_stats[sorted(full_rx_stats.keys())[-1]]['pr_total']['packets']

        lprint("    - Packets send by Tester         : {:-20,}".format(packets_tx))

        lprint("    - Packets received by physical   : {:-20,} [Lost {:,}, Drop {:,}]".
               format(pp_rx, packets_tx - pp_rx, pp_rx_drop))

        lprint("    - Packets send by second physical: {:-20,} [Lost {:,}, Drop {:,}]".
               format(rpp_tx, pp_rx - rpp_tx, rpp_tx_drop))

        lprint("    - Packets received by Tester     : {:-20,} [Lost {:,}]".
               format(packets_rx, rpp_tx - packets_rx))

        rx_pkts_sec = get_packets_per_second_from_traffic_generator_rx_stats(full_rx_stats)

        lprint("  ! Result, average: {:,} pps".format(rx_pkts_sec))

        p2p_results.append(rx_pkts_sec)
        cpu_results.append(get_cpu_monitoring_stats())

        ##################################################
        lprint("  * Restoring state for next test...")
        tester.unconfigure_traffic_stream(config.tester_interface)
        # dut_shell.dut_exec('sh -c "ovs-ofctl del-flows {0} && ovs-appctl dpctl/del-flows"'.\
        #                    format(config.bridge_name),
        #                    die_on_error=True)

        ##################################################
        lprint("- [TEST: {0}(flows={1}, packet_size={2})] END".
               format(inspect.currentframe().f_code.co_name,
                      nr_of_flows, packet_size))

    create_single_graph(packet_sizes, p2p_results,
                        "Packet size", "Packets/second",
                        "Physical to Physical with {} {} flows".
                        format(nr_of_flows, get_flow_type_short()),
                        "test_p2p_{}_{}".
                        format(nr_of_flows, get_flow_type_name()),
                        phy_speed, cpu_utilization=cpu_results)

    return p2p_results, cpu_results


#
# Run VXLAN test
#
# TODO: This is only tested on OVS-DPDK, need modular support
#       so it will work on kernel (hw offload) datapath.
#
#       Also needs encap test, and encap-decap test.
#
#       Also note that this test will not distribute the
#       load among rx queue's as the outer IP+UDP headers
#       do not change. Making the source UDP port of the
#       outer header will solve this, but we have no more
#       modifiers. We could do a destination IP only OF
#       rule and use the source IP counters for src UDP.
#
def test_vxlan(nr_of_flows, packet_sizes):

    vxlan_results = list()
    cpu_results = list()
    tunnel_bridge = (config.bridge_name + "_tterm")[:15]

    for packet_size in packet_sizes:

        ##################################################
        lprint("- [TEST: {0}(flows={1}, packet_size={2})] START".
               format(inspect.currentframe().f_code.co_name,
                      nr_of_flows, packet_size))

        ##################################################
        lprint("  * Get bridge MAC address...")
        tunnel_dst_mac = get_of_bridge_mac_address(tunnel_bridge)

        ##################################################
        lprint("  * Create OVS OpenFlow rules...")
        create_ovs_of_rules(nr_of_flows,
                            of_interfaces['vxlan0'],
                            of_interfaces[config.virtual_interface])

        ##################################################
        if ovs_data_path == "netdev":
            #
            # For DPDK data path only
            #
            lprint("  * Setup neighbor entry...")
            dut_shell.dut_exec('sh -c "ovs-appctl tnl/neigh/set {} '
                               ' 3.1.1.2 00:00:00:00:00:01"'.format(tunnel_bridge),
                               die_on_error=True)
            dut_shell.dut_exec('sh -c "ip addr add 3.1.1.1/24 dev {0};'
                               'ip link set {0} up"'.format(tunnel_bridge),
                               die_on_error=True)

        ##################################################
        lprint("  * Initializing packet generation...")
        tester.configure_traffic_stream(config.tester_interface,
                                        TrafficFlowType.vxlan_l3_ipv4,
                                        nr_of_flows, packet_size,
                                        tunnel_dst_mac=tunnel_dst_mac,
                                        traffic_dst_mac=config.dst_mac_address)

        ##################################################
        lprint("  * Clear all statistics...")
        tester.clear_statistics(config.tester_interface)

        pp_rx_start \
            = get_of_port_packet_stats(of_interfaces[config.physical_interface],
                                       bridge=tunnel_bridge)[2]

        vp_tx_start, vp_tx_drop_start \
            = get_of_port_packet_stats(of_interfaces[config.virtual_interface])[0:2]

        ##################################################
        lprint("  * Start packet receiver on VM...")
        start_traffic_rx_on_vm(config.dut_vm_address,
                               config.dut_vm_nic_pci)

        ##################################################
        lprint("  * Start CPU monitoring on DUT...")
        start_cpu_monitoring()

        ##################################################
        lprint("  * Start packet generation for {0} seconds...".
               format(config.run_time))
        tester.start_traffic(config.tester_interface)
        for i in range(1, config.run_time):
            time.sleep(1)

        ##################################################
        lprint("  * Stop CPU monitoring on DUT...")
        stop_cpu_monitoring()

        ##################################################
        lprint("  * Stopping packet stream...")
        tester.stop_traffic(config.tester_interface)
        time.sleep(1)

        ##################################################
        lprint("  * Stop packet receiver on VM...")
        stop_traffic_rx_on_vm(config.dut_vm_address)

        ##################################################
        lprint("  * Gathering statistics...")

        tester.take_tx_statistics_snapshot(config.tester_interface)
        full_tx_stats = tester.get_tx_statistics_snapshots(config.tester_interface)
        slogger.debug(" full_tx_stats={}".format(full_tx_stats))

        pp_rx_end = get_of_port_packet_stats(of_interfaces[config.physical_interface],
                                             bridge=tunnel_bridge)[2]

        vp_tx_end, vp_tx_drop_end \
            = get_of_port_packet_stats(of_interfaces[config.virtual_interface])[0:2]
        pp_rx = pp_rx_end - pp_rx_start
        vp_tx = vp_tx_end - vp_tx_start
        vp_tx_drop = vp_tx_drop_end - vp_tx_drop_start

        vm_pkts_sec = get_traffic_rx_stats_from_vm(config.dut_vm_address)

        packets_tx = full_tx_stats[sorted(full_tx_stats.keys())[-1]]['pt_total']['packets']

        lprint("    - Packets send by Tester {:,}".format(packets_tx))

        lprint("    - Packets received by physical port {:,} [Lost {:,}]".
               format(pp_rx, packets_tx - pp_rx))

        lprint("    - Packets received by virtual port {:,} [Lost {:,}]".
               format(vp_tx, pp_rx - vp_tx))

        lprint("    - Packets dropped by virtual port {:,}".
               format(vp_tx_drop))

        lprint("  ! Result, average: {:,} pps".format(vm_pkts_sec))

        vxlan_results.append(vm_pkts_sec)
        cpu_results.append(get_cpu_monitoring_stats())

        ##################################################
        lprint("  * Restoring state for next test...")
        tester.unconfigure_traffic_stream(config.tester_interface)

        ##################################################
        lprint("- [TEST: {0}(flows={1}, packet_size={2})] END".
               format(inspect.currentframe().f_code.co_name,
                      nr_of_flows, packet_size))

    create_single_graph(packet_sizes, vxlan_results,
                        "Packet size", "Packets/second",
                        "VXLAN Tunnel with {} {} flows".
                        format(nr_of_flows, get_flow_type_short()),
                        "test_vxlan_{}_{}".
                        format(nr_of_flows, get_flow_type_name()),
                        phy_speed, cpu_utilization=cpu_results)

    return vxlan_results, cpu_results


#
# Count datapath flows
#
def get_active_datapath_flows():
    if ovs_data_path == "netdev":
        cmd = 'sh -c "ovs-appctl dpctl/dump-flows netdev@ovs-netdev | ' \
              "grep -v 'flow-dump from pmd on cpu core:' | " \
              'wc -l"'
    else:
        cmd = 'sh -c "ovs-appctl  dpctl/show system@ovs-system| grep flows| awk \'{print $2}\'"'

    result = dut_shell.dut_exec(cmd, die_on_error=True)
    return int(result.stdout_output)


#
# Warm up verification
#
def warm_up_verify(requested_flows, timeout):
    run_time = 0
    wait_time = 0
    active_flows = 0
    error_continue = 0

    while active_flows < requested_flows:
        run_time += 1
        if timeout != 0 and run_time >= timeout:
	    if config.warm_up_no_fail:
		lprint("WARNING: Warm up failed. Waiting for Datapath flows to flush")

                tester.stop_traffic(config.tester_interface)
                stop_traffic_loop_on_vm(config.dut_vm_address)
                active_flows = get_active_datapath_flows()

                while active_flows > 32:
                    wait_time += 1
                    if wait_time >= 20:
                        lprint("ERROR: Failed to complete cool-down in time (20 seconds)!")
                        sys.exit(-1)
                        break
                    active_flows = get_active_datapath_flows()
                    time.sleep(1)
                error_continue = 1
		return error_continue
            else:
	        lprint("ERROR: Failed to complete warm-up in time ({} seconds)!".
                       format(timeout))
                sys.exit(-1)

        time.sleep(1)
        active_flows = get_active_datapath_flows()
    #
    # Flows exist, we can continue now
    #
    return error_continue


#
# Flush all OVS flows
#
def flush_ovs_flows():
    # data_path = "system@ovs-system"
    #
    # For now we only flush the openflow rules for nedtev, because as soon as
    # we flush the datapath rules no more flows get added to the datapath.
    #
    # However other vendors are also struggling when flushing the datapath.
    #
    # if ovs_data_path == "netdev":
    #     data_path = "netdev@ovs-netdev"
    #
    # cmd = 'sh -c "ovs-ofctl del-flows {0}; ' \
    #       'ovs-appctl dpctl/del-flows {1}"'. \
    #       format(config.bridge_name, data_path)

    cmd = 'sh -c "ovs-ofctl del-flows {0}"'. \
          format(config.bridge_name)

    dut_shell.dut_exec(cmd, die_on_error=True)

    if config.warm_up or not config.no_cool_down:
        lprint("  * Doing flow table cool-down...")
        active_flows = get_active_datapath_flows()
        run_time = 0

        while active_flows > 32:
            run_time += 1
            if run_time >= 20:
                lprint("WARNING: Failed to complete cool-down in time (20 seconds)!")
                break

            active_flows = get_active_datapath_flows()
            time.sleep(1)

        time.sleep(2)


#
# Dump openflow port statistics to logfile
#
def of_dump_port_to_logfile(bridge):
    return dut_shell.dut_exec("ovs-ofctl dump-ports {}".format(bridge),
                              die_on_error=True)


#
# Start packet receive application on VM
#
def start_traffic_rx_on_vm(vm, pci):

    cpu_mask = ((1 << (config.dut_vm_nic_queues + 1)) - 1)
    pmd_cpu_mask = cpu_mask & ~0x1
    disable_hw_vlan = " --disable-hw-vlan" if vm_dpdk_version < \
                      StrictVersion('18.2.0') else ""

    cmd = r"sshpass -p {2} ssh -o UserKnownHostsFile=/dev/null " \
          r"-o StrictHostKeyChecking=no -n {1}@{0} " \
          r"'rm -f ~/results.txt; " \
          r" nohup sh -c " \
          r' "(while sleep 1; do echo show port stats 0; done | ' \
          r" testpmd -c {5:x} -n 4 --socket-mem 2048,0 -w {3} -- "\
          r" --burst 64 -i --rxq={4} --txq={4} --rxd={8} " \
          r" --txd={9} --auto-start --forward-mode=rxonly " \
          r' --port-topology=chained --coremask={6:x}{7})" ' \
          r" &>results.txt &'". \
          format(vm, config.dut_vm_user, config.dut_vm_password, pci,
                 config.dut_vm_nic_queues, cpu_mask, pmd_cpu_mask,
                 disable_hw_vlan, config.dut_vm_nic_rxd,
                 config.dut_vm_nic_txd)

    dut_shell.dut_exec('', raw_cmd=['sh', '-c', cmd], die_on_error=True)
    time.sleep(2)


#
# Stop packet receive application on VM
#
def stop_traffic_rx_on_vm(vm, **kwargs):
    die = kwargs.pop("die", True)

    cmd = r"sshpass -p {2} ssh -o UserKnownHostsFile=/dev/null " \
          r"-o StrictHostKeyChecking=no -n {1}@{0} " \
          r"'kill -SIGINT `pidof testpmd`'". \
          format(vm, config.dut_vm_user, config.dut_vm_password)

    dut_shell.dut_exec('', raw_cmd=['sh', '-c', cmd], die_on_error=die)


#
# Start packet receive and loop application on VM
#
def start_traffic_loop_on_vm(vm, pci):
    cpu_mask = ((1 << (config.dut_vm_nic_queues + 1)) - 1)
    pmd_cpu_mask = cpu_mask & ~0x1
    mac_swap = " --forward-mode=macswap" if config.mac_swap else ""
    disable_hw_vlan = " --disable-hw-vlan" if vm_dpdk_version < \
                      StrictVersion('18.2.0') else ""

    cmd = r"sshpass -p {2} ssh -o UserKnownHostsFile=/dev/null " \
          r"-o StrictHostKeyChecking=no -n {1}@{0} " \
          r"'rm -f ~/results.txt; " \
          r" nohup sh -c " \
          r' "(while sleep 1; do echo show port stats 0; done | ' \
          r" testpmd -c {5:x} -n 4 --socket-mem 2048,0 -w {3} -- "\
          r" --burst 64 -i --rxq={4} --txq={4} --rxd={9} " \
          r" --txd={10} --coremask={6:x} --auto-start " \
          r' --port-topology=chained{7}{8})" ' \
          r" &>results.txt &'". \
          format(vm, config.dut_vm_user, config.dut_vm_password, pci,
                 config.dut_vm_nic_queues, cpu_mask, pmd_cpu_mask,
                 mac_swap, disable_hw_vlan, config.dut_vm_nic_rxd,
                 config.dut_vm_nic_txd)

    dut_shell.dut_exec('', raw_cmd=['sh', '-c', cmd], die_on_error=True)
    time.sleep(2)


#
# Stop packet receive and loop application on VM
#
def stop_traffic_loop_on_vm(vm):
    stop_traffic_rx_on_vm(vm)


#
# Get traffic receive stats from application on VM
#
def get_traffic_rx_stats_from_vm(vm, **kwargs):
    skip_samples = kwargs.pop("skip_samples", 0)

    cmd = r"sshpass -p {2} ssh -o UserKnownHostsFile=/dev/null " \
          r"-o StrictHostKeyChecking=no -n {1}@{0} " \
          "'cat ~/results.txt | grep -E \"Rx-pps|Tx-pps\"'". \
          format(vm, config.dut_vm_user, config.dut_vm_password)

    result = dut_shell.dut_exec('', raw_cmd=['sh', '-c', cmd], die_on_error=True)

    pkt_rates = [int(re.sub(r'^\s*Rx-pps:\s*', '', s))
                 for s in re.findall(r'^\s*Rx-pps:\s*\d+$', result.stdout_output,
                                     re.MULTILINE)]

    if skip_samples > 0:
        pkt_rates = pkt_rates[skip_samples:]

    if len(pkt_rates) <= 10:
        lprint("ERROR: No engough elements to calculate packet rate!")
        sys.exit(-1)

    pkt_rates = pkt_rates[5:-5]
    return sum(pkt_rates) / len(pkt_rates)


#
# Start packet generation application on VM
#
def start_traffic_tx_on_vm(vm, nr_of_flows, packet_size):

    if config.flow_type == 'L2':
        cmd = r"sshpass -p {2} ssh -o UserKnownHostsFile=/dev/null " \
              r"-o StrictHostKeyChecking=no -n {1}@{0} " \
              r"'rm -f ~/results.txt; " \
              r" nohup /bin/trafgen -c 3 -n 4 -- -p 1 --benchmark " \
              r"--flows-per-stream 1 --bursts-per-stream 1 --streams {3} " \
              r"--src-mac {5} --dst-mac {6} " \
              r"--src-ip 1.0.0.0 --dst-ip 2.0.0.0 --packet-size {4} " \
              r"--vary-src mac --vary-dst mac -s ~/results.txt" \
              r"> /dev/null 2>&1 &'". \
              format(vm, config.dut_vm_user,
                     config.dut_vm_password, nr_of_flows, packet_size,
                     config.src_mac_address, config.dst_mac_address)
    elif config.flow_type == 'L3':
        cmd = r"sshpass -p {2} ssh -o UserKnownHostsFile=/dev/null " \
              r"-o StrictHostKeyChecking=no -n {1}@{0} " \
              r"'rm -f ~/results.txt; " \
              r" nohup /bin/trafgen -c 3 -n 4 -- -p 1 --benchmark " \
              r"--flows-per-stream 1 --bursts-per-stream 1 --streams {3} " \
              r"--src-mac {5} --dst-mac {6} " \
              r"--src-ip 1.0.0.0 --dst-ip 2.0.0.0 --packet-size {4} " \
              r"--vary-src ip --vary-dst ip -s ~/results.txt" \
              r"> /dev/null 2>&1 &'". \
              format(vm, config.dut_vm_user,
                     config.dut_vm_password, nr_of_flows, packet_size,
                     config.src_mac_address, config.dst_mac_address)
    elif config.flow_type == 'L4-UDP':
        cmd = r"sshpass -p {2} ssh -o UserKnownHostsFile=/dev/null " \
              r"-o StrictHostKeyChecking=no -n {1}@{0} " \
              r"'rm -f ~/results.txt; " \
              r" nohup /bin/trafgen -c 3 -n 4 -- -p 1 --benchmark " \
              r"--flows-per-stream 1 --bursts-per-stream 1 --streams {3} " \
              r"--src-mac {5} --dst-mac {6} " \
              r"--src-ip 1.0.0.0 --dst-ip 2.0.0.0 --packet-size {4} " \
              r"--src-port 0 --dst-port 0 " \
              r"--vary-src port --vary-dst port -s ~/results.txt" \
              r"> /dev/null 2>&1 &'". \
              format(vm, config.dut_vm_user,
                     config.dut_vm_password, nr_of_flows, packet_size,
                     config.src_mac_address, config.dst_mac_address)
    else:
        raise ValueError("No support for this protocol on!!")

    dut_shell.dut_exec('', raw_cmd=['sh', '-c', cmd], die_on_error=True)


#
# Stop packet generation application on VM
#
def stop_traffic_tx_on_vm(vm, **kwargs):
    die = kwargs.pop("die", True)

    cmd = r"sshpass -p {2} ssh -o UserKnownHostsFile=/dev/null " \
          r"-o StrictHostKeyChecking=no -n {1}@{0} " \
          r"'kill -SIGINT `pidof trafgen`'". \
          format(vm, config.dut_vm_user, config.dut_vm_password)

    dut_shell.dut_exec('', raw_cmd=['sh', '-c', cmd], die_on_error=die)


#
# Get traffic transmit stats from application on VM
#
def get_traffic_tx_stats_from_vm(vm):
    cmd = r"sshpass -p {2} ssh -o UserKnownHostsFile=/dev/null " \
          r"-o StrictHostKeyChecking=no -n {1}@{0} " \
          r"'cat ~/results.txt | grep port0.tx_packets'". \
          format(vm, config.dut_vm_user, config.dut_vm_password)

    result = dut_shell.dut_exec('', raw_cmd=['sh', '-c', cmd], die_on_error=True)

    return get_packets_per_second_from_pkt_counters(result.stdout_output, 5)


#
# Get packets per seconds from traffic rx generator starts
#
def get_packets_per_second_from_traffic_generator_rx_stats(rx_stats):
    avg = cnt = 0
    for timestamp in natsorted(list(rx_stats.keys()))[2:-2]:
        stats = rx_stats[timestamp]
        pps = stats['pr_total']['pps']
        avg += pps
        cnt += 1

    return avg / cnt


#
# Get packets per seconds from traffic tx generator starts
#
def get_packets_per_second_from_traffic_generator_tx_stats(tx_stats):
    avg = cnt = 0
    for timestamp in natsorted(list(tx_stats.keys()))[2:-2]:
        stats = tx_stats[timestamp]
        pps = stats['pt_total']['pps']
        avg += pps
        cnt += 1

    return avg / cnt


#
# Get packets per seconds from a string with packets count values
# It might strip, start, stop number of entries, and than return
# average value.
#
def get_packets_per_second_from_pkt_counters(counters, strip):

    slogger.info("get_pacets_per_second_from_counters(\"{}\", {})".
                 format(counters, strip))

    counters_clean = re.sub(r'.+:\s?', '', counters)
    counter_list = map(int, counters_clean.split())

    if strip < 0 or (len(counter_list) - (strip * 2)) < 2:
        lprint("ERROR: No engough elements to calculate packet rate!")
        sys.exit(-1)

    if strip > 0:
        del counter_list[:strip]
        del counter_list[-strip:]

    slogger.info("[gppsfc] Work list \"{}\"".format(counter_list))

    pkts_sec = 0
    for i in range(1, len(counter_list)):
        pkts_sec = pkts_sec + (counter_list[i] - counter_list[i - 1])

    pkts_sec = pkts_sec / (len(counter_list) - 1)

    slogger.info("[gppsfc] pkts/sec = {:,}".format(pkts_sec))

    return pkts_sec


#
# Add OVS OpenFlow rules
#
def create_ovs_of_rules(number_of_flows, src_port, dst_port, **kwargs):

    if config.flow_type == 'L2':
        create_ovs_l2_of_rules(number_of_flows, src_port, dst_port, **kwargs)
    elif config.flow_type == 'L3':
        create_ovs_l3_of_rules(number_of_flows, src_port, dst_port, **kwargs)
    elif config.flow_type == 'L4-UDP':
        create_ovs_l4_of_rules(number_of_flows, src_port, dst_port, **kwargs)
    else:
        raise ValueError("No support for this protocol!!")


#
# Add OVS OpenFlow rules
#
def create_ovs_bidirectional_of_rules(number_of_flows, src_port, dst_port, **kwargs):

    if config.flow_type == 'L2':
        create_ovs_bidirectional_l2_of_rules(number_of_flows, src_port, dst_port, **kwargs)
    elif config.flow_type == 'L3':
        create_ovs_bidirectional_l3_of_rules(number_of_flows, src_port, dst_port, **kwargs)
    elif config.flow_type == 'L4-UDP':
        create_ovs_bidirectional_l4_of_rules(number_of_flows, src_port, dst_port, **kwargs)
    else:
        raise ValueError("No support for this protocol!!")


#
# Add OVS OpenFlow rule from physical 2 physical, and reverse
#
def create_ovs_bidirectional_of_phy_rules(src_port, dst_port):

    lprint("  * Clear all OpenFlow/Datapath rules on bridge \"{}\"...".
           format(config.bridge_name))

    dut_shell.dut_exec('sh -c "ovs-ofctl del-flows {0}"'.\
                       format(config.bridge_name),
                       die_on_error=True)

    lprint("  * Create two OpenFlow physical to physical rules...")

    cmd = "ovs-ofctl add-flow {0} in_port={1},action={2} && " \
          "ovs-ofctl add-flow {0} in_port={2},action={1}". \
          format(config.bridge_name,
                 src_port, dst_port)
    dut_shell.dut_exec('', raw_cmd=['sh', '-c', cmd], die_on_error=True)

    lprint("  * Verify that of physical port flows exists...")

    result \
        = dut_shell.dut_exec('sh -c "ovs-ofctl dump-flows {0} | grep -v \'NXST_FLOW reply\'"'.
                             format(config.bridge_name),
                             die_on_error=True)

    if result.output.count('\n') != 2:
        lprint("ERROR: Only 2 flows should exsits, but there are {1}!".
               format(result.output.count('\n') - 1))
        sys.exit(-1)


#
# Add OVS OpenFlow rule from physical 2 physical
#
def create_ovs_of_phy_rule(src_port, dst_port, **kwargs):

    clear_rules = kwargs.pop("clear_rules", True)

    if clear_rules:
        lprint("  * Clear all OpenFlow/Datapath rules on bridge \"{}\"...".
               format(config.bridge_name))
        flush_ovs_flows()

    lprint("  * Create OpenFlow physical to physical rules...")

    cmd = "ovs-ofctl add-flow {0} in_port={1},action={2}". \
          format(config.bridge_name, src_port, dst_port)
    dut_shell.dut_exec('', raw_cmd=['sh', '-c', cmd], die_on_error=True)

    lprint("  * Verify that of physical port flows exists...")

    result \
        = dut_shell.dut_exec('sh -c "ovs-ofctl dump-flows {0} | grep -v \'NXST_FLOW reply\'"'.
                             format(config.bridge_name),
                             die_on_error=True)

    if result.output.count('\n') != 1:
        lprint("ERROR: Only 2 flows should exsits, but there are {1}!".
               format(result.output.count('\n') - 1))
        sys.exit(-1)


#
# Add OVS L2 OpenFlow rules
#
def create_ovs_l2_of_rules(number_of_flows, src_port, dst_port, **kwargs):

    total_nr_of_flows = kwargs.pop("total_number_of_flows", number_of_flows)
    clear_rules = kwargs.pop("clear_rules", True)
    mac_swap = kwargs.pop("mac_swap", False)
    base_mac = mac_2_int(config.dst_mac_address if not mac_swap
                         else config.src_mac_address) & 0xffffff000000

    if clear_rules:
        lprint("  * Clear all OpenFlow/Datapath rules on bridge \"{}\"...".
               format(config.bridge_name))
        flush_ovs_flows()

    if config.debug or config.debug_dut_shell:
        of_dump_port_to_logfile(config.bridge_name)

    lprint("  * Create {} L2 OpenFlow rules...".format(number_of_flows))

    cmd = "python -c 'for i in range({4}, {0}): " \
          "print \"add in_port={2}," \
          "dl_dst={{0:02x}}:{{1:02x}}:{{2:02x}}:{{3:02x}}:{{4:02x}}:{{5:02x}}," \
          "action={3}\".format((i >> 40) & 0xff, (i >> 32) & 0xff, (i >> 24) " \
          "& 0xff, (i >> 16) & 0xff, (i >> 8) & 0xff, i & 0xff)'" \
          " | ovs-ofctl add-flow {1} -". \
          format(number_of_flows + base_mac, config.bridge_name,
                 src_port, dst_port, base_mac)

    dut_shell.dut_exec('', raw_cmd=['sh', '-c', cmd], die_on_error=True)

    if total_nr_of_flows != 0:
        lprint("  * Verify requested number of flows exists...")

        result \
            = dut_shell.dut_exec('sh -c "ovs-ofctl dump-flows {0} | grep -v \'NXST_FLOW reply\' | wc -l"'.
                                 format(config.bridge_name),
                                 die_on_error=True)

        if int(result.stdout_output) != total_nr_of_flows:
            lprint("ERROR: Only {0} flows should exsits, but there are {1}!".
                   format(number_of_flows, int(result.stdout_output)))
            sys.exit(-1)


#
# Add OVS Bidirectional L2 OpenFlow rules
#
def create_ovs_bidirectional_l2_of_rules(number_of_flows, src_port, dst_port, **kwargs):
    create_ovs_l2_of_rules(number_of_flows,
                           src_port,
                           dst_port)

    create_ovs_l2_of_rules(number_of_flows,
                           dst_port,
                           src_port,
                           total_number_of_flows=number_of_flows * 2,
                           clear_rules=False,
                           mac_swap=config.mac_swap)


#
# Add OVS L3 OpenFlow rules
#
def create_ovs_l3_of_rules(number_of_flows, src_port, dst_port, **kwargs):

    total_nr_of_flows = kwargs.pop("total_number_of_flows", number_of_flows)
    clear_rules = kwargs.pop("clear_rules", True)
    ip_start_offset = kwargs.pop("ipv4_start", 0x01000000)

    if number_of_flows > 1000000:
        lprint("ERROR: Maximum of 1,000,000 L3 flows are supported!")
        sys.exit(-1)

    if clear_rules:
        lprint("  * Clear all OpenFlow/Datapath rules on bridge \"{}\"...".
               format(config.bridge_name))
        flush_ovs_flows()

    if config.debug or config.debug_dut_shell:
        of_dump_port_to_logfile(config.bridge_name)

    lprint("  * Create {} L3 OpenFlow rules...".format(number_of_flows))

    cmd = "python -c 'for i in range({4}, {0}): " \
          "print \"add in_port={2}," \
          "eth_type(0x800),nw_src={{}}.{{}}.{{}}.{{}},nw_dst={{}}.{{}}.{{}}.{{}}," \
          "action={3}\".format(" \
          "(i >> 24) & 0xff, (i >> 16) & 0xff," \
          "(i >> 8) & 0xff, i & 0xff," \
          "((i + 0x01000000) >> 24) & 0xff, ((i + 0x01000000) >> 16) & 0xff," \
          "((i + 0x01000000) >> 8) & 0xff, (i + 0x01000000)  & 0xff)'" \
          " | ovs-ofctl add-flow {1} -". \
          format(number_of_flows + ip_start_offset, config.bridge_name,
                 src_port, dst_port, ip_start_offset)

    dut_shell.dut_exec('', raw_cmd=['sh', '-c', cmd], die_on_error=True)

    if total_nr_of_flows != 0:
        lprint("  * Verify requested number of flows exists...")

        result \
            = dut_shell.dut_exec('sh -c "ovs-ofctl dump-flows {0} | grep -v \'NXST_FLOW reply\' | wc -l"'.
                                 format(config.bridge_name),
                                 die_on_error=True)

        if int(result.stdout_output) != total_nr_of_flows:
            lprint("ERROR: Only {0} flows should exsits, but there are {1}!".
                   format(number_of_flows, int(result.stdout_output)))
            sys.exit(-1)


#
# Add OVS Bidirectional L3 OpenFlow rules
#
def create_ovs_bidirectional_l3_of_rules(number_of_flows, src_port, dst_port, **kwargs):
    clear_rules = kwargs.pop("clear_rules", True)
    total_nr_of_flows = kwargs.pop("total_number_of_flows", number_of_flows * 2)
    ip_start_offset = kwargs.pop("ipv4_start", 0x01000000)

    create_ovs_l3_of_rules(number_of_flows,
                           src_port,
                           dst_port,
                           clear_rules=clear_rules,
                           total_number_of_flows=0,
                           ipv4_start=ip_start_offset)

    create_ovs_l3_of_rules(number_of_flows,
                           dst_port,
                           src_port,
                           clear_rules=False,
                           total_number_of_flows=total_nr_of_flows,
                           ipv4_start=ip_start_offset)


#
# Add OVS OpenFlow rules for the /16 flow ranges we create
#
def create_ovs_bidirectional_l3_of_slash_16_rules(number_of_flows,
                                                  src_port, dst_port):

    create_ovs_l3_of_slash_16_rules(number_of_flows,
                                    src_port,
                                    dst_port)

    create_ovs_l3_of_slash_16_rules(number_of_flows,
                                    dst_port,
                                    src_port,
                                    total_number_of_flows=number_of_flows * 2,
                                    clear_rules=False)


def create_ovs_l3_of_slash_16_rules(number_of_flows,
                                    src_port, dst_port,
                                    **kwargs):

    total_nr_of_flows = kwargs.pop("total_number_of_flows", number_of_flows)
    clear_rules = kwargs.pop("clear_rules", True)

    if number_of_flows > 255:
        lprint("ERROR: Maximum of 255 /16 flows are supported!")
        sys.exit(-1)

    if clear_rules:
        lprint("  * Clear all OpenFlow/Datapath rules on bridge \"{}\"...".
               format(config.bridge_name))
        flush_ovs_flows()

    if config.debug or config.debug_dut_shell:
        of_dump_port_to_logfile(config.bridge_name)

    lprint("  * Create {} L3 /16 OpenFlow rules...".format(number_of_flows))

    cmd = "python -c 'for i in range(0, {0}): " \
          "print \"add in_port={2}," \
          "eth_type(0x800),nw_src=1.{{0}}.0.0/16,nw_dst=2.{{0}}.0.0/16," \
          "action={3}\".format(i)'" \
          " | ovs-ofctl add-flow {1} -". \
          format(number_of_flows, config.bridge_name,
                 src_port, dst_port)

    dut_shell.dut_exec('', raw_cmd=['sh', '-c', cmd], die_on_error=True)

    if total_nr_of_flows != 0:
        lprint("  * Verify requested number of flows exists...")

        result \
            = dut_shell.dut_exec('sh -c "ovs-ofctl dump-flows {0} | grep -v \'NXST_FLOW reply\' | wc -l"'.
                                 format(config.bridge_name),
                                 die_on_error=True)

        if int(result.stdout_output) != total_nr_of_flows:
            lprint("ERROR: Only {0} flows should exsits, but there are {1}!".
                   format(number_of_flows, int(result.stdout_output)))
            sys.exit(-1)


#
# Add OVS L4 OpenFlow rules
#
def create_ovs_l4_of_rules(number_of_flows, src_port, dst_port, **kwargs):

    total_nr_of_flows = kwargs.pop("total_number_of_flows", number_of_flows)
    clear_rules = kwargs.pop("clear_rules", True)

    if number_of_flows > 1000000:
        lprint("ERROR: Maximum of 1,000,000 L4 flows are supported!")
        sys.exit(-1)

    if clear_rules:
        lprint("  * Clear all OpenFlow/Datapath rules on bridge \"{}\"...".
               format(config.bridge_name))

        dut_shell.dut_exec('sh -c "ovs-ofctl del-flows {0}"'.
                           format(config.bridge_name),
                           die_on_error=True)
        flush_ovs_flows()

    if config.debug or config.debug_dut_shell:
        of_dump_port_to_logfile(config.bridge_name)

    lprint("  * Create {} L4 OpenFlow rules...".format(number_of_flows))

    cmd = "python -c 'for i in range(0, {0}): " \
          "print \"add in_port={2}," \
          "udp,udp_src={{0}},udp_dst={{0}}," \
          "action={3}\".format(i)'" \
          " | ovs-ofctl add-flow {1} -". \
          format(number_of_flows, config.bridge_name,
                 src_port, dst_port)

    dut_shell.dut_exec('', raw_cmd=['sh', '-c', cmd], die_on_error=True)

    if total_nr_of_flows != 0:
        lprint("  * Verify requested number of flows exists...")

        result \
            = dut_shell.dut_exec('sh -c "ovs-ofctl dump-flows {0} | grep -v \'NXST_FLOW reply\' | wc -l"'.
                                 format(config.bridge_name),
                                 die_on_error=True)

        if int(result.stdout_output) != total_nr_of_flows:
            lprint("ERROR: Only {0} flows should exsits, but there are {1}!".
                   format(number_of_flows, int(result.stdout_output)))
            sys.exit(-1)


#
# Add OVS Bidirectional L4 OpenFlow rules
#
def create_ovs_bidirectional_l4_of_rules(number_of_flows, src_port, dst_port, **kwargs):
    create_ovs_l4_of_rules(number_of_flows,
                           src_port,
                           dst_port)

    create_ovs_l4_of_rules(number_of_flows,
                           dst_port,
                           src_port,
                           total_number_of_flows=number_of_flows * 2,
                           clear_rules=False)


#
# Add test bridge setup
#
def create_ovs_bridge():
    lprint("- Configuring bridge...")

    if "dpdk" in config.physical_interface:
        dpdk = True
    else:
        dpdk = False

    #
    # Delete bridge if existing
    #

    dut_shell.dut_exec("ovs-vsctl -- --if-exists del-br {0} "
                       "-- --if-exists del-br {1}".
                       format(config.bridge_name,
                              (config.bridge_name + "_tterm")[:15]),
                       die_on_error=True)

    #
    # Create bridge and set data path if needed
    #
    command = "ovs-vsctl add-br {0} ".format(config.bridge_name)

    if dpdk:
        command += "-- set Bridge {} datapath_type=netdev ".format(config.bridge_name)

    #
    # Add basic ports (1x ingress, and 1x egress)
    #
    command += "-- add-port {0} {1} -- set Interface {1} ofport_request=10 ". \
               format(config.bridge_name, config.physical_interface)

    if config.virtual_interface:
        command += "-- add-port {0} {1} -- set Interface {1} ofport_request=20 ". \
                   format(config.bridge_name, config.virtual_interface)

    if dpdk:
        command += "-- set Interface {0} type=dpdk " . \
                   format(config.physical_interface)

        if config.virtual_interface:
            command += "-- set Interface {0} type=dpdkvhostuser ". \
                       format(config.virtual_interface)

        if config.pmd_rxq_affinity is not None:
            command += "-- set Interface {0} options:n_rxq={1} " \
                       "other_config:pmd-rxq-affinity={2} " . \
                       format(config.physical_interface,
                              config.pmd_rxq_affinity.count(':'), config.pmd_rxq_affinity)

            if config.virtual_interface:
                command += "-- set Interface {0} options:n_rxq={1} " \
                           "other_config:pmd-rxq-affinity={2} ". \
                           format(config.virtual_interface,
                                  config.pmd_rxq_affinity.count(':'),
                                  config.pmd_rxq_affinity)


    #
    # Add second virtual ports if vv test is enabled
    #
    if not config.skip_vv_test:
        command += "-- add-port {0} {1} -- set Interface {1} ofport_request=21 ". \
                  format(config.bridge_name,
                         config.second_virtual_interface)

        if dpdk:
            command += "-- set Interface {0} type=dpdkvhostuser ". \
                        format(config.second_virtual_interface)

            if config.pmd_rxq_affinity is not None:
                command += "-- set Interface {0} options:n_rxq={1} " \
                           "other_config:pmd-rxq-affinity={2} ". \
                           format(config.second_virtual_interface,
                                  config.pmd_rxq_affinity.count(':'), config.pmd_rxq_affinity)

    #
    # Add second physical port if pp test is enabled
    #
    if config.run_pp_test:
        command += "-- add-port {0} {1} -- set Interface {1} ofport_request=11 ". \
                  format(config.bridge_name,
                         config.second_physical_interface)

        if dpdk:
            command += "-- set Interface {0} type=dpdk ". \
                  format(config.second_physical_interface)

            if config.pmd_rxq_affinity is not None:
                command += "-- set Interface {0} options:n_rxq={1} " \
                           "other_config:pmd-rxq-affinity={2} ". \
                           format(config.second_physical_interface,
                                  config.pmd_rxq_affinity.count(':'),
                                  config.pmd_rxq_affinity)

    #
    # If we are running DPDK and it's 2.7 or higher we need to specify the PCI
    # addresses for the physical ports.
    #

    if dpdk and StrictVersion(ovs_version) >= StrictVersion('2.7.0'):
        if not check_pci_address_string(config.physical_interface_pci) or \
           (config.run_pp_test and not
           check_pci_address_string(config.second_physical_interface_pci)):
            lprint("ERROR: For OVS >=2.7 you must supply a valid PCI address "
                   "for the physical interfaces!")
            sys.exit(-1)

        command += "-- set Interface {0} options:dpdk-devargs={1} ". \
                   format(config.physical_interface,
                          config.physical_interface_pci)

        if config.second_physical_interface:
            command += "-- set Interface {0} options:dpdk-devargs={1} " . \
                       format(config.second_physical_interface,
                              config.second_physical_interface_pci)

    #
    # Configure all the above!
    #
    dut_shell.dut_exec(command, die_on_error=True)

    if config.debug or config.debug_dut_shell:
        dut_shell.dut_exec("ovs-vsctl show", die_on_error=True)

    #
    # If this is DPDK, you might need to start the VM for thinks to start
    # working. So we pause here, asking for restart of the VM.
    #
    if dpdk and config.virtual_interface:
        print("!!! Finished configuring the OVS bridge, please restart the Virtual Machine !!!")
        raw_input("Press Enter to continue...")


#
# Add VXLAN test bridge setup
#
def create_ovs_vxlan_bridge():
    lprint("- Configuring bridge...")

    if "dpdk" in config.physical_interface:
        dpdk = True
    else:
        dpdk = False

    tunnel_bridge = (config.bridge_name + "_tterm")[:15]

    #
    # Delete bridge if existing
    #
    dut_shell.dut_exec("ovs-vsctl -- --if-exists del-br {0} "
                       "-- --if-exists del-br {1}".
                       format(config.bridge_name, tunnel_bridge),
                       die_on_error=True)

    #
    # Create bridge and set data path if needed
    #
    command = "ovs-vsctl add-br {0} -- add-br {1} " \
              .format(config.bridge_name, tunnel_bridge)

    if dpdk:
        command += "-- set Bridge {} datapath_type=netdev ".format(config.bridge_name)
        command += "-- set Bridge {} datapath_type=netdev ".format(tunnel_bridge)

    #
    # Add basic ports (1x ingress, and 1x egress)
    #
    command += "-- add-port {3} {1} -- set Interface {1} ofport_request=10 " \
               "-- add-port {0} {2} -- set Interface {2} ofport_request=20 " \
               "-- add-port {0} vxlan0 -- set Interface vxlan0 ofport_request=30 " \
               "-- set interface vxlan0 type=vxlan options:remote_ip=3.1.1.2 options:key=69 ". \
               format(config.bridge_name,
                      config.physical_interface,
                      config.virtual_interface,
                      tunnel_bridge)

    if dpdk:
        command += "-- set Interface {0} type=dpdk " \
                   "-- set Interface {1} type=dpdkvhostuser ". \
                   format(config.physical_interface, config.virtual_interface)

        if config.pmd_rxq_affinity is not None:
            command += "-- set Interface {0} options:n_rxq={2} " \
                       "other_config:pmd-rxq-affinity={3} " \
                       "-- set Interface {1} options:n_rxq={2} " \
                       "other_config:pmd-rxq-affinity={3} ". \
                       format(config.physical_interface, config.virtual_interface,
                              config.pmd_rxq_affinity.count(':'), config.pmd_rxq_affinity)

    #
    # If we are running DPDK and it's 2.7 or higher we need to specify the PCI
    # addresses for the physical ports.
    #

    if dpdk and StrictVersion(ovs_version) >= StrictVersion('2.7.0'):
        if not check_pci_address_string(config.physical_interface_pci) or \
           (config.run_pp_test and not
           check_pci_address_string(config.second_physical_interface_pci)):
            lprint("ERROR: For OVS >=2.7 you must supply a valid PCI address "
                   "for the physical interfaces!")
            sys.exit(-1)

        command += "-- set Interface {0} options:dpdk-devargs={1} ". \
                   format(config.physical_interface,
                          config.physical_interface_pci)

    #
    # Configure all the above!
    #
    dut_shell.dut_exec(command, die_on_error=True)

    if config.debug or config.debug_dut_shell:
        dut_shell.dut_exec("ovs-vsctl show", die_on_error=True)

    #
    # If this is DPDK, you might need to start the VM for thinks to start
    # working. So we pause here, asking for restart of the VM.
    #
    if dpdk:
        print("!!! Finished configuring the OVS bridge, please restart the Virtual Machine !!!")
        raw_input("Press Enter to continue...")


#
# Get bridge port numbers
#
def get_bridge_port_numbers(tunnel=False):
    lprint("- Get OpenFlow and DataPath port numbers...")

    of = dict()
    dp = dict()

    #
    # Get mapping from openvswitch
    #
    command = 'sh -c "ovs-ofctl show {0} && ovs-appctl dpctl/show"'.\
              format(config.bridge_name)

    if tunnel:
        tunnel_bridge = (config.bridge_name + "_tterm")[:15]
        command = 'sh -c "ovs-ofctl show {0} && ovs-ofctl show {1} && '\
                  'ovs-appctl dpctl/show"'.\
                  format(config.bridge_name, tunnel_bridge)

    result = dut_shell.dut_exec(command, die_on_error=True)

    #
    # Create list of interfaces, second interfaces are optional,
    # so check if they exist before adding.
    #
    interfaces = [config.physical_interface]
    if config.virtual_interface != '':
        interfaces.append(config.virtual_interface)

    if config.second_virtual_interface != '':
        interfaces.append(config.second_virtual_interface)

    if config.second_physical_interface != '':
        interfaces.append(config.second_physical_interface)

    if tunnel:
        interfaces.append('vxlan0')

    for interface in interfaces:
        m = re.search('\s*([0-9]*)\({0}\): addr:.*'.format(interface),
                      result.output)
        if m:
            of[interface] = m.group(1)
        else:
            lprint("ERROR: Can't figure out OpenFlow interface for {0}".
                   format(interface))
            sys.exit(-1)

        if interface == 'vxlan0':
            continue

        m = re.search('\s*port\s*([0-9]*):\s*{0}\s*.*'.format(interface),
                      result.output)
        if m:
            dp[interface] = m.group(1)
        else:
            lprint("ERROR: Can't figure out OpenFlow datapath interface for {0}"
                   .format(interface))
            sys.exit(-1)

    slogger.info("OpenFlow ports; {}".format(of))
    slogger.info("DataPath ports; {}".format(dp))

    return of, dp


#
# Get OpenFlow port packet stats
#
def get_of_port_packet_stats(of_port, **kwargs):

    bridge = kwargs.pop("bridge", config.bridge_name)
    port_stats = of_dump_port_to_logfile(bridge)

    m = re.search('\s.*port *{}: rx pkts=.*\n.*tx pkts=([0-9?]*), '.format(of_port),
                  port_stats.output)
    if m:
        if '?' in m.group(1):
            tx = int(0)
        else:
            tx = int(m.group(1))
    else:
        lprint("ERROR: Can't get transmitted packet stats for OpenFlow "
               "port {0} on brige \"{1}\"".
               format(of_port, config.bridge_name))
        sys.exit(-1)

    m = re.search('\s.*port *{}: rx pkts=.*\n.*tx pkts=.* drop=([0-9?]*), .*'.format(of_port),
                  port_stats.output)
    if m:
        if '?' in m.group(1):
            tx_drop = int(0)
        else:
            tx_drop = int(m.group(1))
    else:
        lprint("ERROR: Can't get transmitted drop stats for OpenFlow "
               "port {0} on brige \"{1}\"".
               format(of_port, config.bridge_name))
        sys.exit(-1)

    m = re.search('\s.*port *{}: rx pkts=([0-9?]*), .*'.format(of_port),
                  port_stats.output)
    if m:
        if '?' in m.group(1):
            rx = int(0)
        else:
            rx = int(m.group(1))
    else:
        lprint("ERROR: Can't get received packet stats for OpenFlow "
               "port {0} on brige \"{1}\"".
               format(of_port, config.bridge_name))
        sys.exit(-1)

    m = re.search('\s.*port *{}: rx pkts=.* drop=([0-9?]*), .*'.format(of_port),
                  port_stats.output)
    if m:
        if '?' in m.group(1):
            rx_drop = int(0)
        else:
            rx_drop = int(m.group(1))
    else:
        lprint("ERROR: Can't get received drop stats for OpenFlow port {0} on brige \"{1}\""
               .format(of_port, config.bridge_name))
        sys.exit(-1)

    slogger.debug("OF port {0} stats: tx = {1}, tx_drop = {2}, rx = {3}, tx_drop = {3}".
                  format(of_port, tx, tx_drop, rx, rx_drop))

    return tx, tx_drop, rx, rx_drop


#
# Convert a MAC address string to an integer
#
def mac_2_int(mac_str):
    return int(mac_str.replace(":", ""), 16)


#
# Check tester interface number string
#
def tester_interface_valid(interface):

    if config.tester_type == 'xena':
        xport = interface.split(',')
        if len(xport) != 2:
            return False
    else:
        xport = interface

    for number in xport:
        try:
            if int(number) < 0:
                return False

        except ValueError:
            return False

    return True


#
# Create a single graph
#
def create_single_graph(x, y, x_label, y_label, title,
                        file_name, phy_speed, **kwargs):

    cpu_util = kwargs.pop("cpu_utilization", None)
    show_idle_cpu = kwargs.pop("show_cpu_idle", False)

    slogger.info("create_single_graph[{}], x = {} : y = {}".
                 format(title, x, y))

    if cpu_util is None:
        fig, pps = plt.subplots()
        pps_plot = pps
    else:
        fig, pps = plt.subplots(2)
        pps_plot = pps[0]

        fig.set_figwidth(2 * fig.get_figwidth(), forward=True)
        fig.set_figheight(2 * fig.get_figheight(), forward=True)

    #
    # Main graph showing utilization
    #

    pps_plot.set_title(title)
    pps_plot.set_xlabel(x_label)
    pps_plot.set_ylabel(y_label)
    pps_plot.grid(True)
    pps_plot.autoscale(enable=True, axis='both', tight=False)
    pps_plot.plot(x, y, 'o-', label='average')
    pps_plot.ticklabel_format(axis='y', style='plain')
    pps_plot.grid(b=True, which='minor', color='k', linestyle=':', alpha=0.2)
    pps_plot.minorticks_on()

    #
    # Add second scaled graph showing line utilization
    #

    if phy_speed > 0:
        util_y = list()

        for i in range(0, len(x)):
            util_y.append(eth_utilization(phy_speed,
                                          x[i], y[i]))

        util = pps_plot.twinx()
        util.plot(x, util_y, '.:', color='r')
        util.set_ylim(0, 100)
        util.set_ylabel('Link Utilization in % ({} Gbit/s)'.
                        format(phy_speed / 1000000000), color='r')
        util.tick_params('y', colors='r')

    #
    # Adding CPU utilization if requested
    #
    if cpu_util is not None:

        cpu_plot = pps[1]
        x_cpu = np.arange(len(x))
        bar_width = 0.20

        ovs_y_values = list()
        usr_y_values = list()
        nice_y_values = list()
        sys_y_values = list()
        iowait_y_values = list()
        irq_y_values = list()
        soft_y_values = list()
        steal_y_values = list()
        guest_y_values = list()
        gnice_y_values = list()
        idle_y_values = list()
        for i in range(0, len(x)):
            ovs_y_values.append(cpu_util[i]['ovs_cpu'])
            usr_y_values.append(cpu_util[i]['sys_usr'])
            nice_y_values.append(cpu_util[i]['sys_nice'])
            sys_y_values.append(cpu_util[i]['sys_sys'])
            iowait_y_values.append(cpu_util[i]['sys_iowait'])
            irq_y_values.append(cpu_util[i]['sys_irq'])
            soft_y_values.append(cpu_util[i]['sys_soft'])
            steal_y_values.append(cpu_util[i]['sys_steal'])
            guest_y_values.append(cpu_util[i]['sys_guest'])
            gnice_y_values.append(cpu_util[i]['sys_gnice'])
            idle_y_values.append(cpu_util[i]['sys_idle'])

        y_cpu_values = [usr_y_values, nice_y_values, sys_y_values,
                        iowait_y_values, irq_y_values, soft_y_values,
                        steal_y_values, guest_y_values, gnice_y_values,
                        idle_y_values]
        y_cpu_colors = ['#1f77b4', '#aec7e8', '#ff7f0e', '#ffbb78', '#2ca02c',
                        '#98df8a', '#d62728', '#ff9896', '#9467bd', '#c5b0d5']
        y_cpu_labels = ['usr', 'nice', 'sys', 'iowait', 'irq',
                        'soft', 'steal', 'guest', 'gnice', 'idle']

        cpu_plot.bar(x_cpu, ovs_y_values, bar_width, label='OVS',
                     color='b', edgecolor='b')

        bottom = [0] * len(x)
        for i in range(0, len(y_cpu_values) - (1, 0)[show_idle_cpu]):
            cpu_plot.bar(x_cpu + bar_width, y_cpu_values[i], bar_width,
                         color=y_cpu_colors[i], edgecolor=y_cpu_colors[i],
                         bottom=bottom, label=y_cpu_labels[i])
            bottom = [a + b for a, b in zip(bottom, y_cpu_values[i])]

        if show_idle_cpu:
            total_util = bottom[0]
        else:
            total_util = bottom[0] + y_cpu_values[i+1][0]

        cpu_plot.set_title("Open vSwitch, and system CPU usage (max {:.0f}%)".
                           format(total_util))
        cpu_plot.set_xticks(x_cpu + bar_width)
        cpu_plot.set_xticklabels(x)
        cpu_plot.set_ylabel("CPU utilization")
        cpu_plot.set_xlabel(x_label)
        cpu_plot.grid(b=True, which='major')
        cpu_plot.grid(b=True, which='minor', color='k', linestyle=':', alpha=0.2)
        cpu_plot.minorticks_on()
        cpu_plot.legend(loc='center left', bbox_to_anchor=(1, 0.5))

    #
    # Due to bug in matplotlib we need to disable some np errors
    #
    old_np_seterr = np.seterr(divide='ignore', invalid='ignore')

    #
    # Final tweaking
    #
    fig.tight_layout()
    if cpu_util is not None:
        box = cpu_plot.get_position()
        cpu_plot.set_position([box.x0, box.y0, box.width * 0.9, box.height])

    #
    # Write picture
    #

    if file_name is not None and file_name != "":
        plt.savefig(file_name + '.png')

    #
    # Show picture if requested, and clear the graph
    #
    if config.gui:
        plt.show()

    plt.close()

    np.seterr(**old_np_seterr)


#
# Single graph with multiple results
#
def create_multiple_graph(x, y, x_label, y_label,
                          title, file_name, phy_speed, **kwargs):

    fixed_packet_size = kwargs.pop("fixed_packet_size", None)
    cpu_util = kwargs.pop("cpu_utilization", None)
    show_idle_cpu = kwargs.pop("show_cpu_idle", True)

    slogger.info("create_multiple_graph[{}], x = {} : y = {}".
                 format(title, x, y))

    if cpu_util is None:
        fig, pps = plt.subplots()
        pps_plot = pps
    else:
        fig = plt.figure()
        #
        # This split looked nice, until we used all packets sizes,
        # and multiple flows
        #
        # pps_plot = plt.subplot2grid((2, 2), (0, 0), colspan=2)
        # cpu_plot = plt.subplot2grid((2, 2), (1, 0))
        # sys_plot = plt.subplot2grid((2, 2), (1, 1))
        # fig.set_figwidth(2 * fig.get_figwidth(), forward = True)
        # fig.set_figheight(2 * fig.get_figheight(), forward = True)

        pps_plot = plt.subplot2grid((3, 2), (0, 0), colspan=2)
        cpu_plot = plt.subplot2grid((3, 2), (1, 0), colspan=2)
        sys_plot = plt.subplot2grid((3, 2), (2, 0), colspan=2)

        fig.set_figwidth(2 * fig.get_figwidth(), forward=True)
        fig.set_figheight(3 * fig.get_figheight(), forward=True)

    #
    # Main graph showing utilization
    #
    pps_plot.set_title(title)
    pps_plot.set_xlabel(x_label)
    pps_plot.set_ylabel(y_label)
    pps_plot.grid(True)
    pps_plot.autoscale(enable=True, axis='both', tight=False)
    pps_plot.ticklabel_format(axis='y', style='plain')
    pps_plot.grid(b=True, which='minor', color='k', linestyle=':', alpha=0.2)
    pps_plot.minorticks_on()

    for y_run in natsorted(list(y.keys())):
        pps_plot.plot(x, y[y_run], 'o-', label="{}".format(y_run))

    #
    # Add maximum PPS for the given physical speed
    #
    if phy_speed is not None:
        for speed in phy_speed:
            y_values = list()
            for x_val in x:
                if fixed_packet_size is None:
                    y_values.append(eth_max_pps(speed, x_val))
                else:
                    y_values.append(eth_max_pps(speed, fixed_packet_size))

            pps_plot.plot(x, y_values, '.:', label="Max PPS {}G".
                          format(speed / 1000000000))

    pps_plot.legend(loc='upper right', shadow=True)

    #
    # Add CPU util information if given
    #
    if cpu_util is not None:
        #
        # OVS CPU utilization
        #
        x_cpu = np.arange(len(x))
        bar_width = 0.11
        cpu_plot.set_title("Open vSwitch CPU utilization")

        ovs_y_values = dict(list(zip(list(cpu_util.keys()),
                                     [[] for i in range(len(cpu_util))])))

        for i in range(0, len(x)):
            for key in list(cpu_util.keys()):
                ovs_y_values[key].append(cpu_util[key][i]['ovs_cpu'])

        if len(cpu_util) % 2 != 0:
            align = 'center'
        else:
            align = 'edge'

        for i, key in enumerate(natsorted(list(cpu_util.keys()))):
            colors = plt.rcParams["axes.prop_cycle"].by_key()["color"]
            x_pos = (x_cpu - (len(cpu_util) / 2 * bar_width)) + (i * bar_width)
            cpu_plot.bar(x_pos, ovs_y_values[key], bar_width, align=align,
                         color=colors[i % len(colors)], edgecolor="none")

        cpu_plot.set_xlim(0 - (len(cpu_util) * bar_width),
                          len(x_cpu) - 1 + (len(cpu_util) * bar_width))
        cpu_plot.set_xticks(x_cpu)
        cpu_plot.set_xticklabels(x, ha='center')
        cpu_plot.set_ylabel("CPU utilization")
        cpu_plot.set_xlabel(x_label)
        cpu_plot.grid(b=True, which='major')
        cpu_plot.grid(b=True, which='minor', color='k', linestyle=':', alpha=0.2)
        cpu_plot.minorticks_on()

        #
        # System CPU utilization
        #
        sys_plot.set_title("Total System CPU utilization")

        usr_y_values = dict(list(zip(list(cpu_util.keys()),
                                     [[] for i in range(len(cpu_util))])))
        nice_y_values = dict(list(zip(list(cpu_util.keys()),
                                      [[] for i in range(len(cpu_util))])))
        sys_y_values = dict(list(zip(list(cpu_util.keys()),
                                     [[] for i in range(len(cpu_util))])))
        iowait_y_values = dict(list(zip(list(cpu_util.keys()),
                                        [[] for i in range(len(cpu_util))])))
        irq_y_values = dict(list(zip(list(cpu_util.keys()),
                                     [[] for i in range(len(cpu_util))])))
        soft_y_values = dict(list(zip(list(cpu_util.keys()),
                                      [[] for i in range(len(cpu_util))])))
        steal_y_values = dict(list(zip(list(cpu_util.keys()),
                                       [[] for i in range(len(cpu_util))])))
        guest_y_values = dict(list(zip(list(cpu_util.keys()),
                                       [[] for i in range(len(cpu_util))])))
        gnice_y_values = dict(list(zip(list(cpu_util.keys()),
                                       [[] for i in range(len(cpu_util))])))
        idle_y_values = dict(list(zip(list(cpu_util.keys()),
                                      [[] for i in range(len(cpu_util))])))

        y_cpu_values = [usr_y_values, nice_y_values, sys_y_values,
                        iowait_y_values, irq_y_values, soft_y_values,
                        steal_y_values, guest_y_values, gnice_y_values,
                        idle_y_values]
        y_cpu_labels = ['usr', 'nice', 'sys', 'iowait', 'irq',
                        'soft', 'steal', 'guest', 'gnice', 'idle']
        y_cpu_keys = ['sys_usr', 'sys_nice', 'sys_sys', 'sys_iowait', 'sys_irq',
                      'sys_soft', 'sys_steal', 'sys_guest', 'sys_gnice', 'sys_idle']
        y_cpu_colors = ['#1f77b4', '#aec7e8', '#ff7f0e', '#ffbb78', '#2ca02c',
                        '#98df8a', '#d62728', '#ff9896', '#9467bd', '#c5b0d5']

        for i in range(0, len(x)):
            for key in list(cpu_util.keys()):
                for j, y_cpu_value in enumerate(y_cpu_values):
                    y_cpu_value[key].append(cpu_util[key][i][y_cpu_keys[j]])

        if len(cpu_util) % 2 != 0:
            align = 'center'
        else:
            align = 'edge'

        for i, key in enumerate(natsorted(list(cpu_util.keys()))):
            x_pos = (x_cpu - (len(cpu_util) / 2 * bar_width)) + (i * bar_width)

            bottom = [0] * len(x)
            for j in range(0, len(y_cpu_values) - (1, 0)[show_idle_cpu]):

                sys_plot.bar(x_pos, y_cpu_values[j][key], bar_width, align=align,
                             color=y_cpu_colors[j],
                             label=y_cpu_labels[j] if i == 0 else "",
                             bottom=bottom)
                bottom = [a + b for a, b in zip(bottom, y_cpu_values[j][key])]

        sys_plot.set_xlim(0 - (len(cpu_util) * bar_width),
                          len(x_cpu) - 1 + (len(cpu_util) * bar_width))
        sys_plot.set_xticks(x_cpu)
        sys_plot.set_xticklabels(x, ha='center')
        sys_plot.set_ylabel("CPU utilization")
        sys_plot.set_xlabel(x_label)
        sys_plot.grid(b=True, which='major')
        sys_plot.grid(b=True, which='minor', color='k', linestyle=':', alpha=0.2)
        sys_plot.minorticks_on()

        handles, labels = sys_plot.get_legend_handles_labels()
        sys_plot.legend(list(reversed(handles)),
                        list(reversed(labels)),
                        loc='center left', bbox_to_anchor=(1, 0.5))

    #
    # Due to bug in matplotlib we need to disable some np errors
    #
    old_np_seterr = np.seterr(divide='ignore', invalid='ignore')

    #
    # Final tweaking
    #
    fig.tight_layout()
    if cpu_util is not None:
        box = sys_plot.get_position()
        sys_plot.set_position([box.x0, box.y0, box.width * 0.90, box.height])

    #
    # Write picture
    #
    if file_name is not None and file_name != "":
        plt.savefig(file_name + '.png')

    #
    # Show picture if requested, and clear the graph
    #
    if config.gui:
        plt.show()

    plt.close()

    np.seterr(**old_np_seterr)


#
# Try to get phy speed from physical port
#
def get_physical_port_speed():
    speed = 10000000000

    result = dut_shell.dut_exec("ethtool {}".format(config.physical_interface))

    m = re.search('\s*Speed: ([0-9]*)Mb.*', result.output)
    if m:
        speed = int(m.group(1)) * 1000000
    else:
        slogger.info("Can't determine physical interface \"{0}\" its speed!".
                     format(config.physical_interface))

    slogger.info("Set physical interface \"{0}\" speed to {1} bits/second".
                 format(config.physical_interface, speed))

    return speed


#
# Calculate wire utilization based on packet size and packets per seconds
#
# Packet size = 12 bytes IFG +
#                8 bytes preamble +
#                x bytes packet +
#                4 bytes CRC
#
def eth_utilization(line_speed_bps, packet_size, packets_per_second):

    packet_size_bits = (12 + 8 + packet_size + 4) * 8
    packet_speed_second = packet_size_bits * packets_per_second

    util = int(float(packet_speed_second) / line_speed_bps * 100)

    if util > 100:
        util = 100

    return util


#
# Calculate max packets per second base on packet size and wire speed
#
def eth_max_pps(line_speed_bps, packet_size):
    packet_size_bits = (12 + 8 + packet_size + 4) * 8

    return line_speed_bps / packet_size_bits


#
# Print results in CSV
#
def csv_write_test_results(csv_handle, test_name, flow_size_list,
                           packet_size_list, test_results, cpu_results):

    if config.flow_type == 'L2':
        flow_type = ", L2 flows"
    elif config.flow_type == 'L3':
        flow_type = ", L3 flows"
    elif config.flow_type == 'L4-UDP':
        flow_type = ", L4-udp flows"
    else:
        raise ValueError("No support for this protocol!!")

    csv_handle.writerow([test_name + flow_type])

    if len(test_results) > 0:
        csv_handle.writerow(['', 'Packet size'])
        csv_handle.writerow(['Number of flows'] + packet_size_list)
        for flow in flow_size_list:
            results = [flow]
            for i in range(0, len(packet_size_list)):
                results.append(test_results[flow][i])

            csv_handle.writerow(results)

            results = ["cpu_{}".format(flow)]
            for i in range(0, len(packet_size_list)):
                results.append(cpu_results[flow][i])

            csv_handle.writerow(results)

        for i in range(0, 4):
            csv_handle.writerow([])


#
# Check a string of list entries, and make sure they are valid number,
# and are in order.
#
def check_list(list_string, min_val, max_val):

    last_entry = 0
    list = list_string.split(',')

    if len(list) == 0:
        return False

    for entry in list:
        try:
            value = int(entry)
        except ValueError:
            return False

        if value < min_val or value > max_val or last_entry >= value:
            return False

        last_entry = value

    return True


#
# Check the string to be a valid PCI address in the format "0000:02:00.0".
# In addition we also allow the ",txq_inline=" option needed for some vendors,
# as a workaround for L3 forwarding to work.
#
def check_pci_address_string(pci_address):
    if pci_address is None:
        return False

    if re.match("^\d{4}:\d{2}:[0-9A-Fa-f]{2}\.\d{1}$", pci_address) is None and \
       re.match("^\d{4}:\d{2}:[0-9A-Fa-f]{2}\.\d{1},txq_inline=\d+$", pci_address) is None:
        return False

    return True


#
# Mimic the normal print command, but also send the same output
# put on the console to the log file. But only if the log file option
# is enabled else we end up with the same text on the console twice.
#
def lprint(msg):
    print (msg)
    if config.logging is not None:
        slogger.info(msg)


#
# Start Perf recording on DUT
#
def start_perf_recording(test_name):
    if not config.perf:
        return

    perf_path = "/root/ovs_test_perf_data/run_{}".format(run_start_time)
    perf_file = "{}/{}.perf".format(perf_path, test_name)
    cmd = r"mkdir -p {0}; " \
          r"nohup perf record -o '{1}' -g -p `pidof ovs-vswitchd` &> /dev/null &". \
          format(perf_path, perf_file)

    lprint("  * Start perf recording on DUT ({})...".format(perf_file))
    dut_shell.dut_exec('', raw_cmd=['sh', '-c', cmd], die_on_error=True)


#
# Stop Perf recording on DUT
#
def stop_perf_recording():
    if not config.perf:
        return

    lprint("  * Stop perf recording on DUT...")

    cmd = r"kill -s INT `pidof perf`"
    dut_shell.dut_exec('', raw_cmd=['sh', '-c', cmd], die_on_error=True)

#
# Start CPU monitoring on DUT
#
def start_cpu_monitoring():
    #
    # pidstat -u -t -p `pidof ovs-vswitchd`,`pidof ovsdb-server` 1
    # PIDSTAT for all qemu?
    # mpstat -P ALL 1
    # kill -SIGINT `pidof pidstat`

    cmd = r"rm -f /var/tmp/cpu_ovs.txt /var/tmp/cpu_mpstat.txt; " \
          r"nohup pidstat -u -t -p `pidof ovs-vswitchd`,`pidof ovsdb-server` 1 > /var/tmp/cpu_ovs.txt 2> /dev/null & " \
          r"nohup mpstat -P ALL 1 > /var/tmp/cpu_mpstat.txt 2> /dev/null &"
    dut_shell.dut_exec('', raw_cmd=['sh', '-c', cmd], die_on_error=True)


#
# Stop CPU monitoring on DUT
#
def stop_cpu_monitoring(**kwargs):
    die = kwargs.pop("die", True)
    cmd = r"kill -s INT `pidof pidstat`; " \
          r"kill -s INT `pidof mpstat`"

    dut_shell.dut_exec('', raw_cmd=['sh', '-c', cmd], die_on_error=die)


#
# Get CPU monitoring stats
#
def get_cpu_monitoring_stats():

    cmd = r"cat /var/tmp/cpu_ovs.txt"
    results = dut_shell.dut_exec('', raw_cmd=['sh', '-c', cmd], die_on_error=True)

    #                    Average:   0        -   6982     0.00       0.05       0.00        0.05     -  |__ovs-vswitchd
    regex = re.compile("^Average:\s+[0-9]+\s+-\s+[0-9]+\s+[0-9\.]+\s+[0-9\.]+\s+[0-9\.]+\s+([0-9\.]+).+", re.MULTILINE)
    ovs_cpu_usage = float(0)
    for match in regex.finditer(results.stdout_output):
        ovs_cpu_usage += float(match.group(1))

    cmd = r"cat /var/tmp/cpu_mpstat.txt"
    results = dut_shell.dut_exec('', raw_cmd=['sh', '-c', cmd], die_on_error=True)
    cpu_raw_stats = results.stdout_output

    cpu_usr = float(0)
    cpu_nice = float(0)
    cpu_sys = float(0)
    cpu_iowait = float(0)
    cpu_irq = float(0)
    cpu_soft = float(0)
    cpu_steal = float(0)
    cpu_guest = float(0)
    cpu_gnice = float(0)
    cpu_idle = float(0)
    #  %usr   %nice    %sys %iowait    %irq   %soft  %steal  %guest  %gnice   %idle
    regex = re.compile("^Average:\s+[0-9]+\s+([0-9\.]+)\s+([0-9\.]+)\s+([0-9\.]+)\s+([0-9\.]+)\s+([0-9\.]+)\s+([0-9\.]+)\s+([0-9\.]+)\s+([0-9\.]+)\s+([0-9\.]+)\s+([0-9\.]+)$",
                       re.MULTILINE)
    for match in regex.finditer(results.stdout_output):
        cpu_usr += float(match.group(1))
        cpu_nice += float(match.group(2))
        cpu_sys += float(match.group(3))
        cpu_iowait += float(match.group(4))
        cpu_irq += float(match.group(5))
        cpu_soft += float(match.group(6))
        cpu_steal += float(match.group(7))
        cpu_guest += float(match.group(8))
        cpu_gnice += float(match.group(9))
        cpu_idle += float(match.group(10))

    cpu_total = int(cpu_usr + cpu_nice + cpu_sys + cpu_iowait +
                    cpu_irq + cpu_soft + cpu_steal + cpu_guest +
                    cpu_gnice + cpu_idle)

    cpu_results = dict([('ovs_cpu', ovs_cpu_usage),
                        ('sys_usr', cpu_usr),
                        ('sys_nice', cpu_nice),
                        ('sys_sys', cpu_sys),
                        ('sys_iowait', cpu_iowait),
                        ('sys_irq', cpu_irq),
                        ('sys_soft', cpu_soft),
                        ('sys_steal', cpu_steal),
                        ('sys_guest', cpu_guest),
                        ('sys_gnice', cpu_gnice),
                        ('sys_idle', cpu_idle),
                        ('sys_total', cpu_total)])

    slogger.debug("CPU results: {}".format(cpu_results))
    return cpu_results


#
# Get ovs version
#
def get_ovs_version():
    result = dut_shell.dut_exec('sh -c "ovs-vswitchd --version"'.
                                format(config.bridge_name),
                                die_on_error=True)

    m = re.search('.*([0-9]+.[0-9]+.[0-9]+).*',
                  str(result.output))
    if m:
        return str(m.group(1))

    lprint("ERROR: Can't figure out ovs-vswitchd's version!")
    sys.exit(-1)


#
# Get VM DPDK version
#
def get_vm_dpdk_version(vm):

    cmd = r"sshpass -p {2} ssh -o UserKnownHostsFile=/dev/null " \
          r"-o StrictHostKeyChecking=no -n {1}@{0} " \
          r"'testpmd -v | grep \"EAL: RTE Version\"'". \
          format(vm, config.dut_vm_user, config.dut_vm_password)

    result = dut_shell.dut_exec('', raw_cmd=['sh', '-c', cmd],
                                die_on_error=False)

    m = re.search('.*DPDK ([0-9]+\.[0-9]+\.[0-9]+).*',
                  result.output)
    if m:
        return str(m.group(1))

    lprint("ERROR: Can't figure out VMs DPDK version!")
    sys.exit(-1)


#
# Get ovs data path type
#
def get_ovs_datapath():
    result = dut_shell.dut_exec('sh -c "ovs-appctl dpif/show"',
                                die_on_error=True)
    output = result.output.replace("\n", "")
    m = re.search('(.+@.*{}):.*'.format(config.bridge_name),
                  output)
    if m:
        m = re.search('(.+)@.*'.format(config.bridge_name),
                      m.group(1))

        return m.group(1)

    lprint("ERROR: Can't figure out ovs datapath!")
    sys.exit(-1)


#
# Get bridge MAC address
#
def get_of_bridge_mac_address(bridge):
    command = 'sh -c "ovs-ofctl show {0}"'.format(bridge)
    result = dut_shell.dut_exec(command, die_on_error=True)

    m = re.search('\s*LOCAL\({0}\): addr:(.*)'.format(bridge),
                  result.output)
    if not m:
        lprint("ERROR: Can't figure out MAC address for bridge \"{}\"".
               format(bridge))
        sys.exit(-1)

    slogger.debug("MAC address for bridge \"{}\" is {}".format(bridge,
                                                               m.group(1)))
    return m.group(1)


#
# Flow type definitions
#
flow_types = ['L2', 'L3', 'L4-UDP']


def get_flow_type_short():
    labels = dict(list(zip(flow_types,
                           ['L2', 'L3', 'L4-UDP'])))
    return labels[config.flow_type]


def get_flow_type_name():
    labels = dict(list(zip(flow_types,
                           ['l2', 'l3', 'l4_udp'])))
    return labels[config.flow_type]


def get_traffic_generator_flow():
    flow_type = dict(list(zip(flow_types,
                              [TrafficFlowType.l2_mac,
                               TrafficFlowType.l3_ipv4,
                               TrafficFlowType.l4_udp])))
    return flow_type[config.flow_type]


#
# Traffic tester type definitions
#
traffic_tester_types = ['xena', 'trex']


def get_traffic_generator_type():
    traffic_generator_type = dict(list(zip(traffic_tester_types,
                                           [TrafficGeneratorType.xena,
                                            TrafficGeneratorType.trex])))

    return traffic_generator_type[config.tester_type]


#
# main()
#
def main():
    #
    # Not the best way to share all of this, but will work for this
    # small test script
    #
    global config
    global plt
    global dut_shell
    global slogger
    global of_interfaces
    global ovs_data_path
    global dp_interfaces
    global tester
    global phy_speed
    global ovs_version
    global vm_dpdk_version
    global run_start_time

    run_start_time = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')

    #
    # Command line argument parsing
    #
    parser = argparse.ArgumentParser()

    parser.add_argument("--bridge-name", metavar="BRIDGE",
                        help="Bridge name to use for testing", type=str,
                        default=DEFAULT_BRIDGE_NAME)
    parser.add_argument("-d", "--debug",
                        help="Enable debugging", action="store_true")
    parser.add_argument("--debug-dut-shell",
                        help="Enable DUT shell debugging", action="store_true")
    parser.add_argument("--debug-scapy",
                        help="Enable scapy debugging", action="store_true")
    parser.add_argument("--debug-script",
                        help="Enable script debugging", action="store_true")
    parser.add_argument("--debug-tester",
                        help="Enable tester debugging", action="store_true")
    parser.add_argument("--pmd-rxq-affinity", metavar="AFINITY",
                        help="Set pmd-rxq-affinity when script configures bridges", type=str)
    parser.add_argument("--dut-vm-address", metavar="ADDRESS",
                        help="IP address of VM running on OpenVSwitch DUT", type=str,
                        default=DEFAULT_DUT_VM_ADDRESS)
    parser.add_argument("--dut-vm-nic-pci", metavar="PCI",
                        help="PCI address of VMs virtual NIC", type=str,
                        default=DEFAULT_DUT_VM_NIC_PCI_ADDRESS)
    parser.add_argument("--dut-vm-user", metavar="USER",
                        help="User name of VM running on OpenVSwitch DUT", type=str,
                        default=DEFAULT_DUT_VM_LOGIN_USER)
    parser.add_argument("--dut-vm-password", metavar="PASSWORD",
                        help="User name of VM running on OpenVSwitch DUT", type=str,
                        default=DEFAULT_DUT_VM_LOGIN_PASSWORD)
    parser.add_argument("--dut-vm-nic-queues", metavar="QUEUES",
                        help="Number of VM nic queues (and cores) to allocate, default 1",
                        type=int, default=1)
    parser.add_argument("--dut-vm-nic-rxd", metavar="DESCRIPTORS",
                        help="Number of VM nic receive descriptors, default 4096",
                        type=int, default=4096)
    parser.add_argument("--dut-vm-nic-txd", metavar="DESCRIPTORS",
                        help="Number of VM nic transmit descriptors, default 1024",
                        type=int, default=1024)
    # Removed VV test for now, as it needs non-upstream trafgen tool
    #parser.add_argument("--dut-second-vm-address", metavar="ADDRESS",
    #                    help="IP address of second VM running on OpenVSwitch DUT", type=str,
    #                    default=DEFAULT_DUT_SECOND_VM_ADDRESS)
    #parser.add_argument("--dut-second-vm-nic-pci", metavar="PCI",
    #                    help="PCI address of VMs virtual NIC", type=str,
    #                    default=DEFAULT_DUT_VM_NIC_PCI_ADDRESS)
    parser.add_argument("--flow-type",
                        help="Flow type used for the tests, default L3",
                        choices=flow_types, default='L3')
    parser.add_argument("-g", "--gui",
                        help="Show graph GUI", action="store_true")
    parser.add_argument("--no-bridge-config",
                        help="Do not configure OVS", action="store_true")
    parser.add_argument("-o", "--ovs-address", metavar="ADDRESS",
                        help="IP address of OpenVSwitch DUT", type=str,
                        default=DEFAULT_DUT_ADDRESS)
    parser.add_argument("--ovs-user", metavar="USER",
                        help="User name of OpenVSwitch DUT", type=str,
                        default=DEFAULT_DUT_LOGIN_USER)
    parser.add_argument("--ovs-password", metavar="PASSWORD",
                        help="User name of OpenVSwitch DUT", type=str,
                        default=DEFAULT_DUT_LOGIN_PASSWORD)
    parser.add_argument("-p", "--physical-interface", metavar="DEVICE",
                        help="Physical interface", type=str,
                        default=DEFAULT_PHYSICAL_INTERFACE)
    parser.add_argument("--perf",
                        help="Enable perf profiling", action="store_true")
    parser.add_argument("--physical-interface-pci", metavar="PCI",
                        help="Physical interface's PCI address", type=str)
    parser.add_argument("--second-physical-interface", metavar="DEVICE",
                        help="Second Physical interface", type=str,
                        default=DEFAULT_SECOND_PHYSICAL_INTERFACE)
    parser.add_argument("--second-physical-interface-pci", metavar="PCI",
                        help="Second Physical interface", type=str)
    parser.add_argument("--physical-speed", metavar="GBPS",
                        help="Physical interface speed in Gbit/s", type=int,
                        default=0)
    parser.add_argument("--packet-list", metavar="LIST",
                        help="List of packet sizes to test", type=str,
                        default=DEFAULT_PACKET_LIST)
    parser.add_argument("-r", "--run-time", metavar="SECONDS",
                        help="Traffic run time per test", type=int,
                        default=DEFAULT_RUN_TIME)
    parser.add_argument("--run-pp-test",
                        help="Run the P to P test", action="store_true")
    # Disable VXLAN for now due to it being incomplete
    #parser.add_argument("--run-vxlan-test",
    #                    help="Run the VXLAN tunnel test", action="store_true")
    parser.add_argument("--skip-pv-test",
                        help="Do not run the P to V test", action="store_true")
    parser.add_argument("--skip-pvp-test",
                        help="Do not run the P to V to P test", action="store_true")
    # Removed VV test for now, as it needs non-upstream trafgen tool
    # parser.add_argument("--skip-vv-test",
    #                     help="Do not run the V to V test", action="store_true")
    parser.add_argument("--stream-list", metavar="LIST",
                        help="List of stream sizes to test", type=str,
                        default=DEFAULT_STREAM_LIST)
    parser.add_argument("--warm-up",
                        help="Do flow warm-up round before tests", action="store_true")
    parser.add_argument("--warm-up-timeout", metavar="SECONDS",
                        help="Warm up timeout", type=int,
                        default=DEFAULT_WARM_UP_TIMEOUT)
    parser.add_argument("--warm-up-no-fail",
                        help="Continue running the test even if warm up times out", action="store_true")
    parser.add_argument("--no-cool-down",
                        help="Do not wait for datapath flows to be cleared", action="store_true")
    parser.add_argument("-v", "--virtual-interface", metavar="DEVICE",
                        help="Virtual interface", type=str,
                        default=DEFAULT_VIRTUAL_INTERFACE)
    # Removed VV test for now, as it needs non-upstream trafgen tool
    #parser.add_argument("-w", "--second-virtual-interface", metavar="DEVICE",
    #                    help="Virtual interface for second VM", type=str,
    #                    default=DEFAULT_SECOND_VIRTUAL_INTERFACE)
    parser.add_argument("-x", "--tester-address", metavar="ADDRESS",
                        help="IP address of network tester", type=str,
                        default=DEFAULT_TESTER_SERVER_ADDRESS)
    parser.add_argument("--tester-type",
                        help="Traffic tester type to use, default \"xena\"",
                        choices=traffic_tester_types,
                        default=DEFAULT_TESTER_TYPE)
    parser.add_argument("-i", "--tester-interface", metavar="{MOD,}PORT",
                        help="Tester interface", type=str,
                        default=DEFAULT_TESTER_INTERFACE)
    parser.add_argument("--second-tester-interface", metavar="{MOD,}PORT",
                        help="Second tester interface", type=str,
                        default=DEFAULT_SECOND_TESTER_INTERFACE)
    parser.add_argument("-l", "--logging", metavar="FILE",
                        help="Redirecting log output to file", type=str)
    parser.add_argument("--dst-mac-address",
                        help="Destination Base MAC address",
                        type=str, default=DEFAULT_DST_MAC_ADDRESS)
    parser.add_argument("--src-mac-address",
                        help="Source Base MAC address",
                        type=str, default=DEFAULT_SRC_MAC_ADDRESS)
    parser.add_argument("--mac-swap",
                        help="Swap source/destination mac at VM",
                        action="store_true")

    config = parser.parse_args()

    #
    # Removed VV test for now, as it needs non-upstream trafgen tool
    #
    config.skip_vv_test = True
    config.dut_second_vm_address = DEFAULT_DUT_SECOND_VM_ADDRESS
    config.dut_second_vm_nic_pci = DEFAULT_DUT_VM_NIC_PCI_ADDRESS
    config.second_virtual_interface = DEFAULT_SECOND_VIRTUAL_INTERFACE

    #
    # Disable VXLAN for now due to it being incomplete
    #
    config.run_vxlan_test = False

    #
    # Setting up the logger
    #
    logging.basicConfig(format='%(asctime)s[%(levelname)-8.8s][%(name)s]: %(message)s',
                        datefmt='%H:%M:%S',
                        level=logging.ERROR,
                        filename=config.logging)

    slogger = logging.getLogger('script')
    slogger.setLevel(logging.INFO)

    slogger.info("**********************************************************************")
    slogger.info("** Starting \"%s\"", os.path.basename(__file__))
    slogger.info("**********************************************************************")

    #
    # Check some input parameters
    #
    if config.ovs_address == '':
        lprint("ERROR: You must supply the OVS host address to use for testing!")
        sys.exit(-1)

    if (not config.skip_vv_test or not config.skip_pv_test or \
       not config.skip_pvp_test ) and config.dut_vm_address == '':
        lprint("ERROR: You must supply the DUT VM host address to use for testing!")
        sys.exit(-1)

    if config.dst_mac_address == '':
        lprint("ERROR: You must supply a Destination Base MAC Address")
        sys.exit(-1)

    if config.src_mac_address == '':
        lprint("ERROR: You must supply a Source Base MAC Address")
        sys.exit(-1)

    if config.flow_type == 'L2':
        if (int(config.src_mac_address.replace(":", ""), 16) & 0xffffff) \
           != 0:
            lprint("ERROR: For L2 tests the Source Base MAC address must "
                   "be xx:xx:xx:00:00:00")
            sys.exit(-1)
        if (int(config.dst_mac_address.replace(":", ""), 16) & 0xffffff) \
           != 0:
            lprint("ERROR: For L2 tests the Destination Base MAC address must "
                   "be xx:xx:xx:00:00:00")
            sys.exit(-1)

    if (not config.skip_vv_test or not config.skip_pv_test or \
        not config.skip_pvp_test ) and \
        not check_pci_address_string(config.dut_vm_nic_pci):
        lprint("ERROR: You must supply a valid PCI address for the VMs NIC!")
        sys.exit(-1)

    if not config.skip_vv_test and config.second_virtual_interface == '':
        lprint("ERROR: You must supply a second virtual interface to use for testing!")
        sys.exit(-1)

    if not config.skip_vv_test and config.dut_second_vm_address == '':
        lprint("ERROR: You must supply the second DUT VM address!")
        sys.exit(-1)

    if not config.skip_vv_test and \
       not check_pci_address_string(config.dut_second_vm_nic_pci):
        lprint("ERROR: You must supply a valid PCI address for the second VMs NIC!")
        sys.exit(-1)

    if config.dut_second_vm_address != '' and config.dut_vm_nic_pci == '':
        lprint("ERROR: You must supply the second DUT VM host's NIC PCI address!")
        sys.exit(-1)

    if config.physical_interface == '':
        lprint("ERROR: You must supply the physical interface to use for testing!")
        sys.exit(-1)

    if config.run_pp_test and config.second_physical_interface == '':
        lprint("ERROR: You must supply the second physical interface to use for testing!")
        sys.exit(-1)

    if (not config.skip_vv_test or not config.skip_pv_test or \
       not config.skip_pvp_test) and config.virtual_interface == '':
        lprint("ERROR: You must supply the virtual interface to use for testing!")
        sys.exit(-1)

    if config.tester_address == '':
        lprint("ERROR: You must supply the tester's address to use for testing!")
        sys.exit(-1)

    if config.tester_interface == '':
        lprint("ERROR: You must supply the tester's interface to use for testing!")
        sys.exit(-1)

    if config.run_pp_test and config.second_tester_interface == '':
        lprint("ERROR: You must supply the second tester's interface to use for testing!")
        sys.exit(-1)

    if not tester_interface_valid(config.tester_interface):
        lprint("ERROR: Invalid tester interface configuration!")
        sys.exit(-1)

    if config.second_tester_interface != '' and \
       not tester_interface_valid(config.second_tester_interface):
        lprint("ERROR: Invalid second tester interface configuration!")
        sys.exit(-1)

    if not check_list(config.stream_list, 1, 1000000):
        lprint("ERROR: Invalid stream list, \"{}\", supplied!".format(config.stream_list))
        sys.exit(-1)

    if config.flow_type == 'L4-UDP' and not check_list(config.stream_list, 1, 65535):
        lprint("ERROR: Invalid stream list, \"{}\", supplied for L4 flows!".
               format(config.stream_list))
        sys.exit(-1)

    if not check_list(config.packet_list, 64, 9000):
        lprint("ERROR: Invalid packet list, \"{}\", supplied!".format(config.packet_list))
        sys.exit(-1)

    if config.run_time < 20 or config.run_time > 3600:
        lprint("ERROR: Run time should be [20..3600] seconds!")
        sys.exit(-1)

    if config.physical_speed != 0 and \
       (config.physical_speed < 0 or config.physical_speed > 1000):
        lprint("ERROR: Invalid physical speed supplied [1..1000]!")
        sys.exit(-1)

    if config.dut_vm_nic_queues < 1 or config.dut_vm_nic_queues > 63:
        lprint("ERROR: Invalid VM NIC queue count supplied [1..63]!")
        sys.exit(-1)

    if config.run_vxlan_test and config.no_bridge_config:
        #
        # We can only support tunnels with no bridge config, if no other tests
        # are ran, as it needs a special config compared to the other tests.
        #
        if not config.skip_vv_test or not config.skip_pv_test \
           or not config.skip_pvp_test or config.run_pp_test:
            lprint("ERROR: Tunnel tests can only be run individually "
                   "with the no-bridge-config option!")
            sys.exit(-1)

    if config.run_vxlan_test and config.flow_type != 'L3':
        lprint("ERROR: Tunnel tests only support the L3 flow type!")
        sys.exit(-1)

    if config.run_vxlan_test and not check_list(config.packet_list, 96, 9000):
        #
        # ETH + IPv4 + UDP + VXLAN + ETH + IPv4 + UDP + ETH_CRC
        #
        lprint("ERROR: Minimal packet size for the VXLAN test should be 96 bytes!")
        sys.exit(-1)

    if config.warm_up and (not config.skip_vv_test or config.run_vxlan_test):
        lprint("WARNING: Warm-up only works for P2P, P2V, and P2V2P tests!")

    #
    # Dump settings if global debug is enabled
    #
    if config.debug:
        logger = logging.getLogger()
        logger.setLevel(logging.DEBUG)

    if config.debug_script or config.debug:
        slogger.setLevel(logging.DEBUG)

    if config.debug_scapy or config.debug:
        logging.getLogger("scapy.runtime").setLevel(logging.DEBUG)

    slogger.debug("Configured values:")
    slogger.debug("  %-23.23s: %s", 'Debug', config.debug)
    slogger.debug("  %-23.23s: %s", 'Debug DUT Shell', config.debug_dut_shell)
    slogger.debug("  %-23.23s: %s", 'Debug Scapy', config.debug_scapy)
    slogger.debug("  %-23.23s: %s", 'Debug Script', config.debug_script)
    slogger.debug("  %-23.23s: %s", 'Debug Tester', config.debug_tester)
    slogger.debug("  %-23.23s: %s", 'Flow Type', config.flow_type)
    slogger.debug("  %-23.23s: %s", 'Perf tracing', config.perf)
    slogger.debug("  %-23.23s: %s", 'Tester Type', config.tester_type)
    slogger.debug("  %-23.23s: %s", 'Tester Address', config.tester_address)
    slogger.debug("  %-23.23s: %s", 'Tester Interface', config.tester_interface)
    slogger.debug("  %-23.23s: %s", 'Second Tester Interface', config.second_tester_interface)
    slogger.debug("  %-23.23s: %s", 'OVS Bridge Name', config.bridge_name)
    slogger.debug("  %-23.23s: %s", 'OVS DUT Address', config.ovs_address)
    slogger.debug("  %-23.23s: %s", 'OVS DUT Login', config.ovs_user)
    slogger.debug("  %-23.23s: %s", 'OVS DUT VM1 Address', config.dut_vm_address)
    slogger.debug("  %-23.23s: %s", 'OVS DUT VM2 Address', config.dut_second_vm_address)
    slogger.debug("  %-23.23s: %s", 'OVS DUT VM1 PCI Address', config.dut_vm_nic_pci)
    slogger.debug("  %-23.23s: %s", 'OVS DUT VM2 PCI Address', config.dut_second_vm_nic_pci)
    slogger.debug("  %-23.23s: %s", 'OVS VM Login', config.dut_vm_user)
    slogger.debug("  %-23.23s: %s", 'OVS VM NIC queues', config.dut_vm_nic_queues)
    slogger.debug("  %-23.23s: %s", 'OVS VM NIC rxd', config.dut_vm_nic_rxd)
    slogger.debug("  %-23.23s: %s", 'OVS VM NIC txd', config.dut_vm_nic_txd)
    slogger.debug("  %-23.23s: %s", 'Physical Interface', config.physical_interface)
    slogger.debug("  %-23.23s: %u Gbit/s", 'Physical Int. Speed', config.physical_speed)
    slogger.debug("  %-23.23s: %s", 'Virtual Interface', config.virtual_interface)
    slogger.debug("  %-23.23s: %s", '2nd Virtual Interface', config.second_virtual_interface)
    slogger.debug("  %-23.23s: %s", 'MAC swap', config.mac_swap)
    slogger.debug("  %-23.23s: %s", 'Source MAC', config.src_mac_address)
    slogger.debug("  %-23.23s: %s", 'Destination MAC', config.dst_mac_address)
    slogger.debug("  %-23.23s: %u seconds", 'Test run time', config.run_time)
    slogger.debug("  %-23.23s: %s", 'Run with stream size\'s', config.stream_list)
    slogger.debug("  %-23.23s: %s", 'Run with packet size\'s', config.packet_list)
    slogger.debug("  %-23.23s: %s", 'Skip PV test', config.skip_pv_test)
    slogger.debug("  %-23.23s: %s", 'Skip PVP test', config.skip_pvp_test)
    slogger.debug("  %-23.23s: %s", 'Skip VV test', config.skip_vv_test)
    slogger.debug("  %-23.23s: %s", 'Run PP test', config.run_pp_test)
    slogger.debug("  %-23.23s: %s", 'Warm-up', config.warm_up)
    slogger.debug("  %-23.23s: %s", 'No-cool-down', config.no_cool_down)

    #
    # If we use the GUI, we need to set the correct back-end
    # However this does not seem to work always in a non-Tk back-end, if you get
    # Tinker errors, set the following environment variable:
    #   export MPLBACKEND="agg"
    #
    # if config.gui:
    #     matplotlib.use('TkAgg')
    # else:
    #     matplotlib.use('Agg')
    #
    # Commenting out the above, as it no longer works. Use the export as
    # explained above as python loads the modules beforehand.

    import matplotlib.pyplot as plt
    from matplotlib.ticker import ScalarFormatter, FormatStrFormatter

    #
    # Quick regenerate grapgh from results (DEBUG)
    #
    # packet_sizes = [64, 128, 256, 512, 1024, 1514]
    # p2v_results = [22969229, 25139846, 18116596, 9398727, 4789329, 3259472]
    # create_single_graph(packet_sizes, p2v_results,
    #                     "Packet size", "Packets/second",
    #                     "Physical to Virtual with 1000 flows",
    #                     "test_p2v_1000")
    # sys.exit(-1)

    #
    # Connecting to Tester
    #
    lprint("- Connecting to the tester...")

    tester = TrafficGenerator(get_traffic_generator_type(),
                              hostname=config.tester_address)

    if config.debug_tester:
        logging.getLogger('xenalib.BaseSocket').setLevel(logging.DEBUG)
        logging.getLogger('xenalib.KeepAliveThread').setLevel(logging.DEBUG)
        logging.getLogger('xenalib.XenaManager').setLevel(logging.DEBUG)
        logging.getLogger('xenalib.XenaModifier').setLevel(logging.DEBUG)
        logging.getLogger('xenalib.XenaPort').setLevel(logging.DEBUG)
        logging.getLogger('xenalib.XenaSocket').setLevel(logging.DEBUG)
        logging.getLogger('xenalib.XenaStream').setLevel(logging.DEBUG)

    if not tester.reserve_port(config.tester_interface):
        lprint("ERROR: Failed to add first tester port")
        sys.exit(-1)

    if config.second_tester_interface != '':
        if not tester.reserve_port(config.second_tester_interface):
            lprint("ERROR: Failed to add second tester port")
            sys.exit(-1)

    #
    # Connecting to DUT
    #
    lprint("- Connecting to DUT, \"{}\"...".format(config.ovs_address))

    dut_shell = DutSshShell(hostname=config.ovs_address,
                            username=config.ovs_user,
                            password=config.ovs_password,
                            missing_host_key=spur.ssh.MissingHostKey.accept)

    if config.debug_dut_shell:
        dut_shell.logger.setLevel(logging.DEBUG)

    ovs_version = get_ovs_version()

    #
    # Stop any running test tools on the VMs
    #
    #
    lprint("- Stop any running test tools...")
    stop_cpu_monitoring(die=False)
    if config.dut_vm_address != '':
        stop_traffic_rx_on_vm(config.dut_vm_address, die=False)
        stop_traffic_tx_on_vm(config.dut_vm_address, die=False)
        lprint("- Getting VM's DPDK version...")
        vm_dpdk_version = get_vm_dpdk_version(config.dut_vm_address)
    if config.dut_second_vm_address != '':
        stop_traffic_rx_on_vm(config.dut_second_vm_address, die=False)
        stop_traffic_tx_on_vm(config.dut_second_vm_address, die=False)

    #
    # Create OVS bridge, and get OpenFlow port numbers
    #
    if not config.no_bridge_config:
        if not config.skip_pv_test or not config.skip_pvp_test or \
           not config.skip_vv_test or config.run_pp_test:
            #
            # Also skip if all we are running are the tunnel tests
            #
            create_ovs_bridge()

    #
    # If we run only tunnel tests we need to skip this
    #
    if not config.skip_pv_test or not config.skip_pvp_test or \
       not config.skip_vv_test or config.run_pp_test:

        of_interfaces = dict()
        dp_interfaces = dict()

        of_interfaces, dp_interfaces = get_bridge_port_numbers()

    #
    # Getting physical port speed, used for graphs
    #
    if config.physical_speed != 0:
        phy_speed = config.physical_speed * 1000000000
    else:
        phy_speed = get_physical_port_speed()

    #
    # Get datapath type
    #
    ovs_data_path = get_ovs_datapath()
    lprint("- Get OVS datapath type, \"{}\"...".format(ovs_data_path))

    #
    # Open CSV file for writing
    #
    lprint("- Create \"test_results.csv\" for writing results...")

    if config.flow_type == 'L2':
        csv_file = "test_results_l2.csv"
    elif config.flow_type == 'L3':
        csv_file = "test_results_l3.csv"
    elif config.flow_type == 'L4-UDP':
        csv_file = "test_results_l4_udp.csv"
    else:
        raise ValueError("No support for this protocol!!")

    with open(csv_file, 'w') as csvfile:
        csv_handle = csv.writer(csvfile, dialect='excel')

        csv_handle.writerow(["Physical port, \"{}\", speed {} Gbit/s".
                             format(config.physical_interface,
                                    phy_speed / 1000000000)])
        csv_handle.writerow([])
        csv_handle.writerow([])

        #
        # Run tests
        #
        stream_size_list = [int(i) for i in config.stream_list.split(',')]
        packet_size_list = [int(i) for i in config.packet_list.split(',')]
        flow_str = get_flow_type_short()
        flow_file_str = get_flow_type_name()

        v2v_results = dict()
        v2v_cpu_results = dict()
        p2v_results = dict()
        p2v_cpu_results = dict()
        p2p_results = dict()
        p2p_cpu_results = dict()
        p2v2p_results = dict()
        p2v2p_cpu_results = dict()

        if not config.skip_vv_test:
            for nr_of_streams in stream_size_list:
                v2v_results[nr_of_streams], \
                    v2v_cpu_results[nr_of_streams] = test_v2v(nr_of_streams, packet_size_list)

                create_multiple_graph(packet_size_list, v2v_results,
                                      "Packet size", "Packets/second",
                                      "Virtual to Virtual, {}".
                                      format(get_flow_type_short()),
                                      "test_v2v_all_{}".
                                      format(get_flow_type_name()),
                                      None, cpu_utilization=v2v_cpu_results)

                create_multiple_graph(packet_size_list, v2v_results,
                                      "Packet size", "Packets/second",
                                      "Virtual to Virtual, {}".
                                      format(get_flow_type_short()),
                                      "test_v2v_all_{}_ref".
                                      format(get_flow_type_name()),
                                      [phy_speed], cpu_utilization=v2v_cpu_results)

            csv_write_test_results(csv_handle, 'Virtual to Virtual test',
                                   stream_size_list, packet_size_list,
                                   v2v_results, v2v_cpu_results)

        if not config.skip_pv_test:
            for nr_of_streams in stream_size_list:
                p2v_results[nr_of_streams], \
                    p2v_cpu_results[nr_of_streams] = test_p2v(nr_of_streams, packet_size_list)

                create_multiple_graph(packet_size_list, p2v_results,
                                      "Packet size", "Packets/second",
                                      "Physical to Virtual, {}".format(flow_str),
                                      "test_p2v_all_{}".format(flow_file_str),
                                      None, cpu_utilization=p2v_cpu_results)

                create_multiple_graph(packet_size_list, p2v_results,
                                      "Packet size", "Packets/second",
                                      "Physical to Virtual, {}".format(flow_str),
                                      "test_p2v_all_{}_ref".format(flow_file_str),
                                      [phy_speed], cpu_utilization=p2v_cpu_results)

            csv_write_test_results(csv_handle, 'Physical to Virtual test',
                                   stream_size_list, packet_size_list,
                                   p2v_results, p2v_cpu_results)

        if not config.skip_pvp_test:
            for nr_of_streams in stream_size_list:
                p2v2p_results[nr_of_streams], \
                    p2v2p_cpu_results[nr_of_streams] = test_p2v2p(nr_of_streams,
                                                                  packet_size_list)

                create_multiple_graph(packet_size_list, p2v2p_results,
                                      "Packet size", "Packets/second",
                                      "Physical to Virtual to Physical, {}".format(flow_str),
                                      "test_p2v2p_all_{}".format(flow_file_str),
                                      None, cpu_utilization=p2v2p_cpu_results)

                create_multiple_graph(packet_size_list, p2v2p_results,
                                      "Packet size", "Packets/second",
                                      "Physical to Virtual to Physical, {}".format(flow_str),
                                      "test_p2v2p_all_{}_ref".format(flow_file_str),
                                      [phy_speed], cpu_utilization=p2v2p_cpu_results)

            csv_write_test_results(csv_handle,
                                   'Physical to Virtual to Physical test',
                                   stream_size_list, packet_size_list,
                                   p2v2p_results, p2v2p_cpu_results)

        if config.run_pp_test:
            for nr_of_streams in stream_size_list:
                p2p_results[nr_of_streams], \
                    p2p_cpu_results[nr_of_streams] = test_p2p(nr_of_streams, packet_size_list)

                create_multiple_graph(packet_size_list, p2p_results,
                                      "Packet size", "Packets/second",
                                      "Physical to Physical, {}".format(flow_str),
                                      "test_p2p_all_{}".format(flow_file_str),
                                      None, cpu_utilization=p2p_cpu_results)

                create_multiple_graph(packet_size_list, p2p_results,
                                      "Packet size", "Packets/second",
                                      "Physical to Physical, {}".format(flow_str),
                                      "test_p2p_all_{}_ref".format(flow_file_str),
                                      [phy_speed], cpu_utilization=p2p_cpu_results)

            csv_write_test_results(csv_handle, 'Physical to Physical test',
                                   stream_size_list, packet_size_list,
                                   p2p_results, p2p_cpu_results)

        if config.run_vxlan_test:
            if not config.no_bridge_config:
                create_ovs_vxlan_bridge()

            of_interfaces = dict()
            dp_interfaces = dict()

            of_interfaces, dp_interfaces = get_bridge_port_numbers(tunnel=True)

            vxlan_results = dict()
            vxlan_cpu_results = dict()

            for nr_of_streams in stream_size_list:
                vxlan_results[nr_of_streams], \
                    vxlan_cpu_results[nr_of_streams] = test_vxlan(nr_of_streams,
                                                                  packet_size_list)

                create_multiple_graph(packet_size_list, vxlan_results,
                                      "Packet size", "Packets/second",
                                      "VXLAN Tunnel, {}".format(flow_str),
                                      "test_vxlan_all_{}".format(flow_file_str),
                                      None, cpu_utilization=vxlan_cpu_results)

                create_multiple_graph(packet_size_list, vxlan_results,
                                      "Packet size", "Packets/second",
                                      "VXLAN Tunnel, {}".format(flow_str),
                                      "test_vxlan_all_{}_ref".format(flow_file_str),
                                      [phy_speed], cpu_utilization=vxlan_cpu_results)

            csv_write_test_results(csv_handle, 'VXLAN Tunnel',
                                   stream_size_list, packet_size_list,
                                   vxlan_results, vxlan_cpu_results)

    #
    # Done...
    #
    lprint("- Done running performance tests!")

    #   For now we leave the DUT in the last test state in case we would like
    #   to do some trouble shooting. First step in re-run is to remove bridge,
    #   and delete all openflow rules.
    tester.disconnect()
    del tester


#
# Start main() as default entry point...
#
if __name__ == '__main__':
    main()
