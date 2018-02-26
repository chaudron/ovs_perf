#!/bin/sh
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
#    runfullday.sh
#
#  Description:
#    Simple script to run the OVS performance test script for a day
#
#  Author:
#    Eelco Chaudron
#
#  Initial Created:
#    11 October 2017
#

echo "This script will run the tests as explained in the \"Full day PVP test\""
echo "section. It will start the scripts according to the configuration given below,"
echo "and will archive the results."
echo
echo "NOTE: Make sure you are passing the basic test as explained in \"Running the "
echo "      PVP script\" before starting the full day run!"
echo


#
# Get all the configuration details from the user
#
unset DATAPATH
while [[ ! ${DATAPATH} =~ ^dpdk|kernel|tc$ ]]; do
    echo -n "What datapath are you using, DPDK or Linux Kernel [dpdk/kernel/tc]? "
    read DATAPATH
done

if [[ ${DATAPATH} = "dpdk" ]]; then
  NIC_Q=2
else
  NIC_Q=1
fi

echo -n "What is the IP address where the DUT (Open vSwitch) is running? "
read DUT_IP

echo -n "What is the root password of the DUT? "
read DUT_PW

echo -n "What is the IP address of the virtual machine running on the DUT? "
read VM_IP

echo -n "What is the IP address of the TRex tester? "
read TREX_IP

echo -n "What is the physical interface being used, i.e. dpdk0, em1, p4p5? "
read PHY_INT

echo -n "What is the virtual interface being used, i.e. vhost0, vnet0? "
read VM_INT

echo -n "What is the virtual interface PCI id? "
read VM_PCI

echo -n "What is the TRex tester physical interface being used? "
read TREX_INT

echo -n "What is the link speed of the physical interface, i.e. 10(default),25,40,50,100? "
read NIC_SPD
case $NIC_SPD in
10 | 25 | 40 | 50 | 100) ;;
*) NIC_SPD=10 ;;
esac

#
# Execute the four tests in order...
#
mkdir -p ~/pvp_results_10_l2_$DATAPATH
cd ~/pvp_results_10_l2_$DATAPATH
~/ovs_perf/ovs_performance.py \
  -d -l testrun_log.txt \
  --tester-type trex \
  --tester-address $TREX_IP \
  --tester-interface $TREX_INT \
  --ovs-address $DUT_IP \
  --ovs-user root \
  --ovs-password $DUT_PW \
  --dut-vm-address $VM_IP \
  --dut-vm-user root \
  --dut-vm-password root \
  --dut-vm-nic-queues=$NIC_Q \
  --physical-interface $PHY_INT \
  --physical-speed=$NIC_SPD \
  --virtual-interface $VM_INT \
  --dut-vm-nic-pci=$VM_PCI \
  --no-bridge-config \
  --skip-pv-test \
  --flow-type=L2 \
  --run-time=1000


mkdir -p ~/pvp_results_10_l3_$DATAPATH
cd ~/pvp_results_10_l3_$DATAPATH
~/ovs_perf/ovs_performance.py \
  -d -l testrun_log.txt \
  --tester-type trex \
  --tester-address $TREX_IP \
  --tester-interface $TREX_INT \
  --ovs-address $DUT_IP \
  --ovs-user root \
  --ovs-password $DUT_PW \
  --dut-vm-address $VM_IP \
  --dut-vm-user root \
  --dut-vm-password root \
  --dut-vm-nic-queues=$NIC_Q \
  --physical-interface $PHY_INT \
  --physical-speed=$NIC_SPD \
  --virtual-interface $VM_INT \
  --dut-vm-nic-pci=$VM_PCI \
  --no-bridge-config \
  --skip-pv-test \
  --flow-type=L3 \
  --run-time=1000


mkdir -p ~/pvp_results_1_l2_$DATAPATH
cd ~/pvp_results_1_l2_$DATAPATH
~/ovs_perf/ovs_performance.py \
  -d -l testrun_log.txt \
  --tester-type trex \
  --tester-address $TREX_IP \
  --tester-interface $TREX_INT \
  --ovs-address $DUT_IP \
  --ovs-user root \
  --ovs-password $DUT_PW \
  --dut-vm-address $VM_IP \
  --dut-vm-user root \
  --dut-vm-password root \
  --dut-vm-nic-queues=$NIC_Q \
  --physical-interface $PHY_INT \
  --physical-speed=$NIC_SPD \
  --virtual-interface $VM_INT \
  --dut-vm-nic-pci=$VM_PCI \
  --no-bridge-config \
  --skip-pv-test \
  --flow-type=L2


mkdir -p ~/pvp_results_1_l3_$DATAPATH
cd ~/pvp_results_1_l3_$DATAPATH
~/ovs_perf/ovs_performance.py \
  -d -l testrun_log.txt \
  --tester-type trex \
  --tester-address $TREX_IP \
  --tester-interface $TREX_INT \
  --ovs-address $DUT_IP \
  --ovs-user root \
  --ovs-password $DUT_PW \
  --dut-vm-address $VM_IP \
  --dut-vm-user root \
  --dut-vm-password root \
  --dut-vm-nic-queues=$NIC_Q \
  --physical-interface $PHY_INT \
  --physical-speed=$NIC_SPD \
  --virtual-interface $VM_INT \
  --dut-vm-nic-pci=$VM_PCI \
  --no-bridge-config \
  --skip-pv-test \
  --flow-type=L3


#
# Verify the results are ok, i.e. meaning we received traffic on all occasions.
#
echo "================================================================================="
echo "== ALL TESTS ARE DONE                                                         ==="
echo "================================================================================="
echo

#
# Check that all test have packets passing...
#
if grep -h -E "^10,|^1000,|^10000,|^100000,|^1000000," \
    ~/pvp_results_1*_l*_*/test_results_l*.csv | \
    tr -s '\n\r' ',' | grep -q ",0,"; then
  echo "!! ERROR: Failed test, found a test with 0 packet troughput!!"
fi

#
# Check the 256 byte, 10 Flow test, and make sure they have at least 75%
# of line rate at L3
#
if [[ ${DATAPATH} = "dpdk" ]]; then
    L3_10_DPDK=`grep -h "^10," ~/pvp_results_1*_l3_dpdk/test_results_l3.csv | \
        cut -d ',' -f 4`
    for L3_10_DPDK in $L3_10_DPDK; do
        L3_10_OK=`bc <<-EOF
		${L3_10_DPDK} >= (${NIC_SPD}*1000000000*0.75)/(8*(256+12+8))
		EOF
		`
        case "$L3_10_OK" in
        1) ;; # l3 pvp above 75% line rate
        0|*)
            echo "!! WARNING: L3 PVP test did not hit 75% of $NIC_SPD line rate !!"
            echo
            echo "    NOTE: Depending on the expected throughput of the blade this might be a"
            echo "          problem."
            ;;
        esac
    done
fi
echo
echo "Please verify all the results and make sure they are within the expected"
echo "rates for the blade!!"
echo

#
# tar up the results...
#
echo "================================================================================="

FILENAME=~/pvp_results_`date +%Y-%m-%d_%H%M%S`_${DATAPATH}.tgz
tar -czf ${FILENAME} ~/pvp_results_*_${DATAPATH} && rm -rf ~/pvp_results_*_${DATAPATH}

echo "All test results are saved in: \"${FILENAME}\""
